/**
 * core/mjksmap.ts
 *
 * MajikSignatureMap — a single manifest mapping every file in a batch/zip
 * to its detached MajikSignatureEnvelope.
 *
 * Design constraints (same as MajikSignatureEnvelope):
 *   - Pure/structural only. No crypto — verification is composed by callers
 *     via MajikSignature.verifyFileDetached() using an entry's envelope.
 *   - Immutable. withEntry() returns a new instance.
 *   - Keyed by path, not contentHash — duplicate-content files across a
 *     batch are legitimate and must not collide. contentHash is retained
 *     per-entry as an integrity check and as a secondary lookup index.
 */

import {
  MajikSignatureSerializationError,
  MajikSignatureValidationError,
} from "./errors";
import { hashContent, bytesToBase64 } from "./hash";
import { MajikSignatureEnvelope } from "./envelope";
import {
  MJKSMAP_HEADER_LEN,
  MJKSMAP_MAGIC,
  MJKSMAP_MAGIC_LEN,
  MJKSMAP_MEDIA_TYPE,
  MJKSMAP_SUPPORTED_VERSIONS,
  MJKSMAP_VERSION,
} from "./constants";
import type {
  MajikSignatureEnvelopeJSON,
  MjksMapEntry,
  MjksMapFindResult,
  MjksMapJSON,
  MjksMapResolveResult,
} from "./types";

// ─── Path normalization ────────────────────────────────────────────────────────

/**
 * Normalize a path for use as a map key: forward slashes, no leading slash,
 * no drive letters. Same normalization lesson already hit with Tauri
 * fs:scope globs (backslashes silently fail) — applied here proactively
 * rather than waiting to hit it again in batch workflows.
 */
function normalizePath(path: string): string {
  let p = path.replace(/\\/g, "/").trim();
  p = p.replace(/^[a-zA-Z]:/, ""); // strip drive letters (C:, D:, ...)
  p = p.replace(/^\/+/, ""); // strip leading slashes
  return p;
}

// ─── MajikSignatureMap ─────────────────────────────────────────────────────────

export class MajikSignatureMap {
  private readonly _version: 1;
  private readonly _createdAt: string;
  private readonly _entries: readonly MjksMapEntry[];

  // Lazily built, cached lookup indices — never serialized, purely in-memory
  // acceleration derived from _entries. Rebuilt whenever a new instance is
  // constructed via #withEntries(), never mutated in place.
  private readonly _byPath: ReadonlyMap<string, MjksMapEntry>;
  private readonly _byHash: ReadonlyMap<string, readonly MjksMapEntry[]>;

  private constructor(data: MjksMapJSON) {
    this._version = data.version;
    this._createdAt = data.createdAt;
    this._entries = data.entries.map((e) => ({
      ...e,
      path: normalizePath(e.path),
    }));

    const byPath = new Map<string, MjksMapEntry>();
    const byHash = new Map<string, MjksMapEntry[]>();
    for (const entry of data.entries) {
      byPath.set(entry.path, entry);
      const existing = byHash.get(entry.contentHash);
      if (existing) existing.push(entry);
      else byHash.set(entry.contentHash, [entry]);
    }
    this._byPath = byPath;
    this._byHash = byHash;
  }

  // ── Getters ─────────────────────────────────────────────────────────────────

  get version(): 1 {
    return this._version;
  }
  get createdAt(): string {
    return this._createdAt;
  }
  get entries(): readonly MjksMapEntry[] {
    return this._entries;
  }
  get size(): number {
    return this._entries.length;
  }

  // ── Lookup ─────────────────────────────────────────────────────────────────
  /**
   * Resolve a file against the map, tolerating relocation.
   *
   * Tries the exact given path first (cheap, no hashing needed for the miss
   * case... well, actually a match still needs the hash check below). If
   * that path isn't in the map, falls back to a content-based search — this
   * is what makes the map resilient to the batch being reorganized, renamed,
   * or moved to a different folder/device after signing, since none of that
   * changes a file's content or its signatures.
   *
   * "relocated" is reported as its own status rather than folded into
   * "path_match" — a caller may reasonably want to flag/re-index a file
   * that moved, even though its signature is still perfectly valid.
   */
  async resolveEntry(path: string, file: Blob): Promise<MjksMapResolveResult> {
    const direct = await this.findEntry(path, file);

    if (direct.found) {
      return direct.hashMatches
        ? { status: "path_match", entry: direct.entry }
        : { status: "path_tampered", entry: direct.entry };
    }

    const byHash = await this.findEntriesByHash(file);
    if (byHash.length > 0) {
      // Multiple matches (duplicate-content files) — first is a reasonable
      // default, but exposing all of them lets the caller disambiguate.
      return {
        status: "relocated",
        entry: byHash[0],
        originalPath: byHash[0].path,
      };
    }

    return { status: "not_found" };
  }

  /** Raw entry lookup by exact path — no hash verification, no file needed. */
  getEntry(path: string): MjksMapEntry | undefined {
    return this._byPath.get(normalizePath(path));
  }

  /**
   * Resolve a specific file's envelope, given its path AND its current bytes.
   * Recomputes the hash and compares against the stored contentHash — this
   * is the integrity check that catches "same name, edited after signing."
   *
   * Returns { found: false } if no entry exists at that path at all.
   * Returns { found: true, hashMatches: false } if the entry exists but the
   * file's current content no longer matches what was signed — the caller
   * decides whether that's fatal (it usually should be, but this method
   * doesn't throw so the caller can present a clear message rather than
   * catching an exception).
   */
  async findEntry(path: string, file: Blob): Promise<MjksMapFindResult> {
    const entry = this.getEntry(path);
    if (!entry) return { found: false };

    const bytes = new Uint8Array(await file.arrayBuffer());
    const recomputedHash = bytesToBase64(hashContent(bytes));

    return {
      found: true,
      entry,
      hashMatches: recomputedHash === entry.contentHash,
    };
  }

  /**
   * Find every entry matching a file's content, regardless of path.
   * Returns an array (not a single entry) because duplicate-content files
   * are legitimate — collapsing to one result would silently hide the rest.
   * Use when the file may have been renamed/relocated after extraction.
   */
  async findEntriesByHash(file: Blob): Promise<MjksMapEntry[]> {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const hash = bytesToBase64(hashContent(bytes));
    return [...(this._byHash.get(hash) ?? [])];
  }

  /**
   * Resolve a specific entry's envelope as a rich MajikSignatureEnvelope
   * instance (not just the stored JSON) — matches the convention that every
   * "give me a signature-shaped thing" method in this library returns the
   * behavior-rich class, not raw wire JSON.
   * Returns null if no entry exists at that path.
   */
  getEnvelope(path: string): MajikSignatureEnvelope | null {
    const entry = this.getEntry(path);
    return entry ? MajikSignatureEnvelope.fromJSON(entry.envelope) : null;
  }

  /**
   * All envelopes in the map, each paired with its path, as rich
   * MajikSignatureEnvelope instances. Useful for bulk operations —
   * e.g. rendering a signing-status table for an entire extracted batch
   * without looking up each file individually.
   */
  getAllEnvelopes(): { path: string; envelope: MajikSignatureEnvelope }[] {
    return this._entries.map((entry) => ({
      path: entry.path,
      envelope: MajikSignatureEnvelope.fromJSON(entry.envelope),
    }));
  }

  hasEntry(path: string): boolean {
    return this._byPath.has(normalizePath(path));
  }

  // ── Builders (immutable) ─────────────────────────────────────────────────────

  /**
   * Add or replace an entry by path. Path is normalized before storage and
   * before the uniqueness check, so "docs/a.pdf" and "docs\\a.pdf" collide
   * as the same key rather than silently duplicating.
   */
  withEntry(entry: MjksMapEntry): MajikSignatureMap {
    if (!entry.path || !entry.path.trim()) {
      throw new MajikSignatureValidationError(
        "Entry must have a non-empty path.",
        "path",
      );
    }
    if (!entry.contentHash || !entry.contentHash.trim()) {
      throw new MajikSignatureValidationError(
        "Entry must have a non-empty contentHash.",
        "contentHash",
      );
    }

    const normalized: MjksMapEntry = {
      ...entry,
      path: normalizePath(entry.path),
    };

    const filtered = this._entries.filter((e) => e.path !== normalized.path);

    return new MajikSignatureMap({
      version: this._version,
      createdAt: this._createdAt,
      entries: [...filtered, normalized],
    });
  }

  withoutEntry(path: string): MajikSignatureMap {
    const normalized = normalizePath(path);
    return new MajikSignatureMap({
      version: this._version,
      createdAt: this._createdAt,
      entries: this._entries.filter((e) => e.path !== normalized),
    });
  }

  // ── Serialization ─────────────────────────────────────────────────────────────

  toJSON(): MjksMapJSON {
    return {
      version: this._version,
      createdAt: this._createdAt,
      entries: [...this._entries],
    };
  }

  // ── MJKSMAP binary format ─────────────────────────────────────────────────
  //
  // Same rationale as MJKSIG: length-prefixed JSON behind a versioned,
  // self-identifying header. toMJKSMAP() returns a Blob for direct use in
  // zip packaging / downloads; toMJKSMAPBytes() is the sync Uint8Array
  // escape hatch for non-Blob contexts (Node scripts, direct fs writes).

  toMJKSMAPBytes(): Uint8Array {
    const payloadJson = new TextEncoder().encode(JSON.stringify(this.toJSON()));
    const out = new Uint8Array(MJKSMAP_HEADER_LEN + payloadJson.length);

    out.set(MJKSMAP_MAGIC, 0);
    out[MJKSMAP_MAGIC_LEN] = MJKSMAP_VERSION;
    out[MJKSMAP_MAGIC_LEN + 1] = 0x00; // reserved — always 0 in v1

    const lenOffset = MJKSMAP_MAGIC_LEN + 2;
    out[lenOffset] = (payloadJson.length >>> 24) & 0xff;
    out[lenOffset + 1] = (payloadJson.length >>> 16) & 0xff;
    out[lenOffset + 2] = (payloadJson.length >>> 8) & 0xff;
    out[lenOffset + 3] = payloadJson.length & 0xff;

    out.set(payloadJson, MJKSMAP_HEADER_LEN);
    return out;
  }

  toMJKSMAP(): Blob {
    const bytes = this.toMJKSMAPBytes();
    return new Blob([bytes as BlobPart], { type: MJKSMAP_MEDIA_TYPE });
  }

  static async fromMJKSMAP(
    input: Blob | Uint8Array,
  ): Promise<MajikSignatureMap> {
    const raw =
      input instanceof Blob ? new Uint8Array(await input.arrayBuffer()) : input;
    return MajikSignatureMap.#parseMJKSMAPBytes(raw);
  }

  static #parseMJKSMAPBytes(raw: Uint8Array): MajikSignatureMap {
    if (raw.length < MJKSMAP_HEADER_LEN + 1) {
      throw new MajikSignatureSerializationError(
        "Malformed MJKSMAP: too short to contain a valid header",
      );
    }

    for (let i = 0; i < MJKSMAP_MAGIC_LEN; i++) {
      if (raw[i] !== MJKSMAP_MAGIC[i]) {
        throw new MajikSignatureSerializationError(
          'Malformed MJKSMAP: missing "MJKSMAP" magic bytes',
        );
      }
    }

    const version = raw[MJKSMAP_MAGIC_LEN];
    if (!(MJKSMAP_SUPPORTED_VERSIONS as readonly number[]).includes(version)) {
      throw new MajikSignatureSerializationError(
        `Unsupported MJKSMAP version: ${version} (supported: ${MJKSMAP_SUPPORTED_VERSIONS.join(", ")})`,
      );
    }

    const lenOffset = MJKSMAP_MAGIC_LEN + 2;
    const payloadLen =
      (raw[lenOffset] << 24) |
      (raw[lenOffset + 1] << 16) |
      (raw[lenOffset + 2] << 8) |
      raw[lenOffset + 3];

    if (payloadLen <= 0) {
      throw new MajikSignatureSerializationError(
        "Malformed MJKSMAP: invalid payload length",
      );
    }

    const payloadStart = MJKSMAP_HEADER_LEN;
    const payloadEnd = payloadStart + payloadLen;
    if (payloadEnd > raw.length) {
      throw new MajikSignatureSerializationError(
        "Malformed MJKSMAP: declared payload length exceeds buffer",
      );
    }

    const json = new TextDecoder().decode(raw.slice(payloadStart, payloadEnd));
    return MajikSignatureMap.fromJSON(json);
  }

  static async isMJKSMAP(input: Blob | Uint8Array): Promise<boolean> {
    const header =
      input instanceof Blob
        ? new Uint8Array(await input.slice(0, MJKSMAP_MAGIC_LEN).arrayBuffer())
        : input;

    if (header.length < MJKSMAP_MAGIC_LEN) return false;
    for (let i = 0; i < MJKSMAP_MAGIC_LEN; i++) {
      if (header[i] !== MJKSMAP_MAGIC[i]) return false;
    }
    return true;
  }

  // ── Creation / parsing ───────────────────────────────────────────────────────

  static empty(): MajikSignatureMap {
    return new MajikSignatureMap({
      version: MJKSMAP_VERSION as 1,
      createdAt: new Date().toISOString(),
      entries: [],
    });
  }

  static fromJSON(json: MjksMapJSON | string): MajikSignatureMap {
    let parsed: unknown;
    try {
      parsed = typeof json === "string" ? JSON.parse(json) : json;
    } catch (err) {
      throw new MajikSignatureSerializationError(
        "MJKSMAP payload is not valid JSON",
        err,
      );
    }

    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      throw new MajikSignatureSerializationError(
        "MJKSMAP payload must be a JSON object",
      );
    }

    MajikSignatureMap.#validateShape(parsed as Record<string, unknown>);
    return new MajikSignatureMap(parsed as MjksMapJSON);
  }

  /** Accepts an instance, its JSON shape, or MJKSMAP bytes/Blob. */
  static async from(
    input: MajikSignatureMap | MjksMapJSON | Uint8Array | Blob,
  ): Promise<MajikSignatureMap> {
    if (input instanceof MajikSignatureMap) return input;
    if (input instanceof Uint8Array || input instanceof Blob) {
      return MajikSignatureMap.fromMJKSMAP(input);
    }
    return MajikSignatureMap.fromJSON(input);
  }

  validate(): void {
    MajikSignatureMap.#validateShape(
      this.toJSON() as unknown as Record<string, unknown>,
    );
  }

  isValid(): boolean {
    try {
      this.validate();
      return true;
    } catch {
      return false;
    }
  }

  // ── Private validation ───────────────────────────────────────────────────────

  static #validateShape(obj: Record<string, unknown>): void {
    if (obj.version !== MJKSMAP_VERSION) {
      throw new MajikSignatureValidationError(
        `Unsupported MJKSMAP schema version: ${String(obj.version)}`,
        "version",
      );
    }
    if (typeof obj.createdAt !== "string" || !obj.createdAt) {
      throw new MajikSignatureValidationError(
        "createdAt must be a non-empty ISO 8601 string",
        "createdAt",
      );
    }
    if (!Array.isArray(obj.entries)) {
      throw new MajikSignatureValidationError(
        "entries must be an array",
        "entries",
      );
    }

    const seenPaths = new Set<string>();
    for (const [i, entry] of (obj.entries as unknown[]).entries()) {
      MajikSignatureMap.#validateEntry(entry, i);
      const path = (entry as MjksMapEntry).path;
      if (seenPaths.has(path)) {
        throw new MajikSignatureValidationError(
          `Duplicate path in entries: "${path}"`,
          "path",
        );
      }
      seenPaths.add(path);
    }
  }

  static #validateEntry(entry: unknown, index: number): void {
    if (entry === null || typeof entry !== "object") {
      throw new MajikSignatureValidationError(
        `entries[${index}] must be an object`,
        "entries",
      );
    }
    const obj = entry as Record<string, unknown>;
    if (typeof obj.path !== "string" || !obj.path.trim()) {
      throw new MajikSignatureValidationError(
        `entries[${index}].path must be a non-empty string`,
        "path",
      );
    }
    if (typeof obj.contentHash !== "string" || !obj.contentHash.trim()) {
      throw new MajikSignatureValidationError(
        `entries[${index}].contentHash must be a non-empty string`,
        "contentHash",
      );
    }
    if (obj.envelope === null || typeof obj.envelope !== "object") {
      throw new MajikSignatureValidationError(
        `entries[${index}].envelope must be an object`,
        "envelope",
      );
    }
    // Delegates to MajikSignatureEnvelope's own validation rather than
    // duplicating envelope-shape checks here — single source of truth.
    MajikSignatureEnvelope.fromJSON(obj.envelope as MajikSignatureEnvelopeJSON);
  }
}

// Freeze static methods
Object.freeze(MajikSignatureMap);

// Freeze instance methods
Object.freeze(MajikSignatureMap.prototype);

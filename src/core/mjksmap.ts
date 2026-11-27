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
} from "./errors.js";
import { hashContent, bytesToBase64 } from "./hash.js";
import { MajikSignatureEnvelope } from "./envelope.js";
import { decodeCBOR, encodeCBOR } from "./cbor/cbor.js";
import { mjksMapFromCBOR, mjksMapToCBOR } from "./cbor/cbor-wire.js";
import {
  MAX_MJKSMAP_BYTES,
  MAX_MJKSMAP_JSON_BYTES,
  MAX_MJKSMAP_ENTRIES,
  MAX_MJKSMAP_PATH_CHARS,
  MJKSMAP_HEADER_LEN,
  MJKSMAP_MAGIC,
  MJKSMAP_MAGIC_LEN,
  MJKSMAP_MEDIA_TYPE,
  MJKSMAP_SUPPORTED_VERSIONS,
  MJKSMAP_VERSION,
  MJKSMAP_JSON_VERSION,
  MJKSMAP_SCHEMA_VERSION,
} from "./constants.js";
import { MajikSignatureValidator } from "./validator.js";
import type {
  MajikSignatureEnvelopeJSON,
  MjksMapEntry,
  MjksMapFindResult,
  MjksMapJSON,
  MjksMapResolveResult,
} from "./types.js";

// ─── Path normalization ────────────────────────────────────────────────────────

/**
 * Normalize a path for use as a map key: forward slashes, no leading slash,
 * no drive letters. Same normalization lesson already hit with Tauri
 * fs:scope globs (backslashes silently fail) — applied here proactively
 * rather than waiting to hit it again in batch workflows.
 */
function normalizePath(path: unknown): string {
  if (typeof path !== "string") return "";
  let p = path.replace(/\\/g, "/").trim();
  p = p.replace(/^[a-zA-Z]:/, ""); // strip drive letters (C:, D:, ...)
  p = p.replace(/^\/+/, ""); // strip leading slashes
  return p;
}

/** Recursively freeze JSON snapshots before exposing manifest entry references. */
function deepFreezeJson<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as unknown as Record<string, unknown>)) {
      deepFreezeJson(child);
    }
    Object.freeze(value);
  }
  return value;
}

/** Validate untrusted logical paths before using them as manifest keys. */
function validateAndNormalizePath(path: unknown, field: string): string {
  if (typeof path !== "string" || path.trim().length === 0) {
    throw new MajikSignatureValidationError(`${field} must be a non-empty string`, field);
  }
  if (
    path.length > MAX_MJKSMAP_PATH_CHARS ||
    /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(path)
  ) {
    throw new MajikSignatureValidationError(
      `${field} exceeds the supported path length or contains unsafe control characters`,
      field,
    );
  }

  const normalized = normalizePath(path);
  if (!normalized || normalized.split("/").some((segment) => segment === "..")) {
    throw new MajikSignatureValidationError(
      `${field} must resolve to a non-traversing relative path`,
      field,
    );
  }
  return normalized;
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
    // Enforce the binary-format ceiling against the actual CBOR-native
    // representation, not the larger Base64 JSON model.
    try {
      encodeCBOR(mjksMapToCBOR(data));
    } catch (error) {
      throw new MajikSignatureSerializationError(
        `MJKSMAP CBOR payload exceeds the maximum supported size of ${MAX_MJKSMAP_BYTES} bytes or contains invalid binary fields`,
        error,
      );
    }

    // Clone first so freezing our internal state never freezes caller-owned
    // entry/envelope objects and later caller mutation cannot alter a map.
    const snapshot = JSON.parse(JSON.stringify(data)) as MjksMapJSON;
    this._version = snapshot.version;
    this._createdAt = snapshot.createdAt;
    this._entries = deepFreezeJson(
      snapshot.entries.map((entry) => ({
        ...entry,
        path: normalizePath(entry.path),
      })),
    );

    const byPath = new Map<string, MjksMapEntry>();
    const byHash = new Map<string, MjksMapEntry[]>();
    for (const entry of this._entries) {
      byPath.set(entry.path, entry);
      const existing = byHash.get(entry.contentHash);
      if (existing) existing.push(entry);
      else byHash.set(entry.contentHash, [entry]);
    }
    this._byPath = byPath;
    this._byHash = byHash;
    Object.freeze(this);
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
    const normalized: MjksMapEntry = {
      ...entry,
      path: validateAndNormalizePath(entry.path, "path"),
    };
    MajikSignatureValidator.validateCanonicalBase64(
      normalized.contentHash,
      "contentHash",
      32,
    );
    if (
      normalized.size !== undefined &&
      (!Number.isSafeInteger(normalized.size) || normalized.size < 0)
    ) {
      throw new MajikSignatureValidationError(
        "size must be a non-negative safe integer when present",
        "size",
      );
    }
    if (normalized.mimeType !== undefined) {
      MajikSignatureValidator.validateContentType(normalized.mimeType, "mimeType");
    }
    MajikSignatureEnvelope.fromJSON(normalized.envelope);

    const filtered = this._entries.filter((e) => e.path !== normalized.path);
    const data: MjksMapJSON = {
      version: this._version,
      createdAt: this._createdAt,
      entries: [...filtered, normalized],
    };
    MajikSignatureMap.#validateShape(data as unknown as Record<string, unknown>);
    return new MajikSignatureMap(data);
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
    const snapshot: MjksMapJSON = {
      version: this._version,
      createdAt: this._createdAt,
      entries: [...this._entries],
    };
    return JSON.parse(JSON.stringify(snapshot)) as MjksMapJSON;
  }

  // ── MJKSMAP binary format ─────────────────────────────────────────────────
  //
  // The fixed header dispatches the payload encoding. Version 1 remains
  // readable as UTF-8 JSON; all new output uses version 2 CBOR.

  toMJKSMAPBytes(): Uint8Array {
    const payloadCbor = encodeCBOR(mjksMapToCBOR(this.toJSON()));
    if (payloadCbor.byteLength > MAX_MJKSMAP_BYTES) {
      throw new MajikSignatureSerializationError(
        `MJKSMAP CBOR payload exceeds the maximum supported size of ${MAX_MJKSMAP_BYTES} bytes`,
      );
    }
    const out = new Uint8Array(MJKSMAP_HEADER_LEN + payloadCbor.length);

    out.set(MJKSMAP_MAGIC, 0);
    out[MJKSMAP_MAGIC_LEN] = MJKSMAP_VERSION;
    out[MJKSMAP_MAGIC_LEN + 1] = 0x00; // reserved — always 0

    const lenOffset = MJKSMAP_MAGIC_LEN + 2;
    new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(
      lenOffset,
      payloadCbor.length,
      false,
    );

    out.set(payloadCbor, MJKSMAP_HEADER_LEN);
    return out;
  }

  toMJKSMAP(): Blob {
    const bytes = this.toMJKSMAPBytes();
    return new Blob([bytes as BlobPart], { type: MJKSMAP_MEDIA_TYPE });
  }

  static async fromMJKSMAP(
    input: Blob | Uint8Array,
  ): Promise<MajikSignatureMap> {
    if (
      input instanceof Blob &&
      input.size > MAX_MJKSMAP_BYTES + MJKSMAP_HEADER_LEN
    ) {
      throw new MajikSignatureSerializationError(
        `MJKSMAP input exceeds the maximum supported size of ${MAX_MJKSMAP_BYTES + MJKSMAP_HEADER_LEN} bytes`,
      );
    }
    if (
      input instanceof Uint8Array &&
      input.byteLength > MAX_MJKSMAP_BYTES + MJKSMAP_HEADER_LEN
    ) {
      throw new MajikSignatureSerializationError(
        `MJKSMAP input exceeds the maximum supported size of ${MAX_MJKSMAP_BYTES + MJKSMAP_HEADER_LEN} bytes`,
      );
    }
    const raw =
      input instanceof Blob ? new Uint8Array(await input.arrayBuffer()) : input;
    return MajikSignatureMap.#parseMJKSMAPBytes(raw);
  }

  static #parseMJKSMAPBytes(raw: Uint8Array): MajikSignatureMap {
    if (raw.byteLength > MAX_MJKSMAP_BYTES + MJKSMAP_HEADER_LEN) {
      throw new MajikSignatureSerializationError(
        `MJKSMAP input exceeds the maximum supported size of ${MAX_MJKSMAP_BYTES + MJKSMAP_HEADER_LEN} bytes`,
      );
    }
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

    const reserved = raw[MJKSMAP_MAGIC_LEN + 1];
    if (reserved !== 0x00) {
      throw new MajikSignatureSerializationError(
        `Malformed MJKSMAP: reserved byte must be 0x00, got 0x${reserved.toString(16).padStart(2, "0")}`,
      );
    }

    const lenOffset = MJKSMAP_MAGIC_LEN + 2;
    const payloadLen = new DataView(
      raw.buffer,
      raw.byteOffset,
      raw.byteLength,
    ).getUint32(lenOffset, false);

    if (payloadLen <= 0 || payloadLen > MAX_MJKSMAP_BYTES) {
      throw new MajikSignatureSerializationError(
        "Malformed MJKSMAP: invalid or oversized payload length",
      );
    }

    const payloadStart = MJKSMAP_HEADER_LEN;
    const payloadEnd = payloadStart + payloadLen;
    if (payloadEnd > raw.length) {
      throw new MajikSignatureSerializationError(
        "Malformed MJKSMAP: declared payload length exceeds buffer",
      );
    }
    if (payloadEnd !== raw.length) {
      throw new MajikSignatureSerializationError(
        "Malformed MJKSMAP: trailing bytes after the declared payload",
      );
    }

    const payload = raw.subarray(payloadStart, payloadEnd);
    if (version === MJKSMAP_JSON_VERSION) {
      let json: string;
      try {
        json = new TextDecoder("utf-8", { fatal: true }).decode(payload);
      } catch (error) {
        throw new MajikSignatureSerializationError(
          "Malformed MJKSMAP: payload is not valid UTF-8",
          error,
        );
      }
      return MajikSignatureMap.fromJSON(json);
    }

    try {
      const decoded = decodeCBOR(payload);
      return MajikSignatureMap.fromJSON(mjksMapFromCBOR(decoded));
    } catch (error) {
      throw new MajikSignatureSerializationError(
        "Malformed MJKSMAP: payload is not a valid CBOR manifest",
        error,
      );
    }
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
      version: MJKSMAP_SCHEMA_VERSION,
      createdAt: new Date().toISOString(),
      entries: [],
    });
  }

  static fromJSON(json: MjksMapJSON | string): MajikSignatureMap {
    let parsed: unknown;
    try {
      if (typeof json === "string") {
        if (
          json.length > MAX_MJKSMAP_JSON_BYTES ||
          new TextEncoder().encode(json).byteLength > MAX_MJKSMAP_JSON_BYTES
        ) {
          throw new MajikSignatureSerializationError(
            `MJKSMAP JSON model exceeds the maximum supported size of ${MAX_MJKSMAP_JSON_BYTES} bytes`,
          );
        }
        parsed = JSON.parse(json);
      } else {
        const serialized = JSON.stringify(json);
        if (
          typeof serialized !== "string" ||
          new TextEncoder().encode(serialized).byteLength > MAX_MJKSMAP_JSON_BYTES
        ) {
          throw new MajikSignatureSerializationError(
            `MJKSMAP JSON model exceeds the maximum supported size of ${MAX_MJKSMAP_JSON_BYTES} bytes`,
          );
        }
        parsed = JSON.parse(serialized);
      }
    } catch (err) {
      if (
        err instanceof MajikSignatureSerializationError &&
        /maximum supported size/i.test(err.message)
      ) {
        throw err;
      }
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
    let serialized: string | undefined;
    try {
      serialized = JSON.stringify(obj);
    } catch (error) {
      throw new MajikSignatureSerializationError(
        "MJKSMAP payload cannot be safely serialized",
        error,
      );
    }
    if (
      typeof serialized !== "string" ||
      serialized.length > MAX_MJKSMAP_JSON_BYTES ||
      new TextEncoder().encode(serialized).byteLength > MAX_MJKSMAP_JSON_BYTES
    ) {
      throw new MajikSignatureValidationError(
        `MJKSMAP JSON model exceeds the maximum supported size of ${MAX_MJKSMAP_JSON_BYTES} bytes`,
        "payload",
      );
    }

    if (obj.version !== MJKSMAP_SCHEMA_VERSION) {
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

    if ((obj.entries as unknown[]).length > MAX_MJKSMAP_ENTRIES) {
      throw new MajikSignatureValidationError(
        `MJKSMAP entries exceeds the limit of ${MAX_MJKSMAP_ENTRIES}`,
        "entries",
      );
    }

    MajikSignatureValidator.validateTimestamp(obj.createdAt, "createdAt");

    const seenPaths = new Set<string>();
    for (const [i, entry] of (obj.entries as unknown[]).entries()) {
      MajikSignatureMap.#validateEntry(entry, i);
      const path = validateAndNormalizePath(
        (entry as MjksMapEntry).path,
        `entries[${i}].path`,
      );
      if (seenPaths.has(path)) {
        throw new MajikSignatureValidationError(
          `Duplicate normalized path in entries: "${path}"`,
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
    validateAndNormalizePath(obj.path, `entries[${index}].path`);
    MajikSignatureValidator.validateCanonicalBase64(
      obj.contentHash,
      `entries[${index}].contentHash`,
      32,
    );
    if (
      obj.size !== undefined &&
      (typeof obj.size !== "number" ||
        !Number.isSafeInteger(obj.size) ||
        obj.size < 0)
    ) {
      throw new MajikSignatureValidationError(
        `entries[${index}].size must be a non-negative safe integer when present`,
        "size",
      );
    }
    if (obj.mimeType !== undefined) {
      if (obj.mimeType === null) {
        throw new MajikSignatureValidationError(
          `entries[${index}].mimeType must be a string when present`,
          "mimeType",
        );
      }
      MajikSignatureValidator.validateContentType(
        obj.mimeType,
        `entries[${index}].mimeType`,
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

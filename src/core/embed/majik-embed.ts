/**
 * majik-embed.ts — MajikSignatureEmbed
 *
 * Universal MajikSignature embedding and extraction for any file format.
 *
 * Circular dependency note:
 * ─────────────────────────
 * majik-embed lives inside the majik-signature package and cannot import
 * MajikSignature directly — that would create a circular dependency:
 *
 *   majik-signature → majik-embed → majik-signature  ✗
 *
 * Operations that need MajikSignature (signing, verifying) receive it via
 * the MajikSignatureStaticAdapter interface — no circular import needed.
 *
 * MajikSignatureEnvelope, by contrast, is pure/structural (no crypto), so it
 * IS imported directly here — no adapter required for it. All parsing,
 * validation, allowlist enforcement, seal computation, and signatory/issuer
 * resolution now live on that class (core/envelope.ts). This file is
 * reduced to file-format orchestration: read bytes → resolve handler →
 * extract/strip → delegate to the envelope class → re-embed.
 */

import type { MajikKey } from "@majikah/majik-key";

import type {
  BatchFileInput,
  BatchSignFailure,
  BatchSignOptions,
  BatchSignResult,
  BatchVerifyInput,
  BatchVerifyOptions,
  BatchVerifySummary,
  EmbedOptions,
  EmbedResult,
  EnvelopeInfo,
  ExpectedSigner,
  ExtractOptions,
  ExtractResult,
  FileVerifyResult,
  FormatHandler,
  MajikSignatureEnvelopeJSON,
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  MajikTimestamp,
  SealInfo,
  SealVerificationResult,
  SignatoriesFilter,
  SignatoriesResult,
  SignOptions,
  VerificationResult,
} from "../../core/types";
import { MajikSignatureEnvelope } from "../../core/envelope";
import { FormatHandlerRegistry } from "./registry";
import { blobToBytes, bytesToBlob, detectMimeType } from "./utils";

import { PdfHandler } from "./handlers/pdf";
import { PngHandler } from "./handlers/png";
import { JpegHandler } from "./handlers/jpeg";
import { WavHandler } from "./handlers/wav";
import { Mp3Handler } from "./handlers/mp3";
import { Mp4Handler } from "./handlers/mp4";
import { FlacHandler } from "./handlers/flac";
import { MkvHandler } from "./handlers/mkv";
import { OfficeHandler } from "./handlers/office";
import { TextHandler } from "./handlers/text";
import { FallbackHandler } from "./fallback";
import { bytesToBase64, hashContent } from "../hash";
import { MajikSignatureError, MajikSignatureValidationError } from "../errors";
import { MajikChainAnchor } from "../../anchor/types";
import { MajikSignatureMap } from "../mjksmap";

// ─── Adapter interfaces ───────────────────────────────────────────────────────
// Unchanged — these solve the crypto-side circular dependency, orthogonal to
// the envelope class (see file header).

export interface MajikSignatureAdapter {
  toJSON(): MajikSignatureJSON;
  /**
   * Optional — attach a TSA timestamp to this signature. Present because
   * MajikSignature implements it; declared optional here so any future
   * adapter that doesn't support TSA still satisfies this interface.
   */
  addTSA?(tsa: MajikTimestamp): void;
}

export interface MajikSignatureStaticAdapter {
  sign(
    content: Uint8Array | string,
    key: MajikKey,
    options?: SignOptions & { allowlistHash?: string },
  ): Promise<MajikSignatureAdapter>;

  verify(
    content: Uint8Array | string,
    signature: MajikSignatureAdapter | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
  ): VerificationResult;

  publicKeysFromMajikKey(key: MajikKey): MajikSignerPublicKeys;

  fromJSON(json: MajikSignatureJSON | string): MajikSignatureAdapter;
}

// ─── Registry ─────────────────────────────────────────────────────────────────

const DEFAULT_REGISTRY = new FormatHandlerRegistry()
  .register(new PdfHandler())
  .register(new PngHandler())
  .register(new JpegHandler())
  .register(new WavHandler())
  .register(new Mp3Handler())
  .register(new Mp4Handler())
  .register(new FlacHandler())
  .register(new MkvHandler())
  .register(new OfficeHandler())
  .register(new TextHandler());

// ─── MajikSignatureEmbed ──────────────────────────────────────────────────────

export class MajikSignatureEmbed {
  // ── embed ──────────────────────────────────────────────────────────────────

  /**
   * Embed a pre-computed signature into a file Blob.
   * Reads any existing envelope, upserts the new signature by signerId,
   * and writes the updated envelope back.
   * Does NOT sign — call signAndEmbed() for sign + embed together.
   */
  static async embed(
    file: Blob,
    signature: MajikSignatureAdapter | MajikSignatureJSON,
    options?: EmbedOptions,
  ): Promise<EmbedResult> {
    const { bytes, mimeType, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const sigJson =
      typeof (signature as MajikSignatureAdapter).toJSON === "function"
        ? (signature as MajikSignatureAdapter).toJSON()
        : (signature as MajikSignatureJSON);

    const envelope = await MajikSignatureEmbed._readEnvelope(handler, bytes);
    // withSignature() throws MajikSignatureError if the envelope is sealed
    const updated = envelope.withSignature(sigJson);

    const strippedBytes = await handler.strip(bytes);
    const resultBytes = await handler.embed(
      strippedBytes,
      JSON.stringify(updated.toJSON()),
    );
    const blob = bytesToBlob(resultBytes, mimeType);

    return { blob, handler: handler.name, mimeType };
  }

  // ── signAndEmbed ───────────────────────────────────────────────────────────

  /**
   * Sign a file and embed the signature in one call.
   *
   * Flow:
   *   1. Read existing envelope (or start fresh)
   *   2. assertCanSign() — rejects sealed envelopes and non-allowlisted signers
   *      before any cryptographic operation (issuer always bypasses)
   *   3. Strip existing envelope to get clean original bytes
   *   4. Resolve allowlistHash for this signer (establishing / re-signing / none)
   *   5. Sign the clean bytes
   *   6. If establishing an allowlist, attach it BEFORE upserting the signature
   *      (withAllowlist() requires zero existing signatures — see note below)
   *   7. Upsert signature into envelope
   *   8. Embed updated envelope back into the file
   */
  static async signAndEmbed<T extends MajikSignatureAdapter>(
    file: Blob,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: EmbedOptions & {
      contentType?: string;
      timestamp?: string;
      expectedSigners?: ExpectedSigner[];
    },
    debug: boolean = false,
  ): Promise<EmbedResult & { signature: T; envelope: MajikSignatureEnvelope }> {
    const { bytes, mimeType, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const envelope = await MajikSignatureEmbed._readEnvelope(handler, bytes);

    // ── Sealed + allowlist gate (throws before any crypto) ──────────────────
    envelope.assertCanSign(key);

    // ── Clean original bytes ─────────────────────────────────────────────────
    const originalBytes = await handler.strip(bytes);

    if (debug) {
      console.log(
        "signAndEmbed — original bytes hash:",
        bytesToBase64(hashContent(originalBytes)),
      );
    }

    // ── Resolve allowlistHash for this signer's payload ──────────────────────
    const allowlistHashValue = envelope.resolveAllowlistHashFor(
      key,
      options?.expectedSigners,
    );

    // ── Sign ──────────────────────────────────────────────────────────────────
    const signature = await MajikSig.sign(originalBytes, key, {
      contentType: options?.contentType,
      timestamp: options?.timestamp,
      ...(allowlistHashValue !== undefined
        ? { allowlistHash: allowlistHashValue }
        : {}),
    });

    // ── Attach allowlist FIRST (requires zero signatures), then upsert ───────
    // NOTE: withAllowlist() enforces "first signer only" by checking the
    // envelope's current signature count. It must run before withSignature()
    // adds this signer's entry, or the guard trips on the count it just added.
    const establishingAllowlist =
      envelope.isFirstSigner() && !!options?.expectedSigners?.length;

    const envelopeWithAllowlist = establishingAllowlist
      ? envelope.withAllowlist(options!.expectedSigners!, key.fingerprint)
      : envelope;

    const nextEnvelope = envelopeWithAllowlist.withSignature(
      signature.toJSON(),
    );

    // ── Embed ─────────────────────────────────────────────────────────────────
    const resultBytes = await handler.embed(
      originalBytes,
      JSON.stringify(nextEnvelope.toJSON()),
    );
    const blob = bytesToBlob(resultBytes, mimeType);

    return {
      blob,
      handler: handler.name,
      mimeType,
      signature: signature as T,
      envelope: nextEnvelope,
    };
  }

  // ── signDetached ───────────────────────────────────────────────────────────

  /**
   * Sign a file and return the envelope detached, along with the specific
   * signature just produced.
   *
   * If options.tsa is provided, it's attached to this signer's signature
   * via addTSA() immediately after signing and before it's upserted into
   * the envelope — addTSA() itself validates that the TSA's digest matches
   * this content's hash and that the TSA's own signature verifies, so no
   * duplicate validation is needed here. If the adapter doesn't support
   * addTSA (i.e. MajikSig.addTSA is undefined), a TSA option is a hard
   * error rather than a silent no-op — attaching a timestamp is something
   * the caller explicitly asked for, so failing to do it must be loud.
   *
   * Returns `signature` — the most recent signature produced by this call
   * (with the TSA attached, if one was provided) — in addition to the full
   * `envelope`, so callers don't have to re-extract it via
   * envelope.findSignature(key.fingerprint) themselves.
   */
  static async signDetached<
    T extends MajikSignatureAdapter = MajikSignatureAdapter,
  >(
    file: Blob,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: EmbedOptions & {
      contentType?: string;
      timestamp?: string;
      expectedSigners?: ExpectedSigner[];
      existingEnvelope?:
        | MajikSignatureEnvelope
        | MajikSignatureEnvelopeJSON
        | Uint8Array
        | Blob;
      tsa?: MajikTimestamp;
    },
    debug: boolean = false,
  ): Promise<{
    blob: Blob;
    envelope: MajikSignatureEnvelope;
    signature: T;
    handler: string;
    mimeType: string;
  }> {
    const { bytes, mimeType, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const envelope = options?.existingEnvelope
      ? await MajikSignatureEnvelope.from(options.existingEnvelope)
      : await MajikSignatureEmbed._readEnvelope(handler, bytes);

    envelope.assertCanSign(key);

    const originalBytes = await handler.strip(bytes);

    if (debug) {
      console.log(
        "signDetached — original bytes hash:",
        bytesToBase64(hashContent(originalBytes)),
      );
    }

    const allowlistHashValue = envelope.resolveAllowlistHashFor(
      key,
      options?.expectedSigners,
    );

    const signature = await MajikSig.sign(originalBytes, key, {
      contentType: options?.contentType,
      timestamp: options?.timestamp,
      ...(allowlistHashValue !== undefined
        ? { allowlistHash: allowlistHashValue }
        : {}),
    });

    // ── Attach TSA, if provided ──────────────────────────────────────────────
    // Must happen before toJSON()/upsert — the envelope needs the signature
    // WITH its tsa field already set, not a bare signature followed by a
    // separate mutation the caller has to remember to do.
    if (options?.tsa) {
      if (typeof signature.addTSA !== "function") {
        throw new MajikSignatureError(
          "options.tsa was provided, but the given MajikSig adapter does not support TSA attachment (addTSA is not implemented).",
        );
      }
      signature.addTSA(options.tsa);
    }

    const establishingAllowlist =
      envelope.isFirstSigner() && !!options?.expectedSigners?.length;

    const envelopeWithAllowlist = establishingAllowlist
      ? envelope.withAllowlist(options!.expectedSigners!, key.fingerprint)
      : envelope;

    const nextEnvelope = envelopeWithAllowlist.withSignature(
      signature.toJSON(),
    );

    // ── Return DETACHED (no embedding) ───────────────────────────────────────
    const blob = bytesToBlob(originalBytes, mimeType);

    return {
      blob,
      handler: handler.name,
      mimeType,
      envelope: nextEnvelope,
      signature: signature as T,
    };
  }

  // ── signBatchDetached ────────────────────────────────────────────────────────

  /**
   * Sign a batch of files (folder or zip contents) as detached envelopes,
   * packaged either as one MajikSignatureMap (default) or as separate
   * .mjksig Blobs per file.
   *
   * Reuses signDetached() per file — no duplicated crypto path. The only
   * new logic here is path-uniqueness validation and result packaging.
   */
  static async signBatchDetached(
    files: BatchFileInput[],
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: BatchSignOptions,
    debug: boolean = false,
  ): Promise<BatchSignResult> {
    MajikSignatureEmbed._assertValidBatch(files);

    const mode = options?.mode ?? "map";
    const continueOnError = options?.continueOnError ?? false;

    const failures: BatchSignFailure[] = [];
    let map = mode === "map" ? MajikSignatureMap.empty() : undefined;
    const signatures: { path: string; blob: Blob }[] = [];

    for (const file of files) {
      try {
        const { envelope, contentHash } =
          await MajikSignatureEmbed._signOneDetached(
            file,
            key,
            MajikSig,
            options,
            debug,
          );

        if (mode === "map") {
          map = map!.withEntry({
            path: file.path,
            contentHash,
            size: file.blob.size,
            mimeType: file.blob.type || undefined,
            envelope: envelope.toJSON(),
          });
        } else {
          signatures.push({ path: file.path, blob: envelope.toMJKSIG() });
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);

        if (!continueOnError) {
          throw err instanceof MajikSignatureError
            ? err
            : new MajikSignatureError(
                `Batch signing failed on "${file.path}": ${message}`,
                err,
              );
        }

        failures.push({ path: file.path, error: message });
      }
    }

    return mode === "map"
      ? { mode: "map", map: map!, mapBlob: map!.toMJKSMAP(), failures }
      : { mode: "separate", signatures, failures };
  }

  // ── Private batch helpers ───────────────────────────────────────────────────

  /**
   * Sign one file detached and extract the contentHash this signer produced
   * for it — needed to populate the map entry without re-hashing separately.
   */
  private static async _signOneDetached(
    file: BatchFileInput,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options: BatchSignOptions | undefined,
    debug: boolean,
  ): Promise<{ envelope: MajikSignatureEnvelope; contentHash: string }> {
    const { envelope } = await MajikSignatureEmbed.signDetached(
      file.blob,
      key,
      MajikSig,
      {
        contentType: options?.contentType,
        timestamp: options?.timestamp,
        expectedSigners: options?.expectedSigners,
      },
      debug,
    );

    const sig = envelope.findSignature(key.fingerprint);
    if (!sig) {
      // Should be unreachable — signDetached() always upserts this signer's
      // entry — but fail loudly rather than silently omitting the file from
      // the map if signDetached's contract is ever violated.
      throw new MajikSignatureError(
        `Internal error: no signature found for this signer after signing "${file.path}"`,
      );
    }

    return { envelope, contentHash: sig.contentHash };
  }

  /**
   * Validate the batch before touching any crypto: non-empty, every file has
   * a non-empty path, and no two files share a path. Duplicate paths would
   * otherwise silently overwrite each other's map entry via withEntry()'s
   * replace-on-match semantics — catching it here means the failure is
   * "your batch has a duplicate path" up front, not a mysteriously missing
   * entry discovered later.
   */
  private static _assertValidBatch(files: BatchFileInput[]): void {
    if (!files || files.length === 0) {
      throw new MajikSignatureValidationError(
        "Batch must contain at least one file.",
        "files",
      );
    }

    const seen = new Set<string>();
    for (const file of files) {
      if (!file.path || !file.path.trim()) {
        throw new MajikSignatureValidationError(
          "Every batch file must have a non-empty path.",
          "path",
        );
      }
      if (seen.has(file.path)) {
        throw new MajikSignatureValidationError(
          `Duplicate path in batch: "${file.path}"`,
          "path",
        );
      }
      seen.add(file.path);
    }
  }

  // ── extract ────────────────────────────────────────────────────────────────

  /**
   * Extract the envelope from a file as a MajikSignatureEnvelope instance.
   * Returns null if no signature is found.
   */
  static async extract(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<ExtractResult | null> {
    const { bytes, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const raw = await handler.extract(bytes);
    if (!raw) return null;

    const envelope = MajikSignatureEnvelope.fromJSON(raw);
    return { envelope, handler: handler.name };
  }

  // ── verify ─────────────────────────────────────────────────────────────────

  /**
   * Verify a file's embedded signatures against public keys.
   * Returns one VerificationResult per signature in the envelope.
   */
  static async verify(
    file: Blob,
    publicKeys: MajikSignerPublicKeys,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { expectedSignerId?: string },
    debug: boolean = false,
  ): Promise<VerificationResult[]> {
    const { bytes, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const raw = await handler.extract(bytes);
    if (!raw) return [MajikSignatureEmbed._noSignatureResult()];

    let envelope: MajikSignatureEnvelope;
    try {
      envelope = MajikSignatureEnvelope.fromJSON(raw);
    } catch {
      return [
        {
          valid: false,
          reason: "Embedded signature payload is malformed",
          timestamp: new Date().toISOString(),
        },
      ];
    }

    const originalBytes = await handler.strip(bytes);

    if (debug) {
      console.log(
        "verify — original bytes hash:",
        bytesToBase64(hashContent(originalBytes)),
      );
    }

    const integrity = envelope.verifyAllowlistIntegrity();
    if (!integrity.valid) {
      return [
        {
          valid: false,
          reason: integrity.reason,
          timestamp: new Date().toISOString(),
        },
      ];
    }

    return MajikSignatureEmbed._verifySignatures(
      envelope,
      originalBytes,
      publicKeys,
      MajikSig,
      handler.name,
      options?.expectedSignerId,
    );
  }

  // ── verifyWithKey ──────────────────────────────────────────────────────────

  static async verifyWithKey(
    file: Blob,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { expectedSignerId?: string },
    debug: boolean = false,
  ): Promise<VerificationResult[]> {
    const publicKeys = MajikSig.publicKeysFromMajikKey(key);
    return MajikSignatureEmbed.verify(
      file,
      publicKeys,
      MajikSig,
      options,
      debug,
    );
  }

  // ── verifyDetached ─────────────────────────────────────────────────────────

  /**
   * Verify a file against a provided, detached envelope (instance, blob or JSON).
   * Still strips the file in case it also contains an embedded envelope,
   * ensuring verification runs against the clean original bytes.
   */
  static async verifyDetached(
    file: Blob,
    envelopeInput:
      | MajikSignatureEnvelope
      | MajikSignatureEnvelopeJSON
      | Uint8Array
      | Blob,
    publicKeys: MajikSignerPublicKeys,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { expectedSignerId?: string },
    debug: boolean = false,
  ): Promise<VerificationResult[]> {
    const { bytes, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const envelope = await MajikSignatureEnvelope.from(envelopeInput);
    const originalBytes = await handler.strip(bytes);

    if (debug) {
      console.log(
        "verifyDetached — original bytes hash:",
        bytesToBase64(hashContent(originalBytes)),
      );
    }

    const integrity = envelope.verifyAllowlistIntegrity();
    if (!integrity.valid) {
      return [
        {
          valid: false,
          reason: integrity.reason,
          timestamp: new Date().toISOString(),
        },
      ];
    }

    return MajikSignatureEmbed._verifySignatures(
      envelope,
      originalBytes,
      publicKeys,
      MajikSig,
      handler.name,
      options?.expectedSignerId,
    );
  }

  // ── verifyDetachedWithKey ──────────────────────────────────────────────────

  static async verifyDetachedWithKey(
    file: Blob,
    envelopeInput:
      | MajikSignatureEnvelope
      | MajikSignatureEnvelopeJSON
      | Uint8Array
      | Blob,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { expectedSignerId?: string },
    debug: boolean = false,
  ): Promise<VerificationResult[]> {
    const publicKeys = MajikSig.publicKeysFromMajikKey(key);
    return MajikSignatureEmbed.verifyDetached(
      file,
      envelopeInput,
      publicKeys,
      MajikSig,
      options,
      debug,
    );
  }

  // ── verifyFilesFromMjksMap ───────────────────────────────────────────────────

  /**
   * Verify a batch of extracted files against a MajikSignatureMap.
   *
   * For each file: resolve against the map (tolerating relocation — a file
   * moved or renamed after signing is still found and verified by content,
   * not just by its original path), then run the normal signature
   * verification via the envelope stored in that entry. Never throws
   * per-file — every outcome (missing, tampered, relocated-but-valid,
   * invalid, verified) is reported in the returned array, so a caller can
   * render a full per-file status table in one pass instead of catching
   * exceptions.
   *
   * Set options.requireAllPresent to escalate a missing file to a thrown
   * error instead — useful when the caller expects a closed, complete set
   * (e.g. "this zip must contain everything the map lists").
   */
  static async verifyFilesFromMjksMap(
    map: MajikSignatureMap,
    files: BatchVerifyInput[],
    publicKeys: MajikSignerPublicKeys,
    MajikSig: MajikSignatureStaticAdapter,
    options?: BatchVerifyOptions,
    debug: boolean = false,
  ): Promise<FileVerifyResult[]> {
    const results: FileVerifyResult[] = [];

    for (const file of files) {
      const resolved = await map.resolveEntry(file.path, file.blob);

      if (resolved.status === "not_found") {
        if (options?.requireAllPresent) {
          throw new MajikSignatureError(
            `File "${file.path}" was not found in the signature map.`,
          );
        }
        results.push({
          path: file.path,
          status: "not_in_map",
          reason: `No signature entry found for "${file.path}" (checked by path and by content).`,
        });
        continue;
      }

      if (resolved.status === "path_tampered") {
        results.push({
          path: file.path,
          status: "tampered",
          reason:
            "File content no longer matches what was signed — it may have been modified after signing.",
        });
        continue;
      }

      // At this point status is "path_match" or "relocated" — both have a
      // confirmed content match against resolved.entry, so verification
      // proceeds identically. Only the reported metadata differs.
      const originalBytes = new Uint8Array(await file.blob.arrayBuffer());

      if (debug) {
        console.log(
          `verifyFilesFromMjksMap — "${file.path}" bytes hash:`,
          bytesToBase64(hashContent(originalBytes)),
        );
      }

      const envelope = MajikSignatureEnvelope.fromJSON(
        resolved.entry!.envelope,
      );
      const integrity = envelope.verifyAllowlistIntegrity();

      const relocatedFrom =
        resolved.status === "relocated" ? resolved.originalPath : undefined;

      if (!integrity.valid) {
        results.push({
          path: file.path,
          status: "invalid",
          reason: integrity.reason,
          ...(relocatedFrom ? { relocatedFrom } : {}),
        });
        continue;
      }

      const verifyResults = MajikSignatureEmbed._verifySignatures(
        envelope,
        originalBytes,
        publicKeys,
        MajikSig,
        "mjksmap",
        options?.expectedSignerId,
      );

      const allValid = verifyResults.every((r) => r.valid);
      results.push({
        path: file.path,
        status: allValid ? "verified" : "invalid",
        results: verifyResults,
        ...(relocatedFrom ? { relocatedFrom } : {}),
        ...(relocatedFrom
          ? {
              reason: allValid
                ? `Verified by content match — originally signed as "${relocatedFrom}".`
                : undefined,
            }
          : {}),
      });
    }

    return results;
  }

  /** Convenience overload — resolves public keys from a MajikKey. */
  static async verifyFilesFromMjksMapWithKey(
    map: MajikSignatureMap,
    files: BatchVerifyInput[],
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: BatchVerifyOptions,
    debug: boolean = false,
  ): Promise<FileVerifyResult[]> {
    const publicKeys = MajikSig.publicKeysFromMajikKey(key);
    return MajikSignatureEmbed.verifyFilesFromMjksMap(
      map,
      files,
      publicKeys,
      MajikSig,
      options,
      debug,
    );
  }

  /**
   * Summarize a batch verification result — one glance at pass/fail counts
   * without the caller re-deriving it from the array each time.
   */
  static summarizeBatchVerification(
    results: FileVerifyResult[],
  ): BatchVerifySummary {
    const summary = {
      total: results.length,
      verified: 0,
      invalid: 0,
      tampered: 0,
      notInMap: 0,
      allValid: false,
    };

    for (const r of results) {
      if (r.status === "verified") summary.verified++;
      else if (r.status === "invalid") summary.invalid++;
      else if (r.status === "tampered") summary.tampered++;
      else if (r.status === "not_in_map") summary.notInMap++;
    }

    summary.allValid = summary.verified === summary.total && summary.total > 0;
    return summary;
  }

  // ── seal ───────────────────────────────────────────────────────────────────

  /**
   * Seal a multi-sig envelope, preventing any further signatures.
   * Issuer-only / already-sealed checks are enforced by envelope.withSeal().
   */
  static async seal(
    file: Blob,
    key: MajikKey,
    options?: ExtractOptions & { timestamp?: string },
  ): Promise<{
    blob: Blob;
    sealInfo: SealInfo;
    handler: string;
    mimeType: string;
  }> {
    const { bytes, mimeType, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const raw = await handler.extract(bytes);
    if (!raw) {
      throw new MajikSignatureError(
        "Cannot seal an unsigned file — no envelope found.",
      );
    }

    const envelope = MajikSignatureEnvelope.fromJSON(raw);
    // Throws MajikSignatureError (already sealed) or MajikSignatureKeyError
    // (wrong issuer) — same failure modes as the previous implementation.
    const sealedEnvelope = envelope.withSeal(
      key.fingerprint,
      options?.timestamp,
    );

    const originalBytes = await handler.strip(bytes);
    const resultBytes = await handler.embed(
      originalBytes,
      JSON.stringify(sealedEnvelope.toJSON()),
    );
    const blob = bytesToBlob(resultBytes, mimeType);

    return {
      blob,
      sealInfo: sealedEnvelope.getSealInfo()!,
      handler: handler.name,
      mimeType,
    };
  }

  // ── verifySeal ─────────────────────────────────────────────────────────────

  static async verifySeal(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<SealVerificationResult> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return { valid: false, reason: "No embedded envelope found" };
    return result.envelope.verifySeal();
  }

  // ── getSealInfo ────────────────────────────────────────────────────────────

  static async getSealInfo(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<SealInfo | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.getSealInfo() : null;
  }

  // ── isSealed ───────────────────────────────────────────────────────────────

  static async isSealed(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<boolean> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.isSealed() : false;
  }

  // ── isMultiSig ─────────────────────────────────────────────────────────────

  static async isMultiSig(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<boolean> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.isMultiSig() : false;
  }

  // ── canSign ────────────────────────────────────────────────────────────────

  static async canSign(
    file: Blob,
    key: MajikKey,
    options?: ExtractOptions,
  ): Promise<{ permitted: boolean; reason?: string }> {
    const result = await MajikSignatureEmbed.extract(file, options);
    // No envelope — unsigned file, anyone may sign
    if (!result) return { permitted: true };
    return result.envelope.canSign(key);
  }

  // ── getSignatories ─────────────────────────────────────────────────────────

  static async getSignatories(
    file: Blob,
    options?: ExtractOptions,
    filter?: SignatoriesFilter,
  ): Promise<SignatoriesResult | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.getSignatories(filter) : null;
  }

  // ── getIssuer ──────────────────────────────────────────────────────────────

  static async getIssuer(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<import("../../core/types").SignatoryInfo | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.resolveIssuer() : null;
  }

  // ── getEnvelopeInfo ────────────────────────────────────────────────────────

  static async getEnvelopeInfo(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<EnvelopeInfo | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.getEnvelopeInfo() : null;
  }

  // ── strip ──────────────────────────────────────────────────────────────────

  static async strip(file: Blob, options?: ExtractOptions): Promise<Blob> {
    const { bytes, mimeType, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );
    const stripped = await handler.strip(bytes);
    return bytesToBlob(stripped, mimeType);
  }

  // ── hasSignature ───────────────────────────────────────────────────────────

  static async hasSignature(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<boolean> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result !== null;
  }

  // ── getAllowlist ───────────────────────────────────────────────────────────

  static async getAllowlist(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<ExpectedSigner[] | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result || !result.envelope.allowlist) return null;
    return [...result.envelope.allowlist];
  }

  static readonly registry = DEFAULT_REGISTRY;

  static listHandlers(): string[] {
    return DEFAULT_REGISTRY.listHandlers();
  }

  // ── canAnchor ──────────────────────────────────────────────────────────────

  static async canAnchor(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<{ permitted: boolean; reason?: string }> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) {
      return {
        permitted: false,
        reason: "Cannot anchor an unsigned file — no envelope found.",
      };
    }
    return result.envelope.canAnchor();
  }

  // ── registerChainAnchor ───────────────────────────────────────────────────

  /**
   * Embed an already-confirmed chain anchor into the envelope.
   * Sealed check, digest match, and upsert-by-id dedup are all enforced by
   * envelope.withChainAnchor().
   */
  static async registerChainAnchor(
    file: Blob,
    anchor: MajikChainAnchor,
    options?: ExtractOptions,
  ): Promise<EmbedResult> {
    const { bytes, mimeType, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const raw = await handler.extract(bytes);
    if (!raw) {
      throw new MajikSignatureError(
        "Cannot register a chain anchor on an unsigned file — no envelope found.",
      );
    }

    const envelope = MajikSignatureEnvelope.fromJSON(raw);
    const nextEnvelope = envelope.withChainAnchor(anchor);

    const originalBytes = await handler.strip(bytes);
    const resultBytes = await handler.embed(
      originalBytes,
      JSON.stringify(nextEnvelope.toJSON()),
    );
    const blob = bytesToBlob(resultBytes, mimeType);

    return { blob, handler: handler.name, mimeType };
  }

  // ── getChainAnchors ────────────────────────────────────────────────────────

  static async getChainAnchors(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<MajikChainAnchor[]> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? [...result.envelope.chainAnchors] : [];
  }

  // ── Private helpers ───────────────────────────────────────────────────────
  // Consolidates the bytes → mimeType → handler resolution and the
  // extract-or-empty envelope read, both previously repeated at the top of
  // nearly every public method.

  private static async _prepare(
    file: Blob,
    options?: { mimeType?: string; forceFallback?: boolean },
  ): Promise<{ bytes: Uint8Array; mimeType: string; handler: FormatHandler }> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);
    const handler = options?.forceFallback
      ? new FallbackHandler()
      : DEFAULT_REGISTRY.resolve(bytes, mimeType);
    return { bytes, mimeType, handler };
  }

  /** Extract + parse, or a fresh empty envelope when none exists. */
  private static async _readEnvelope(
    handler: FormatHandler,
    bytes: Uint8Array,
  ): Promise<MajikSignatureEnvelope> {
    const raw = await handler.extract(bytes);
    return raw
      ? MajikSignatureEnvelope.fromJSON(raw)
      : MajikSignatureEnvelope.empty();
  }

  private static _noSignatureResult(): VerificationResult {
    return {
      valid: false,
      reason: "No embedded signature found",
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Shared by verify() and verifyDetached(): filter by expectedSignerId,
   * verify each remaining signature, and stamp the handler name onto each
   * result. Previously duplicated near-verbatim in both methods.
   */
  private static _verifySignatures(
    envelope: MajikSignatureEnvelope,
    originalBytes: Uint8Array,
    publicKeys: MajikSignerPublicKeys,
    MajikSig: MajikSignatureStaticAdapter,
    handlerName: string,
    expectedSignerId?: string,
  ): VerificationResult[] {
    const sigsToVerify = expectedSignerId
      ? envelope.signatures.filter((s) => s.signerId === expectedSignerId)
      : envelope.signatures;

    if (sigsToVerify.length === 0) {
      return [
        {
          valid: false,
          reason: expectedSignerId
            ? `No signature found for signerId "${expectedSignerId}"`
            : "Envelope contains no signatures",
          timestamp: new Date().toISOString(),
        },
      ];
    }

    return sigsToVerify.map((sig) => ({
      ...MajikSig.verify(originalBytes, sig, publicKeys),
      handler: handlerName,
    }));
  }
}

// Freeze static methods
Object.freeze(MajikSignatureEmbed);

// Freeze instance methods
Object.freeze(MajikSignatureEmbed.prototype);

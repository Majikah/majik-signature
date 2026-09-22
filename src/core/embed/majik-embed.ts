/**
 * majik-embed.ts — MajikSignatureEmbed
 *
 * Universal MajikSignature embedding and extraction for any file format.
 *
 * @remarks
 * This module is the file-orchestration layer of Majik Signature. It does not
 * own the signing primitives themselves; instead, it coordinates file bytes,
 * format handlers, `MajikSignatureEnvelope`, and a small crypto adapter that
 * supplies the actual `sign()` / `verify()` operations.
 *
 * The public APIs are intentionally expressed in terms of `FileLike` so the
 * same code can be used with browser `Blob`/`File` objects as well as raw
 * `Uint8Array` / `ArrayBuffer` data in Node.js, Bun, Deno, and Tauri.
 *
 * Circular dependency note:
 * ─────────────────────────
 * `majik-embed` lives inside the majik-signature package and cannot import
 * `MajikSignature` directly — that would create a circular dependency:
 *
 *   majik-signature → majik-embed → majik-signature  ✗
 *
 * Operations that need `MajikSignature` (signing, verifying) receive it via
 * the `MajikSignatureStaticAdapter` interface — no circular import needed.
 *
 * `MajikSignatureEnvelope`, by contrast, is pure/structural (no crypto), so it
 * IS imported directly here — no adapter required for it. All parsing,
 * validation, allowlist enforcement, seal computation, and signatory/issuer
 * resolution now live on that class (core/envelope.ts). This file is
 * reduced to file-format orchestration: read bytes → resolve handler →
 * extract/strip → delegate to the envelope class → re-embed.
 *
 * @internal
 * This module is primarily an implementation-level orchestration surface.
 * The public `MajikSignature` class exposes the higher-level user-facing API.
 */

import type { ISODateString, MajikKey } from "@majikah/majik-key";

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
  EnvelopeInput,
  ExpectedSigner,
  ExtractOptions,
  ExtractResult,
  FileChainVerification,
  FileLike,
  FileVerifyResult,
  FileVersion,
  FormatHandler,
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  MajikTimestamp,
  RevisionCheckResult,
  RevisionCommitmentResult,
  RevisionSetVerification,
  SealInfo,
  SealVerificationResult,
  SignatoriesFilter,
  SignatoriesResult,
  SignOptions,
  VerificationResult,
} from "../../core/types";
import { MajikSignatureEnvelope } from "../../core/envelope";
import { FormatHandlerRegistry } from "./registry";
import {
  bytesToBlob,
  detectMimeType,
  normalizeToBlob,
  normalizeToBytes,
} from "./utils";

import {
  PdfHandler,
  PngHandler,
  FlacHandler,
  JpegHandler,
  MkvHandler,
  Mp3Handler,
  Mp4Handler,
  OfficeHandler,
  TextHandler,
  WavHandler,
} from "./handlers";

import { FallbackHandler } from "./fallback";
import { base64ToBytes, bytesToBase64, hashContent } from "../hash";
import { MajikSignatureError, MajikSignatureValidationError } from "../errors";
import { MajikChainAnchor } from "../../anchor/types";
import { MajikSignatureMap } from "../mjksmap";
import {
  SignatureOrderResult,
  verifySignatureOrder,
  VerifySignatureOrderOptions,
} from "../order";
import {
  assertCanonical,
  noSignatureReason,
  prepareDetachedBytes,
} from "./canonical";

// ─── Adapter interfaces ───────────────────────────────────────────────────────

/**
 * Minimal instance-level bridge between `MajikSignatureEmbed` and the concrete
 * `MajikSignature` class.
 *
 * @remarks
 * The adapter exists solely to break the `MajikSignature ↔ majik-embed`
 * circular dependency. `MajikSignatureEmbed` only needs to serialize a
 * produced signature and, optionally, attach a trusted timestamp.
 *
 * Implementations may expose additional methods; only the members declared
 * here are consumed by this module.
 */
export interface MajikSignatureAdapter {
  /**
   * Return the complete wire-format representation of this signature.
   *
   * @remarks
   * The returned object is inserted into a `MajikSignatureEnvelope`. It must
   * therefore contain the signer keys, content hash, timestamp, and both
   * hybrid signature values expected by `MajikSignatureJSON`.
   */
  toJSON(): MajikSignatureJSON;

  /**
   * Attach and validate a trusted timestamp to this signature, when supported.
   *
   * @remarks
   * This member is optional so adapters that do not implement TSA support can
   * still satisfy the interface. Callers requesting TSA explicitly must treat
   * its absence as an error rather than silently dropping the timestamp.
   */
  addTSA?(tsa: MajikTimestamp): void;
}

/**
 * Static crypto bridge consumed by `MajikSignatureEmbed`.
 *
 * @remarks
 * This interface represents the subset of `MajikSignature` functionality
 * needed by the embedding layer. Keeping it structural prevents a runtime
 * circular import while preserving strong typing between the two modules.
 *
 * The adapter owns cryptographic signing and verification; this file owns
 * byte preparation, handler selection, envelope orchestration, and result
 * packaging.
 */
export interface MajikSignatureStaticAdapter {
  /**
   * Create a hybrid signature over content bytes.
   *
   * @param content Content bytes (or a UTF-8 string) to sign.
   * @param key Unlocked `MajikKey` containing the signing material.
   * @param options Standard signing options plus internal commitments used by
   * file-level workflows such as allowlists and revision chains.
   * @returns A signature adapter whose `toJSON()` result can be inserted into
   * an envelope.
   */
  sign(
    content: Uint8Array | string,
    key: MajikKey,
    options?: SignOptions & {
      allowlistHash?: string;
      versionChainHash?: string;
    },
  ): Promise<MajikSignatureAdapter>;

  /**
   * Verify one signature against content and the caller-supplied public keys.
   *
   * @param content Canonical content bytes being verified.
   * @param signature Signature adapter or serialized signature JSON.
   * @param publicKeys Public keys that the caller has chosen to trust for the
   * signer being checked.
   * @param now Optional verification time used when evaluating `validUntil`.
   * @returns A normal verification result; cryptographic failure is reported
   * as `valid: false` rather than as an exception in the normal case.
   */
  verify(
    content: Uint8Array | string,
    signature: MajikSignatureAdapter | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
    now?: Date,
  ): VerificationResult;

  /**
   * Verify the cryptographic commitment carried by a signature without the
   * original content bytes.
   *
   * @remarks
   * Used for earlier revisions in self-contained file-chain verification.
   * This checks the canonical signature commitment and expiry, but cannot
   * independently prove that the referenced historical content bytes existed.
   */
  verifyCommitment(
    signature: MajikSignatureAdapter | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
    now?: Date,
  ): VerificationResult;

  /**
   * Extract public verification keys from a `MajikKey`.
   *
   * @remarks
   * This operation only needs public material and therefore also works with a
   * locked key, provided the underlying `MajikKey` can expose its public keys.
   */
  publicKeysFromMajikKey(key: MajikKey): MajikSignerPublicKeys;

  /** Rehydrate a concrete signature instance from its JSON representation. */
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

/**
 * File-format orchestration layer for Majik Signature.
 *
 * @remarks
 * `MajikSignatureEmbed` coordinates the complete embedded/detached file flow:
 *
 * `FileLike → bytes → MIME/handler detection → extract/strip → envelope → crypto adapter → embed`
 *
 * It intentionally does **not** implement the signing algorithms themselves.
 * Those operations are supplied through `MajikSignatureStaticAdapter`, while
 * structural envelope operations are delegated to `MajikSignatureEnvelope`.
 *
 * The class supports native handlers for known formats and a universal
 * fallback handler for formats without a dedicated embedding strategy.
 *
 * @internal
 * The higher-level `MajikSignature` API normally calls this class rather than
 * application code importing it directly.
 */
export class MajikSignatureEmbed {
  // ── embed ──────────────────────────────────────────────────────────────────

  /**
   * Embed a pre-computed signature into a file.
   *
   * @remarks
   * This method **does not perform signing**. It reads the existing embedded
   * envelope (if any), upserts the supplied signature by `signerId`, strips the
   * previous envelope, and writes the updated envelope back using the selected
   * format handler.
   *
   * Because `MajikSignatureEnvelope.withSignature()` enforces sealing rules,
   * adding a signature to a sealed envelope fails before any file is rewritten.
   * Re-embedding is idempotent: an existing envelope is replaced rather than
   * stacked on top of itself.
   *
   * @param file Source file or raw file-like bytes.
   * @param signature Signature instance or its serializable JSON representation.
   * @param options MIME-type override or fallback-handler override.
   * @returns Embedded file plus the handler and MIME type used.
   * @throws `MajikSignatureError` when the target envelope is sealed or the
   * signature/envelope cannot be processed.
   * @example
   * ```ts
   * const signed = await MajikSignatureEmbed.embed(file, signature);
   * ```
   */
  static async embed(
    file: FileLike,
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
   * Sign a file and embed the resulting signature in one operation.
   *
   * @remarks
   * This is the canonical embedded-signing pipeline. The method:
   *
   * 1. Resolves the file format handler and extracts any existing envelope.
   * 2. Enforces seal and allowlist rules before signing.
   * 3. Strips the current envelope to recover the canonical content bytes.
   * 4. Computes allowlist and revision-chain commitments where applicable.
   * 5. Delegates the actual cryptographic signing to `MajikSig.sign()`.
   * 6. Establishes the allowlist when this is the first signer.
   * 7. Appends the new `FileVersion` and signature to the immutable envelope.
   * 8. Embeds the updated envelope back into the original file format.
   *
   * `priorSignedFile` changes the workflow into revision-aware signing: the
   * previous signed file is independently checked before its version chain is
   * extended. This is intended for visual-stamping workflows where each
   * signer's turn changes the underlying file bytes.
   *
   * @param file File received by the current signer. If `priorSignedFile` is
   * supplied, this is the file after the current signer's own modification.
   * @param key Signing key used for this signer.
   * @param MajikSig Static crypto adapter supplied by the concrete signature implementation.
   * @param options File embedding, content-signing, allowlist, expiry, and
   * revision options.
   * @param debug When true, emits content-hash diagnostics to the console.
   * @returns Embedded file metadata plus the newly created signature and the
   * resulting immutable envelope.
   * @throws `MajikSignatureError` for sealed files, invalid prior revisions,
   * malformed envelopes, or other orchestration failures.
   * @throws `MajikSignatureValidationError` when revision-chain input is structurally invalid.
   * @example
   * ```ts
   * const result = await MajikSignatureEmbed.signAndEmbed(file, key, MajikSignature, {
   *   expectedSigners: [alice, bob],
   * });
   * ```
   */
  static async signAndEmbed<T extends MajikSignatureAdapter>(
    file: FileLike,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: EmbedOptions & {
      contentType?: string;
      timestamp?: ISODateString;
      expectedSigners?: ExpectedSigner[];
      validUntil?: ISODateString;
      message?: string;
      /** The file as received, BEFORE this signer's own stamp. Presence of
       *  this option is what makes this call a revision (2nd signer+) rather
       *  than a fresh signature. */
      priorSignedFile?: FileLike;
    },
    debug: boolean = false,
  ): Promise<EmbedResult & { signature: T; envelope: MajikSignatureEnvelope }> {
    const { bytes, mimeType, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const envelope = options?.priorSignedFile
      ? await MajikSignatureEmbed._readAndVerifyPriorEnvelope(
          options.priorSignedFile,
          MajikSig,
          debug,
        )
      : await MajikSignatureEmbed._readEnvelope(handler, bytes);

    envelope.assertCanSign(key);

    const originalBytes = await handler.strip(bytes);
    if (debug)
      console.log(
        "signAndEmbed — bytes hash:",
        bytesToBase64(hashContent(originalBytes)),
      );

    const allowlistHashValue = envelope.resolveAllowlistHashFor(
      key,
      options?.expectedSigners,
    );

    const lastVersion = envelope.lastFileVersion;
    const newVersionEntry: FileVersion = {
      version: lastVersion ? lastVersion.version + 1 : 1,
      timestamp: options?.timestamp ?? new Date().toISOString(),
      contentHash: bytesToBase64(hashContent(originalBytes)),
      ...(lastVersion
        ? {
            previousVersionHash:
              MajikSignatureEnvelope.hashFileVersionEntry(lastVersion),
          }
        : {}),
      createdBy: key.fingerprint,
      ...(options?.message ? { message: options.message } : {}),
    };
    const versionChainHash = MajikSignatureEnvelope.hashFileVersionChain([
      ...envelope.fileVersions,
      newVersionEntry,
    ]);

    const signature = await MajikSig.sign(originalBytes, key, {
      contentType: options?.contentType,
      timestamp: newVersionEntry.timestamp,
      validUntil: options?.validUntil,
      versionChainHash,
      ...(allowlistHashValue !== undefined
        ? { allowlistHash: allowlistHashValue }
        : {}),
    });

    const establishingAllowlist =
      envelope.isFirstSigner() && !!options?.expectedSigners?.length;
    const envelopeWithAllowlist = establishingAllowlist
      ? envelope.withAllowlist(options!.expectedSigners!, key.fingerprint)
      : envelope;

    const nextEnvelope = envelopeWithAllowlist
      .withFileVersion(newVersionEntry)
      .withSignature(signature.toJSON());

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

  // ── Private: read prior file's envelope, verify it fully, bootstrap chain ──

  /**
   * Read and fully self-verify the prior signed file used by revision-aware signing.
   *
   * @remarks
   * This is intentionally stricter than simply parsing the previous envelope.
   * It verifies allowlist integrity, revision-chain structure, canonical file
   * form, and the cryptographic state of the previous signers before permitting
   * a new revision to build on top of them.
   *
   * Legacy files that predate `fileVersions` are bootstrapped with a synthetic
   * version-1 entry derived from their first signature and the current stripped
   * content hash.
   *
   * @param priorFile Previous signed file supplied as the revision baseline.
   * @param MajikSig Static crypto adapter used for self-contained verification.
   * @param debug Emit diagnostic content hashes when enabled.
   * @returns A validated envelope ready for the next revision.
   * @throws `MajikSignatureError` when the prior file is missing, non-canonical,
   * tampered, or otherwise unsafe to extend.
   */
  private static async _readAndVerifyPriorEnvelope(
    priorFile: FileLike,
    MajikSig: MajikSignatureStaticAdapter,
    debug: boolean,
  ): Promise<MajikSignatureEnvelope> {
    const { bytes: priorBytes, handler: priorHandler } =
      await MajikSignatureEmbed._prepare(priorFile);
    const raw = await priorHandler.extract(priorBytes);
    if (!raw) {
      throw new MajikSignatureError(
        "priorSignedFile has no embedded signature envelope.",
      );
    }

    let envelope = MajikSignatureEnvelope.fromJSON(raw);

    const allowlistIntegrity = envelope.verifyAllowlistIntegrity();
    if (!allowlistIntegrity.valid) {
      throw new MajikSignatureError(
        `priorSignedFile allowlist integrity failed: ${allowlistIntegrity.reason}`,
      );
    }
    const chainIntegrity = envelope.verifyVersionChainIntegrity();
    if (!chainIntegrity.valid) {
      throw new MajikSignatureError(
        `priorSignedFile version chain integrity failed: ${chainIntegrity.reason}`,
      );
    }

    const priorCanonical = await assertCanonical(priorHandler, priorBytes, raw);
    if (!priorCanonical.ok) {
      throw new MajikSignatureError(
        `priorSignedFile is not in canonical signed form: ${priorCanonical.reason}`,
      );
    }
    const priorStrippedBytes = priorCanonical.original;

    const { ok, latest, history } =
      MajikSignatureEmbed._verifyEnvelopeSelfContained(
        envelope,
        priorStrippedBytes,
        MajikSig,
      );
    if (!ok) {
      const failed = [latest, ...history].find((r) => !r.valid);
      throw new MajikSignatureError(
        `Refusing to build on priorSignedFile — signature by "${failed?.signerId}" is invalid: ${failed?.reason}`,
      );
    }

    // Bootstrap fileVersions[0] for files signed before this feature existed.
    if (envelope.fileVersions.length === 0 && envelope.signatures.length > 0) {
      const firstSig = envelope.signatures[0];
      envelope = envelope.withFileVersion({
        version: 1,
        timestamp: firstSig.timestamp,
        contentHash: bytesToBase64(hashContent(priorStrippedBytes)),
        createdBy: firstSig.signerId,
      });
    }

    if (debug)
      console.log(
        "priorSignedFile bytes hash:",
        bytesToBase64(hashContent(priorStrippedBytes)),
      );
    return envelope;
  }

  /**
   * Verify the current revision plus all historical signer commitments using
   * only the final stripped bytes and the envelope's stored chain metadata.
   *
   * @remarks
   * The newest matching signature is verified against the current bytes.
   * Earlier signatures are verified with the adapter's commitment-only path,
   * because their original bytes are no longer necessarily available.
   *
   * This is the Tier-1/self-contained path: it proves the signature commitments
   * and chain integrity, but does not independently prove that archived
   * historical bytes once existed.
   */
  private static _verifyEnvelopeSelfContained(
    envelope: MajikSignatureEnvelope,
    currentStrippedBytes: Uint8Array,
    MajikSig: MajikSignatureStaticAdapter,
    now?: Date,
  ): {
    latest: VerificationResult;
    history: RevisionCommitmentResult[];
    ok: boolean;
  } {
    const chain = envelope.fileVersions;
    const currentHash = bytesToBase64(hashContent(currentStrippedBytes));
    const fullChainHash = MajikSignatureEnvelope.hashFileVersionChain(chain);

    let latestSig = envelope.signatures.find(
      (s) =>
        s.contentHash === currentHash && s.versionChainHash === fullChainHash,
    );

    if (!latestSig) {
      // Fallback for pre-feature files
      latestSig = envelope.signatures.find(
        (s) => s.contentHash === currentHash,
      );
    }

    const checkChainHash = (
      sig: MajikSignatureJSON,
    ): { ok: boolean; reason?: string } => {
      if (sig.versionChainHash === undefined && chain.length === 0)
        return { ok: true }; // pre-feature file

      const idx = chain.findIndex(
        (v, i) =>
          v.contentHash === sig.contentHash &&
          (sig.versionChainHash
            ? MajikSignatureEnvelope.hashFileVersionChain(
                chain.slice(0, i + 1),
              ) === sig.versionChainHash
            : true),
      );

      if (idx === -1)
        return {
          ok: false,
          reason: "No fileVersions entry matches this signature's state.",
        };

      const expected = MajikSignatureEnvelope.hashFileVersionChain(
        chain.slice(0, idx + 1),
      );
      return sig.versionChainHash === undefined ||
        sig.versionChainHash === expected
        ? { ok: true }
        : {
            ok: false,
            reason:
              "versionChainHash does not match the recomputed chain prefix — chain may be tampered.",
          };
    };

    const publicKeysOf = (sig: MajikSignatureJSON): MajikSignerPublicKeys => ({
      signerId: sig.signerId,
      edPublicKey: base64ToBytes(sig.signerEdPublicKey),
      mlDsaPublicKey: base64ToBytes(sig.signerMlDsaPublicKey),
    });

    let latest: VerificationResult;
    if (!latestSig) {
      latest = {
        valid: false,
        reason: "No signature's contentHash matches the current bytes.",
        timestamp: new Date().toISOString(),
      };
    } else {
      const chainCheck = checkChainHash(latestSig);
      latest = chainCheck.ok
        ? MajikSig.verify(
            currentStrippedBytes,
            latestSig,
            publicKeysOf(latestSig),
            now,
          )
        : {
            valid: false,
            signerId: latestSig.signerId,
            contentHash: latestSig.contentHash,
            timestamp: latestSig.timestamp,
            reason: chainCheck.reason,
          };
    }

    const history: RevisionCommitmentResult[] = envelope.signatures
      .filter((s) => s !== latestSig)
      .map((sig) => {
        const chainCheck = checkChainHash(sig);
        const result = chainCheck.ok
          ? MajikSig.verifyCommitment(sig, publicKeysOf(sig), now)
          : {
              valid: false,
              signerId: sig.signerId,
              contentHash: sig.contentHash,
              timestamp: sig.timestamp,
              reason: chainCheck.reason,
            };
        return { ...result, commitmentOnly: true as const };
      });

    return {
      latest,
      history,
      ok: latest.valid && history.every((h) => h.valid),
    };
  }

  // ── signDetached ───────────────────────────────────────────────────────────

  /**
   * Sign a file without embedding the resulting envelope.
   *
   * @remarks
   * The returned `blob` is the clean/stripped file content. The envelope is
   * returned separately so callers can persist it as JSON, base64, MJKSIG, or
   * another application-specific record.
   *
   * `existingEnvelope` continues a detached multi-signature workflow without
   * requiring the envelope to be embedded in the file first. TSA attachment is
   * performed before the signature is added to the returned envelope; if the
   * adapter does not support `addTSA()`, explicitly requesting `tsa` fails
   * rather than silently dropping the timestamp.
   *
   * @param file Source file or raw bytes.
   * @param key Signing key for this signer.
   * @param MajikSig Static crypto adapter.
   * @param options Signing, allowlist, expiry, detached-envelope, and TSA options.
   * @param debug Emit the stripped content hash for diagnostics.
   * @returns Clean file Blob, resulting envelope, this call's signature, and
   * resolved handler metadata.
   * @throws `MajikSignatureError` when signing is disallowed, the envelope is
   * sealed, or TSA was requested but unsupported.
   */
  static async signDetached<
    T extends MajikSignatureAdapter = MajikSignatureAdapter,
  >(
    file: FileLike,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: EmbedOptions & {
      contentType?: string;
      timestamp?: ISODateString;
      /** ISO 8601 expiry for this signature. Omit for one that never expires. */
      validUntil?: ISODateString;
      expectedSigners?: ExpectedSigner[];
      existingEnvelope?: EnvelopeInput;
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
      validUntil: options?.validUntil,
      ...(allowlistHashValue !== undefined
        ? { allowlistHash: allowlistHashValue }
        : {}),
    });

    // ── Attach TSA, if provided ──────────────────────────────────────────────
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
   * Sign multiple files as detached envelopes and package the results.
   *
   * @remarks
   * Each file is processed through `signDetached()`, so the batch path uses the
   * same handler selection, canonicalization, allowlist, and cryptographic
   * behavior as single-file detached signing.
   *
   * In `"map"` mode, results are collected into one immutable
   * `MajikSignatureMap` plus a ready-to-store `.mjksmap` Blob. In `"separate"`
   * mode, each file gets its own `.mjksig` Blob.
   *
   * Duplicate paths and an empty batch are rejected before cryptography starts.
   * By default the first signing failure aborts the entire operation; with
   * `continueOnError: true`, failures are collected and successful files remain
   * in the returned result.
   *
   * @param files Batch inputs. Paths must be unique and non-empty.
   * @param key Signing key shared by every file in the batch.
   * @param MajikSig Static crypto adapter.
   * @param options Batch mode and shared signing options.
   * @param debug Emit per-file hash diagnostics.
   * @returns Discriminated union keyed by `mode` containing the packaged
   * signatures and any collected failures.
   * @throws `MajikSignatureValidationError` for invalid batch structure.
   * @throws `MajikSignatureError` when signing fails and `continueOnError` is false.
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
          throw new MajikSignatureError(
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
   * Sign one batch item through the normal detached-signing path and reuse the
   * resulting signature's content hash when constructing the manifest entry.
   *
   * @internal
   * Avoids a second content hash computation solely for manifest bookkeeping.
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
        validUntil: options?.validUntil,
      },
      debug,
    );

    const sig = envelope.findSignature(key.fingerprint);
    if (!sig) {
      throw new MajikSignatureError(
        `Internal error: no signature found for this signer after signing "${file.path}"`,
      );
    }

    return { envelope, contentHash: sig.contentHash };
  }

  /**
   * Validate batch shape before any cryptographic work begins.
   *
   * @remarks
   * Paths must be non-empty and unique because `MajikSignatureMap` keys entries
   * by path. Rejecting duplicates here prevents a later `withEntry()` upsert
   * from silently replacing a sibling file's manifest entry.
   *
   * @throws `MajikSignatureValidationError` when the batch is empty or contains
   * a missing/duplicate path.
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
   * Extract an embedded envelope without performing cryptographic verification.
   *
   * @remarks
   * Extraction answers "is there a parseable embedded envelope?" rather than
   * "are its signatures valid?". Use the verification APIs when authenticity
   * or integrity must be established.
   *
   * The returned envelope is an immutable `MajikSignatureEnvelope` instance.
   * Legacy bare single-signature payloads are transparently promoted by the
   * envelope parser.
   *
   * @param file Source file or raw file-like bytes.
   * @param options MIME override or fallback-handler selection.
   * @returns Parsed envelope plus handler name, or `null` when no envelope exists.
   * @throws `MajikSignatureSerializationError` when an embedded payload exists
   * but cannot be parsed as a valid envelope.
   */
  static async extract(
    file: FileLike,
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
   * Verify every embedded signature against caller-supplied public keys.
   *
   * @remarks
   * The file is first canonicalized and stripped so the embedded envelope is
   * not included in the content hash. All signatures in the envelope are then
   * checked unless `expectedSignerId` is provided.
   *
   * Verification failures are returned as `VerificationResult` values. They
   * are not treated as exceptions in the normal cryptographic-failure path.
   *
   * @param file Signed file or raw file-like bytes.
   * @param publicKeys Public keys used for cryptographic verification.
   * @param MajikSig Static crypto adapter.
   * @param options MIME override, signer filter, and verification clock.
   * @param debug Emit canonical content hash diagnostics.
   * @returns One `VerificationResult` per selected signer, or a single failure
   * result describing the missing/malformed envelope or canonicalization problem.
   */
  static async verify(
    file: FileLike,
    publicKeys: MajikSignerPublicKeys,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { expectedSignerId?: string; now?: Date },
    debug: boolean = false,
  ): Promise<VerificationResult[]> {
    const { bytes, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const raw = await handler.extract(bytes);
    if (!raw)
      return [
        MajikSignatureEmbed._noSignatureResult(
          noSignatureReason(handler, bytes),
        ),
      ];

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

    const canonical = await assertCanonical(handler, bytes, raw);
    if (!canonical.ok) {
      return [
        {
          valid: false,
          reason: canonical.reason,
          timestamp: new Date().toISOString(),
        },
      ];
    }
    const originalBytes = canonical.original;

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
      options?.now,
    );
  }

  // ── verifyWithKey ──────────────────────────────────────────────────────────

  /**
   * Convenience form of `verify()` that derives public keys from a `MajikKey`.
   *
   * @remarks
   * Only public key material is consumed by verification, so the supplied key
   * does not need to be unlocked merely to verify an existing signature.
   *
   * @param file Signed file to verify.
   * @param key `MajikKey` whose public signing keys should be used.
   * @param MajikSig Static crypto adapter.
   * @param options Same extraction and verification options as `verify()`.
   * @param debug Emit verification diagnostics when enabled.
   * @returns Same result shape as `verify()`.
   */
  static async verifyWithKey(
    file: FileLike,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { expectedSignerId?: string; now?: Date },
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
   * Verify file bytes against an externally supplied detached envelope.
   *
   * @remarks
   * The detached envelope may be an instance, JSON shape, MJKSIG `Blob`, or
   * raw MJKSIG bytes. The file is always prepared into canonical verification
   * bytes, and any accidentally embedded envelope is stripped so the detached
   * envelope never becomes part of the content hash.
   *
   * `requireCanonical` can be used when the caller wants a non-canonical file
   * representation to be rejected instead of merely stripped for verification.
   *
   * @param file File whose content is being verified.
   * @param envelopeInput Detached envelope in any accepted representation.
   * @param publicKeys Public keys used for cryptographic verification.
   * @param MajikSig Static crypto adapter.
   * @param options MIME override, signer filter, verification time, and canonicality policy.
   * @param debug Emit the canonical content hash.
   * @returns One verification result per selected signer.
   */
  static async verifyDetached(
    file: FileLike,
    envelopeInput: EnvelopeInput,
    publicKeys: MajikSignerPublicKeys,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & {
      expectedSignerId?: string;
      now?: Date;
      requireCanonical?: boolean;
    },
    debug: boolean = false,
  ): Promise<VerificationResult[]> {
    const { bytes, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const envelope = await MajikSignatureEnvelope.from(envelopeInput);
    const prepared = await prepareDetachedBytes(handler, bytes, {
      requireCanonical: options?.requireCanonical,
      validateEnvelope: (r) => void MajikSignatureEnvelope.fromJSON(r),
    });
    if (!prepared.ok) {
      return [
        {
          valid: false,
          reason: prepared.reason,
          timestamp: new Date().toISOString(),
        },
      ];
    }
    const originalBytes = prepared.original;

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
      options?.now,
    );
  }

  // ── verifyDetachedWithKey ──────────────────────────────────────────────────

  /**
   * Convenience form of `verifyDetached()` using public keys derived from a `MajikKey`.
   *
   * @param file File whose canonical content is being checked.
   * @param envelopeInput Detached envelope in instance, JSON, MJKSIG bytes, or Blob form.
   * @param key `MajikKey` supplying the public verification keys.
   * @param MajikSig Static crypto adapter.
   * @param options Detached-verification options.
   * @param debug Emit diagnostic content hashes.
   * @returns Same verification result shape as `verifyDetached()`.
   */
  static async verifyDetachedWithKey(
    file: FileLike,
    envelopeInput: EnvelopeInput,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & {
      expectedSignerId?: string;
      now?: Date;
      requireCanonical?: boolean;
    },
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
   * Verify a collection of files against a `MajikSignatureMap` manifest.
   *
   * @remarks
   * Each file is first resolved against the manifest by path and then, when
   * necessary, by content hash. This makes the workflow tolerant of files that
   * were renamed or moved after signing.
   *
   * Normal verification outcomes are reported per file instead of thrown:
   * `verified`, `invalid`, `tampered`, and `not_in_map`. Set
   * `requireAllPresent` when a missing file should instead abort the operation.
   *
   * @param map Immutable batch manifest.
   * @param files Files being checked. Paths need not match their original
   * locations when relocation-by-hash is desired.
   * @param publicKeys Public keys used for signature verification.
   * @param MajikSig Static crypto adapter.
   * @param options Expected signer filter, missing-file policy, and verification time.
   * @param debug Emit per-file content hashes.
   * @returns One `FileVerifyResult` per supplied file.
   * @throws `MajikSignatureError` only for configured hard-failure conditions,
   * such as `requireAllPresent` encountering a missing file.
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
        options?.now,
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

  /**
   * Convenience overload for batch-map verification using a `MajikKey`.
   *
   * @param map Manifest containing detached signature envelopes.
   * @param files Files to resolve and verify against the manifest.
   * @param key `MajikKey` supplying the public verification keys.
   * @param MajikSig Static crypto adapter.
   * @param options Batch verification options.
   * @param debug Emit diagnostics when enabled.
   * @returns Same result shape as `verifyFilesFromMjksMap()`.
   */
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
   * Reduce per-file batch verification results to one aggregate summary.
   *
   * @param results Results returned by `verifyFilesFromMjksMap()`.
   * @returns Count of every status plus `allValid`, which is true only when
   * every supplied file has status `"verified"` and the result set is non-empty.
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

  /**
   * Verify the chronological signing order of an embedded envelope.
   *
   * @remarks
   * `expectedOrder` may mix `MajikKey` instances and `ExpectedSigner` objects.
   * The underlying order verifier normalizes these identities and compares only
   * valid signatures belonging to the expected sequence.
   *
   * TSA-attested timestamps are preferred by the order-verification layer when
   * available; self-reported timestamps remain distinguishable through the
   * returned order result.
   *
   * @param file Signed file containing the envelope to inspect.
   * @param expectedOrder Signers in the required chronological sequence.
   * @param MajikSig Static crypto adapter used for signature verification.
   * @param options Extraction settings plus strictness configuration.
   * @returns Detailed order-verification status, including pending, invalid,
   * unexpected, and ordering-violation information.
   * @throws `MajikSignatureError` when the envelope is structurally present but
   * fails required pre-verification integrity/canonicality checks.
   */
  static async verifyFileOrder(
    file: FileLike,
    expectedOrder: readonly (MajikKey | ExpectedSigner)[],
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & VerifySignatureOrderOptions,
  ): Promise<SignatureOrderResult> {
    const { bytes, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const raw = await handler.extract(bytes);
    const envelope = raw
      ? MajikSignatureEnvelope.fromJSON(raw)
      : MajikSignatureEnvelope.empty();

    if (raw) {
      const integrity = envelope.verifyAllowlistIntegrity();
      if (!integrity.valid) {
        throw new MajikSignatureError(
          integrity.reason ?? "Allowlist integrity check failed",
        );
      }
    }

    let originalBytes = bytes;
    if (raw) {
      const c = await assertCanonical(handler, bytes, raw);
      if (!c.ok) throw new MajikSignatureError(c.reason);
      originalBytes = c.original;
    }

    return verifySignatureOrder(
      envelope,
      originalBytes,
      expectedOrder,
      (content, sig, pk) => MajikSig.verify(content, sig, pk),
      { strict: options?.strict },
    );
  }

  /**
   * Verify chronological signing order against a detached envelope.
   *
   * @param file File whose canonical content is being checked.
   * @param envelopeInput Detached envelope in instance, JSON, MJKSIG bytes, or Blob form.
   * @param expectedOrder Required chronological signer sequence.
   * @param MajikSig Static crypto adapter.
   * @param options Extraction and strict-order options.
   * @returns Detailed `SignatureOrderResult` for the supplied sequence.
   * @throws `MajikSignatureError` when envelope integrity or canonical file
   * preparation fails.
   */
  static async verifyDetachedOrder(
    file: FileLike,
    envelopeInput: EnvelopeInput,
    expectedOrder: readonly (MajikKey | ExpectedSigner)[],
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & VerifySignatureOrderOptions,
  ): Promise<SignatureOrderResult> {
    const { bytes, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );

    const envelope = await MajikSignatureEnvelope.from(envelopeInput);
    const integrity = envelope.verifyAllowlistIntegrity();
    if (!integrity.valid) {
      throw new MajikSignatureError(
        integrity.reason ?? "Allowlist integrity check failed",
      );
    }

    const prepared = await prepareDetachedBytes(handler, bytes, {
      validateEnvelope: (r) => void MajikSignatureEnvelope.fromJSON(r),
    });
    if (!prepared.ok) throw new MajikSignatureError(prepared.reason);
    const originalBytes = prepared.original;

    return verifySignatureOrder(
      envelope,
      originalBytes,
      expectedOrder,
      (content, sig, pk) => MajikSig.verify(content, sig, pk),
      { strict: options?.strict },
    );
  }

  /**
   * Perform Tier-1, self-contained verification of a file revision chain.
   *
   * @remarks
   * The current/latest signer is verified against the current stripped bytes.
   * Earlier signers are checked through commitment-only verification and the
   * version-chain hash. No archived copies of earlier revisions are required.
   *
   * This method proves chain and signature commitment integrity, but not the
   * historical existence of the exact earlier bytes; use
   * `verifyFileRevisions()` for archive-assisted Tier-2 verification.
   *
   * @param file Final file containing the revision chain.
   * @param MajikSig Static crypto adapter.
   * @param options MIME override and verification clock.
   * @returns Latest verification, historical commitment results, and aggregate
   * `chainValid` status.
   * @throws `MajikSignatureError` when no embedded envelope exists or the file
   * cannot be prepared canonically.
   */
  static async verifyFileChain(
    file: FileLike,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { now?: Date },
  ): Promise<FileChainVerification> {
    const { bytes, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );
    const raw = await handler.extract(bytes);
    if (!raw)
      throw new MajikSignatureError(
        "Cannot verify chain — no embedded envelope found.",
      );

    const envelope = MajikSignatureEnvelope.fromJSON(raw);
    const canonical = await assertCanonical(handler, bytes, raw);
    if (!canonical.ok) throw new MajikSignatureError(canonical.reason);
    const originalBytes = canonical.original;

    const allowlistIntegrity = envelope.verifyAllowlistIntegrity();
    const chainIntegrity = envelope.verifyVersionChainIntegrity();

    const { latest, history, ok } =
      MajikSignatureEmbed._verifyEnvelopeSelfContained(
        envelope,
        originalBytes,
        MajikSig,
        options?.now,
      );
    const chainValid = allowlistIntegrity.valid && chainIntegrity.valid && ok;
    return { latest, history, chainValid };
  }

  /**
   * Perform Tier-2, archive-assisted verification of every recorded revision.
   *
   * @remarks
   * The supplied historical files are canonicalized and matched to
   * `fileVersions[].contentHash`. Each matched revision is then verified with
   * its corresponding signature and chain commitment.
   *
   * The final file is automatically included in the supplied set, so callers
   * do not need to pass it again in `revisions`.
   *
   * When `resolvePublicKeys` is omitted, the public keys embedded in each
   * signature are used. Applications with an external identity/key registry
   * can provide a resolver to verify against independently supplied keys.
   *
   * @param finalFile Current signed file containing the revision chain.
   * @param revisions Retained earlier revision files. Each may be `Blob`,
   * `File`, `Uint8Array`, or `ArrayBuffer` through `FileLike`.
   * @param MajikSig Static crypto adapter.
   * @param options Verification clock and optional trusted public-key resolver.
   * @returns Per-revision status plus `allValid` and `isCompleteSet` aggregates.
   * @throws `MajikSignatureError` when the final file has no envelope or no
   * revision chain to verify.
   */
  static async verifyFileRevisions(
    finalFile: FileLike,
    revisions: FileLike[],
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & {
      now?: Date;
      resolvePublicKeys?: (
        signerId: string,
      ) => MajikSignerPublicKeys | Promise<MajikSignerPublicKeys>;
    },
  ): Promise<RevisionSetVerification> {
    const { bytes, handler } = await MajikSignatureEmbed._prepare(
      finalFile,
      options,
    );
    const raw = await handler.extract(bytes);
    if (!raw)
      throw new MajikSignatureError(
        "Cannot verify revisions — no embedded envelope found.",
      );

    const envelope = MajikSignatureEnvelope.fromJSON(raw);
    const chain = envelope.fileVersions;
    if (chain.length === 0) {
      throw new MajikSignatureError(
        "This file has no fileVersions chain to verify against.",
      );
    }

    const normalized = (
      await Promise.all(
        [...revisions, finalFile].map(async (input) => {
          const revBlob = normalizeToBlob(await normalizeToBytes(input));
          const { bytes: rBytes, handler: rHandler } =
            await MajikSignatureEmbed._prepare(revBlob);
          const rRaw = await rHandler.extract(rBytes);
          let stripped: Uint8Array;
          if (rRaw !== null) {
            const c = await assertCanonical(rHandler, rBytes, rRaw);
            if (!c.ok) return null;
            stripped = c.original;
          } else {
            stripped = await rHandler.strip(rBytes);
          }
          return {
            stripped,
            contentHash: bytesToBase64(hashContent(stripped)),
          };
        }),
      )
    ).filter(
      (r): r is { stripped: Uint8Array; contentHash: string } => r !== null,
    );

    const results: RevisionCheckResult[] = [];

    for (let i = 0; i < chain.length; i++) {
      const entry = chain[i];
      const match = normalized.find((r) => r.contentHash === entry.contentHash);
      if (!match) {
        results.push({
          version: entry.version,
          status: "unmatched",
          reason: `No supplied file matches fileVersions[${i}].`,
        });
        continue;
      }

      const expectedPrev =
        i === 0
          ? undefined
          : MajikSignatureEnvelope.hashFileVersionEntry(chain[i - 1]);
      if (entry.previousVersionHash !== expectedPrev) {
        results.push({
          version: entry.version,
          status: "chain_broken",
          reason: `fileVersions[${i}] does not chain onto the prior entry.`,
        });
        continue;
      }
      const expectedChainHash = MajikSignatureEnvelope.hashFileVersionChain(
        chain.slice(0, i + 1),
      );

      const sig = envelope.signatures.find(
        (s) =>
          s.contentHash === entry.contentHash &&
          (entry.createdBy ? s.signerId === entry.createdBy : true) &&
          (s.versionChainHash
            ? s.versionChainHash === expectedChainHash
            : true),
      );

      if (!sig) {
        results.push({
          version: entry.version,
          status: "unmatched",
          reason: `No signature matches fileVersions[${i}].`,
        });
        continue;
      }

      if (sig.versionChainHash && sig.versionChainHash !== expectedChainHash) {
        results.push({
          version: entry.version,
          status: "chain_broken",
          signerId: sig.signerId,
          reason:
            "versionChainHash does not match this revision's chain state.",
        });
        continue;
      }

      const publicKeys = options?.resolvePublicKeys
        ? await options.resolvePublicKeys(sig.signerId)
        : {
            signerId: sig.signerId,
            edPublicKey: base64ToBytes(sig.signerEdPublicKey),
            mlDsaPublicKey: base64ToBytes(sig.signerMlDsaPublicKey),
          };

      const verifyResult = MajikSig.verify(
        match.stripped,
        sig,
        publicKeys,
        options?.now,
      );
      results.push({
        version: entry.version,
        status: verifyResult.valid ? "verified" : "signature_invalid",
        signerId: sig.signerId,
        reason: verifyResult.reason,
      });
    }

    return {
      allValid:
        results.length === chain.length &&
        results.every((r) => r.status === "verified"),
      isCompleteSet: results.every((r) => r.status !== "unmatched"),
      results,
    };
  }

  // ── seal ───────────────────────────────────────────────────────────────────

  /**
   * Apply a cryptographic seal to an embedded envelope.
   *
   * @remarks
   * Sealing computes a SHA3-512 integrity hash over the current signatories
   * and seal timestamp and permanently prevents further signatures through the
   * envelope state model. It is an integrity lock, not another signer
   * signature.
   *
   * With an allowlist, only the issuer may seal. An already sealed envelope
   * cannot be sealed again.
   *
   * @param file Signed file containing the envelope to seal.
   * @param key Key/fingerprint of the actor attempting to seal the envelope.
   * @param options MIME override and optional deterministic seal timestamp.
   * @returns Sealed file, seal metadata, and handler information.
   * @throws `MajikSignatureError` when no envelope exists or it is already sealed.
   * @throws `MajikSignatureKeyError` when a restricted envelope is sealed by
   * someone other than its issuer.
   */
  static async seal(
    file: FileLike,
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

  /**
   * Verify the structural integrity of an embedded seal.
   *
   * @remarks
   * This verifies the seal hash against the current envelope state; it does
   * **not** verify the individual Ed25519/ML-DSA-87 signatures contained in the
   * envelope. Use `verify()` / `verifyWithKey()` for signer verification too.
   *
   * @returns `SealVerificationResult`, or an invalid result when no envelope exists.
   */
  static async verifySeal(
    file: FileLike,
    options?: ExtractOptions,
  ): Promise<SealVerificationResult> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return { valid: false, reason: "No embedded envelope found" };
    return result.envelope.verifySeal();
  }

  /**
   * Read seal metadata without verifying the seal hash.
   *
   * @returns `{ sealHash, sealTimestamp, sealedBy }` when sealed, otherwise `null`.
   */
  static async getSealInfo(
    file: FileLike,
    options?: ExtractOptions,
  ): Promise<SealInfo | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.getSealInfo() : null;
  }

  /**
   * Perform a cheap structural check for whether a file contains a sealed envelope.
   *
   * @remarks Does not verify the seal hash or individual signatures.
   */
  static async isSealed(
    file: FileLike,
    options?: ExtractOptions,
  ): Promise<boolean> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.isSealed() : false;
  }

  /**
   * Check whether a file contains a restricted multi-signature envelope.
   *
   * @remarks The result follows `MajikSignatureEnvelope.isMultiSig()` semantics:
   * an allowlist with more than one expected signer is required. Unsigned,
   * open-signing, and single-signer files return `false`.
   */
  static async isMultiSig(
    file: FileLike,
    options?: ExtractOptions,
  ): Promise<boolean> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.isMultiSig() : false;
  }

  /**
   * Check whether a key is currently permitted to sign a file.
   *
   * @remarks
   * For an unsigned file, no envelope-level restriction exists and the method
   * returns `{ permitted: true }`. For existing envelopes, seal and allowlist
   * rules are evaluated without performing a new signature operation.
   *
   * @returns Permission status and, on denial, a human-readable reason.
   */
  static async canSign(
    file: FileLike,
    key: MajikKey,
    options?: ExtractOptions,
  ): Promise<{ permitted: boolean; reason?: string }> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return { permitted: true };
    return result.envelope.canSign(key);
  }

  /**
   * Resolve expected/signed/pending signatory state from an embedded envelope.
   *
   * @param filter Optional requested view. The returned object preserves the
   * full `{ all, signed, pending }` shape.
   * @returns Signatory status, or `null` when no relevant envelope state exists.
   */
  static async getSignatories(
    file: FileLike,
    options?: ExtractOptions,
    filter?: SignatoriesFilter,
  ): Promise<SignatoriesResult | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.getSignatories(filter) : null;
  }

  /**
   * Resolve the envelope issuer.
   *
   * @remarks For restricted envelopes this is the allowlist establisher. For
   * open-signing envelopes it falls back to the first signer. Unsigned files
   * return `null`.
   */
  static async getIssuer(
    file: FileLike,
    options?: ExtractOptions,
  ): Promise<import("../../core/types").SignatoryInfo | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.resolveIssuer() : null;
  }

  /**
   * Return a one-call snapshot of the embedded envelope state.
   *
   * @remarks Useful for rendering signing-status UI without repeatedly parsing
   * the same file for multi-sig, seal, issuer, allowlist, and signature-count
   * information.
   */
  static async getEnvelopeInfo(
    file: FileLike,
    options?: ExtractOptions,
  ): Promise<EnvelopeInfo | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? result.envelope.getEnvelopeInfo() : null;
  }

  // ── strip ──────────────────────────────────────────────────────────────────

  /**
   * Remove the embedded signature envelope from a file.
   *
   * @remarks
   * Native handlers remove only their own signature representation. For the
   * universal fallback, the trailer is removed. The returned Blob is the clean
   * file representation used as signing/verification input.
   *
   * @returns A new Blob containing the stripped file bytes.
   */
  static async strip(file: FileLike, options?: ExtractOptions): Promise<Blob> {
    const { bytes, mimeType, handler } = await MajikSignatureEmbed._prepare(
      file,
      options,
    );
    const stripped = await handler.strip(bytes);
    return bytesToBlob(stripped, mimeType);
  }

  // ── hasSignature ───────────────────────────────────────────────────────────

  /**
   * Check for structural presence of an embedded signature envelope.
   *
   * @remarks This does not perform cryptographic verification and should be used
   * as a cheap guard before calling `verify()` when appropriate.
   */
  static async hasSignature(
    file: FileLike,
    options?: ExtractOptions,
  ): Promise<boolean> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result !== null;
  }

  // ── getAllowlist ───────────────────────────────────────────────────────────

  /**
   * Read the current signing allowlist from an embedded envelope.
   *
   * @returns A defensive copy of the allowlist, or `null` for unsigned/open-signing files.
   */
  static async getAllowlist(
    file: FileLike,
    options?: ExtractOptions,
  ): Promise<ExpectedSigner[] | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result || !result.envelope.allowlist) return null;
    return [...result.envelope.allowlist];
  }

  /**
   * Default format-handler registry used by all file operations.
   *
   * @remarks
   * The registry is exposed for discovery/introspection. Callers should prefer
   * the higher-level file APIs rather than mutating the registry during normal
   * application execution.
   */
  static readonly registry = DEFAULT_REGISTRY;

  /**
   * List the names of handlers currently registered in the default registry.
   *
   * @returns Handler names in registry order.
   */
  static listHandlers(): string[] {
    return DEFAULT_REGISTRY.listHandlers();
  }

  // ── canAnchor ──────────────────────────────────────────────────────────────

  /**
   * Check whether an embedded envelope is structurally eligible for chain anchoring.
   *
   * @remarks Anchoring requires the envelope to be sealed. This method does not
   * submit anything to a blockchain and does not inspect on-chain state.
   */
  static async canAnchor(
    file: FileLike,
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
   * Embed an already-confirmed external chain anchor into a sealed envelope.
   *
   * @remarks
   * This method does **not** submit or verify a blockchain transaction. The
   * caller is responsible for obtaining a confirmed `MajikChainAnchor` first.
   * `MajikSignatureEnvelope.withChainAnchor()` enforces the sealed-state and
   * seal-digest match, and upserts anchors by `anchor.id`.
   *
   * @param file Sealed signed file whose envelope will receive the anchor.
   * @param anchor Previously confirmed chain-anchor record.
   * @param options File handler options.
   * @returns Updated embedded file.
   * @throws `MajikSignatureError` when the envelope is missing, unsealed, or
   * the anchor's digest does not match the current seal hash.
   */
  static async registerChainAnchor(
    file: FileLike,
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

  /**
   * Read all chain anchors currently embedded in a file envelope.
   *
   * @returns Defensive copy of the anchors, or an empty array for unsigned files.
   */
  static async getChainAnchors(
    file: FileLike,
    options?: ExtractOptions,
  ): Promise<MajikChainAnchor[]> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result ? [...result.envelope.chainAnchors] : [];
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  /**
   * Normalize input bytes, determine the MIME type, and resolve the format handler.
   *
   * @remarks
   * This is the common entry point for nearly every public file operation. When
   * `forceFallback` is enabled, native format detection is bypassed and the
   * universal trailer handler is used explicitly.
   *
   * @internal
   */
  private static async _prepare(
    file: FileLike,
    options?: { mimeType?: string; forceFallback?: boolean },
  ): Promise<{ bytes: Uint8Array; mimeType: string; handler: FormatHandler }> {
    const bytes = await normalizeToBytes(file);

    const declaredType = file instanceof Blob ? file.type : undefined;
    const mimeType = options?.mimeType ?? detectMimeType(bytes, declaredType);

    const handler = options?.forceFallback
      ? new FallbackHandler()
      : DEFAULT_REGISTRY.resolve(bytes, mimeType);

    return { bytes, mimeType, handler };
  }

  /**
   * Extract and parse an embedded envelope, or produce an empty envelope when
   * the file is currently unsigned.
   *
   * @internal
   */
  private static async _readEnvelope(
    handler: FormatHandler,
    bytes: Uint8Array,
  ): Promise<MajikSignatureEnvelope> {
    const raw = await handler.extract(bytes);
    return raw
      ? MajikSignatureEnvelope.fromJSON(raw)
      : MajikSignatureEnvelope.empty();
  }

  /**
   * Construct the standard no-signature verification result used by file-level
   * verification APIs.
   *
   * @internal
   */
  private static _noSignatureResult(
    reason = "No embedded signature found",
  ): VerificationResult {
    return { valid: false, reason, timestamp: new Date().toISOString() };
  }

  /**
   * Verify selected envelope signatures against canonical file bytes.
   *
   * @remarks
   * Centralizes signer filtering and handler metadata so `verify()` and
   * `verifyDetached()` remain behaviorally aligned. If `expectedSignerId` is
   * supplied, only that signer is verified. A missing selected signer produces
   * a normal invalid result rather than an exception.
   *
   * @internal
   */
  private static _verifySignatures(
    envelope: MajikSignatureEnvelope,
    originalBytes: Uint8Array,
    publicKeys: MajikSignerPublicKeys,
    MajikSig: MajikSignatureStaticAdapter,
    handlerName: string,
    expectedSignerId?: string,
    now?: Date,
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
      ...MajikSig.verify(originalBytes, sig, publicKeys, now),
      handler: handlerName,
    }));
  }
}

// Freeze static methods
Object.freeze(MajikSignatureEmbed);

// Freeze instance methods
Object.freeze(MajikSignatureEmbed.prototype);

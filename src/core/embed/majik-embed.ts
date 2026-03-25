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
 * Instead, operations that need MajikSignature receive it via the
 * MajikSignatureStaticAdapter interface — no circular import needed.
 *
 * Multi-sig + allowlist + seal:
 * ─────────────────────────────
 * Files embed a MultiSigEnvelope (array of per-signer envelopes + optional
 * allowlist + optional seal). parseEnvelope() transparently promotes old
 * single-sig files — all code here always operates on MultiSigEnvelope.
 */

import type { MajikKey } from "@majikah/majik-key";

import type {
  EmbedOptions,
  EmbedResult,
  EnvelopeInfo,
  ExpectedSigner,
  ExtractOptions,
  ExtractResult,
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  MultiSigEnvelope,
  SealInfo,
  SealVerificationResult,
  SignatoriesFilter,
  SignatoriesResult,
  SignOptions,
  VerificationResult,
} from "../../core/types";
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
import {
  MajikSignatureAllowlistError,
  MajikSignatureError,
  MajikSignatureKeyError,
  MajikSignatureSerializationError,
} from "../errors";
import {
  parseEnvelope,
  upsertSignature,
  checkAllowlist,
  hashAllowlist,
  computeSealHash,
  buildSignatoriesResult,
} from "../multi-sig";

// ─── Adapter interfaces ───────────────────────────────────────────────────────

export interface MajikSignatureAdapter {
  toJSON(): MajikSignatureJSON;
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
   * and writes the updated MultiSigEnvelope back.
   * Does NOT sign — call signAndEmbed() for sign + embed together.
   */
  static async embed(
    file: Blob,
    signature: MajikSignatureAdapter | MajikSignatureJSON,
    options?: EmbedOptions,
  ): Promise<EmbedResult> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);

    const handler = options?.forceFallback
      ? new FallbackHandler()
      : DEFAULT_REGISTRY.resolve(bytes, mimeType);

    const sigJson =
      typeof (signature as MajikSignatureAdapter).toJSON === "function"
        ? (signature as MajikSignatureAdapter).toJSON()
        : (signature as MajikSignatureJSON);

    // Read existing envelope (if any) and upsert
    const existingRaw = await handler.extract(bytes);
    const envelope: MultiSigEnvelope = existingRaw
      ? parseEnvelope(existingRaw)
      : { version: 1, signatures: [] };

    // Refuse to embed into a sealed envelope
    if (envelope.sealHash) {
      throw new MajikSignatureError(
        "Cannot embed a signature into a sealed envelope.",
      );
    }

    const updated = upsertSignature(envelope, sigJson);
    // Strip before re-embedding so the old envelope bytes are not included
    const strippedBytes = await handler.strip(bytes);
    const resultBytes = await handler.embed(
      strippedBytes,
      JSON.stringify(updated),
    );
    const blob = bytesToBlob(resultBytes, mimeType);

    return { blob, handler: handler.name, mimeType };
  }

  // ── signAndEmbed ───────────────────────────────────────────────────────────

  /**
   * Sign a file and embed the signature in one call.
   *
   * Flow:
   *   1. Extract existing MultiSigEnvelope (or start fresh)
   *   2. Reject if envelope is sealed
   *   3. Enforce allowlist — throw MajikSignatureAllowlistError before any crypto
   *   4. Strip existing envelope to get clean original bytes
   *   5. If first signer and options.expectedSigners provided: compute allowlistHash
   *      to bind the allowlist into the signing payload
   *   6. Sign the clean bytes (allowlistHash included in payload when present)
   *   7. Upsert signature into envelope; if establishing allowlist, attach
   *      allowlist + allowlistSignerId to envelope
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
  ): Promise<EmbedResult & { signature: T }> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);

    const handler = options?.forceFallback
      ? new FallbackHandler()
      : DEFAULT_REGISTRY.resolve(bytes, mimeType);

    // ── Step 1: Extract existing envelope ─────────────────────────────────
    const existingRaw = await handler.extract(bytes);
    const envelope: MultiSigEnvelope = existingRaw
      ? parseEnvelope(existingRaw)
      : { version: 1, signatures: [] };

    // ── Step 2: Reject sealed envelopes ────────────────────────────────────
    if (envelope.sealHash) {
      throw new MajikSignatureError(
        "Cannot sign a sealed envelope. The issuer has locked this file against further signatures.",
      );
    }

    // ── Step 3: Allowlist enforcement ──────────────────────────────────────
    const allowlistCheck = checkAllowlist(envelope, key);
    if (!allowlistCheck.permitted) {
      throw new MajikSignatureAllowlistError(
        `Signer "${key.fingerprint}" is not permitted to sign this file. ` +
          `The file has a signing allowlist established by "${envelope.allowlistSignerId}".`,
        key.fingerprint,
      );
    }

    // ── Step 4: Get clean original bytes ───────────────────────────────────
    const originalBytes = await handler.strip(bytes);

    if (debug) {
      const recomputedHash = bytesToBase64(hashContent(originalBytes));
      console.log("signAndEmbed — original bytes hash:", recomputedHash);
    }

    // ── Step 5: Compute allowlistHash if establishing an allowlist ─────────
    const isFirstSigner = envelope.signatures.length === 0;
    const establishingAllowlist =
      isFirstSigner &&
      options?.expectedSigners &&
      options.expectedSigners.length > 0;

    const allowlistHashValue = establishingAllowlist
      ? hashAllowlist(options!.expectedSigners!)
      : undefined;

    // ── Step 6: Sign ───────────────────────────────────────────────────────
    const signature = await MajikSig.sign(originalBytes, key, {
      contentType: options?.contentType,
      timestamp: options?.timestamp,
      ...(allowlistHashValue !== undefined
        ? { allowlistHash: allowlistHashValue }
        : {}),
    });

    // ── Step 7: Build updated envelope ────────────────────────────────────
    let nextEnvelope = upsertSignature(envelope, signature.toJSON());

    if (establishingAllowlist) {
      nextEnvelope = {
        ...nextEnvelope,
        allowlist: options!.expectedSigners!,
        allowlistSignerId: key.fingerprint,
      };
    }

    // ── Step 8: Embed ──────────────────────────────────────────────────────
    const resultBytes = await handler.embed(
      originalBytes,
      JSON.stringify(nextEnvelope),
    );
    const blob = bytesToBlob(resultBytes, mimeType);

    return { blob, handler: handler.name, mimeType, signature: signature as T };
  }

  // ── extract ────────────────────────────────────────────────────────────────

  /**
   * Extract the MultiSigEnvelope from a file.
   * Returns null if no signature is found.
   * Old single-sig files are promoted to MultiSigEnvelope transparently.
   */
  static async extract(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<ExtractResult | null> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);
    const handler = DEFAULT_REGISTRY.resolve(bytes, mimeType);

    const raw = await handler.extract(bytes);
    if (!raw) return null;

    const envelope = parseEnvelope(raw);
    return { envelope, handler: handler.name };
  }

  // ── verify ─────────────────────────────────────────────────────────────────

  /**
   * Verify a file's embedded signatures against public keys.
   * Returns one VerificationResult per signature in the envelope.
   * Old single-sig files return a single-item array.
   */
  static async verify(
    file: Blob,
    publicKeys: MajikSignerPublicKeys,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { expectedSignerId?: string },
    debug: boolean = false,
  ): Promise<VerificationResult[]> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);
    const handler = DEFAULT_REGISTRY.resolve(bytes, mimeType);

    const raw = await handler.extract(bytes);
    if (!raw) {
      return [
        {
          valid: false,
          reason: "No embedded signature found",
          timestamp: new Date().toISOString(),
        },
      ];
    }

    let envelope: MultiSigEnvelope;
    try {
      envelope = parseEnvelope(raw);
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
      const recomputedHash = bytesToBase64(hashContent(originalBytes));
      console.log("verify — original bytes hash:", recomputedHash);
    }

    // ── Allowlist integrity check ──────────────────────────────────────────
    if (envelope.allowlist && envelope.allowlistSignerId) {
      const recomputedAllowlistHash = hashAllowlist(envelope.allowlist);
      const establisherSig = envelope.signatures.find(
        (s) => s.signerId === envelope.allowlistSignerId,
      );
      if (!establisherSig) {
        return [
          {
            valid: false,
            reason: `Allowlist establisher "${envelope.allowlistSignerId}" has no signature in this envelope`,
            timestamp: new Date().toISOString(),
          },
        ];
      }
      if (establisherSig.allowlistHash !== recomputedAllowlistHash) {
        return [
          {
            valid: false,
            reason:
              "Allowlist integrity check failed — allowlist may have been tampered with",
            timestamp: new Date().toISOString(),
          },
        ];
      }
    }

    // ── Filter by expectedSignerId if provided ─────────────────────────────
    const sigsToVerify = options?.expectedSignerId
      ? envelope.signatures.filter(
          (s) => s.signerId === options.expectedSignerId,
        )
      : envelope.signatures;

    if (sigsToVerify.length === 0) {
      return [
        {
          valid: false,
          reason: options?.expectedSignerId
            ? `No signature found for signerId "${options.expectedSignerId}"`
            : "Envelope contains no signatures",
          timestamp: new Date().toISOString(),
        },
      ];
    }

    // ── Verify each signature ──────────────────────────────────────────────
    const results: VerificationResult[] = [];
    for (const sig of sigsToVerify) {
      const result = MajikSig.verify(originalBytes, sig, publicKeys);
      results.push({ ...result, handler: handler.name });
    }

    return results;
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

  // ── seal ───────────────────────────────────────────────────────────────────

  /**
   * Seal a multi-sig envelope, preventing any further signatures.
   *
   * Rules:
   *   - Only the issuer (allowlistSignerId) may seal
   *   - The envelope must have an allowlist (must be a restricted multi-sig file)
   *   - The envelope must not already be sealed
   *   - The key must be unlocked
   *
   * The seal hash is SHA3-512 of all current signatories + sealTimestamp,
   * prefixed with MAJIK_SEAL_DOMAIN. It is stored in the envelope alongside
   * the sealTimestamp and sealedBy fields. No new cryptographic signature
   * is produced — the seal is a hash-based integrity lock.
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
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);
    const handler = DEFAULT_REGISTRY.resolve(bytes, mimeType);

    const raw = await handler.extract(bytes);
    if (!raw) {
      throw new MajikSignatureError(
        "Cannot seal an unsigned file — no envelope found.",
      );
    }

    const envelope = parseEnvelope(raw);

    // Must be a restricted multi-sig file (has an allowlist)
    if (!envelope.allowlist || !envelope.allowlistSignerId) {
      throw new MajikSignatureError(
        "Cannot seal an open-signing file. Sealing is only available for files with an allowlist.",
      );
    }

    // Only the issuer may seal
    if (key.fingerprint !== envelope.allowlistSignerId) {
      throw new MajikSignatureKeyError(
        `Only the issuer ("${envelope.allowlistSignerId}") may seal this file. ` +
          `Provided key fingerprint: "${key.fingerprint}".`,
      );
    }

    // Already sealed
    if (envelope.sealHash) {
      throw new MajikSignatureError("This envelope is already sealed.");
    }

    const sealTimestamp = options?.timestamp ?? new Date().toISOString();
    const sealHash = computeSealHash(envelope.signatures, sealTimestamp);

    const sealedEnvelope: MultiSigEnvelope = {
      ...envelope,
      sealHash,
      sealTimestamp,
      sealedBy: key.fingerprint,
    };

    const originalBytes = await handler.strip(bytes);
    const resultBytes = await handler.embed(
      originalBytes,
      JSON.stringify(sealedEnvelope),
    );
    const blob = bytesToBlob(resultBytes, mimeType);

    const sealInfo: SealInfo = {
      sealHash,
      sealTimestamp,
      sealedBy: key.fingerprint,
    };

    return { blob, sealInfo, handler: handler.name, mimeType };
  }

  // ── verifySeal ─────────────────────────────────────────────────────────────

  /**
   * Verify the seal hash against the current signatories and sealTimestamp.
   * Returns invalid if the envelope is not sealed.
   * Does NOT verify the individual cryptographic signatures — call verify() for that.
   */
  static async verifySeal(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<SealVerificationResult> {
    const result = await MajikSignatureEmbed.extract(file, options);

    if (!result) {
      return {
        valid: false,
        reason: "No embedded envelope found",
      };
    }

    const { envelope } = result;

    if (!envelope.sealHash || !envelope.sealTimestamp || !envelope.sealedBy) {
      return {
        valid: false,
        reason: "Envelope is not sealed",
      };
    }

    const recomputed = computeSealHash(
      envelope.signatures,
      envelope.sealTimestamp,
    );

    if (recomputed !== envelope.sealHash) {
      return {
        valid: false,
        sealedBy: envelope.sealedBy,
        sealTimestamp: envelope.sealTimestamp,
        reason:
          "Seal hash does not match — signatories or timestamp may have been tampered with",
      };
    }

    return {
      valid: true,
      sealedBy: envelope.sealedBy,
      sealTimestamp: envelope.sealTimestamp,
    };
  }

  // ── getSealInfo ────────────────────────────────────────────────────────────

  /**
   * Return seal metadata without verifying.
   * Returns null if the envelope is not sealed or has no envelope.
   */
  static async getSealInfo(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<SealInfo | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return null;

    const { envelope } = result;
    if (!envelope.sealHash || !envelope.sealTimestamp || !envelope.sealedBy) {
      return null;
    }

    return {
      sealHash: envelope.sealHash,
      sealTimestamp: envelope.sealTimestamp,
      sealedBy: envelope.sealedBy,
    };
  }

  // ── isSealed ───────────────────────────────────────────────────────────────

  /**
   * Returns true if the file has a sealed envelope (structural check only).
   * Does not verify the seal hash.
   */
  static async isSealed(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<boolean> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return false;
    return result.envelope.sealHash !== undefined;
  }

  // ── isMultiSig ─────────────────────────────────────────────────────────────

  /**
   * Returns true when the file has a restricted multi-sig envelope
   * (allowlist present with more than one expected signer).
   * Returns false for unsigned files, open-signing files, or single-signer files.
   */
  static async isMultiSig(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<boolean> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return false;
    const { envelope } = result;
    return envelope.allowlist !== undefined && envelope.allowlist.length > 1;
  }

  // ── canSign ────────────────────────────────────────────────────────────────

  /**
   * Check whether a MajikKey is permitted to add a signature to this file.
   *
   * Returns false (with a reason) when:
   *   - The file is sealed
   *   - The file has an allowlist and the key is not on it (all three fields checked)
   *
   * Returns true when:
   *   - The file has no envelope (unsigned — anyone may sign)
   *   - The file has no allowlist (open signing — anyone may sign)
   *   - The key is on the allowlist
   *
   * Always requires a full MajikKey — fingerprint-only checks are not supported
   * because they cannot verify the public key fields required by the allowlist.
   */
  static async canSign(
    file: Blob,
    key: MajikKey,
    options?: ExtractOptions,
  ): Promise<{ permitted: boolean; reason?: string }> {
    const result = await MajikSignatureEmbed.extract(file, options);

    // No envelope — unsigned file, anyone may sign
    if (!result) return { permitted: true };

    const { envelope } = result;

    // Sealed — no one may sign
    if (envelope.sealHash) {
      return {
        permitted: false,
        reason: "The envelope is sealed. No further signatures are permitted.",
      };
    }

    // No allowlist — open signing
    if (!envelope.allowlist || envelope.allowlist.length === 0) {
      return { permitted: true };
    }

    // Allowlist present — check all three fields
    const check = checkAllowlist(envelope, key);
    if (!check.permitted) {
      return {
        permitted: false,
        reason: `Signer "${key.fingerprint}" is not on the allowlist for this file.`,
      };
    }

    return { permitted: true };
  }

  // ── getSignatories ─────────────────────────────────────────────────────────

  /**
   * Core signatories method. Returns all, signed, and pending arrays.
   * Pass filter to narrow the return — the filtered array is still returned
   * inside the full SignatoriesResult so callers always have the complete picture.
   *
   * Returns null if the file has no envelope.
   */
  static async getSignatories(
    file: Blob,
    options?: ExtractOptions,
    filter?: SignatoriesFilter,
  ): Promise<SignatoriesResult | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return null;

    const signatories = buildSignatoriesResult(result.envelope);
    if (!signatories) return null;

    // When filter is provided, return only the requested slice
    // but still within the full SignatoriesResult shape for consistency
    if (filter && filter !== "all") {
      const filtered = signatories[filter];
      return {
        all: signatories.all,
        signed: filter === "signed" ? filtered : signatories.signed,
        pending: filter === "pending" ? filtered : signatories.pending,
      };
    }

    return signatories;
  }

  // ── getIssuer ──────────────────────────────────────────────────────────────

  /**
   * Return the issuer (the signer who established the allowlist and controls sealing).
   * Returns null for open-signing files or unsigned files.
   */
  static async getIssuer(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<import("../../core/types").SignatoryInfo | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return null;

    const { envelope } = result;

    // 1. Check strict allowlist issuer first
    if (envelope.allowlistSignerId) {
      const issuerEntry = envelope.allowlist?.find(
        (e) => e.signerId === envelope.allowlistSignerId,
      );
      const issuerSig = envelope.signatures.find(
        (s) => s.signerId === envelope.allowlistSignerId,
      );

      if (issuerEntry) {
        return {
          signerId: issuerEntry.signerId,
          edPublicKey: issuerEntry.edPublicKey,
          mlDsaPublicKey: issuerEntry.mlDsaPublicKey,
          hasSigned: issuerSig !== undefined,
          signedAt: issuerSig?.timestamp,
        };
      }
    }

    // 2. FALLBACK: The very first signer is the issuer (Open Signing)
    if (envelope.signatures.length > 0) {
      const firstSig = envelope.signatures[0];
      return {
        signerId: firstSig.signerId,
        edPublicKey: firstSig.signerEdPublicKey,
        mlDsaPublicKey: firstSig.signerMlDsaPublicKey,
        hasSigned: true,
        signedAt: firstSig.timestamp,
      };
    }

    return null;
  }

  // ── getEnvelopeInfo ────────────────────────────────────────────────────────

  /**
   * Return a full summary of the envelope state in a single file read.
   * Useful for rendering UI state (badge, status, signatories list) without
   * making multiple separate calls.
   * Returns null if the file has no envelope.
   */
  static async getEnvelopeInfo(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<EnvelopeInfo | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return null;

    const { envelope } = result;

    const isSealed = envelope.sealHash !== undefined;
    const isMultiSig =
      envelope.allowlist !== undefined && envelope.allowlist.length > 1;
    const hasMultipleSignatories = isMultiSig || envelope.signatures.length > 1;

    const sealInfo: SealInfo | undefined =
      envelope.sealHash && envelope.sealTimestamp && envelope.sealedBy
        ? {
            sealHash: envelope.sealHash,
            sealTimestamp: envelope.sealTimestamp,
            sealedBy: envelope.sealedBy,
          }
        : undefined;

    const signatories = buildSignatoriesResult(envelope);

    // Build issuer info
    let issuer: import("../../core/types").SignatoryInfo | null = null;

    // 1. Check strict allowlist issuer first
    if (envelope.allowlistSignerId) {
      const issuerEntry = envelope.allowlist?.find(
        (e) => e.signerId === envelope.allowlistSignerId,
      );
      const issuerSig = envelope.signatures.find(
        (s) => s.signerId === envelope.allowlistSignerId,
      );

      if (issuerEntry) {
        issuer = {
          signerId: issuerEntry.signerId,
          edPublicKey: issuerEntry.edPublicKey,
          mlDsaPublicKey: issuerEntry.mlDsaPublicKey,
          hasSigned: issuerSig !== undefined,
          signedAt: issuerSig?.timestamp,
        };
      }
    }

    // 2. FALLBACK: The very first signer is the issuer (Open Signing)
    if (envelope.signatures.length > 0) {
      const firstSig = envelope.signatures[0];
      issuer = {
        signerId: firstSig.signerId,
        edPublicKey: firstSig.signerEdPublicKey,
        mlDsaPublicKey: firstSig.signerMlDsaPublicKey,
        hasSigned: true,
        signedAt: firstSig.timestamp,
      };
    }

    return {
      isMultiSig,
      hasMultipleSignatories,
      isSealed,
      sealInfo,
      issuer,
      signatories,
      allowlist: envelope.allowlist ?? null,
      signatureCount: envelope.signatures.length,
    };
  }

  // ── strip ──────────────────────────────────────────────────────────────────

  static async strip(file: Blob, options?: ExtractOptions): Promise<Blob> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);
    const handler = DEFAULT_REGISTRY.resolve(bytes, mimeType);
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
    if (!result) return null;
    return result.envelope.allowlist ?? null;
  }

  static readonly registry = DEFAULT_REGISTRY;

  static listHandlers(): string[] {
    return DEFAULT_REGISTRY.listHandlers();
  }
}

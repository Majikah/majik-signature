/**
 * validator.ts
 * Input validation and assertion helpers for MajikSignature.
 */

import { ISODateString } from "@majikah/majik-key";
import { base64ToBytes, bytesToBase64 } from "./hash.js";
import {
  MAJIK_SIGNATURE_VERSION,
  MAJIK_ENVELOPE_VERSION,
  MIN_ED_PUBLIC_KEY_B64_LEN,
  MIN_DSA_PUBLIC_KEY_B64_LEN,
  MIN_SIGNATURE_B64_LEN,
  CONTENT_HASH_B64_LEN,
  ALLOWLIST_HASH_B64_LEN,
  SEAL_HASH_HEX_LEN,
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  SHA256_DIGEST_BYTES,
  MAX_SIGNER_ID_CHARS,
  MAX_CONTENT_TYPE_CHARS,
  MAX_TIMESTAMP_CHARS,
  MAX_TSA_FIELD_CHARS,
  MAX_SIGNATURES_PER_ENVELOPE,
  MAX_ALLOWLIST_ENTRIES,
} from "./constants.js";
import {
  MajikSignatureValidationError,
  MajikSignatureKeyError,
} from "./errors.js";
import type {
  ExpectedSigner,
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  MajikTimestamp,
  MajikTSAPayload,
  MultiSigEnvelope,
} from "./types.js";

export class MajikSignatureValidator {
  // ── Assertions ──────────────────────────────────────────────────────────────

  static assert(
    condition: unknown,
    message: string,
    field?: string,
  ): asserts condition {
    if (!condition) throw new MajikSignatureValidationError(message, field);
  }

  static assertDefined<T>(
    value: T | undefined | null,
    field: string,
  ): asserts value is T {
    if (value === undefined || value === null)
      throw new MajikSignatureValidationError(
        `${field} is required and must not be null or undefined`,
        field,
      );
  }

  static assertNonEmptyString(
    value: unknown,
    field: string,
  ): asserts value is string {
    if (typeof value !== "string" || value.trim().length === 0)
      throw new MajikSignatureValidationError(
        `${field} must be a non-empty string`,
        field,
      );
  }

  static assertUint8Array(
    value: unknown,
    field: string,
    expectedLen?: number,
  ): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array))
      throw new MajikSignatureValidationError(
        `${field} must be a Uint8Array`,
        field,
      );
    if (expectedLen !== undefined && value.length !== expectedLen)
      throw new MajikSignatureValidationError(
        `${field} must be exactly ${expectedLen} bytes (got ${value.length})`,
        field,
      );
  }

  static validateBoundedString(
    value: unknown,
    field: string,
    maxLength: number,
  ): asserts value is string {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > maxLength ||
      /[\\u0000-\\u001f\\u007f]/.test(value)
    ) {
      throw new MajikSignatureValidationError(
        `${field} must be a non-empty string of at most ${maxLength} characters without control characters`,
        field,
      );
    }
  }

  static validateCanonicalBase64(
    value: unknown,
    field: string,
    expectedBytes: number,
  ): asserts value is string {
    const expectedChars = Math.ceil(expectedBytes / 3) * 4;
    if (typeof value !== "string" || value.length !== expectedChars) {
      throw new MajikSignatureValidationError(
        `${field} must be canonical base64 encoding of exactly ${expectedBytes} bytes`,
        field,
      );
    }

    try {
      const decoded = base64ToBytes(value);
      if (
        decoded.length !== expectedBytes ||
        bytesToBase64(decoded) !== value
      ) {
        throw new Error("non-canonical base64");
      }
    } catch (err) {
      throw new MajikSignatureValidationError(
        `${field} must be canonical base64 encoding of exactly ${expectedBytes} bytes`,
        field,
        err,
      );
    }
  }

  static validateTimestamp(
    value: unknown,
    field = "timestamp",
  ): asserts value is string {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > MAX_TIMESTAMP_CHARS ||
      Number.isNaN(Date.parse(value))
    ) {
      throw new MajikSignatureValidationError(
        `${field} must be a valid ISO 8601 timestamp of at most ${MAX_TIMESTAMP_CHARS} characters`,
        field,
      );
    }
  }

  // ── Content validators ───────────────────────────────────────────────────────

  static validateContent(
    content: Uint8Array | string,
    field = "content",
  ): void {
    if (typeof content === "string") {
      if (content.length === 0)
        throw new MajikSignatureValidationError(
          `${field} string must not be empty`,
          field,
        );
      return;
    }
    if (content instanceof Uint8Array) {
      if (content.length === 0)
        throw new MajikSignatureValidationError(
          `${field} Uint8Array must not be empty`,
          field,
        );
      return;
    }
    throw new MajikSignatureValidationError(
      `${field} must be a string or Uint8Array`,
      field,
    );
  }

  static validateContentType(
    contentType: unknown,
    field = "contentType",
  ): void {
    if (contentType === undefined || contentType === null) return;
    if (
      typeof contentType !== "string" ||
      contentType.trim().length === 0 ||
      contentType.length > MAX_CONTENT_TYPE_CHARS ||
      /[\\u0000-\\u001f\\u007f]/.test(contentType)
    )
      throw new MajikSignatureValidationError(
        `${field} must be a non-empty string of at most ${MAX_CONTENT_TYPE_CHARS} characters without control characters`,
        field,
      );
  }

  // ── Key validators ───────────────────────────────────────────────────────────

  static validateSignerPublicKeys(keys: MajikSignerPublicKeys): void {
    MajikSignatureValidator.assertNonEmptyString(keys.signerId, "signerId");

    if (
      !(keys.edPublicKey instanceof Uint8Array) ||
      keys.edPublicKey.length !== 32
    )
      throw new MajikSignatureKeyError(
        `edPublicKey must be a 32-byte Uint8Array (got ${keys.edPublicKey?.length ?? "undefined"})`,
      );

    if (
      !(keys.mlDsaPublicKey instanceof Uint8Array) ||
      keys.mlDsaPublicKey.length !== 2592
    )
      throw new MajikSignatureKeyError(
        `mlDsaPublicKey must be a 2592-byte Uint8Array (got ${keys.mlDsaPublicKey?.length ?? "undefined"})`,
      );
  }

  static validateEdSecretKey(key: Uint8Array): void {
    if (!(key instanceof Uint8Array) || key.length !== 64)
      throw new MajikSignatureKeyError(
        `Ed25519 secret key must be 64 bytes (got ${key?.length ?? "undefined"})`,
      );
  }

  static validateMlDsaSecretKey(key: Uint8Array): void {
    if (!(key instanceof Uint8Array) || key.length !== 4896)
      throw new MajikSignatureKeyError(
        `ML-DSA-87 secret key must be 4896 bytes (got ${key?.length ?? "undefined"})`,
      );
  }

  // ── Per-signer envelope validator ────────────────────────────────────────────

  static validateJSON(json: unknown): asserts json is MajikSignatureJSON {
    if (typeof json !== "object" || json === null)
      throw new MajikSignatureValidationError(
        "Signature JSON must be an object",
      );

    const j = json as Record<string, unknown>;

    if (j.version !== MAJIK_SIGNATURE_VERSION)
      throw new MajikSignatureValidationError(
        "Unsupported signature version",
        "version",
      );

    const requiredStrings: (keyof MajikSignatureJSON)[] = [
      "signerId",
      "signerEdPublicKey",
      "signerMlDsaPublicKey",
      "contentHash",
      "timestamp",
      "edSignature",
      "mlDsaSignature",
    ];

    for (const field of requiredStrings) {
      if (
        typeof j[field] !== "string" ||
        (j[field] as string).trim().length === 0
      )
        throw new MajikSignatureValidationError(
          `${field} must be a non-empty string`,
          field,
        );
    }

    MajikSignatureValidator.validateBoundedString(
      j.signerId,
      "signerId",
      MAX_SIGNER_ID_CHARS,
    );
    MajikSignatureValidator.validateCanonicalBase64(
      j.signerEdPublicKey,
      "signerEdPublicKey",
      ED25519_PUBLIC_KEY_BYTES,
    );
    MajikSignatureValidator.validateCanonicalBase64(
      j.signerMlDsaPublicKey,
      "signerMlDsaPublicKey",
      ML_DSA_87_PUBLIC_KEY_BYTES,
    );
    MajikSignatureValidator.validateCanonicalBase64(
      j.contentHash,
      "contentHash",
      SHA256_DIGEST_BYTES,
    );
    MajikSignatureValidator.validateCanonicalBase64(
      j.edSignature,
      "edSignature",
      ED25519_SIGNATURE_BYTES,
    );
    MajikSignatureValidator.validateCanonicalBase64(
      j.mlDsaSignature,
      "mlDsaSignature",
      ML_DSA_87_SIGNATURE_BYTES,
    );
    MajikSignatureValidator.validateTimestamp(j.timestamp);

    if (j.contentType !== undefined) {
      MajikSignatureValidator.validateContentType(j.contentType);
    }
    if (j.validUntil !== undefined) {
      MajikSignatureValidator.validateValidUntil(j.validUntil as ISODateString);
    }
    if (j.versionChainHash !== undefined) {
      MajikSignatureValidator.validateCanonicalBase64(
        j.versionChainHash,
        "versionChainHash",
        SHA256_DIGEST_BYTES,
      );
    }
    if (j.sessionContextHash !== undefined) {
      MajikSignatureValidator.validateSessionContextHash(j.sessionContextHash);
    }
    if (j.allowlistHash !== undefined) {
      MajikSignatureValidator.validateCanonicalBase64(
        j.allowlistHash,
        "allowlistHash",
        SHA256_DIGEST_BYTES,
      );
    }
  }

  // ── ExpectedSigner validator ─────────────────────────────────────────────────

  static validateExpectedSigner(
    entry: unknown,
    index?: number,
  ): asserts entry is ExpectedSigner {
    const label =
      index !== undefined ? `allowlist[${index}]` : "allowlist entry";

    if (typeof entry !== "object" || entry === null)
      throw new MajikSignatureValidationError(
        `${label} must be an object`,
        label,
      );

    const e = entry as Record<string, unknown>;

    MajikSignatureValidator.validateBoundedString(
      e.signerId,
      `${label}.signerId`,
      MAX_SIGNER_ID_CHARS,
    );
    MajikSignatureValidator.validateCanonicalBase64(
      e.edPublicKey,
      `${label}.edPublicKey`,
      ED25519_PUBLIC_KEY_BYTES,
    );
    MajikSignatureValidator.validateCanonicalBase64(
      e.mlDsaPublicKey,
      `${label}.mlDsaPublicKey`,
      ML_DSA_87_PUBLIC_KEY_BYTES,
    );
  }

  // ── Seal validator ───────────────────────────────────────────────────────────

  /**
   * Validate that a seal is structurally complete.
   * All three seal fields must be present together — partial seals are invalid.
   * Does NOT verify the seal hash cryptographically — call verifySeal() for that.
   */
  static validateSeal(env: MultiSigEnvelope): void {
    const hasSealHash = env.sealHash !== undefined;
    const hasSealTimestamp = env.sealTimestamp !== undefined;
    const hasSealedBy = env.sealedBy !== undefined;

    // All three must be present or all three must be absent
    const count = [hasSealHash, hasSealTimestamp, hasSealedBy].filter(
      Boolean,
    ).length;

    if (count > 0 && count < 3)
      throw new MajikSignatureValidationError(
        "Seal is incomplete — sealHash, sealTimestamp, and sealedBy must all be present together",
        "seal",
      );

    if (!hasSealHash) return; // no seal — nothing more to check

    if (
      typeof env.sealHash !== "string" ||
      env.sealHash.length !== SEAL_HASH_HEX_LEN ||
      !/^[0-9a-fA-F]+$/.test(env.sealHash)
    )
      throw new MajikSignatureValidationError(
        `sealHash must be exactly ${SEAL_HASH_HEX_LEN} hex chars (SHA3-512)`,
        "sealHash",
      );

    if (
      typeof env.sealTimestamp !== "string" ||
      env.sealTimestamp.length > MAX_TIMESTAMP_CHARS ||
      isNaN(new Date(env.sealTimestamp).getTime())
    )
      throw new MajikSignatureValidationError(
        "sealTimestamp must be a valid ISO 8601 date string",
        "sealTimestamp",
      );

    if (
      typeof env.sealedBy !== "string" ||
      env.sealedBy.trim().length === 0 ||
      env.sealedBy.length > MAX_SIGNER_ID_CHARS ||
      /[\\u0000-\\u001f\\u007f]/.test(env.sealedBy)
    )
      throw new MajikSignatureValidationError(
        "sealedBy must be a non-empty string",
        "sealedBy",
      );
  }

  static validateSealHash(hash: string): void {
    if (
      typeof hash !== "string" ||
      hash.length !== SEAL_HASH_HEX_LEN ||
      !/^[0-9a-fA-F]+$/.test(hash)
    )
      throw new MajikSignatureValidationError(
        `sealHash must be exactly ${SEAL_HASH_HEX_LEN} hex chars (SHA3-512)`,
        "sealHash",
      );
  }

  static validateSessionContextHash(value: unknown): asserts value is string {
    MajikSignatureValidator.validateCanonicalBase64(
      value,
      "sessionContextHash",
      SHA256_DIGEST_BYTES,
    );
  }

  static validateValidUntil(value: ISODateString | undefined): void {
    if (value === undefined) return;
    if (
      typeof value !== "string" ||
      value.length > MAX_TIMESTAMP_CHARS ||
      Number.isNaN(Date.parse(value))
    ) {
      throw new MajikSignatureValidationError(
        "validUntil must be a valid ISO 8601 timestamp string",
        "validUntil",
      );
    }
  }

  // ── MultiSigEnvelope validator ───────────────────────────────────────────────

  static validateMultiSigEnvelope(
    env: unknown,
  ): asserts env is MultiSigEnvelope {
    if (typeof env !== "object" || env === null)
      throw new MajikSignatureValidationError(
        "MultiSigEnvelope must be an object",
      );

    const e = env as Record<string, unknown>;

    if (e.version !== MAJIK_ENVELOPE_VERSION)
      throw new MajikSignatureValidationError(
        `Unsupported envelope version: ${e.version}`,
        "version",
      );

    if (!Array.isArray(e.signatures))
      throw new MajikSignatureValidationError(
        "MultiSigEnvelope.signatures must be an array",
        "signatures",
      );
    if ((e.signatures as unknown[]).length > MAX_SIGNATURES_PER_ENVELOPE)
      throw new MajikSignatureValidationError(
        `MultiSigEnvelope.signatures exceeds the limit of ${MAX_SIGNATURES_PER_ENVELOPE}`,
        "signatures",
      );

    for (let i = 0; i < (e.signatures as unknown[]).length; i++) {
      try {
        MajikSignatureValidator.validateJSON((e.signatures as unknown[])[i]);
      } catch (err) {
        throw new MajikSignatureValidationError(
          `signatures[${i}] is invalid: ${(err as Error).message}`,
          `signatures[${i}]`,
          err,
        );
      }
    }

    if (e.allowlist !== undefined) {
      if (!Array.isArray(e.allowlist))
        throw new MajikSignatureValidationError(
          "MultiSigEnvelope.allowlist must be an array if present",
          "allowlist",
        );

      if ((e.allowlist as unknown[]).length === 0)
        throw new MajikSignatureValidationError(
          "MultiSigEnvelope.allowlist must not be empty if present — omit the field for open signing",
          "allowlist",
        );
      if ((e.allowlist as unknown[]).length > MAX_ALLOWLIST_ENTRIES)
        throw new MajikSignatureValidationError(
          `MultiSigEnvelope.allowlist exceeds the limit of ${MAX_ALLOWLIST_ENTRIES}`,
          "allowlist",
        );

      for (let i = 0; i < (e.allowlist as unknown[]).length; i++) {
        MajikSignatureValidator.validateExpectedSigner(
          (e.allowlist as unknown[])[i],
          i,
        );
      }

      if (
        typeof e.allowlistSignerId !== "string" ||
        e.allowlistSignerId.trim().length === 0 ||
        e.allowlistSignerId.length > MAX_SIGNER_ID_CHARS ||
        /[\\u0000-\\u001f\\u007f]/.test(e.allowlistSignerId)
      )
        throw new MajikSignatureValidationError(
          "MultiSigEnvelope.allowlistSignerId must be a non-empty string when allowlist is present",
          "allowlistSignerId",
        );
    }

    // Validate seal fields if any are present
    MajikSignatureValidator.validateSeal(env as MultiSigEnvelope);
  }

  static validateMajikTSAPayload(
    payload: unknown,
  ): asserts payload is MajikTSAPayload {
    if (!payload || typeof payload !== "object")
      throw new MajikSignatureValidationError("TSA payload must be an object");
    const p = payload as Record<string, unknown>;
    if (!p.digest || typeof p.digest !== "object")
      throw new MajikSignatureValidationError("TSA payload missing digest");
    const d = p.digest as Record<string, unknown>;
    if (d.algorithm !== "SHA-256")
      throw new MajikSignatureValidationError(
        "TSA payload digest algorithm must be SHA-256",
      );
    if (
      d.scope !== undefined &&
      d.scope !== "content" &&
      d.scope !== "signature"
    ) {
      throw new MajikSignatureValidationError(
        "TSA payload digest scope must be content or signature",
      );
    }
    MajikSignatureValidator.validateCanonicalBase64(
      d.value,
      "digest.value",
      SHA256_DIGEST_BYTES,
    );
    if (
      typeof p.nonce !== "string" ||
      p.nonce.length === 0 ||
      p.nonce.length > MAX_TSA_FIELD_CHARS ||
      /[\\u0000-\\u001f\\u007f]/.test(p.nonce)
    )
      throw new MajikSignatureValidationError("TSA payload nonce is invalid or too long");
    if (
      typeof p.timestamp !== "string" ||
      p.timestamp.length === 0 ||
      p.timestamp.length > MAX_TIMESTAMP_CHARS ||
      Number.isNaN(Date.parse(p.timestamp))
    )
      throw new MajikSignatureValidationError("TSA payload timestamp is invalid or too long");
    if (!p.tsa || typeof p.tsa !== "object")
      throw new MajikSignatureValidationError("TSA payload missing tsa");
    const t = p.tsa as Record<string, unknown>;
    if (
      typeof t.id !== "string" ||
      t.id.length === 0 ||
      t.id.length > MAX_TSA_FIELD_CHARS ||
      /[\\u0000-\\u001f\\u007f]/.test(t.id)
    )
      throw new MajikSignatureValidationError("TSA payload tsa.id is invalid or too long");
    if (
      typeof t.signerFingerprint !== "string" ||
      t.signerFingerprint.length === 0 ||
      t.signerFingerprint.length > MAX_TSA_FIELD_CHARS ||
      /[\\u0000-\\u001f\\u007f]/.test(t.signerFingerprint)
    )
      throw new MajikSignatureValidationError(
        "TSA payload tsa.signerFingerprint missing",
      );
  }

  static validateMajikTimestamp(tsa: unknown): asserts tsa is MajikTimestamp {
    if (!tsa || typeof tsa !== "object")
      throw new MajikSignatureValidationError(
        "MajikTimestamp must be an object",
      );
    const t = tsa as Record<string, unknown>;
    if (t.version !== 1)
      throw new MajikSignatureValidationError(
        "MajikTimestamp version must be 1",
      );
    if (
      typeof t.id !== "string" ||
      t.id.length === 0 ||
      t.id.length > MAX_TSA_FIELD_CHARS ||
      /[\\u0000-\\u001f\\u007f]/.test(t.id)
    )
      throw new MajikSignatureValidationError("MajikTimestamp id is invalid or too long");
    MajikSignatureValidator.validateMajikTSAPayload(t.payload);
    MajikSignatureValidator.validateJSON(t.signature); // reuses existing envelope validation
  }
}

// Freeze static methods
Object.freeze(MajikSignatureValidator);

// Freeze instance methods
Object.freeze(MajikSignatureValidator.prototype);

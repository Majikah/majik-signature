/**
 * validator.ts
 * Input validation and assertion helpers for MajikSignature.
 */

import { ISODateString } from "@majikah/majik-key";
import {
  MAJIK_SIGNATURE_VERSION,
  MAJIK_ENVELOPE_VERSION,
  MIN_ED_PUBLIC_KEY_B64_LEN,
  MIN_DSA_PUBLIC_KEY_B64_LEN,
  MIN_SIGNATURE_B64_LEN,
  CONTENT_HASH_B64_LEN,
  ALLOWLIST_HASH_B64_LEN,
  SEAL_HASH_HEX_LEN,
} from "./constants";
import {
  MajikSignatureValidationError,
  MajikSignatureKeyError,
} from "./errors";
import type {
  ExpectedSigner,
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  MajikTimestamp,
  MajikTSAPayload,
  MultiSigEnvelope,
} from "./types";

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
    if (typeof contentType !== "string" || contentType.trim().length === 0)
      throw new MajikSignatureValidationError(
        `${field} must be a non-empty string if provided`,
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
        `Unsupported signature version: ${j.version}`,
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

    const edPub = j.signerEdPublicKey as string;
    if (edPub.length < MIN_ED_PUBLIC_KEY_B64_LEN)
      throw new MajikSignatureValidationError(
        "signerEdPublicKey is too short to be a valid Ed25519 public key",
        "signerEdPublicKey",
      );

    const dsaPub = j.signerMlDsaPublicKey as string;
    if (dsaPub.length < MIN_DSA_PUBLIC_KEY_B64_LEN)
      throw new MajikSignatureValidationError(
        "signerMlDsaPublicKey is too short to be a valid ML-DSA-87 public key",
        "signerMlDsaPublicKey",
      );

    const hash = j.contentHash as string;
    if (hash.length !== CONTENT_HASH_B64_LEN)
      throw new MajikSignatureValidationError(
        `contentHash must be exactly ${CONTENT_HASH_B64_LEN} base64 chars (SHA-256)`,
        "contentHash",
      );

    const edSig = j.edSignature as string;
    if (edSig.length < MIN_SIGNATURE_B64_LEN)
      throw new MajikSignatureValidationError(
        "edSignature is too short to be a valid Ed25519 signature",
        "edSignature",
      );

    const ts = new Date(j.timestamp as string);
    if (isNaN(ts.getTime()))
      throw new MajikSignatureValidationError(
        "timestamp must be a valid ISO 8601 date string",
        "timestamp",
      );

    if (j.contentType !== undefined) {
      if (
        typeof j.contentType !== "string" ||
        j.contentType.trim().length === 0
      )
        throw new MajikSignatureValidationError(
          "contentType must be a non-empty string if present",
          "contentType",
        );
    }

    if (j.allowlistHash !== undefined) {
      if (
        typeof j.allowlistHash !== "string" ||
        j.allowlistHash.length !== ALLOWLIST_HASH_B64_LEN
      )
        throw new MajikSignatureValidationError(
          `allowlistHash must be exactly ${ALLOWLIST_HASH_B64_LEN} base64 chars (SHA-256) if present`,
          "allowlistHash",
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

    if (typeof e.signerId !== "string" || e.signerId.trim().length === 0)
      throw new MajikSignatureValidationError(
        `${label}.signerId must be a non-empty string`,
        `${label}.signerId`,
      );

    if (
      typeof e.edPublicKey !== "string" ||
      e.edPublicKey.length < MIN_ED_PUBLIC_KEY_B64_LEN
    )
      throw new MajikSignatureValidationError(
        `${label}.edPublicKey is too short to be a valid Ed25519 public key`,
        `${label}.edPublicKey`,
      );

    if (
      typeof e.mlDsaPublicKey !== "string" ||
      e.mlDsaPublicKey.length < MIN_DSA_PUBLIC_KEY_B64_LEN
    )
      throw new MajikSignatureValidationError(
        `${label}.mlDsaPublicKey is too short to be a valid ML-DSA-87 public key`,
        `${label}.mlDsaPublicKey`,
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
      env.sealHash.length !== SEAL_HASH_HEX_LEN
    )
      throw new MajikSignatureValidationError(
        `sealHash must be exactly ${SEAL_HASH_HEX_LEN} hex chars (SHA3-512)`,
        "sealHash",
      );

    if (
      typeof env.sealTimestamp !== "string" ||
      isNaN(new Date(env.sealTimestamp).getTime())
    )
      throw new MajikSignatureValidationError(
        "sealTimestamp must be a valid ISO 8601 date string",
        "sealTimestamp",
      );

    if (typeof env.sealedBy !== "string" || env.sealedBy.trim().length === 0)
      throw new MajikSignatureValidationError(
        "sealedBy must be a non-empty string",
        "sealedBy",
      );
  }

  static validateSealHash(hash: string): void {
    if (typeof hash !== "string" || hash.length !== SEAL_HASH_HEX_LEN)
      throw new MajikSignatureValidationError(
        `sealHash must be exactly ${SEAL_HASH_HEX_LEN} hex chars (SHA3-512)`,
        "sealHash",
      );
  }

  static validateValidUntil(value: ISODateString | undefined): void {
    if (value === undefined) return;
    if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
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

      for (let i = 0; i < (e.allowlist as unknown[]).length; i++) {
        MajikSignatureValidator.validateExpectedSigner(
          (e.allowlist as unknown[])[i],
          i,
        );
      }

      if (
        typeof e.allowlistSignerId !== "string" ||
        e.allowlistSignerId.trim().length === 0
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
    if (typeof d.value !== "string" || d.value.length !== CONTENT_HASH_B64_LEN)
      throw new MajikSignatureValidationError(
        "TSA payload digest value must be a 44-char base64 string",
      );
    if (typeof p.nonce !== "string" || p.nonce.length === 0)
      throw new MajikSignatureValidationError("TSA payload missing nonce");
    if (typeof p.timestamp !== "string" || p.timestamp.length === 0)
      throw new MajikSignatureValidationError("TSA payload missing timestamp");
    if (!p.tsa || typeof p.tsa !== "object")
      throw new MajikSignatureValidationError("TSA payload missing tsa");
    const t = p.tsa as Record<string, unknown>;
    if (typeof t.id !== "string" || t.id.length === 0)
      throw new MajikSignatureValidationError("TSA payload tsa.id missing");
    if (
      typeof t.signerFingerprint !== "string" ||
      t.signerFingerprint.length === 0
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
    if (typeof t.id !== "string" || t.id.length === 0)
      throw new MajikSignatureValidationError("MajikTimestamp missing id");
    MajikSignatureValidator.validateMajikTSAPayload(t.payload);
    MajikSignatureValidator.validateJSON(t.signature); // reuses existing envelope validation
  }
}

// Freeze static methods
Object.freeze(MajikSignatureValidator);

// Freeze instance methods
Object.freeze(MajikSignatureValidator.prototype);

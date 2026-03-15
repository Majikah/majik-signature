/**
 * validator.ts
 * Input validation and assertion helpers for MajikSignature.
 */

import {
  MAJIK_SIGNATURE_VERSION,
  MIN_ED_PUBLIC_KEY_B64_LEN,
  MIN_DSA_PUBLIC_KEY_B64_LEN,
  MIN_SIGNATURE_B64_LEN,
  CONTENT_HASH_B64_LEN,
} from "./constants";
import {
  MajikSignatureValidationError,
  MajikSignatureKeyError,
} from "./errors";
import type { MajikSignatureJSON, MajikSignerPublicKeys } from "./types";

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
    if (contentType === undefined || contentType === null) return; // optional
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
    // @stablelib/ed25519 secretKey is 64 bytes (seed || publicKey)
    if (!(key instanceof Uint8Array) || key.length !== 64)
      throw new MajikSignatureKeyError(
        `Ed25519 secret key must be 64 bytes (got ${key?.length ?? "undefined"})`,
      );
  }

  static validateMlDsaSecretKey(key: Uint8Array): void {
    // ML-DSA-87 secret key is 4896 bytes
    if (!(key instanceof Uint8Array) || key.length !== 4896)
      throw new MajikSignatureKeyError(
        `ML-DSA-87 secret key must be 4896 bytes (got ${key?.length ?? "undefined"})`,
      );
  }

  // ── Envelope validators ──────────────────────────────────────────────────────

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

    // Sanity-check base64 lengths
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

    // Validate ISO timestamp
    const ts = new Date(j.timestamp as string);
    if (isNaN(ts.getTime()))
      throw new MajikSignatureValidationError(
        "timestamp must be a valid ISO 8601 date string",
        "timestamp",
      );

    // contentType is optional — validate only if present
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
  }
}

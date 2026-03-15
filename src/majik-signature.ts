/**
 * majik-signature.ts
 *
 * MajikSignature — hybrid Ed25519 + ML-DSA-87 content signing and verification.
 *
 * Signing requires an unlocked MajikKey with signing keys present.
 * Verification requires only the signer's public keys — no private key needed.
 *
 * Signature envelope (MajikSignatureJSON):
 *   - Ed25519 signature    (64 bytes, classical)
 *   - ML-DSA-87 signature  (4595 bytes, post-quantum)
 *   - Both cover the same canonical payload (domain + JSON metadata)
 *   - Verification requires BOTH to pass — hybrid security
 *
 * Canonical payload:
 *   "majik-signature-v1:" + JSON({ v, id, ts, ct, hash })
 *   where hash = SHA-256(content), base64
 */

import * as ed25519 from "@stablelib/ed25519";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import type { MajikKey } from "@majikah/majik-key";

import { MAJIK_SIGNATURE_VERSION } from "./core/constants";
import {
  MajikSignatureError,
  MajikSignatureKeyError,
  MajikSignatureVerificationError,
  MajikSignatureSerializationError,
} from "./core/errors";
import { MajikSignatureValidator } from "./core/validator";
import { buildSigningPayload } from "./core/payload";
import { hashContent, bytesToBase64, base64ToBytes } from "./core/hash";
import type {
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  SignOptions,
  VerificationResult,
} from "./core/types";

// ─── MajikSignature ───────────────────────────────────────────────────────────

export class MajikSignature {
  private readonly _version: 1;
  private readonly _signerId: string;
  private readonly _signerEdPublicKey: string;
  private readonly _signerMlDsaPublicKey: string;
  private readonly _contentHash: string;
  private readonly _contentType?: string;
  private readonly _timestamp: string;
  private readonly _edSignature: string;
  private readonly _mlDsaSignature: string;

  private constructor(data: MajikSignatureJSON) {
    this._version = data.version;
    this._signerId = data.signerId;
    this._signerEdPublicKey = data.signerEdPublicKey;
    this._signerMlDsaPublicKey = data.signerMlDsaPublicKey;
    this._contentHash = data.contentHash;
    this._contentType = data.contentType;
    this._timestamp = data.timestamp;
    this._edSignature = data.edSignature;
    this._mlDsaSignature = data.mlDsaSignature;
  }

  // ── Getters ─────────────────────────────────────────────────────────────────

  get version(): 1 {
    return this._version;
  }
  get signerId(): string {
    return this._signerId;
  }
  get signerEdPublicKey(): string {
    return this._signerEdPublicKey;
  }
  get signerMlDsaPublicKey(): string {
    return this._signerMlDsaPublicKey;
  }
  get contentHash(): string {
    return this._contentHash;
  }
  get contentType(): string | undefined {
    return this._contentType;
  }
  get timestamp(): string {
    return this._timestamp;
  }
  get edSignature(): string {
    return this._edSignature;
  }
  get mlDsaSignature(): string {
    return this._mlDsaSignature;
  }

  // ── SIGN ────────────────────────────────────────────────────────────────────

  /**
   * Sign content with an unlocked MajikKey.
   *
   * The key must be unlocked and must have signing keys (hasSigningKeys === true).
   * Both Ed25519 and ML-DSA-87 sign the same canonical payload.
   *
   * @param content   - Raw bytes or UTF-8 string to sign
   * @param key       - Unlocked MajikKey with signing keys
   * @param options   - Optional content type label and timestamp override
   * @returns         - MajikSignature instance (ready to serialize)
   */
  static async sign(
    content: Uint8Array | string,
    key: MajikKey,
    options?: SignOptions,
  ): Promise<MajikSignature> {
    try {
      // ── Input validation ──
      MajikSignatureValidator.validateContent(content);
      MajikSignatureValidator.assertDefined(key, "key");
      MajikSignatureValidator.validateContentType(options?.contentType);

      if (key.isLocked)
        throw new MajikSignatureKeyError(
          "MajikKey is locked. Call unlock() before signing.",
        );

      if (!key.hasSigningKeys)
        throw new MajikSignatureKeyError(
          "MajikKey has no signing keys. Re-import via importFromMnemonicBackup() to enable signing.",
        );

      // ── Retrieve secret keys (throws if locked or missing) ──
      const edSecretKey = key.getEdSecretKey();
      const mlDsaSecretKey = key.getMlDsaSecretKey();
      const edPublicKey = key.edPublicKey!;
      const mlDsaPublicKey = key.mlDsaPublicKey!;

      MajikSignatureValidator.validateEdSecretKey(edSecretKey);
      MajikSignatureValidator.validateMlDsaSecretKey(mlDsaSecretKey);

      // ── Hash content ──
      const contentHashBytes = hashContent(content);
      const contentHash = bytesToBase64(contentHashBytes);
      const timestamp = options?.timestamp ?? new Date().toISOString();
      const signerId = key.fingerprint;
      const contentType = options?.contentType;

      // ── Build canonical payload ──
      const payload = buildSigningPayload({
        signerId,
        timestamp,
        contentHash,
        contentType,
      });

      // ── Sign with Ed25519 ──
      const edSigBytes = ed25519.sign(edSecretKey, payload);

      // ── Sign with ML-DSA-87 ──
      const mlDsaSigBytes = ml_dsa87.sign(mlDsaSecretKey, payload);

      // ── Assemble envelope ──
      const envelope: MajikSignatureJSON = {
        version: MAJIK_SIGNATURE_VERSION,
        signerId,
        signerEdPublicKey: bytesToBase64(edPublicKey),
        signerMlDsaPublicKey: bytesToBase64(mlDsaPublicKey),
        contentHash,
        contentType,
        timestamp,
        edSignature: bytesToBase64(edSigBytes),
        mlDsaSignature: bytesToBase64(mlDsaSigBytes),
      };

      return new MajikSignature(envelope);
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureError("Failed to sign content", err);
    }
  }

  // ── VERIFY ──────────────────────────────────────────────────────────────────

  /**
   * Verify a MajikSignature against content and the signer's public keys.
   *
   * No private key is needed. Safe to call in any public context.
   * Both Ed25519 AND ML-DSA-87 must verify — if either fails, returns invalid.
   *
   * @param content   - The original content that was signed
   * @param signature - The MajikSignature to verify (instance or JSON)
   * @param publicKeys - Signer's Ed25519 + ML-DSA-87 public keys
   * @returns VerificationResult with valid: true/false and envelope metadata
   */
  static verify(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
  ): VerificationResult {
    try {
      MajikSignatureValidator.validateContent(content);
      MajikSignatureValidator.validateSignerPublicKeys(publicKeys);

      const env: MajikSignatureJSON =
        signature instanceof MajikSignature ? signature.toJSON() : signature;

      MajikSignatureValidator.validateJSON(env);

      const invalid = (reason?: string): VerificationResult =>
        ({
          valid: false,
          signerId: env.signerId,
          contentHash: env.contentHash,
          timestamp: env.timestamp,
          contentType: env.contentType,
          ...(reason ? { reason } : {}),
        }) as VerificationResult;

      // ── Step 1: Recompute content hash and compare ──
      const recomputedHashBytes = hashContent(content);
      const recomputedHash = bytesToBase64(recomputedHashBytes);

      if (recomputedHash !== env.contentHash) return invalid();

      // ── Step 2: Rebuild canonical payload ──
      const payload = buildSigningPayload({
        signerId: env.signerId,
        timestamp: env.timestamp,
        contentHash: env.contentHash,
        contentType: env.contentType,
      });

      // ── Step 3: Verify Ed25519 ──
      let edOk: boolean;
      try {
        edOk = ed25519.verify(
          publicKeys.edPublicKey,
          payload,
          base64ToBytes(env.edSignature),
        );
      } catch {
        return invalid();
      }
      if (!edOk) return invalid();

      // ── Step 4: Verify ML-DSA-87 ──
      let mlDsaOk: boolean;
      try {
        mlDsaOk = ml_dsa87.verify(
          publicKeys.mlDsaPublicKey,
          payload,
          base64ToBytes(env.mlDsaSignature),
        );
      } catch {
        return invalid();
      }
      if (!mlDsaOk) return invalid();

      // ── Both passed ──
      return {
        valid: true,
        signerId: env.signerId,
        contentHash: env.contentHash,
        timestamp: env.timestamp,
        contentType: env.contentType,
      };
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureVerificationError(
        "Verification failed unexpectedly",
        err,
      );
    }
  }

  // ── SELF-VALIDATE ───────────────────────────────────────────────────────────

  /**
   * Validate this envelope's internal structure without verifying signatures.
   * Useful for a quick integrity check before storing or transmitting.
   * Throws MajikSignatureValidationError on any structural problem.
   */
  validate(): void {
    MajikSignatureValidator.validateJSON(this.toJSON());
  }

  /**
   * Returns true if the envelope is structurally valid, false otherwise.
   * Never throws — safe to use as a boolean guard.
   */
  isValid(): boolean {
    try {
      this.validate();
      return true;
    } catch {
      return false;
    }
  }

  // ── EXTRACT PUBLIC KEYS ─────────────────────────────────────────────────────

  /**
   * Extract the signer's public keys from the envelope.
   * Useful when you want to verify without maintaining a separate key store.
   *
   * NOTE: The public keys embedded in the envelope are self-reported by the
   * signer. You should cross-check signerEdPublicKey + signerId against a
   * trusted source (e.g. a MajikKey fingerprint or a registry) before trusting
   * the extracted keys for verification.
   */
  extractPublicKeys(): MajikSignerPublicKeys {
    try {
      const edPublicKey = base64ToBytes(this._signerEdPublicKey);
      const mlDsaPublicKey = base64ToBytes(this._signerMlDsaPublicKey);

      MajikSignatureValidator.assertUint8Array(
        edPublicKey,
        "signerEdPublicKey",
        32,
      );
      MajikSignatureValidator.assertUint8Array(
        mlDsaPublicKey,
        "signerMlDsaPublicKey",
        2592,
      );

      return {
        signerId: this._signerId,
        edPublicKey,
        mlDsaPublicKey,
      };
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureKeyError(
        "Failed to extract public keys from envelope",
        err,
      );
    }
  }

  // ── SERIALIZATION ────────────────────────────────────────────────────────────

  toJSON(): MajikSignatureJSON {
    return {
      version: this._version,
      signerId: this._signerId,
      signerEdPublicKey: this._signerEdPublicKey,
      signerMlDsaPublicKey: this._signerMlDsaPublicKey,
      contentHash: this._contentHash,
      contentType: this._contentType,
      timestamp: this._timestamp,
      edSignature: this._edSignature,
      mlDsaSignature: this._mlDsaSignature,
    };
  }

  /**
   * Serialize to a base64 string suitable for embedding in files,
   * database fields, HTTP headers, or QR codes.
   */
  serialize(): string {
    try {
      const bytes = new TextEncoder().encode(JSON.stringify(this.toJSON()));
      let binary = "";
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    } catch (err) {
      throw new MajikSignatureSerializationError(
        "Failed to serialize signature",
        err,
      );
    }
  }

  toString(): string {
    return this.serialize();
  }

  // ── DESERIALIZATION ──────────────────────────────────────────────────────────

  /**
   * Reconstruct a MajikSignature from its JSON representation.
   * Validates structure on parse — throws on any invalid field.
   */
  static fromJSON(json: MajikSignatureJSON | string): MajikSignature {
    try {
      const parsed: unknown =
        typeof json === "string" ? JSON.parse(json) : json;
      MajikSignatureValidator.validateJSON(parsed);
      return new MajikSignature(parsed as MajikSignatureJSON);
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureSerializationError(
        "Failed to parse MajikSignature from JSON",
        err,
      );
    }
  }

  /**
   * Reconstruct a MajikSignature from a base64 serialized string.
   */
  static deserialize(base64: string): MajikSignature {
    try {
      MajikSignatureValidator.assertNonEmptyString(base64, "base64");
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      const json = new TextDecoder().decode(bytes);
      return MajikSignature.fromJSON(json);
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureSerializationError(
        "Failed to deserialize MajikSignature from base64",
        err,
      );
    }
  }

  // ── STATIC HELPERS ───────────────────────────────────────────────────────────

  /**
   * Convenience: extract public keys from a MajikKey for use in verify().
   * Works on both locked and unlocked keys — only needs public key fields.
   */
  static publicKeysFromMajikKey(key: MajikKey): MajikSignerPublicKeys {
    MajikSignatureValidator.assertDefined(key, "key");

    if (!key.hasSigningKeys)
      throw new MajikSignatureKeyError(
        "MajikKey has no signing public keys. Key may need re-import via importFromMnemonicBackup().",
      );

    const edPublicKey = key.edPublicKey!;
    const mlDsaPublicKey = key.mlDsaPublicKey!;

    MajikSignatureValidator.assertUint8Array(edPublicKey, "edPublicKey", 32);
    MajikSignatureValidator.assertUint8Array(
      mlDsaPublicKey,
      "mlDsaPublicKey",
      2592,
    );

    return {
      signerId: key.fingerprint,
      edPublicKey,
      mlDsaPublicKey,
    };
  }

  /**
   * Convenience: verify content directly against a MajikKey instance.
   * Extracts public keys from the key automatically.
   * Works on locked keys — only public fields are used.
   */
  static verifyWithKey(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON,
    key: MajikKey,
  ): VerificationResult {
    const publicKeys = MajikSignature.publicKeysFromMajikKey(key);
    return MajikSignature.verify(content, signature, publicKeys);
  }
}

/**
 * majik-signature.ts
 * MajikSignature — hybrid Ed25519 + ML-DSA-87 content signing and verification.
 *
 */

import * as ed25519 from "@stablelib/ed25519";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import type {
  ISODateString,
  MajikKey,
  MajikKeyFingerprint,
} from "@majikah/majik-key";

import {
  MAJIK_NOTARY_MEMO_DOMAIN,
  MAJIK_SIGNATURE_VERSION,
  MAJIK_TIMESTAMP_VERSION,
} from "./core/constants.js";
import {
  MajikSignatureError,
  MajikSignatureKeyError,
  MajikSignatureVerificationError,
  MajikSignatureSerializationError,
  MajikSignatureValidationError,
} from "./core/errors.js";
import { MajikSignatureValidator } from "./core/validator.js";
import {
  buildSignatureAttestationBytes,
  buildSigningPayload,
  buildTSACanonicalBytes,
} from "./core/payload.js";
import { hashContent, bytesToBase64, base64ToBytes } from "./core/hash.js";
import { hashSource } from "./core/streaming/index.js";
import type { StreamingByteSource, StreamingHashOptions } from "./core/streaming/types.js";
import { buildSessionContextHash } from "./core/session-context.js";
import type {
  BatchFileInput,
  BatchSignOptions,
  BatchSignFailure,
  BatchStreamingVerifyOptions,
  StreamingBatchVerifyInput,
  BatchSignResult,
  BatchStreamingOptions,
  StreamingBatchFileInput,
  BatchVerifyInput,
  BatchVerifyOptions,
  ED25519Signature,
  EnvelopeInfo,
  EnvelopeInput,
  ExpectedSigner,
  FileChainVerification,
  FileLike,
  FileVerifyResult,
  MajikSignatureCompactJSON,
  MajikSignatureEnvelopeJSON,
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  MajikTimestamp,
  MajikTSAPayload,
  MajikTSARequest,
  MLDSA87Signature,
  RevisionCommitmentResult,
  RevisionSetVerification,
  SealInfo,
  SealVerificationResult,
  SessionFileSignOptions,
  SessionFileVerifyOptions,
  SessionFileVerificationResult,
  SessionFileTsaVerificationResult,
  SignatoriesFilter,
  SignatoriesResult,
  SignatoryInfo,
  SignOptions,
  TSADigestScope,
  VerificationResult,
} from "./core/types.js";
import { MajikSignatureEmbed } from "./core/embed/majik-embed.js";

// ── Stamp (image signing) imports ─────────────────────────────────────────────
import { MajikImageSignature } from "./core/stamp/image-signature.js";
import type {
  ImageVerificationResult,
  ImageSignOptions,
  ImageSignatureStub,
} from "./core/stamp/index.js";
import { MajikChainAnchor, MajikChainAnchorMemo } from "./anchor/types.js";
import { MajikSignatureEnvelope } from "./core/envelope.js";
import { MajikSignatureMap } from "./core/mjksmap.js";
import {
  SignatureOrderResult,
  normalizeExpectedOrder as normalizeExpectedOrderUtil,
} from "./core/order.js";
import {
  decodeCBOR,
  encodeCBOR,
  signatureFromCBOR,
  signatureToCBOR,
} from "./core/cbor/index.js";

const secureFill = Uint8Array.prototype.fill;

/**
 * Majik Signature
 * ---
 * Hybrid Ed25519 + ML-DSA-87 content signing and verification.
 *
 * Signing requires an unlocked MajikKey with signing keys present.
 * Verification requires only the signer's public keys — no private key needed.
 *
 * Signature envelope (MajikSignatureJSON):
 *   - Ed25519 signature    (64 bytes, classical)
 *   - ML-DSA-87 signature  (4627 bytes, post-quantum)
 *   - Both cover the same canonical payload (domain + JSON metadata)
 *   - Verification requires BOTH to pass — hybrid security
 *
 * Multi-sig support:
 *   - Files embed a MultiSigEnvelope containing an array of MajikSignatureJSON
 *   - Each signer's entry is identified by their signerId (fingerprint)
 *   - Re-signing with the same key overwrites that signer's existing entry
 *   - Old single-sig files are promoted transparently — no migration needed
 *
 * Allowlist:
 *   - The first signer may optionally restrict future signers via expectedSigners
 *   - The allowlist is cryptographically committed to via allowlistHash in the
 *     establishing signer's canonical payload (covered by Ed25519 + ML-DSA-87)
 *   - Non-listed signers are rejected before any cryptographic operation
 *
 * Seal:
 *   - Only the issuer (allowlistSignerId) may seal a restricted multi-sig file
 *   - Sealing computes a SHA3-512 hash over all current signatories + timestamp
 *   - A sealed envelope rejects all further signing attempts
 *
 * Expiry:
 *   - A signer may optionally set validUntil (ISO 8601) when signing
 *   - Cryptographically committed to via the canonical payload — the field
 *     cannot be added, stripped, or extended post-hoc without breaking both
 *     Ed25519 and ML-DSA-87
 *   - verify() checks expiry only AFTER both signatures pass, so an
 *     expired-but-forged signature is reported as invalid, not "expired"
 *   - Absent = never expires, matching every signature that predates this
 *     feature — fully backward compatible, no migration needed
 *
 * Canonical payload:
 *   "majik-signature-v1:" + JSON({ v, id, ts, ct, hash[, alh][, vu] })
 *   where hash = SHA-256(content), alh = SHA-256(canonical allowlist), and
 *   vu = validUntil — each omitted (not nulled) when unset, preserving
 *   backward compat with signatures made before that field existed.
 */
export class MajikSignature {
  private readonly _version: 1;
  private readonly _signerId: MajikKeyFingerprint;
  private readonly _signerEdPublicKey: string;
  private readonly _signerMlDsaPublicKey: string;
  private readonly _contentHash: string;
  private readonly _contentType?: string;
  private readonly _timestamp: ISODateString;
  private readonly _edSignature: ED25519Signature;
  private readonly _mlDsaSignature: MLDSA87Signature;
  private readonly _allowlistHash?: string;
  private readonly _validUntil?: ISODateString;
  private readonly _versionChainHash?: string;
  private readonly _sessionContextHash?: string;
  private _tsa?: MajikTimestamp;

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
    this._allowlistHash = data.allowlistHash;
    this._validUntil = data.validUntil;
    this._versionChainHash = data.versionChainHash;
    this._sessionContextHash = data.sessionContextHash;
    this._tsa = data.tsa;
  }

  // ── Getters ─────────────────────────────────────────────────────────────────

  get version(): 1 {
    return this._version;
  }
  get signerId(): MajikKeyFingerprint {
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
  get timestamp(): ISODateString {
    return this._timestamp;
  }
  get edSignature(): ED25519Signature {
    return this._edSignature;
  }
  get mlDsaSignature(): MLDSA87Signature {
    return this._mlDsaSignature;
  }

  /**
   * SHA-256 hash of the canonical allowlist, base64.
   * Present only on the envelope of the signer who established the allowlist.
   * Undefined on all other signers and on pre-allowlist signatures.
   */
  get allowlistHash(): string | undefined {
    return this._allowlistHash;
  }

  /**
   * ISO 8601 timestamp after which this signature is considered expired by
   * verify(). Undefined means the signature never expires — this is the case
   * for every signature created before expiry support existed.
   */
  get validUntil(): ISODateString | undefined {
    return this._validUntil;
  }

  get versionChainHash(): string | undefined {
    return this._versionChainHash;
  }

  /** Signed commitment to the SignRoom session, challenge, and policy. */
  get sessionContextHash(): string | undefined {
    return this._sessionContextHash;
  }

  get tsa(): MajikTimestamp | undefined {
    return this._tsa;
  }

  /**
   * Structural expiry check against this signature's validUntil — does NOT
   * verify the cryptographic signature. Always false when validUntil is unset.
   * Use verify() for a full trust decision; use this for a quick UI-facing
   * "is this stale" check without needing the original content or public keys.
   *
   * @param now - Time to check against. Defaults to the current time.
   */
  isExpired(now: Date = new Date()): boolean {
    return (
      this._validUntil !== undefined &&
      now.getTime() > Date.parse(this._validUntil)
    );
  }

  // ── SIGN ────────────────────────────────────────────────────────────────────

  /**
   * Sign content with an unlocked MajikKey.
   *
   * Both Ed25519 and ML-DSA-87 sign the same canonical payload.
   * When options.allowlistHash is provided (injected internally by signAndEmbed),
   * it is included in the payload so both algorithms cover the allowlist.
   * When options.validUntil is provided, it is likewise included in the payload
   * so both algorithms cover the expiry — a verifier cannot strip or extend it
   * without invalidating the signature. Omit it for a signature that never
   * expires.
   */
  static async sign(
    content: Uint8Array | string,
    key: MajikKey,
    options?: SignOptions & {
      allowlistHash?: string;
      versionChainHash?: string;
    },
    debug: boolean = false,
  ): Promise<MajikSignature> {
    MajikSignatureValidator.validateContent(content);
    return MajikSignature._signDigest(hashContent(content), key, options, debug);
  }

  /**
   * Sign an arbitrary byte stream without materializing the complete input.
   * This produces the same canonical contentHash as sign() for identical bytes.
   *
   * This is a raw-content/detached signing primitive. Format-aware embedded
   * signing still uses the existing format handlers and is not implicitly
   * converted to streaming by this API.
   */
  static async signStream(
    source: StreamingByteSource,
    key: MajikKey,
    options?: SignOptions & {
      allowlistHash?: string;
      versionChainHash?: string;
      streaming?: StreamingHashOptions;
    },
    debug: boolean = false,
  ): Promise<MajikSignature> {
    const result = await hashSource(source, options?.streaming);
    if (result.bytesProcessed === 0) {
      MajikSignatureValidator.validateContent(new Uint8Array());
    }
    return MajikSignature._signDigest(result.digest, key, options, debug);
  }

  private static async _signDigest(
    contentHashBytes: Uint8Array,
    key: MajikKey,
    options?: SignOptions & {
      allowlistHash?: string;
      versionChainHash?: string;
    },
    debug: boolean = false,
  ): Promise<MajikSignature> {
    if (contentHashBytes.byteLength !== 32) {
      throw new MajikSignatureError("Internal SHA-256 digest must be exactly 32 bytes");
    }
    MajikSignatureValidator.assertDefined(key, "key");
    MajikSignatureValidator.validateContentType(options?.contentType);
    MajikSignatureValidator.validateTimestamp(options?.timestamp ?? new Date().toISOString());
    MajikSignatureValidator.validateValidUntil(options?.validUntil);
    if (options?.allowlistHash !== undefined) {
      MajikSignatureValidator.validateCanonicalBase64(
        options.allowlistHash,
        "allowlistHash",
        32,
      );
    }
    if (options?.versionChainHash !== undefined) {
      MajikSignatureValidator.validateCanonicalBase64(
        options.versionChainHash,
        "versionChainHash",
        32,
      );
    }
    if (options?.sessionContextHash !== undefined) {
      MajikSignatureValidator.validateSessionContextHash(options.sessionContextHash);
    }

    if (key.isLocked)
      throw new MajikSignatureKeyError(
        "MajikKey is locked. Call unlock() before signing.",
      );

    if (!key.hasSigningKeys)
      throw new MajikSignatureKeyError(
        "MajikKey has no signing keys. Re-import via importFromMnemonicBackup() to enable signing.",
      );

    let edSecretKeyClone: Uint8Array | undefined;
    let mlDsaSecretKeyClone: Uint8Array | undefined;
    const rawEdKey = key.getEdSecretKey();
    const rawMlDsaKey = key.getMlDsaSecretKey();

    edSecretKeyClone = rawEdKey.slice();
    mlDsaSecretKeyClone = rawMlDsaKey.slice();
    try {
      MajikSignatureValidator.validateEdSecretKey(edSecretKeyClone);
      MajikSignatureValidator.validateMlDsaSecretKey(mlDsaSecretKeyClone);
      const edPublicKey = key.edPublicKey!;
      const mlDsaPublicKey = key.mlDsaPublicKey!;

      const contentHash = bytesToBase64(contentHashBytes);
      const timestamp = options?.timestamp ?? new Date().toISOString();
      const signerId = key.fingerprint;
      const contentType = options?.contentType;
      const allowlistHash = options?.allowlistHash;
      const validUntil = options?.validUntil;
      const versionChainHash = options?.versionChainHash;
      const sessionContextHash = options?.sessionContextHash;
      const payload = buildSigningPayload({
        signerId,
        timestamp,
        contentHash,
        contentType,
        allowlistHash,
        validUntil,
        versionChainHash,
        sessionContextHash,
      });

      if (debug) console.log("Signing Payload:", payload);

      const edSigBytes = ed25519.sign(edSecretKeyClone, payload);
      const mlDsaSigBytes = ml_dsa87.sign(payload, mlDsaSecretKeyClone);

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
        ...(allowlistHash !== undefined ? { allowlistHash } : {}),
        ...(validUntil !== undefined ? { validUntil } : {}),
        ...(versionChainHash !== undefined ? { versionChainHash } : {}),
        ...(sessionContextHash !== undefined ? { sessionContextHash } : {}),
      };

      return new MajikSignature(envelope);
    } catch (err) {
      if (debug) console.error("Raw Signing Error:", err);
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureError("Failed to sign content", err);
    } finally {
      if (edSecretKeyClone) {
        secureFill.call(edSecretKeyClone, 0);
        edSecretKeyClone = undefined;
      }
      if (mlDsaSecretKeyClone) {
        secureFill.call(mlDsaSecretKeyClone, 0);
        mlDsaSecretKeyClone = undefined;
      }
    }
  }

  // ── VERIFY ──────────────────────────────────────────────────────────────────

  /**
   * Verify a MajikSignature against content and the signer's public keys.
   * Both Ed25519 AND ML-DSA-87 must verify — if either fails, returns invalid.
   *
   * If the envelope carries a validUntil, expiry is checked only after both
   * signatures have already passed — so a forged-but-expired signature is
   * reported as an invalid signature (wrong reason), never mistaken for a
   * merely-expired-but-otherwise-valid one. A signature with no validUntil
   * never expires.
   *
   * @param now - Time to check expiry against. Defaults to the current time;
   *   override for deterministic tests or to verify "as of" a past/future moment.
   * @returns valid: false with reason "Signature expired at ..." and
   *   expired: true when the only failure is expiry; expired is omitted
   *   otherwise.
   */
  static verify(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
    now: Date = new Date(),
  ): VerificationResult {
    MajikSignatureValidator.validateContent(content);
    return MajikSignature._verifyDigest(hashContent(content), signature, publicKeys, now);
  }

  /**
   * Verify arbitrary streamed bytes against a detached signature.
   * The resulting SHA-256 digest is identical to verify() over the same bytes.
   */
  static async verifyStream(
    source: StreamingByteSource,
    signature: MajikSignature | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
    options?: { now?: Date; streaming?: StreamingHashOptions },
  ): Promise<VerificationResult> {
    const result = await hashSource(source, options?.streaming);
    if (result.bytesProcessed === 0) {
      MajikSignatureValidator.validateContent(new Uint8Array());
    }
    return MajikSignature._verifyDigest(
      result.digest,
      signature,
      publicKeys,
      options?.now ?? new Date(),
    );
  }

  private static _verifyDigest(
    digest: Uint8Array,
    signature: MajikSignature | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
    now: Date,
  ): VerificationResult {
    try {
      if (digest.byteLength !== 32) {
        throw new MajikSignatureError("Internal SHA-256 digest must be exactly 32 bytes");
      }
      if (!Number.isFinite(now.getTime())) {
        throw new MajikSignatureError("Verification time must be a valid Date");
      }
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

      if (publicKeys.signerId !== env.signerId) {
        return invalid("Signer key fingerprint does not match signature signerId");
      }
      if (
        bytesToBase64(publicKeys.edPublicKey) !== env.signerEdPublicKey ||
        bytesToBase64(publicKeys.mlDsaPublicKey) !== env.signerMlDsaPublicKey
      ) {
        return invalid("Supplied signer public keys do not match the signature record");
      }

      const recomputedHash = bytesToBase64(digest);
      if (recomputedHash !== env.contentHash) return invalid();

      const payload = buildSigningPayload({
        signerId: env.signerId,
        timestamp: env.timestamp,
        contentHash: env.contentHash,
        contentType: env.contentType,
        allowlistHash: env.allowlistHash,
        validUntil: env.validUntil,
        versionChainHash: env.versionChainHash,
        sessionContextHash: env.sessionContextHash,
      });

      let edOk: boolean;
      try {
        edOk = ed25519.verify(
          publicKeys.edPublicKey,
          payload,
          base64ToBytes(env.edSignature),
        );
      } catch {
        return invalid("Failed to verify Ed25519 signature");
      }
      if (!edOk) return invalid("Invalid Ed25519 signature");

      let mlDsaOk: boolean;
      try {
        mlDsaOk = ml_dsa87.verify(
          base64ToBytes(env.mlDsaSignature),
          payload,
          publicKeys.mlDsaPublicKey,
        );
      } catch {
        return invalid("Failed to verify ML-DSA-87 signature");
      }
      if (!mlDsaOk) return invalid("Invalid ML-DSA-87 signature");

      if (
        env.validUntil !== undefined &&
        now.getTime() > Date.parse(env.validUntil)
      ) {
        return {
          ...invalid(
            `Signature expired at ${env.validUntil} (verified at ${now.toISOString()})`,
          ),
          expired: true,
        };
      }

      return {
        valid: true,
        signerId: env.signerId,
        contentHash: env.contentHash,
        timestamp: env.timestamp,
        contentType: env.contentType,
        ...(env.sessionContextHash !== undefined
          ? { sessionContextHash: env.sessionContextHash }
          : {}),
      };
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureVerificationError(
        "Verification failed unexpectedly",
        err,
      );
    }
  }

  static verifyCommitment(
    signature: MajikSignature | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
    now: Date = new Date(),
  ): RevisionCommitmentResult {
    try {
      MajikSignatureValidator.validateSignerPublicKeys(publicKeys);
      const env: MajikSignatureJSON =
        signature instanceof MajikSignature ? signature.toJSON() : signature;
      MajikSignatureValidator.validateJSON(env);

      const invalid = (reason?: string): RevisionCommitmentResult => ({
        valid: false,
        signerId: env.signerId,
        contentHash: env.contentHash,
        timestamp: env.timestamp,
        contentType: env.contentType,
        commitmentOnly: true,
        ...(reason ? { reason } : {}),
      });

      if (publicKeys.signerId !== env.signerId) {
        return invalid("Signer key fingerprint does not match signature signerId");
      }
      if (
        bytesToBase64(publicKeys.edPublicKey) !== env.signerEdPublicKey ||
        bytesToBase64(publicKeys.mlDsaPublicKey) !== env.signerMlDsaPublicKey
      ) {
        return invalid("Supplied signer public keys do not match the signature record");
      }

      const payload = buildSigningPayload({
        signerId: env.signerId,
        timestamp: env.timestamp,
        contentHash: env.contentHash,
        contentType: env.contentType,
        allowlistHash: env.allowlistHash,
        validUntil: env.validUntil,
        versionChainHash: env.versionChainHash,
        sessionContextHash: env.sessionContextHash,
      });

      let edOk: boolean;
      try {
        edOk = ed25519.verify(
          publicKeys.edPublicKey,
          payload,
          base64ToBytes(env.edSignature),
        );
      } catch {
        return invalid("Failed to verify Ed25519 signature");
      }
      if (!edOk) return invalid("Invalid Ed25519 signature");

      let mlDsaOk: boolean;
      try {
        mlDsaOk = ml_dsa87.verify(
          base64ToBytes(env.mlDsaSignature),
          payload,
          publicKeys.mlDsaPublicKey,
        );
      } catch {
        return invalid("Failed to verify ML-DSA-87 signature");
      }
      if (!mlDsaOk) return invalid("Invalid ML-DSA-87 signature");

      if (
        env.validUntil !== undefined &&
        now.getTime() > Date.parse(env.validUntil)
      ) {
        return {
          ...invalid(`Signature expired at ${env.validUntil}`),
          expired: true,
        };
      }

      return {
        valid: true,
        signerId: env.signerId,
        contentHash: env.contentHash,
        timestamp: env.timestamp,
        contentType: env.contentType,
        ...(env.sessionContextHash !== undefined
          ? { sessionContextHash: env.sessionContextHash }
          : {}),
        commitmentOnly: true,
      };
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureVerificationError(
        "Commitment verification failed unexpectedly",
        err,
      );
    }
  }

  // ── SELF-VALIDATE ───────────────────────────────────────────────────────────
  /**
   * Verify a hybrid signature against a trusted SHA-256 digest without
   * possessing the original plaintext bytes.
   *
   * The caller must independently establish that expectedContentHash is the
   * trusted digest of the stored document. When expectedSessionContextHash is
   * supplied, it must match the session/challenge/policy commitment in the
   * signer's canonical payload.
   *
   * This does not authorize the signer, issue or consume a one-time challenge,
   * or establish TSA trust. Those remain application/API responsibilities.
   */
  static verifyDigest(
    expectedContentHash: string,
    signature: MajikSignature | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
    options: {
      expectedSessionContextHash?: string;
      now?: Date;
    } = {},
  ): RevisionCommitmentResult {
    MajikSignatureValidator.validateSignerPublicKeys(publicKeys);
    const env =
      signature instanceof MajikSignature ? signature.toJSON() : signature;
    MajikSignatureValidator.validateJSON(env);

    const invalid = (reason: string): RevisionCommitmentResult => ({
      valid: false,
      signerId: env.signerId,
      contentHash: env.contentHash,
      timestamp: env.timestamp,
      contentType: env.contentType,
      ...(env.sessionContextHash !== undefined
        ? { sessionContextHash: env.sessionContextHash }
        : {}),
      commitmentOnly: true,
      reason,
    });

    if (
      typeof expectedContentHash !== "string" ||
      expectedContentHash.length !== 44
    ) {
      return invalid("Expected content hash must be a base64 SHA-256 digest");
    }
    try {
      const digestBytes = base64ToBytes(expectedContentHash);
      if (
        digestBytes.length !== 32 ||
        bytesToBase64(digestBytes) !== expectedContentHash
      ) {
        return invalid("Expected content hash is not a canonical SHA-256 digest");
      }
    } catch {
      return invalid("Expected content hash is not a valid base64 SHA-256 digest");
    }

    if (env.contentHash !== expectedContentHash) {
      return invalid("Signature contentHash does not match the expected digest");
    }

    if (options.expectedSessionContextHash !== undefined) {
      try {
        MajikSignatureValidator.validateSessionContextHash(
          options.expectedSessionContextHash,
        );
      } catch {
        return invalid("Expected session context hash is invalid");
      }
      if (env.sessionContextHash !== options.expectedSessionContextHash) {
        return invalid("Signature session context does not match the expected session");
      }
    } else if (env.sessionContextHash !== undefined) {
      return invalid("Expected session context hash is required for session-bound signatures");
    }

    if (publicKeys.signerId !== env.signerId) {
      return invalid("Signer key fingerprint does not match signature signerId");
    }

    return MajikSignature.verifyCommitment(
      signature,
      publicKeys,
      options.now ?? new Date(),
    );
  }



  validate(): void {
    MajikSignatureValidator.validateJSON(this.toJSON());
  }

  isValid(): boolean {
    try {
      this.validate();
      return true;
    } catch {
      return false;
    }
  }

  // ── EXTRACT PUBLIC KEYS ─────────────────────────────────────────────────────

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

      return { signerId: this._signerId, edPublicKey, mlDsaPublicKey };
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
      timestamp: this._timestamp,
      edSignature: this._edSignature,
      mlDsaSignature: this._mlDsaSignature,
      ...(this._contentType !== undefined
        ? { contentType: this._contentType }
        : {}),
      ...(this._allowlistHash !== undefined
        ? { allowlistHash: this._allowlistHash }
        : {}),
      ...(this._validUntil !== undefined
        ? { validUntil: this._validUntil }
        : {}),
      ...(this._tsa !== undefined ? { tsa: this._tsa } : {}),
      ...(this._versionChainHash !== undefined
        ? { versionChainHash: this._versionChainHash }
        : {}),
      ...(this._sessionContextHash !== undefined
        ? { sessionContextHash: this._sessionContextHash }
        : {}),
    };
  }

  serialize(): string {
    try {
      const bytes = new TextEncoder().encode(JSON.stringify(this.toJSON()));
      let binary = "";
      for (let i = 0; i < bytes.length; i++)
        binary += String.fromCharCode(bytes[i]);
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

  static deserialize(base64: string): MajikSignature {
    try {
      MajikSignatureValidator.assertNonEmptyString(base64, "base64");
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return MajikSignature.fromJSON(new TextDecoder().decode(bytes));
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureSerializationError(
        "Failed to deserialize MajikSignature from base64",
        err,
      );
    }
  }

  // ── CBOR SERIALIZATION/DESERIALIZATION ───────────────────────────────────────────────────────

  /**
   * Encode this signature as CBOR using native byte strings for cryptographic
   * fields. This changes the transport representation, not the signed payload.
   */
  toCBOR(): Uint8Array {
    try {
      return encodeCBOR(signatureToCBOR(this.toJSON()));
    } catch (err) {
      throw new MajikSignatureSerializationError(
        "Failed to serialize MajikSignature as CBOR",
        err,
      );
    }
  }

  /**
   * Decode CBOR into a validated MajikSignature.
   *
   * Decoding and structural validation do not verify the cryptographic
   * signatures. Call verify() with the original content and public keys.
   */
  static fromCBOR(input: Uint8Array | ArrayBuffer): MajikSignature {
    try {
      const decoded = decodeCBOR(input);
      const json = signatureFromCBOR(decoded);

      return MajikSignature.fromJSON(json);
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;

      throw new MajikSignatureSerializationError(
        "Failed to deserialize MajikSignature from CBOR",
        err,
      );
    }
  }

  // ── STATIC KEY HELPERS ───────────────────────────────────────────────────────

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
    return { signerId: key.fingerprint, edPublicKey, mlDsaPublicKey };
  }

  static verifyWithKey(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON,
    key: MajikKey,
  ): VerificationResult {
    return MajikSignature.verify(
      content,
      signature,
      MajikSignature.publicKeysFromMajikKey(key),
    );
  }

  /**
   * Build an ExpectedSigner entry from a MajikKey.
   * Used to construct the expectedSigners array for signFile().
   * The key does not need to be unlocked.
   *
   * @example
   *   expectedSigners: [
   *     MajikSignature.expectedSignerFromKey(aliceKey),
   *     MajikSignature.expectedSignerFromKey(bobKey),
   *   ]
   */
  static expectedSignerFromKey(key: MajikKey): ExpectedSigner {
    MajikSignatureValidator.assertDefined(key, "key");
    if (!key.hasSigningKeys)
      throw new MajikSignatureKeyError(
        "MajikKey has no signing public keys — cannot build ExpectedSigner.",
      );
    return {
      signerId: key.fingerprint,
      edPublicKey: bytesToBase64(key.edPublicKey!),
      mlDsaPublicKey: bytesToBase64(key.mlDsaPublicKey!),
    };
  }

  // ── FILE-AWARE METHODS ────────────────────────────────────────────────────

  /**
   * Sign a file and embed the signature.
   *
   * On first sign: pass options.expectedSigners to restrict future signers.
   * On re-sign: the signer's existing entry is overwritten; others untouched.
   * Non-allowlisted signers are rejected before any crypto (MajikSignatureAllowlistError).
   * Sealed files are always rejected.
   *
   * Pass options.validUntil (ISO 8601) to make this specific signature expire —
   * cryptographically bound into the payload, so it cannot be stripped or
   * extended without invalidating the signature. Omit for a signature that
   * never expires. In multi-sig files, expiry is per-signer: each signer's
   * validUntil (or absence of one) applies only to their own entry.
   *
   * @example
   *   const { blob } = await MajikSignature.signFile(file, aliceKey, {
   *     expectedSigners: [
   *       MajikSignature.expectedSignerFromKey(aliceKey),
   *       MajikSignature.expectedSignerFromKey(bobKey),
   *     ],
   *     validUntil: "2027-01-01T00:00:00.000Z",
   *   });
   */
  static async signFile(
    file: FileLike,
    key: MajikKey,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      expectedSigners?: ExpectedSigner[];
      validUntil?: string;
      message?: string;
      priorSignedFile?: Blob;
    },
  ): ReturnType<typeof MajikSignatureEmbed.signAndEmbed<MajikSignature>> {
    return MajikSignatureEmbed.signAndEmbed<MajikSignature>(
      file,
      key,
      MajikSignature,
      options,
    );
  }


  /**
   * Sign one detached document as part of a SignRoom session.
   *
   * Unlike signFileDetached(), this method requires a canonical session
   * context and commits it into the Ed25519 + ML-DSA-87 signing payload.
   * Each participant should call this with their own one-time challenge
   * context. Existing envelopes and priorFile revision handling use the
   * same orchestration path as ordinary detached signing.
   *
   * The returned mjksig Blob serializes the resulting envelope in the
   * current binary MJKSIG format. It is a detached sidecar; the document
   * itself remains clean and separate.
   *
   * This method does not issue a TSA token or authorize/consume the session
   * challenge. Those responsibilities remain with the session service.
   */
  static async signSessionFile(
    file: FileLike,
    key: MajikKey,
    options: SessionFileSignOptions,
  ) {
    const {
      sessionContext,
      fileVersion,
      ...signingOptions
    } = options;
    const sessionContextHash = buildSessionContextHash(sessionContext);
    const sessionEnvelope = signingOptions.existingEnvelope
      ? await MajikSignatureEnvelope.from(signingOptions.existingEnvelope)
      : MajikSignatureEnvelope.empty();

    if (fileVersion && signingOptions.priorFile) {
      throw new MajikSignatureError(
        "Pass fileVersion or priorFile to signSessionFile(), not both. fileVersion is the explicit SignRoom revision entry.",
      );
    }

    let versionChainHash: string | undefined;
    if (fileVersion) {
      const lastVersion = sessionEnvelope.lastFileVersion;
      const expectedVersion = (lastVersion?.version ?? 0) + 1;
      const expectedPreviousVersionHash = lastVersion
        ? MajikSignatureEnvelope.hashFileVersionEntry(lastVersion)
        : undefined;
      if (
        fileVersion.version !== expectedVersion ||
        fileVersion.createdBy !== key.fingerprint ||
        fileVersion.previousVersionHash !== expectedPreviousVersionHash ||
        typeof fileVersion.timestamp !== "string" ||
        !Number.isFinite(Date.parse(fileVersion.timestamp)) ||
        new Date(Date.parse(fileVersion.timestamp)).toISOString() !== fileVersion.timestamp ||
        typeof fileVersion.contentHash !== "string" ||
        !/^[A-Za-z0-9+/]{43}=$/.test(fileVersion.contentHash)
      ) {
        throw new MajikSignatureError(
          "The supplied SignRoom FileVersion must be the next valid revision, linked to the existing envelope and created by the signing key.",
        );
      }
      versionChainHash = MajikSignatureEnvelope.hashFileVersionChain([
        ...sessionEnvelope.fileVersions,
        fileVersion,
      ]);
    } else if (sessionEnvelope.fileVersions.length > 0) {
      // Even when this signer does not alter the document, bind the signature
      // to the exact current revision chain already stored in the sidecar.
      versionChainHash = MajikSignatureEnvelope.hashFileVersionChain(
        sessionEnvelope.fileVersions,
      );
    }

    const result = await MajikSignatureEmbed.signDetached<MajikSignature>(
      file,
      key,
      MajikSignature,
      {
        ...signingOptions,
        existingEnvelope: sessionEnvelope,
        ...(fileVersion ? { timestamp: fileVersion.timestamp } : {}),
        sessionContextHash,
        ...(versionChainHash !== undefined ? { versionChainHash } : {}),
      },
    );

    if (
      fileVersion &&
      result.signature.contentHash !== fileVersion.contentHash
    ) {
      throw new MajikSignatureError(
        "The supplied SignRoom FileVersion contentHash does not match the document bytes being signed.",
      );
    }

    const envelope = fileVersion
      ? result.envelope.withFileVersion(fileVersion)
      : result.envelope;

    return {
      ...result,
      envelope,
      mjksig: envelope.toMJKSIG(),
    };
  }

  /**
   * Sign a file and return the signature envelope detached.
   *
   * Strips the file of any embedded envelopes, incorporates your new signature
   * into the multi-sig structure, but does NOT embed it back.
   * Useful for external verification workflows where payloads and envelopes travel out-of-band.
   *
   * Pass options.tsa to attach a Trusted Timestamp to this signature before
   * it's added to the envelope — the digest-match and TSA-signature checks
   * happen automatically inside addTSA().
   *
   * Pass options.validUntil (ISO 8601) to make this signature expire — see
   * signFile() for the same semantics; identical here since both funnel
   * through the same underlying sign() call.
   *
   * @example
   *   const { blob, envelope, signature } = await MajikSignature.signFileDetached(file, aliceKey, {
   *     existingEnvelope: outOfBandEnvelope,
   *     tsa: myTsaTimestamp,
   *     validUntil: "2027-01-01T00:00:00.000Z",
   *   });
   *   console.log(signature.hasTSA); // true if tsa was provided and accepted
   */
  static async signFileDetached(
    file: FileLike,
    key: MajikKey,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      expectedSigners?: ExpectedSigner[];
      validUntil?: string;
      existingEnvelope?: EnvelopeInput;
      tsa?: MajikTimestamp;
      priorFile?: FileLike;
      message?: string;
    },
  ): ReturnType<typeof MajikSignatureEmbed.signDetached<MajikSignature>> {
    return MajikSignatureEmbed.signDetached<MajikSignature>(
      file,
      key,
      MajikSignature,
      options,
    );
  }

  /**
   * Sign a batch of files (e.g. a folder or zip's contents) as detached
   * envelopes. Packaged either as one MajikSignatureMap covering the whole
   * batch (default — meant to sit at the root of the zip as one .mjksmap),
   * or as separate .mjksig Blobs per file when options.mode === "separate".
   *
   * options.validUntil, if set, is applied identically to every signature in
   * the batch — there is no per-file override. Sign files individually via
   * signFileDetached() if different files need different expiries.
   *
   * @example
   *   const result = await MajikSignature.signBatchDetached(
   *     [
   *       { path: "docs/report.pdf", blob: reportBlob },
   *       { path: "docs/appendix.pdf", blob: appendixBlob },
   *     ],
   *     aliceKey,
   *     { validUntil: "2027-01-01T00:00:00.000Z" },
   *   );
   *   if (result.mode === "map") {
   *     zip.file("signatures.mjksmap", await result.mapBlob.arrayBuffer());
   *   }
   */
  static async signBatchDetached(
    files: BatchFileInput[],
    key: MajikKey,
    options?: BatchSignOptions,
  ): ReturnType<typeof MajikSignatureEmbed.signBatchDetached> {
    return MajikSignatureEmbed.signBatchDetached(
      files,
      key,
      MajikSignature,
      options,
    );
  }

  /**
   * Verify a file's embedded signatures.
   * Returns one VerificationResult per signer. Old single-sig files return a single-item array.
   * Pass options.expectedSignerId to verify only a specific signer.
   * Pass options.now to check expiry as of a specific time instead of the
   * current time. Any signer whose validUntil has passed comes back with
   * valid: false, expired: true, and a reason noting the expiry.
   */
  /**
   * Sign a collection of exact byte streams as detached signatures without
   * materializing their source contents. Files are consumed sequentially so
   * memory use is bounded by the configured per-stream chunk size.
   *
   * Sources must provide the canonical bytes to sign. This low-level API does
   * not parse or strip an existing embedded envelope from a stream.
   */
  static async signBatchDetachedStream(
    files: StreamingBatchFileInput[],
    key: MajikKey,
    options?: BatchStreamingOptions,
  ): Promise<BatchSignResult> {
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

    const mode = options?.mode ?? "map";
    const continueOnError = options?.continueOnError ?? false;
    const failures: BatchSignFailure[] = [];
    let map = mode === "map" ? MajikSignatureMap.empty() : undefined;
    const signatures: { path: string; blob: Blob }[] = [];

    for (let index = 0; index < files.length; index++) {
      const file = files[index]!;
      let bytesProcessed = 0;
      try {
        const emptyEnvelope = MajikSignatureEnvelope.empty();
        const allowlistHash = emptyEnvelope.resolveAllowlistHashFor(
          key,
          options?.expectedSigners,
        );
        const signature = await MajikSignature.signStream(file.source, key, {
          contentType: options?.contentType,
          timestamp: options?.timestamp,
          validUntil: options?.validUntil,
          allowlistHash,
          streaming: {
            ...options?.streaming,
            totalBytes: file.totalBytes,
            onProgress: (progress) => {
              bytesProcessed = progress.bytesProcessed;
              options?.onProgress?.({
                index,
                totalFiles: files.length,
                path: file.path,
                bytesProcessed: progress.bytesProcessed,
                ...(progress.totalBytes !== undefined
                  ? { totalBytes: progress.totalBytes }
                  : {}),
              });
            },
          },
        });

        let envelope = emptyEnvelope;
        if (options?.expectedSigners?.length) {
          envelope = envelope.withAllowlist(
            options.expectedSigners,
            key.fingerprint,
          );
        }
        envelope = envelope.withSignature(signature.toJSON());

        if (mode === "map") {
          map = map!.withEntry({
            path: file.path,
            contentHash: signature.contentHash,
            size: bytesProcessed,
            mimeType: file.mimeType || undefined,
            envelope: envelope.toJSON(),
          });
        } else {
          signatures.push({ path: file.path, blob: envelope.toMJKSIG() });
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (!continueOnError) {
          throw new MajikSignatureError(
            `Batch streaming signing failed on "${file.path}": ${message}`,
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

  /**
   * Verify streamed files against a MJKSMAP manifest without materializing
   * the complete file contents. Inputs are consumed sequentially; the
   * manifest is resolved by path first and by content hash for relocations.
   */
  static async verifyFilesFromMjksMapStream(
    map: MajikSignatureMap,
    files: StreamingBatchVerifyInput[],
    publicKeys: MajikSignerPublicKeys,
    options?: BatchStreamingVerifyOptions,
  ): Promise<FileVerifyResult[]> {
    const results: FileVerifyResult[] = [];
    const now = options?.now ?? new Date();

    for (let index = 0; index < files.length; index++) {
      const file = files[index]!;
      const streamed = await hashSource(file.source, {
        ...options?.streaming,
        totalBytes: file.totalBytes,
        onProgress: (progress) => {
          options?.onProgress?.({
            index,
            totalFiles: files.length,
            path: file.path,
            bytesProcessed: progress.bytesProcessed,
            ...(progress.totalBytes !== undefined
              ? { totalBytes: progress.totalBytes }
              : {}),
          });
        },
      });
      const contentHash = bytesToBase64(streamed.digest);

      // Preserve map resolution order: a path match with different bytes is
      // tampered, not a relocation candidate.
      let entry = map.getEntry(file.path);
      let relocatedFrom: string | undefined;
      if (entry && entry.contentHash !== contentHash) {
        results.push({
          path: file.path,
          status: "tampered",
          reason:
            "File content no longer matches what was signed — it may have been modified after signing.",
        });
        continue;
      }

      if (!entry) {
        entry = map.entries.find((candidate) => candidate.contentHash === contentHash);
        if (entry) relocatedFrom = entry.path;
      }

      if (!entry) {
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

      const envelope = MajikSignatureEnvelope.fromJSON(entry.envelope);
      const integrity = envelope.verifyAllowlistIntegrity();
      if (!integrity.valid) {
        results.push({
          path: file.path,
          status: "invalid",
          reason: integrity.reason,
          ...(relocatedFrom ? { relocatedFrom } : {}),
        });
        continue;
      }

      const signatures = options?.expectedSignerId
        ? envelope.signatures.filter(
            (signature) => signature.signerId === options.expectedSignerId,
          )
        : [...envelope.signatures];

      const verifyResults: VerificationResult[] = signatures.length
        ? signatures.map((signature) =>
            MajikSignature._verifyDigest(
              streamed.digest,
              signature,
              publicKeys,
              now,
            ),
          )
        : [
            {
              valid: false,
              reason: options?.expectedSignerId
                ? `No signature found for signerId "${options.expectedSignerId}"`
                : "Envelope contains no signatures",
              timestamp: now.toISOString(),
            },
          ];

      const allValid = verifyResults.every((result) => result.valid);
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

  static async verifyFile(
    file: FileLike,
    keyOrPublicKeys: MajikKey | MajikSignerPublicKeys,
    options?: { expectedSignerId?: string; mimeType?: string; now?: Date },
    debug: boolean = false,
  ): Promise<VerificationResult[]> {
    if (MajikSignature._isMajikKey(keyOrPublicKeys)) {
      return MajikSignatureEmbed.verifyWithKey(
        file,
        keyOrPublicKeys,
        MajikSignature,
        options,
        debug,
      );
    }
    return MajikSignatureEmbed.verify(
      file,
      keyOrPublicKeys,
      MajikSignature,
      options,
      debug,
    );
  }


  /**
   * Verify a detached document and every participant signature against
   * authoritative SignRoom contexts.
   *
   * expectedSessionContexts must contain one context per signer, keyed by
   * signer fingerprint. This is necessary because each participant signs
   * with a distinct one-time challenge. Unknown signers, missing contexts,
   * standalone signatures, and context mismatches fail closed.
   *
   * The method verifies the current document bytes and, when present, the
   * self-contained revision chain. Historical revisions are verified at the
   * commitment level, matching verifyFileDetachedChain() semantics.
   *
   * TSA attestations are checked when present. Without trustedTsaPublicKeys,
   * that check only proves consistency with the key embedded in the TSA
   * record; it does not establish external trust.
   */
  static async verifySessionFile(
    file: FileLike,
    envelopeInput: EnvelopeInput,
    options: SessionFileVerifyOptions,
  ): Promise<SessionFileVerificationResult> {
    if (
      !options ||
      !options.expectedSessionContexts ||
      typeof options.expectedSessionContexts !== "object" ||
      !options.expectedSignerPublicKeys ||
      typeof options.expectedSignerPublicKeys !== "object"
    ) {
      throw new TypeError(
        "expectedSessionContexts and expectedSignerPublicKeys must be signer-keyed maps",
      );
    }
    if (options.requireTrustedTSA && !options.trustedTsaPublicKeys) {
      throw new TypeError(
        "trustedTsaPublicKeys is required when requireTrustedTSA is enabled",
      );
    }

    const envelope = await MajikSignatureEnvelope.from(envelopeInput);
    const signatures = [...envelope.signatures];
    if (signatures.length === 0) {
      return {
        valid: false,
        results: [],
        tsaResults: [],
        reason: "Session envelope contains no participant signatures",
      };
    }

    const now = options.now ?? new Date();
    let chain: FileChainVerification | undefined;
    let cryptographicResults: VerificationResult[];

    if (envelope.fileVersions.length > 0) {
      chain = await MajikSignature.verifyFileDetachedChain(
        file,
        envelope,
        { mimeType: options.mimeType, now },
      );
      const bySigner = new Map<string, VerificationResult>();
      for (const result of [...chain.history, chain.latest]) {
        if (result.signerId) bySigner.set(result.signerId, result);
      }
      cryptographicResults = signatures.map((signature) => {
        const trustedKeys =
          options.expectedSignerPublicKeys[signature.signerId];
        if (!trustedKeys) {
          return {
            valid: false,
            signerId: signature.signerId,
            contentHash: signature.contentHash,
            timestamp: signature.timestamp,
            contentType: signature.contentType,
            sessionContextHash: signature.sessionContextHash,
            reason: "No trusted public keys were supplied for signer " + signature.signerId,
          };
        }

        const commitment = MajikSignature.verifyCommitment(
          signature,
          trustedKeys,
          now,
        );
        if (!commitment.valid) return commitment;

        return bySigner.get(signature.signerId) ?? {
          valid: false,
          signerId: signature.signerId,
          contentHash: signature.contentHash,
          timestamp: signature.timestamp,
          contentType: signature.contentType,
          sessionContextHash: signature.sessionContextHash,
          reason: "No verified revision-chain result exists for this signer",
        };
      });
    } else {
      const hasUnverifiableRevisionCommitment = signatures.some(
        (signature) => signature.versionChainHash !== undefined,
      );
      const stripped = await MajikSignature.stripFrom(file, {
        mimeType: options.mimeType,
      });
      const content = new Uint8Array(await stripped.arrayBuffer());

      cryptographicResults = signatures.map((signature) => {
        if (hasUnverifiableRevisionCommitment) {
          return {
            valid: false,
            signerId: signature.signerId,
            contentHash: signature.contentHash,
            timestamp: signature.timestamp,
            contentType: signature.contentType,
            sessionContextHash: signature.sessionContextHash,
            reason: "Signature commits to a revision chain, but fileVersions is missing",
          };
        }
        const trustedKeys =
          options.expectedSignerPublicKeys[signature.signerId];
        if (!trustedKeys) {
          return {
            valid: false,
            signerId: signature.signerId,
            contentHash: signature.contentHash,
            timestamp: signature.timestamp,
            contentType: signature.contentType,
            sessionContextHash: signature.sessionContextHash,
            reason: "No trusted public keys were supplied for signer " + signature.signerId,
          };
        }
        try {
          return MajikSignature.verify(
            content,
            signature,
            trustedKeys,
            now,
          );
        } catch (error) {
          return {
            valid: false,
            signerId: signature.signerId,
            contentHash: signature.contentHash,
            timestamp: signature.timestamp,
            contentType: signature.contentType,
            sessionContextHash: signature.sessionContextHash,
            reason: error instanceof Error
              ? error.message
              : "Unable to verify participant signature",
          };
        }
      });
    }

    const resolvedSessionContexts = signatures
      .map((signature) => ({
        signerId: signature.signerId,
        context: Object.prototype.hasOwnProperty.call(
          options.expectedSessionContexts,
          signature.signerId,
        )
          ? options.expectedSessionContexts[signature.signerId]
          : undefined,
      }))
      .filter(
        (entry): entry is {
          signerId: string;
          context: NonNullable<typeof entry.context>;
        } => entry.context !== undefined,
      );
    const sessionIds = new Set(
      resolvedSessionContexts.map((entry) => entry.context.sessionId),
    );
    const policyHashes = new Set(
      resolvedSessionContexts.map((entry) => entry.context.policyHash),
    );
    const challengeIds = resolvedSessionContexts.map(
      (entry) => entry.context.challengeId,
    );
    const hasUniqueChallenges =
      new Set(challengeIds).size === challengeIds.length;
    const sessionScopeReason =
      resolvedSessionContexts.length !== signatures.length
        ? undefined // Missing signer contexts are reported on their individual result.
        : sessionIds.size !== 1
          ? "All participant signatures must belong to the same SignRoom session"
          : policyHashes.size !== 1
            ? "All participant signatures must commit to the same immutable session policy"
            : !hasUniqueChallenges
              ? "Each participant must use a distinct one-time challenge"
              : undefined;

    const results = signatures.map((signature, index) => {
      const base = cryptographicResults[index];
      const context = resolvedSessionContexts.find(
        (entry) => entry.signerId === signature.signerId,
      )?.context;

      if (envelope.hasAllowlist()) {
        const isIssuer = signature.signerId === envelope.allowlistSignerId;
        const allowed = envelope.allowlist?.some(
          (entry) =>
            entry.signerId === signature.signerId &&
            entry.edPublicKey === signature.signerEdPublicKey &&
            entry.mlDsaPublicKey === signature.signerMlDsaPublicKey,
        ) ?? false;
        if (!isIssuer && !allowed) {
          return {
            ...base,
            valid: false,
            sessionContextHash: signature.sessionContextHash,
            reason: "Signer is not authorized by the envelope allowlist",
          };
        }
      }

      if (sessionScopeReason) {
        return {
          ...base,
          valid: false,
          sessionContextHash: signature.sessionContextHash,
          reason: sessionScopeReason,
        };
      }

      if (!context) {
        return {
          ...base,
          valid: false,
          sessionContextHash: signature.sessionContextHash,
          reason: "No authoritative session context was supplied for signer " + signature.signerId,
        };
      }

      let expectedHash: string;
      try {
        expectedHash = buildSessionContextHash(context);
      } catch (error) {
        return {
          ...base,
          valid: false,
          sessionContextHash: signature.sessionContextHash,
          reason: error instanceof Error
            ? "Invalid expected session context: " + error.message
            : "Invalid expected session context",
        };
      }

      if (signature.sessionContextHash !== expectedHash) {
        return {
          ...base,
          valid: false,
          sessionContextHash: signature.sessionContextHash,
          reason: "Signature session context does not match the authoritative session, challenge, and policy",
        };
      }

      return {
        ...base,
        sessionContextHash: signature.sessionContextHash,
      };
    });

    const tsaResults: SessionFileTsaVerificationResult[] = signatures.map(
      (signature) => {
        const instance = MajikSignature.fromJSON(signature);
        if (!instance.hasTSA) {
          return {
            signerId: signature.signerId,
            present: false,
            valid: options.requireTSA !== true,
            trusted: false,
            ...(options.requireTSA
              ? { reason: "A TSA attestation is required for this participant" }
              : {}),
          };
        }

        try {
          const tsaVerification = instance.verifyTSA(
            options.trustedTsaPublicKeys,
          );
          return {
            signerId: signature.signerId,
            present: true,
            valid: tsaVerification.valid,
            trusted: options.trustedTsaPublicKeys !== undefined &&
              tsaVerification.valid,
            ...(tsaVerification.reason
              ? { reason: tsaVerification.reason }
              : {}),
          };
        } catch (error) {
          return {
            signerId: signature.signerId,
            present: true,
            valid: false,
            trusted: false,
            reason: error instanceof Error
              ? error.message
              : "TSA verification failed",
          };
        }
      },
    );

    const allowlistIntegrity = envelope.verifyAllowlistIntegrity();
    const versionChainIntegrity = envelope.verifyVersionChainIntegrity();
    const sealIntegrity: SealVerificationResult = envelope.isSealed()
      ? envelope.verifySeal()
      : { valid: true };
    const chainValid = chain ? chain.chainValid : versionChainIntegrity.valid;
    const tsaValid = tsaResults.every((result) => result.valid);
    const trustedTsaValid =
      options.requireTrustedTSA !== true ||
      tsaResults.every((result) =>
        result.present && result.valid && result.trusted,
      );

    const valid =
      results.every((result) => result.valid) &&
      allowlistIntegrity.valid &&
      versionChainIntegrity.valid &&
      sealIntegrity.valid &&
      chainValid &&
      tsaValid &&
      trustedTsaValid;

    const reason =
      results.find((result) => !result.valid)?.reason ??
      allowlistIntegrity.reason ??
      versionChainIntegrity.reason ??
      sealIntegrity.reason ??
      (chain && !chain.chainValid
        ? "Detached revision chain verification failed"
        : undefined) ??
      tsaResults.find((result) => !result.valid)?.reason ??
      (!trustedTsaValid
        ? "Every TSA attestation must verify against the trusted TSA public key"
        : undefined);

    return {
      valid,
      results,
      ...(chain ? { chain } : {}),
      tsaResults,
      ...(reason ? { reason } : {}),
    };
  }

  /**
   * Verify a file against a detached signature envelope.
   * Skips extraction and verifies the stripped file bytes directly against the provided envelope.
   * Returns one VerificationResult per signer.
   * Pass options.expectedSignerId to verify only a specific signer.
   * Pass options.now to check expiry as of a specific time instead of the
   * current time.
   */
  static async verifyFileDetached(
    file: FileLike,
    envelope: EnvelopeInput,
    keyOrPublicKeys: MajikKey | MajikSignerPublicKeys,
    options?: {
      expectedSignerId?: string;
      mimeType?: string;
      now?: Date;
      requireCanonical?: boolean;
    },
    debug: boolean = false,
  ): Promise<VerificationResult[]> {
    if (MajikSignature._isMajikKey(keyOrPublicKeys)) {
      return MajikSignatureEmbed.verifyDetachedWithKey(
        file,
        envelope,
        keyOrPublicKeys,
        MajikSignature,
        options,
        debug,
      );
    }
    return MajikSignatureEmbed.verifyDetached(
      file,
      envelope,
      keyOrPublicKeys,
      MajikSignature,
      options,
      debug,
    );
  }

  /**
   * Verify a batch of extracted files against a MajikSignatureMap (loaded via
   * MajikSignatureMap.fromMJKSMAP()). Reports a per-file status rather than
   * throwing — a missing, tampered, or invalidly-signed file is a normal
   * possible outcome to display, not an exceptional one to catch.
   *
   * A file whose signature has passed its validUntil comes back with
   * status "invalid" and results[].expired === true — same status as any
   * other failed signature, so summarizeBatchVerification()'s allValid check
   * still works unchanged. Pass options.now to check "as of" a specific time.
   *
   * @example
   *   const map = await MajikSignatureMap.fromMJKSMAP(mjksmapBlob);
   *   const results = await MajikSignature.verifyFilesFromMjksMap(
   *     map,
   *     extractedFiles,
   *     publicKeys,
   *   );
   *   const summary = MajikSignature.summarizeBatchVerification(results);
   *   if (!summary.allValid) { ... }
   */
  static async verifyFilesFromMjksMap(
    map: MajikSignatureMap,
    files: BatchVerifyInput[],
    publicKeys: MajikSignerPublicKeys,
    options?: BatchVerifyOptions,
    debug: boolean = false,
  ): Promise<FileVerifyResult[]> {
    return MajikSignatureEmbed.verifyFilesFromMjksMap(
      map,
      files,
      publicKeys,
      MajikSignature,
      options,
      debug,
    );
  }

  static async verifyFilesFromMjksMapWithKey(
    map: MajikSignatureMap,
    files: BatchVerifyInput[],
    key: MajikKey,
    options?: BatchVerifyOptions,
    debug: boolean = false,
  ): Promise<FileVerifyResult[]> {
    return MajikSignatureEmbed.verifyFilesFromMjksMapWithKey(
      map,
      files,
      key,
      MajikSignature,
      options,
      debug,
    );
  }

  static summarizeBatchVerification(
    results: FileVerifyResult[],
  ): ReturnType<typeof MajikSignatureEmbed.summarizeBatchVerification> {
    return MajikSignatureEmbed.summarizeBatchVerification(results);
  }

  /**
   * Verify that a file's embedded signatures were produced in the given
   * order. expectedOrder accepts MajikKey instances and/or ExpectedSigner
   * objects, mixed freely.
   *
   * @example
   *   const result = await MajikSignature.verifyFileOrder(file, [bobKey, daveKey]);
   *   if (!result.valid) console.warn(result.reason);
   */
  static async verifyFileOrder(
    file: FileLike,
    expectedOrder: readonly (MajikKey | ExpectedSigner)[],
    options?: { mimeType?: string; strict?: boolean },
  ): Promise<SignatureOrderResult> {
    return MajikSignatureEmbed.verifyFileOrder(
      file,
      expectedOrder,
      MajikSignature,
      options,
    );
  }

  /**
   * Verify signing order against a detached envelope.
   */
  static async verifyFileDetachedOrder(
    file: FileLike,
    envelope:
      | MajikSignatureEnvelope
      | MajikSignatureEnvelopeJSON
      | Uint8Array
      | Blob,
    expectedOrder: readonly (MajikKey | ExpectedSigner)[],
    options?: { mimeType?: string; strict?: boolean },
  ): Promise<SignatureOrderResult> {
    return MajikSignatureEmbed.verifyDetachedOrder(
      file,
      envelope,
      expectedOrder,
      MajikSignature,
      options,
    );
  }

  static async verifyFileChain(
    file: FileLike,
    options?: { mimeType?: string; now?: Date },
  ): Promise<FileChainVerification> {
    return MajikSignatureEmbed.verifyFileChain(file, MajikSignature, options);
  }

  static async verifyFileRevisions(
    finalFile: FileLike,
    revisions: FileLike[],
    options?: {
      mimeType?: string;
      now?: Date;
      resolvePublicKeys?: (
        signerId: string,
      ) => MajikSignerPublicKeys | Promise<MajikSignerPublicKeys>;
    },
  ): Promise<RevisionSetVerification> {
    return MajikSignatureEmbed.verifyFileRevisions(
      finalFile,
      revisions,
      MajikSignature,
      options,
    );
  }

  static async verifyFileRevisionsDetached(
    finalFile: FileLike,
    revisions: FileLike[],
    envelope: EnvelopeInput,
    options?: {
      mimeType?: string;
      now?: Date;
      resolvePublicKeys?: (
        signerId: string,
      ) => MajikSignerPublicKeys | Promise<MajikSignerPublicKeys>;
    },
  ): Promise<RevisionSetVerification> {
    return MajikSignatureEmbed.verifyDetachedRevisions(
      finalFile,
      revisions,
      envelope,
      MajikSignature,
      options,
    );
  }

  static async verifyFileDetachedChain(
    file: FileLike,
    envelope: EnvelopeInput,
    options?: { mimeType?: string; now?: Date },
  ): Promise<FileChainVerification> {
    return MajikSignatureEmbed.verifyDetachedChain(
      file,
      envelope,
      MajikSignature,
      options,
    );
  }

  /**
   * Normalize a mixed array of MajikKey instances / ExpectedSigner objects
   * into a plain ExpectedSigner[]. Exposed standalone in case you want to
   * cache/store the normalized order without immediately verifying.
   */
  static normalizeExpectedOrder(
    expectedOrder: readonly (MajikKey | ExpectedSigner)[],
  ): ExpectedSigner[] {
    return normalizeExpectedOrderUtil(expectedOrder);
  }

  /**
   * Embed this MajikSignature instance into a file.
   * The signature must cover the original file bytes BEFORE embedding.
   * Use signFile() if you want signing + embedding together.
   */
  async embedIn(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<Blob> {
    const { blob } = await MajikSignatureEmbed.embed(file, this, options);
    return blob;
  }

  /**
   * Extract all embedded MajikSignature instances from a file.
   * Returns an array — old single-sig files return a single-item array.
   * Returns an empty array if no signatures are found.
   */
  static async extractFrom(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<MajikSignature[]> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return [];
    return result.envelope.signatures.map((json) =>
      MajikSignature.fromJSON(json),
    );
  }

  /**
   * Return the file with any embedded signatures removed.
   * The returned bytes are exactly what was originally signed.
   */
  static async stripFrom(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<Blob> {
    return MajikSignatureEmbed.strip(file, options);
  }

  /**
   * Check whether a file contains any embedded signatures.
   * Does not verify — structural presence check only.
   */
  static async isSigned(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<boolean> {
    return MajikSignatureEmbed.hasSignature(file, options);
  }

  /**
   * Get the allowlist from a file without verifying any signatures.
   * Returns null for open-signing files or unsigned files.
   */
  static async getAllowlist(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<ExpectedSigner[] | null> {
    return MajikSignatureEmbed.getAllowlist(file, options);
  }

  // ── SEAL METHODS ──────────────────────────────────────────────────────────

  /**
   * Seal a restricted multi-sig file, preventing any further signatures.
   *
   * Only the issuer (the signer who established the allowlist) may seal.
   * The seal is a SHA3-512 hash of all current signatories + the seal timestamp,
   * stored in the envelope. It does not produce a new cryptographic signature.
   *
   * @example
   *   const { blob, sealInfo } = await MajikSignature.seal(signedBlob, issuerKey);
   *   console.log("Sealed at", sealInfo.sealTimestamp);
   */
  static async seal(
    file: FileLike,
    key: MajikKey,
    options?: { mimeType?: string; timestamp?: string },
  ): Promise<{
    blob: Blob;
    sealInfo: SealInfo;
    handler: string;
    mimeType: string;
  }> {
    return MajikSignatureEmbed.seal(file, key, options);
  }

  /**
   * Verify the seal hash against the current signatories and seal timestamp.
   * Returns invalid if the envelope is not sealed.
   * Does NOT verify individual cryptographic signatures — call verifyFile() for that.
   *
   * @example
   *   const result = await MajikSignature.verifySeal(sealedBlob);
   *   if (result.valid) console.log("Sealed by", result.sealedBy, "at", result.sealTimestamp);
   */
  static async verifySeal(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SealVerificationResult> {
    return MajikSignatureEmbed.verifySeal(file, options);
  }

  /**
   * Get seal metadata without verifying.
   * Returns null if the file is not sealed or has no envelope.
   *
   * @example
   *   const info = await MajikSignature.getSealInfo(blob);
   *   if (info) console.log("Sealed by", info.sealedBy);
   */
  static async getSealInfo(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SealInfo | null> {
    return MajikSignatureEmbed.getSealInfo(file, options);
  }

  /**
   * Returns true if the file has a sealed envelope (structural check, no crypto).
   */
  static async isSealed(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<boolean> {
    return MajikSignatureEmbed.isSealed(file, options);
  }

  // ── MULTI-SIG QUERY METHODS ───────────────────────────────────────────────

  /**
   * Returns true when the file has a restricted multi-sig envelope
   * (allowlist with more than one expected signer).
   * Returns false for unsigned, open-signing, or single-signer files.
   */
  static async isMultiSig(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<boolean> {
    return MajikSignatureEmbed.isMultiSig(file, options);
  }

  /**
   * Check whether a MajikKey is permitted to add a signature to this file.
   * Accounts for seal status and allowlist membership (full three-field check).
   *
   * @example
   *   const { permitted, reason } = await MajikSignature.canSign(blob, key);
   *   if (!permitted) console.warn(reason);
   */
  static async canSign(
    file: FileLike,
    key: MajikKey,
    options?: { mimeType?: string },
  ): Promise<{ permitted: boolean; reason?: string }> {
    return MajikSignatureEmbed.canSign(file, key, options);
  }

  /**
   * Core signatories method — returns all, signed, and pending arrays.
   *
   * When an allowlist is present:
   *   - all     = every expected signer with their signing status
   *   - signed  = those who have already signed
   *   - pending = those who are expected but have not yet signed
   *
   * When no allowlist is present:
   *   - all / signed = actual signers (everyone has signed by definition)
   *   - pending      = always empty
   *
   * Returns null if the file has no envelope.
   *
   * @example
   *   const result = await MajikSignature.getSignatories(blob);
   *   console.log(result.pending.map(s => s.signerId));
   */
  static async getSignatories(
    file: FileLike,
    options?: { mimeType?: string },
    filter?: SignatoriesFilter,
  ): Promise<SignatoriesResult | null> {
    return MajikSignatureEmbed.getSignatories(file, options, filter);
  }

  /**
   * Returns only signatories who have already signed.
   * Alias for getSignatories(file, options, "signed").
   */
  static async getSignedSignatories(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    return MajikSignatureEmbed.getSignatories(file, options, "signed");
  }

  /**
   * Returns only signatories who are expected but have not yet signed.
   * Alias for getSignatories(file, options, "pending").
   */
  static async getPendingSignatories(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    return MajikSignatureEmbed.getSignatories(file, options, "pending");
  }

  /**
   * Returns all signatories with full status information.
   * Alias for getSignatories(file, options, "all").
   */
  static async getAllSignatories(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    return MajikSignatureEmbed.getSignatories(file, options, "all");
  }

  /**
   * Returns the issuer — the signer who established the allowlist and controls sealing.
   * Returns null for open-signing files or unsigned files.
   *
   * @example
   *   const issuer = await MajikSignature.getIssuer(blob);
   *   if (issuer) console.log("Issued by", issuer.signerId, "| signed:", issuer.hasSigned);
   */
  static async getIssuer(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<SignatoryInfo | null> {
    return MajikSignatureEmbed.getIssuer(file, options);
  }

  /**
   * Return a complete summary of the envelope state in one file read.
   * Covers: isMultiSig, isSealed, issuer, all signatories, allowlist, seal info.
   * Useful for rendering a signing status UI without making multiple separate calls.
   *
   * Returns null if the file has no envelope.
   *
   * @example
   *   const info = await MajikSignature.getEnvelopeInfo(blob);
   *   if (info?.isSealed) console.log("Sealed by", info.sealInfo?.sealedBy);
   *   console.log(`${info?.signatories?.signed.length} of ${info?.signatories?.all.length} signed`);
   */
  static async getEnvelopeInfo(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<EnvelopeInfo | null> {
    return MajikSignatureEmbed.getEnvelopeInfo(file, options);
  }

  // ── STAMP (compression-resistant image signing) ───────────────────────────

  /** @experimental ⚠️ API not stable. */
  static async stampImage(
    image: Blob,
    key: MajikKey,
    options?: ImageSignOptions,
  ): Promise<{
    blob: Blob;
    stub: ImageSignatureStub;
    fullEnvelope: MajikSignatureJSON;
  }> {
    return MajikImageSignature.sign(image, key, MajikSignature, options);
  }

  /** @experimental ⚠️ API not stable. */
  static async verifyStamp(
    image: Blob,
    options?: { hammingThreshold?: number },
  ): Promise<ImageVerificationResult> {
    return MajikImageSignature.verify(image, MajikSignature, options);
  }

  /** @experimental ⚠️ API not stable. */
  static async inspectStamp(image: Blob): Promise<{
    hasPixelRow: boolean;
    hasDct: boolean;
    pixelRowMeta?: { signerId: string; timestamp: string };
    dctMeta?: { signerId: string; timestamp: string; pHash: string };
  }> {
    return MajikImageSignature.inspect(image);
  }

  /** @experimental ⚠️ API not stable. */
  static async isStamped(image: Blob): Promise<boolean> {
    return MajikImageSignature.isSigned(image);
  }

  // ── TRUSTED TIMESTAMPS ───────────────────────────────────────────────────────

  buildTSARequestPayload(
    scope: TSADigestScope = "content",
  ): MajikTSARequest {
    if (scope === "signature") {
      const digest = bytesToBase64(
        hashContent(buildSignatureAttestationBytes(this.toJSON())),
      );
      return {
        digest: {
          algorithm: "SHA-256",
          value: digest,
          scope: "signature",
        },
      };
    }

    // An omitted scope retains the legacy content-hash timestamp behavior.
    return {
      digest: {
        algorithm: "SHA-256",
        value: this._contentHash,
      },
    };
  }

  addTSA(tsa: MajikTimestamp, trustedTsaPublicKeys?: MajikSignerPublicKeys): void {
    if (this._tsa !== undefined)
      throw new MajikSignatureError(
        "TSA is already set and cannot be replaced",
      );

    MajikSignatureValidator.validateMajikTimestamp(tsa);

    const expectedDigest =
      tsa.payload.digest.scope === "signature"
        ? bytesToBase64(
            hashContent(buildSignatureAttestationBytes(this.toJSON())),
          )
        : this._contentHash;

    if (tsa.payload.digest.value !== expectedDigest)
      throw new MajikSignatureError(
        tsa.payload.digest.scope === "signature"
          ? "TSA digest does not match the canonical signature record"
          : "TSA digest does not match signature contentHash",
      );

    if (tsa.payload.tsa.signerFingerprint !== tsa.signature.signerId) {
      throw new MajikSignatureVerificationError(
        "TSA identity fingerprint does not match the embedded TSA signer",
      );
    }

    const canonicalBytes = buildTSACanonicalBytes(tsa.payload);
    const tsaSig = MajikSignature.fromJSON(tsa.signature);
    const embeddedPublicKeys = tsaSig.extractPublicKeys();
    const verificationKeys = trustedTsaPublicKeys ?? embeddedPublicKeys;

    if (trustedTsaPublicKeys !== undefined) {
      MajikSignatureValidator.validateSignerPublicKeys(trustedTsaPublicKeys);
      if (
        tsa.payload.tsa.signerFingerprint !== trustedTsaPublicKeys.signerId ||
        tsa.signature.signerId !== trustedTsaPublicKeys.signerId
      ) {
        throw new MajikSignatureVerificationError(
          "TSA identity does not match the trusted TSA public-key fingerprint",
        );
      }
    }

    const result = MajikSignature.verify(
      canonicalBytes,
      tsaSig,
      verificationKeys,
    );

    if (!result.valid)
      throw new MajikSignatureVerificationError(
        `TSA signature verification failed: ${result.reason ?? "unknown"}`,
      );

    this._tsa = tsa;
  }

  /**
   * Verify the TSA token on this signature without re-calling addTSA().
   * Use after deserialization to confirm the embedded TSA is still valid.
   * Returns a VerificationResult from the TSA signature check.
   */
  verifyTSA(trustedTsaPublicKeys?: MajikSignerPublicKeys): VerificationResult {
    if (!this._tsa)
      throw new MajikSignatureError("No TSA present on this signature");

    const expectedDigest =
      this._tsa.payload.digest.scope === "signature"
        ? bytesToBase64(
            hashContent(buildSignatureAttestationBytes(this.toJSON())),
          )
        : this._contentHash;

    if (this._tsa.payload.digest.value !== expectedDigest)
      throw new MajikSignatureError(
        this._tsa.payload.digest.scope === "signature"
          ? "TSA digest does not match the canonical signature record"
          : "TSA digest does not match signature contentHash",
      );

    if (
      this._tsa.payload.tsa.signerFingerprint !== this._tsa.signature.signerId
    ) {
      throw new MajikSignatureVerificationError(
        "TSA identity fingerprint does not match the embedded TSA signer",
      );
    }

    const canonicalBytes = buildTSACanonicalBytes(this._tsa.payload);
    const tsaSig = MajikSignature.fromJSON(this._tsa.signature);
    const embeddedPublicKeys = tsaSig.extractPublicKeys();
    const verificationKeys = trustedTsaPublicKeys ?? embeddedPublicKeys;

    if (trustedTsaPublicKeys !== undefined) {
      MajikSignatureValidator.validateSignerPublicKeys(trustedTsaPublicKeys);
      if (
        this._tsa.payload.tsa.signerFingerprint !== trustedTsaPublicKeys.signerId ||
        this._tsa.signature.signerId !== trustedTsaPublicKeys.signerId
      ) {
        throw new MajikSignatureVerificationError(
          "TSA identity does not match the trusted TSA public-key fingerprint",
        );
      }
    }

    return MajikSignature.verify(
      canonicalBytes,
      tsaSig,
      verificationKeys,
    );
  }

  get hasTSA(): boolean {
    return this._tsa !== undefined;
  }

  /**
   * Sign a TSA payload and return a complete MajikTimestamp.
   * Intended for server-side use — the TSA server calls this with its MajikKey.
   *
   * @example
   *   const timestamp = await MajikSignature.signTSA(
   *     { digest: { algorithm: "SHA-256", value: contentHash } },
   *     tsaKey,
   *     { id: "tsa.majikah.solutions", signerFingerprint: tsaKey.fingerprint }
   *   );
   */
  static async signTSA(
    request: MajikTSARequest,
    key: MajikKey,
    tsa: { id: string; signerFingerprint: string },
    options?: { timestamp?: string },
  ): Promise<MajikTimestamp> {
    const payload: MajikTSAPayload = {
      digest: request.digest,
      nonce: bytesToBase64(crypto.getRandomValues(new Uint8Array(32))),
      timestamp: options?.timestamp ?? new Date().toISOString(),
      tsa,
    };

    MajikSignatureValidator.validateMajikTSAPayload(payload);
    const canonicalBytes = buildTSACanonicalBytes(payload);
    const signature = await MajikSignature.sign(canonicalBytes, key);

    return {
      version: MAJIK_TIMESTAMP_VERSION,
      id: crypto.randomUUID(),
      payload,
      signature: signature.toJSON(),
    };
  }

  // ── CHAIN ANCHOR METHODS ──────────────────────────────────────────────────

  // majik-signature — core/anchor (or wherever the anchor-related statics live)
  static buildChainAnchorMemo(sealHash: string): MajikChainAnchorMemo {
    MajikSignatureValidator.validateSealHash(sealHash);

    return MAJIK_NOTARY_MEMO_DOMAIN + sealHash;
  }

  /**
   * Check whether a file is eligible for chain anchoring (requires seal).
   */
  static async canAnchor(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<{ permitted: boolean; reason?: string }> {
    return MajikSignatureEmbed.canAnchor(file, options);
  }

  /**
   * Embed an already-confirmed MajikChainAnchor into the file's envelope.
   * Does not talk to any chain — the caller (majik-notary) is responsible
   * for submitting and confirming the transaction first.
   *
   * @example
   *   const blob = await MajikSignature.registerChainAnchor(sealedBlob, anchor);
   */
  static async registerChainAnchor(
    file: FileLike,
    anchor: MajikChainAnchor,
    options?: { mimeType?: string },
  ): Promise<Blob> {
    const { blob } = await MajikSignatureEmbed.registerChainAnchor(
      file,
      anchor,
      options,
    );
    return blob;
  }

  /**
   * Get all chain anchors embedded in a file's envelope.
   * Returns an empty array if none, or if the file has no envelope.
   */
  static async getChainAnchors(
    file: FileLike,
    options?: { mimeType?: string },
  ): Promise<MajikChainAnchor[]> {
    return MajikSignatureEmbed.getChainAnchors(file, options);
  }

  // ── COMPACT FORMAT ─────────────────────────────────────────────────────────

  /**
   * Strip the embedded public keys, producing the wire/storage-optimized form.
   * The verifier must supply the signer's public keys out-of-band via
   * fromCompact() / verifyCompact() — never trust keys recovered from the
   * compact payload itself, because there are none.
   *
   * allowlistHash and validUntil, when present, carry over unchanged — both
   * are already part of what was signed, so compacting doesn't affect their
   * enforcement.
   */
  toCompact(): MajikSignatureCompactJSON {
    return {
      v: this._version,
      signerId: this._signerId,
      contentHash: this._contentHash,
      contentType: this._contentType,
      timestamp: this._timestamp,
      edSignature: this._edSignature,
      mlDsaSignature: this._mlDsaSignature,
      allowlistHash: this._allowlistHash,
      validUntil: this._validUntil,
      versionChainHash: this._versionChainHash,
      ...(this._sessionContextHash !== undefined
        ? { sessionContextHash: this._sessionContextHash }
        : {}),
    };
  }

  /**
   * Rehydrate a full MajikSignature from a compact payload + externally
   * resolved public keys. Throws if signerId doesn't match the supplied keys —
   * this is a cheap sanity check, not a substitute for verify().
   *
   * allowlistHash and validUntil are carried through unchanged from the
   * compact payload; verify() will still enforce them via the recomputed
   * canonical payload, so an out-of-band edit to either field here would
   * simply fail verification rather than being silently trusted.
   */
  static fromCompact(
    compact: MajikSignatureCompactJSON,
    publicKeys: Pick<MajikSignerPublicKeys, "edPublicKey" | "mlDsaPublicKey">,
  ): MajikSignature {
    if (!publicKeys?.edPublicKey || !publicKeys?.mlDsaPublicKey) {
      throw new MajikSignatureKeyError(
        "fromCompact() requires the signer's public keys — resolve them by compact.signerId from your key registry / MUID service.",
      );
    }

    const full: MajikSignatureJSON = {
      version: compact.v,
      signerId: compact.signerId,
      signerEdPublicKey: bytesToBase64(publicKeys.edPublicKey),
      signerMlDsaPublicKey: bytesToBase64(publicKeys.mlDsaPublicKey),
      contentHash: compact.contentHash,
      contentType: compact.contentType,
      timestamp: compact.timestamp,
      edSignature: compact.edSignature,
      mlDsaSignature: compact.mlDsaSignature,
      allowlistHash: compact.allowlistHash,
      validUntil: compact.validUntil,
      versionChainHash: compact.versionChainHash,
      ...(compact.sessionContextHash !== undefined
        ? { sessionContextHash: compact.sessionContextHash }
        : {}),
    };

    return MajikSignature.fromJSON(full);
  }

  /**
   * Verify content against a compact envelope. signerId is checked against
   * publicKeys.signerId before any crypto runs, so a mismatched lookup fails
   * fast with a clear reason instead of a cryptic signature failure.
   *
   * Delegates to verify() after rehydration, so allowlistHash and validUntil
   * (when present in the compact payload) are enforced identically to the
   * full-envelope path — including the "expired" reason/flag on a signature
   * past its validUntil.
   *
   * @example
   *   const keys = await resolvePublicKeysForMuid(slink.muid); // your registry
   *   const result = MajikSignature.verifyCompact(canonical, slink.signatureJSON, keys);
   */
  static verifyCompact(
    content: Uint8Array | string,
    compact: MajikSignatureCompactJSON,
    publicKeys: MajikSignerPublicKeys,
  ): VerificationResult {
    if (compact.signerId !== publicKeys.signerId) {
      return {
        valid: false,
        signerId: compact.signerId,
        contentHash: compact.contentHash,
        timestamp: compact.timestamp,
        contentType: compact.contentType,
        reason: `signerId mismatch: envelope is "${compact.signerId}", provided publicKeys are for "${publicKeys.signerId}"`,
      };
    }
    const full = MajikSignature.fromCompact(compact, publicKeys);
    return MajikSignature.verify(content, full, publicKeys);
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private static _isMajikKey(
    v: MajikKey | MajikSignerPublicKeys,
  ): v is MajikKey {
    return typeof (v as MajikKey).fingerprint === "string";
  }
}

// Freeze static methods
Object.freeze(MajikSignature);

// Freeze instance methods
Object.freeze(MajikSignature.prototype);

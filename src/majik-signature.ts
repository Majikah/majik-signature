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
} from "./core/constants";
import {
  MajikSignatureError,
  MajikSignatureKeyError,
  MajikSignatureVerificationError,
  MajikSignatureSerializationError,
} from "./core/errors";
import { MajikSignatureValidator } from "./core/validator";
import { buildSigningPayload, buildTSACanonicalBytes } from "./core/payload";
import { hashContent, bytesToBase64, base64ToBytes } from "./core/hash";
import type {
  BatchFileInput,
  BatchSignOptions,
  BatchVerifyInput,
  BatchVerifyOptions,
  ED25519Signature,
  EnvelopeInfo,
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
  SignatoriesFilter,
  SignatoriesResult,
  SignatoryInfo,
  SignOptions,
  VerificationResult,
} from "./core/types";
import { MajikSignatureEmbed } from "./core/embed/majik-embed";

// ── Stamp (image signing) imports ─────────────────────────────────────────────
import { MajikImageSignature } from "./core/stamp/image-signature";
import type {
  ImageVerificationResult,
  ImageSignOptions,
  ImageSignatureStub,
} from "./core/stamp";
import { MajikChainAnchor, MajikChainAnchorMemo } from "./anchor/types";
import { MajikSignatureEnvelope } from "./core/envelope";
import { MajikSignatureMap } from "./core/mjksmap";
import {
  SignatureOrderResult,
  normalizeExpectedOrder as normalizeExpectedOrderUtil,
} from "./core/order";

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
 *   - ML-DSA-87 signature  (4595 bytes, post-quantum)
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
    MajikSignatureValidator.assertDefined(key, "key");
    MajikSignatureValidator.validateContentType(options?.contentType);
    MajikSignatureValidator.validateValidUntil(options?.validUntil);

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
    MajikSignatureValidator.validateEdSecretKey(edSecretKeyClone);
    MajikSignatureValidator.validateMlDsaSecretKey(mlDsaSecretKeyClone);
    try {
      const edPublicKey = key.edPublicKey!;
      const mlDsaPublicKey = key.mlDsaPublicKey!;

      const contentHashBytes = hashContent(content);
      const contentHash = bytesToBase64(contentHashBytes);
      const timestamp = options?.timestamp ?? new Date().toISOString();
      const signerId = key.fingerprint;
      const contentType = options?.contentType;
      const allowlistHash = options?.allowlistHash;
      const validUntil = options?.validUntil; // NEW

      const versionChainHash = options?.versionChainHash;
      const payload = buildSigningPayload({
        signerId,
        timestamp,
        contentHash,
        contentType,
        allowlistHash,
        validUntil,
        versionChainHash,
      });

      if (debug) console.log("Signing Payload:", payload);

      const edSigBytes = ed25519.sign(edSecretKeyClone, payload);

      if (debug) {
        console.log(
          "mlDsaSecretKey type:",
          mlDsaSecretKeyClone?.constructor?.name,
        );
        console.log("mlDsaSecretKey length:", mlDsaSecretKeyClone?.length);
        console.log(
          "is Uint8Array:",
          mlDsaSecretKeyClone instanceof Uint8Array,
        );
      }

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
      };

      return new MajikSignature(envelope);
    } catch (err) {
      if (debug) console.error("Raw Signing Error:", err);
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureError("Failed to sign content", err);
    } finally {
      // 3. Securely wipe the clones, leaving the originals in MajikKey safe
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

      const recomputedHash = bytesToBase64(hashContent(content));
      if (recomputedHash !== env.contentHash) return invalid();

      // allowlistHash omitted when undefined — preserves backward compat
      const payload = buildSigningPayload({
        signerId: env.signerId,
        timestamp: env.timestamp,
        contentHash: env.contentHash,
        contentType: env.contentType,
        allowlistHash: env.allowlistHash,
        validUntil: env.validUntil,
        versionChainHash: env.versionChainHash,
      });

      let edOk: boolean;
      try {
        edOk = ed25519.verify(
          publicKeys.edPublicKey,
          payload,
          base64ToBytes(env.edSignature),
        );
      } catch (e) {
        console.error(e);
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
      } catch (e) {
        console.error(e);
        return invalid("Failed to verify ML-DSA-87 signature");
      }
      if (!mlDsaOk) return invalid("Invalid ML-DSA-87 signature");

      // NEW — expiry check, only after crypto has checked out
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

      const payload = buildSigningPayload({
        signerId: env.signerId,
        timestamp: env.timestamp,
        contentHash: env.contentHash,
        contentType: env.contentType,
        allowlistHash: env.allowlistHash,
        validUntil: env.validUntil,
        versionChainHash: env.versionChainHash,
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
      contentType: this._contentType,
      timestamp: this._timestamp,
      edSignature: this._edSignature,
      mlDsaSignature: this._mlDsaSignature,
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
    file: Blob,
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
    file: Blob,
    key: MajikKey,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      expectedSigners?: ExpectedSigner[];
      validUntil?: string;
      existingEnvelope?:
        | MajikSignatureEnvelope
        | MajikSignatureEnvelopeJSON
        | Uint8Array
        | Blob;
      tsa?: MajikTimestamp;
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
  static async verifyFile(
    file: Blob,
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
   * Verify a file against a detached signature envelope.
   * Skips extraction and verifies the stripped file bytes directly against the provided envelope.
   * Returns one VerificationResult per signer.
   * Pass options.expectedSignerId to verify only a specific signer.
   * Pass options.now to check expiry as of a specific time instead of the
   * current time.
   */
  static async verifyFileDetached(
    file: Blob,
    envelope:
      | MajikSignatureEnvelope
      | MajikSignatureEnvelopeJSON
      | Uint8Array
      | Blob,
    keyOrPublicKeys: MajikKey | MajikSignerPublicKeys,
    options?: { expectedSignerId?: string; mimeType?: string; now?: Date },
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
    file: Blob,
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
    file: Blob,
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
    file: Blob,
    options?: { mimeType?: string; now?: Date },
  ): Promise<FileChainVerification> {
    return MajikSignatureEmbed.verifyFileChain(file, MajikSignature, options);
  }

  static async verifyFileRevisions(
    finalFile: Blob,
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
  async embedIn(file: Blob, options?: { mimeType?: string }): Promise<Blob> {
    const { blob } = await MajikSignatureEmbed.embed(file, this, options);
    return blob;
  }

  /**
   * Extract all embedded MajikSignature instances from a file.
   * Returns an array — old single-sig files return a single-item array.
   * Returns an empty array if no signatures are found.
   */
  static async extractFrom(
    file: Blob,
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
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<Blob> {
    return MajikSignatureEmbed.strip(file, options);
  }

  /**
   * Check whether a file contains any embedded signatures.
   * Does not verify — structural presence check only.
   */
  static async isSigned(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<boolean> {
    return MajikSignatureEmbed.hasSignature(file, options);
  }

  /**
   * Get the allowlist from a file without verifying any signatures.
   * Returns null for open-signing files or unsigned files.
   */
  static async getAllowlist(
    file: Blob,
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
    file: Blob,
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
    file: Blob,
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
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<SealInfo | null> {
    return MajikSignatureEmbed.getSealInfo(file, options);
  }

  /**
   * Returns true if the file has a sealed envelope (structural check, no crypto).
   */
  static async isSealed(
    file: Blob,
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
    file: Blob,
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
    file: Blob,
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
    file: Blob,
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
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    return MajikSignatureEmbed.getSignatories(file, options, "signed");
  }

  /**
   * Returns only signatories who are expected but have not yet signed.
   * Alias for getSignatories(file, options, "pending").
   */
  static async getPendingSignatories(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<SignatoriesResult | null> {
    return MajikSignatureEmbed.getSignatories(file, options, "pending");
  }

  /**
   * Returns all signatories with full status information.
   * Alias for getSignatories(file, options, "all").
   */
  static async getAllSignatories(
    file: Blob,
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
    file: Blob,
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
    file: Blob,
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

  buildTSARequestPayload(): MajikTSARequest {
    return {
      digest: {
        algorithm: "SHA-256",
        value: this._contentHash,
      },
    };
  }

  addTSA(tsa: MajikTimestamp): void {
    if (this._tsa !== undefined)
      throw new MajikSignatureError(
        "TSA is already set and cannot be replaced",
      );

    MajikSignatureValidator.validateMajikTimestamp(tsa);

    if (tsa.payload.digest.value !== this._contentHash)
      throw new MajikSignatureError(
        "TSA digest does not match signature contentHash",
      );

    const canonicalBytes = buildTSACanonicalBytes(tsa.payload);
    const tsaSig = MajikSignature.fromJSON(tsa.signature);
    const publicKeys = tsaSig.extractPublicKeys();
    const result = MajikSignature.verify(canonicalBytes, tsaSig, publicKeys);

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
  verifyTSA(): VerificationResult {
    if (!this._tsa)
      throw new MajikSignatureError("No TSA present on this signature");

    if (this._tsa.payload.digest.value !== this._contentHash)
      throw new MajikSignatureError(
        "TSA digest does not match signature contentHash",
      );

    const canonicalBytes = buildTSACanonicalBytes(this._tsa.payload);
    const tsaSig = MajikSignature.fromJSON(this._tsa.signature);
    const publicKeys = tsaSig.extractPublicKeys();
    return MajikSignature.verify(canonicalBytes, tsaSig, publicKeys);
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
    file: Blob,
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
    file: Blob,
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
    file: Blob,
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

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
import { MajikSignatureEmbed } from "./core/embed/majik-embed";

// ── Stamp (image signing) imports ─────────────────────────────────────────────
// One-way import: majik-signature → core/stamp/image-signature.
// MajikImageSignature receives MajikSignature back as an adapter at call time
// (typed as MajikSignatureStaticAdapter) — no circular dependency.
import { MajikImageSignature } from "./core/stamp/image-signature";
import type {
  ImageVerificationResult,
  ImageSignOptions,
  ImageSignatureStub,
} from "./core/stamp";

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
    debug: boolean = false,
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

      if (debug) {
        console.log("Signing Payload:", payload);
      }

      // ── Sign with Ed25519 ──
      const edSigBytes = ed25519.sign(edSecretKey, payload);

      if (debug) {
        console.log("mlDsaSecretKey type:", mlDsaSecretKey?.constructor?.name);
        console.log("mlDsaSecretKey length:", mlDsaSecretKey?.length);
        console.log("mlDsaSecretKey byteLength:", mlDsaSecretKey?.byteLength);
        console.log("mlDsaSecretKey byteOffset:", mlDsaSecretKey?.byteOffset);
        console.log(
          "mlDsaSecretKey buffer.byteLength:",
          mlDsaSecretKey?.buffer?.byteLength,
        );
        console.log("is Uint8Array:", mlDsaSecretKey instanceof Uint8Array);
      }

      // ── Sign with ML-DSA-87 ──
      const mlDsaSigBytes = ml_dsa87.sign(payload, mlDsaSecretKey);

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
      if (debug) {
        console.error("Raw Signing Error:", err);
      }
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
          base64ToBytes(env.mlDsaSignature), // sig
          payload, // msg
          publicKeys.mlDsaPublicKey, // publicKey
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

  // ── FILE-AWARE METHODS ────────────────────────────────────────────────────
  //
  // These delegate to MajikSignatureEmbed, passing `MajikSignature` itself
  // as the `MajikSig` adapter argument. This breaks the circular import:
  //
  //   majik-signature  →  majik-embed            (one-way, static import ✓)
  //   majik-embed      →  MajikSignatureAdapter   (interface only, no import)
  //
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Sign a file and embed the signature into it in one call.
   *
   * Strips any existing signature before signing (idempotent re-signing).
   * The returned blob is the same format as the input — PDF stays PDF, etc.
   *
   * @example
   *   const { blob, signature } = await MajikSignature.signFile(file, key);
   */
  static async signFile(
    file: Blob,
    key: MajikKey,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
    },
  ): Promise<{
    blob: Blob;
    signature: MajikSignature;
    handler: string;
    mimeType: string;
  }> {
    return MajikSignatureEmbed.signAndEmbed<MajikSignature>(
      file,
      key,
      MajikSignature, // ← passed as adapter, not imported by embed
      options,
    );
  }

  /**
   * Verify a file's embedded signature against a MajikKey or raw public keys.
   *
   * Accepts either a MajikKey instance (locked or unlocked — only public
   * fields are used) or a raw MajikSignerPublicKeys object.
   *
   * @example
   *   const result = await MajikSignature.verifyFile(signedBlob, key);
   *   if (result.valid) console.log("Signed by", result.signerId);
   */
  static async verifyFile(
    file: Blob,
    keyOrPublicKeys: MajikKey | MajikSignerPublicKeys,
    options?: {
      expectedSignerId?: string;
      mimeType?: string;
    },
    debug: boolean = false,
  ): Promise<VerificationResult & { handler?: string }> {
    if (MajikSignature._isMajikKey(keyOrPublicKeys)) {
      if (debug) console.log("Verifying with MajikKey");
      return MajikSignatureEmbed.verifyWithKey(
        file,
        keyOrPublicKeys,
        MajikSignature, // ← adapter
        options,
        debug,
      );
    }
    if (debug) console.log("Verifying with public keys");
    return MajikSignatureEmbed.verify(
      file,
      keyOrPublicKeys,
      MajikSignature, // ← adapter
      options,
      debug,
    );
  }

  /**
   * Embed this MajikSignature instance into a file.
   *
   * The signature must cover the original file bytes BEFORE embedding.
   * Use signFile() if you want signing + embedding together.
   *
   * @example
   *   const sig = await MajikSignature.sign(originalBytes, key);
   *   const signedBlob = await sig.embedIn(file);
   */
  async embedIn(file: Blob, options?: { mimeType?: string }): Promise<Blob> {
    const { blob } = await MajikSignatureEmbed.embed(file, this, options);
    return blob;
  }

  /**
   * Extract the embedded MajikSignature from a file.
   * Returns a fully typed instance, not raw JSON. Returns null if not found.
   *
   * @example
   *   const sig = await MajikSignature.extractFrom(signedBlob);
   *   if (sig) console.log(sig.signerId, sig.timestamp);
   */
  static async extractFrom(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<MajikSignature | null> {
    const result = await MajikSignatureEmbed.extract(file, options);
    if (!result) return null;
    return MajikSignature.fromJSON(result.signatureJson);
  }

  /**
   * Return the file with any embedded signature removed.
   * The returned bytes are exactly what was originally signed.
   *
   * @example
   *   const cleanBlob = await MajikSignature.stripFrom(signedBlob);
   */
  static async stripFrom(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<Blob> {
    return MajikSignatureEmbed.strip(file, options);
  }

  /**
   * Check whether a file contains an embedded MajikSignature.
   * Does not verify — purely a structural presence check.
   *
   * @example
   *   if (await MajikSignature.isSigned(file)) { ... }
   */
  static async isSigned(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<boolean> {
    return MajikSignatureEmbed.hasSignature(file, options);
  }

  // ── STAMP (compression-resistant image signing) ───────────────────────────
  //
  // These methods delegate to MajikImageSignature, passing `MajikSignature`
  // itself as the adapter — the same pattern used by signFile → MajikSignatureEmbed.
  //
  // The adapter is typed as MajikSignatureStaticAdapter (an interface defined
  // in core/stamp/image-signature.ts) so no circular import is introduced:
  //
  //   majik-signature → core/stamp/image-signature → (adapter interface only)
  //
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Sign an image with dual-layer embedding.
   *
   * @experimental
   * ⚠️ This API is not stable yet and may change without notice.
   * 
   * Every signed image carries two independent proofs:
   *
   *   Layer 1 — Pixel rows appended at the bottom (+~6px height)
   *     Full MajikSignature: Ed25519 + ML-DSA-87 (post-quantum)
   *     Survives: direct sharing, email attachments, Slack, internal tools
   *     Stripped by: platforms that crop/resize (Gmail, LinkedIn, Facebook)
   *
   *   Layer 2 — DCT coefficient steganography (invisible, no size change)
   *     Ed25519-only stub + Reed-Solomon ECC (205 bytes)
   *     Survives: Q70+ JPEG recompression, WebP conversion, platform uploads
   *     Does not survive: screenshots, heavy crop, below-Q70 recompression
   *
   * Output is PNG by default. When uploaded to a platform, Layer 1 may be
   * stripped but Layer 2 survives — verifyStamp() handles both automatically.
   *
   * Minimum image size: 600×600px (smaller images are padded with white).
   *
   * @param image    Any image format the browser supports (JPEG, PNG, WebP…)
   * @param key      Unlocked MajikKey with signing keys
   * @param options  Output MIME type, JPEG quality, timestamp override
   * @returns        blob (signed image), stub (DCT layer metadata),
   *                 fullEnvelope (complete MajikSignatureJSON for Layer 1)
   *
   * @example
   *   const { blob, stub } = await MajikSignature.stampImage(imageBlob, key);
   *   // blob  → upload or attach; visually identical to the original
   *   // stub  → signerId, timestamp, pHash for display
   */
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

  /**
   * Verify a stamped image's embedded MajikImageSignature.
   *
   * @experimental
   * ⚠️ This API is not stable yet and may change without notice.
   * 
   * Tries both layers automatically:
   *   - Both present → both must pass (maximum integrity, post-quantum proof)
   *   - Pixel row only → pixel row must pass (full Ed25519 + ML-DSA-87)
   *   - DCT only → DCT must pass (Ed25519 fallback, typical after platform upload)
   *   - Neither → invalid
   *
   * The `layer` field in the result communicates the trust level so callers
   * can surface it in UI: 'both' > 'pixel-row' > 'dct-only'.
   *
   * @param image    The image to verify — may be platform-compressed
   * @param options  hammingThreshold override (default 8 — strict)
   *
   * @example
   *   const result = await MajikSignature.verifyStamp(imageBlob);
   *   if (result.valid) {
   *     console.log(`✓ Signed by ${result.signerId}`);
   *     console.log(`  Verified via: ${result.layer}`);
   *     // result.layer: 'both' | 'pixel-row' | 'dct-only'
   *   }
   */
  static async verifyStamp(
    image: Blob,
    options?: { hammingThreshold?: number },
  ): Promise<ImageVerificationResult> {
    return MajikImageSignature.verify(image, MajikSignature, options);
  }

  /**
   * Inspect which stamp layers are present without verifying.
   *
   * @experimental
   * ⚠️ This API is not stable yet and may change without notice.
   * 
   * Fast — useful for rendering a "Signed by X on Y" badge in a UI before
   * committing to a full cryptographic verify call.
   *
   * Does NOT confirm the signatures are valid — call verifyStamp() for that.
   *
   * @example
   *   const info = await MajikSignature.inspectStamp(imageBlob);
   *   if (info.hasPixelRow) console.log('Full post-quantum proof present');
   *   if (info.hasDct)      console.log('Compression-resistant stub present');
   *   info.dctMeta?.signerId        // signer ID (unverified — display only)
   *   info.pixelRowMeta?.timestamp  // timestamp (unverified — display only)
   */
  static async inspectStamp(image: Blob): Promise<{
    hasPixelRow: boolean;
    hasDct: boolean;
    pixelRowMeta?: { signerId: string; timestamp: string };
    dctMeta?: { signerId: string; timestamp: string; pHash: string };
  }> {
    return MajikImageSignature.inspect(image);
  }

  /**
   * Returns true if the image contains any MajikImageSignature layer.
   *
   * @experimental
   * ⚠️ This API is not stable yet and may change without notice.
   * 
   * Does not verify — structural presence check only.
   * Use verifyStamp() to confirm the signature is cryptographically valid.
   *
   * @example
   *   if (await MajikSignature.isStamped(imageBlob)) { ... }
   * 
   */
  static async isStamped(image: Blob): Promise<boolean> {
    return MajikImageSignature.isSigned(image);
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  /**
   * Duck-type check to distinguish MajikKey from MajikSignerPublicKeys.
   * MajikKey always has a `fingerprint` string property.
   */
  private static _isMajikKey(
    v: MajikKey | MajikSignerPublicKeys,
  ): v is MajikKey {
    return typeof (v as MajikKey).fingerprint === "string";
  }
}

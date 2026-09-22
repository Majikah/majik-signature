/**
 * Public TypeScript types for Majik Signature.
 *
 * These types intentionally describe both the serialized wire format and the
 * inputs/outputs used by the high-level `MajikSignature` APIs. The JSDoc is
 * part of the developer-facing API: prefer these descriptions over having to
 * inspect the implementation when working with IntelliSense or generated docs.
 */

import type { ISODateString, MajikKeyFingerprint } from "@majikah/majik-key";
import type { MajikChainAnchor } from "../anchor/types";
import type { ContentType } from "./constants";
import type { MajikSignatureEnvelope } from "./envelope";

/** Standard content-type constants exposed by Majik Signature. */
export type { ContentType };

/**
 * JSON-compatible wire representation of a {@link MajikSignatureEnvelope}.
 *
 * @remarks
 * This alias points at {@link MultiSigEnvelope}, the actual serialized
 * top-level envelope shape used by embedded files and detached signatures.
 * Use the `MajikSignatureEnvelope` class when you need behavior, validation,
 * immutable builders, or serialization helpers.
 */
export type MajikSignatureEnvelopeJSON = MultiSigEnvelope;

/**
 * Base64-encoded Ed25519 signature produced for a Majik Signature payload.
 *
 * @remarks
 * The decoded signature is 64 bytes. Keeping this as a branded semantic alias
 * makes generated documentation and API signatures easier to read without
 * changing the underlying JSON representation (`string`).
 */
export type ED25519Signature = string;

/**
 * Base64-encoded ML-DSA-87 signature produced for a Majik Signature payload.
 *
 * @remarks
 * The decoded signature is 4,595 bytes. This remains a `string` on the wire so
 * envelopes can be represented directly as JSON.
 */
export type MLDSA87Signature = string;

/**
 * Serializable signature record for one signer.
 *
 * @remarks
 * This is the per-signer object nested inside a {@link MultiSigEnvelope}.
 * It is self-contained for verification because it includes the signer's
 * Ed25519 and ML-DSA-87 public keys; no private key material is ever stored.
 *
 * `contentHash` commits the signature to the original content bytes. The
 * signatures cover a canonical, domain-separated payload containing the
 * signer identity, timestamp, content hash, and any applicable allowlist,
 * expiry, or revision-chain commitments.
 *
 * Optional properties are omitted when they do not apply; they are not
 * serialized as `null`.
 */
export interface MajikSignatureJSON {
  /**
   * Serialized signature-envelope version.
   *
   * @remarks
   * Currently fixed to `1`. The runtime validator rejects unsupported
   * envelope versions rather than silently interpreting them.
   */
  version: 1;

  /**
   * MajikKey fingerprint that identifies the signer.
   *
   * @remarks
   * This is the base64-encoded SHA-256 fingerprint of the signer's X25519
   * public key. Treat the fingerprint as the identity reference used by the
   * rest of the Majikah ecosystem, rather than deriving identity from the
   * embedded signing keys alone.
   */
  signerId: MajikKeyFingerprint;

  /**
   * Base64-encoded Ed25519 public key used to verify `edSignature`.
   *
   * @remarks
   * The decoded key is 32 bytes. The public key is included so a serialized
   * signature can be verified offline without a separate key registry.
   */
  signerEdPublicKey: string;

  /**
   * Base64-encoded ML-DSA-87 public key used to verify `mlDsaSignature`.
   *
   * @remarks
   * The decoded key is 2,592 bytes. Both the Ed25519 and ML-DSA-87 public keys
   * are required for hybrid verification.
   */
  signerMlDsaPublicKey: string;

  /**
   * Base64-encoded SHA-256 digest of the original, unsigned content.
   *
   * @remarks
   * The digest is 32 bytes when decoded (typically 44 base64 characters).
   * File embedding is excluded from this hash: verification strips the
   * embedded envelope before recomputing the digest.
   */
  contentHash: string;

  /**
   * Advisory media/content type associated with the signed content.
   *
   * @remarks
   * Examples include `application/pdf` and `audio/wav`. This value is included
   * in the signed canonical payload, but it is descriptive rather than an
   * authorization or security control; do not use it to decide whether bytes
   * are trustworthy.
   */
  contentType?: string;

  /**
   * ISO 8601 timestamp recorded when this signature was created.
   *
   * @remarks
   * The value is part of the canonical payload and therefore cannot be changed
   * after signing without invalidating the signature.
   */
  timestamp: ISODateString;

  /**
   * Base64-encoded Ed25519 signature over the canonical Majik Signature payload.
   *
   * @remarks
   * The decoded signature is 64 bytes. Verification succeeds only when this
   * signature and the corresponding ML-DSA-87 signature both verify.
   */
  edSignature: ED25519Signature;

  /**
   * Base64-encoded ML-DSA-87 signature over the same canonical payload.
   *
   * @remarks
   * The decoded signature is 4,595 bytes. This is the post-quantum half of
   * Majik Signature's hybrid signing model.
   */
  mlDsaSignature: MLDSA87Signature;

  /**
   * Base64-encoded SHA-256 digest of the canonical allowlist JSON.
   *
   * @remarks
   * Present only on the signature created by the signer who established an
   * allowlist. The digest is covered by that signer's canonical payload, so
   * changing the allowlist after signing causes that signature to fail
   * verification. Omitted on other signers and on legacy signatures.
   */
  allowlistHash?: string;

  /**
   * Optional ISO 8601 expiry for this signature.
   *
   * @remarks
   * When present, verification reports the signature as invalid after the
   * current time passes this value and marks the result with `expired: true`.
   * When omitted, the signature has no library-enforced expiry. The expiry is
   * part of the signed payload, so it cannot be extended or removed afterward
   * without invalidating both cryptographic signatures.
   */
  validUntil?: ISODateString;

  /**
   * Base64-encoded SHA-256 commitment to the revision chain at signing time.
   *
   * @remarks
   * For file-versioned signing, this commits to the complete `fileVersions`
   * state including the signer's own new entry. It lets chain verification
   * detect rewritten revision metadata without requiring earlier file bytes.
   * Omitted for signatures that are not part of the revision-chain workflow.
   */
  versionChainHash?: string;

  /**
   * Optional Trusted Timestamp Authority attestation for this signature.
   *
   * @remarks
   * When present, the TSA record binds the signed content digest to a
   * server-generated nonce and server-authoritative timestamp. The embedded
   * TSA signature is itself a full Majik Signature and can be re-verified with
   * `signature.verifyTSA()`.
   */
  tsa?: MajikTimestamp;
}

/**
 * Canonical payload signed by a Trusted Timestamp Authority (TSA).
 *
 * @remarks
 * This payload binds a SHA-256 content digest to a server-generated nonce and
 * a server-authoritative timestamp. It is signed as its own Majik Signature.
 * Consumers should verify both the TSA signature and whether the TSA identity
 * is trusted for their application.
 */
export interface MajikTSAPayload {
  /** Digest of the content/signature being timestamped. */
  digest: {
    /** TSA digest algorithm. Majik TSA currently uses SHA-256. */
    algorithm: "SHA-256";
    /** Base64-encoded digest value. */
    value: string;
  };

  /**
   * Base64-encoded random bytes generated by the TSA server.
   *
   * @remarks
   * The nonce is server-generated and is included in the signed TSA payload
   * to make each issuance distinct even when digest and timing inputs repeat.
   */
  nonce: string;

  /** Server-authoritative ISO 8601 timestamp included in the TSA payload. */
  timestamp: string;

  /** Identity metadata for the TSA key that signed this payload. */
  tsa: {
    /** Stable identifier for the TSA service/entity. */
    id: string;
    /** MajikKey fingerprint of the TSA signing key. */
    signerFingerprint: string;
  };
}

/**
 * Compact, wire-optimized signature representation without embedded public keys.
 *
 * @remarks
 * Use this shape only when the verifier resolves the signer's public keys from
 * a trusted external source. It is useful for APIs or other workflows that
 * already perform a network lookup (for example, registry-backed verification).
 * It is not a self-contained replacement for {@link MajikSignatureJSON}; an
 * offline verifier cannot recover the missing public keys from this object.
 */
export interface MajikSignatureCompactJSON {
  /** Compact signature version; currently fixed to `1`. */
  v: 1;
  /** Signer identity/fingerprint resolved by the verifier's trusted key source. */
  signerId: MajikKeyFingerprint;
  /** Base64-encoded SHA-256 digest of the original content. */
  contentHash: string;
  /** Advisory content type included in the canonical payload when present. */
  contentType?: string;
  /** ISO 8601 signing timestamp. */
  timestamp: ISODateString;
  /** Ed25519 signature over the canonical payload. */
  edSignature: ED25519Signature;
  /** ML-DSA-87 signature over the canonical payload. */
  mlDsaSignature: MLDSA87Signature;
  /** Allowlist commitment, present when this signer established an allowlist. */
  allowlistHash?: string;
  /** Optional signed expiry. */
  validUntil?: ISODateString;
  /** Optional signed revision-chain commitment. */
  versionChainHash?: string;
}

/**
 * Digest descriptor used by the Trusted Timestamp Authority API.
 */
export interface TSADigest {
  /** Hash function used for the digest. */
  algorithm: "SHA-256";
  /** Base64-encoded digest value. */
  value: string;
}

/**
 * Client-to-TSA request payload built from an existing signature.
 *
 * @example
 * ```ts
 * const request = signature.buildTSARequestPayload();
 * // send `request` to your TSA service
 * ```
 */
export interface MajikTSARequest {
  /** Digest the TSA must attest to. */
  digest: TSADigest;
}

/**
 * Complete trusted-timestamp record returned by a TSA.
 *
 * @remarks
 * The `payload` is the exact canonical object that was signed by the TSA, and
 * `signature` contains the corresponding full Majik Signature envelope so the
 * attestation can be verified independently after storage or transport.
 */
export interface MajikTimestamp {
  /** TSA payload version; currently fixed to `1`. */
  version: 1;
  /** Unique issuance identifier (UUID). */
  id: string;
  /** Exact TSA payload covered by `signature`. */
  payload: MajikTSAPayload;
  /** Full Majik Signature produced by the TSA signing key. */
  signature: MajikSignatureJSON;
}

/**
 * Public-key identity entry allowed to sign a restricted envelope.
 *
 * @remarks
 * All three identity fields are checked together. Matching `signerId` alone is
 * not sufficient: the signing public keys must match the allowlisted identity
 * entry as well. `MajikSignature.expectedSignerFromKey()` is the recommended
 * way to construct this shape from a `MajikKey`.
 */
export interface ExpectedSigner {
  /** MajikKey fingerprint (base64 SHA-256 fingerprint of the X25519 public key). */
  signerId: MajikKeyFingerprint;
  /** Base64-encoded Ed25519 public key (32 decoded bytes). */
  edPublicKey: string;
  /** Base64-encoded ML-DSA-87 public key (2,592 decoded bytes). */
  mlDsaPublicKey: string;
}

/**
 * Top-level serialized envelope containing one or more signer records.
 *
 * @remarks
 * This is the wire-format structure used for embedded and detached signatures.
 * The runtime class counterpart is {@link MajikSignatureEnvelope}, which adds
 * validation, immutable builders, queries, and serialization helpers.
 *
 * Open-signing envelopes omit `allowlist`. Restricted multi-signature envelopes
 * carry an `allowlist` plus `allowlistSignerId`. A seal permanently prevents
 * additional signatures. `chainAnchors` and `fileVersions` are optional
 * extensions for anchoring and revision-aware workflows.
 *
 * @remarks Backward compatibility
 * Files produced before multi-signature support may contain a bare
 * {@link MajikSignatureJSON} at the root. The parser transparently promotes
 * that legacy shape to a version-1 `MultiSigEnvelope` with one signature.
 */
export interface MultiSigEnvelope {
  /** Top-level envelope version; currently fixed to `1`. */
  version: 1;

  /**
   * Optional signing allowlist.
   *
   * @remarks
   * When present, only listed signers may add signatures. Membership is checked
   * before cryptographic signing. When omitted, the envelope is open-signing.
   * An existing allowlist takes precedence over later `expectedSigners` input.
   */
  allowlist?: ExpectedSigner[];

  /**
   * Fingerprint of the signer who established `allowlist`.
   *
   * @remarks
   * This signer is the envelope issuer and is the only signer permitted to
   * seal a restricted envelope. Their own `allowlistHash` commits the signed
   * payload to the exact allowlist contents.
   */
  allowlistSignerId?: MajikKeyFingerprint;

  /**
   * Per-signer signature records, in the order they were added.
   *
   * @remarks
   * Each entry identifies one signer through `signerId`. For revision-aware
   * workflows, this array represents the signatory history used by the seal and
   * file-version commitments.
   */
  signatures: MajikSignatureJSON[];

  /**
   * SHA3-512 integrity hash of the canonical sealed-envelope payload.
   *
   * @remarks
   * Hex-encoded (128 characters). Present only after sealing. Once present, the
   * envelope rejects further signatures, including signatures from the issuer.
   */
  sealHash?: string;

  /**
   * ISO 8601 timestamp recorded when the envelope was sealed.
   *
   * @remarks
   * This value is included in the seal-hash input, so changing it invalidates
   * the seal.
   */
  sealTimestamp?: ISODateString;

  /**
   * Fingerprint of the signer who applied the seal.
   *
   * @remarks
   * For the current sealing model this must match `allowlistSignerId`, because
   * only the issuer may seal a restricted envelope.
   */
  sealedBy?: string;

  /**
   * Confirmed external blockchain anchors associated with the sealed envelope.
   *
   * @remarks
   * Majik Signature stores and reads these records but does not submit or
   * confirm blockchain transactions itself. Register an anchor only after the
   * external chain integration has confirmed it.
   */
  chainAnchors?: MajikChainAnchor[];

  /**
   * Append-only revision history for visually-mutated multi-sig workflows.
   *
   * @remarks
   * Each entry represents the file state at a signer's revision point. Older
   * files may omit this field because file versioning was introduced later.
   */
  fileVersions?: FileVersion[];
}

/**
 * Public key material required to verify one Majik Signature.
 *
 * @remarks
 * This is intentionally verification-only data: it contains no private or
 * secret key material and may be passed across trust boundaries as needed for
 * verification. `MajikSignature.publicKeysFromMajikKey()` produces this shape
 * from a `MajikKey`, including when that key is locked.
 */
export interface MajikSignerPublicKeys {
  /** MajikKey fingerprint corresponding to the supplied signing public keys. */
  signerId: MajikKeyFingerprint;
  /** Raw Ed25519 public key bytes; exactly 32 bytes. */
  edPublicKey: Uint8Array;
  /** Raw ML-DSA-87 public key bytes; exactly 2,592 bytes. */
  mlDsaPublicKey: Uint8Array;
}

/**
 * Options for raw-content signing and signature-level creation.
 *
 * @remarks
 * Some properties, such as `expectedSigners`, are accepted for API symmetry
 * with file-level signing but are only meaningful when creating an envelope
 * through the file/multi-signature APIs. Bare `MajikSignature.sign()` does not
 * establish a file allowlist.
 */
export interface SignOptions {
  /**
   * Advisory content-type label such as `application/pdf` or `text/plain`.
   *
   * @remarks
   * The value is included in the canonical payload when present, but it is not
   * a security boundary and is not enforced against the actual bytes.
   */
  contentType?: string;

  /**
   * Explicit ISO 8601 signing time.
   *
   * @remarks
   * Omit this for the normal behavior, which uses the current time. Supplying a
   * fixed timestamp is useful for deterministic tests and fixtures.
   */
  timestamp?: ISODateString;

  /**
   * Restrict future file signers to these public-key identities.
   *
   * @remarks
   * Honored only when this call creates the first signature on a file. On later
   * `signFile()` calls, the envelope's existing allowlist is authoritative and
   * this option is ignored. Every entry must contain matching `signerId`,
   * `edPublicKey`, and `mlDsaPublicKey` values.
   */
  expectedSigners?: ExpectedSigner[];

  /**
   * Optional ISO 8601 expiry for the created signature.
   *
   * @remarks
   * Once the current time is past this value, verification reports the
   * signature as expired. Omit the field for a signature with no expiry.
   * The expiry is signed as part of the canonical payload.
   */
  validUntil?: string;
}

/**
 * Result of cryptographic verification for one signer.
 *
 * @remarks
 * A `valid: false` result is an expected verification outcome, not an
 * exception. Use `reason` for user-facing diagnostics and `expired` to
 * distinguish a time-expired signature from other verification failures.
 *
 * `verifyFile()` and related file-level APIs return one result per signer.
 */
export interface VerificationResult {
  /** Whether this signer's complete hybrid signature currently verifies. */
  valid: boolean;

  /** Signer fingerprint associated with the verified envelope entry, when available. */
  signerId?: MajikKeyFingerprint;

  /** Base64-encoded SHA-256 content digest associated with the signature, when available. */
  contentHash?: string;

  /** ISO 8601 signing timestamp from the signature envelope. */
  timestamp: ISODateString;

  /** Advisory content type stored in the signature envelope, when present. */
  contentType?: string;

  /**
   * File-format handler that processed the file.
   *
   * @remarks
   * Present for file-level verification and useful for diagnostics or UI
   * reporting. It is not present for raw-content verification.
   */
  handler?: string;

  /**
   * Human-readable explanation when `valid === false`.
   *
   * @remarks
   * Treat this as diagnostic text rather than a machine-stable error code.
   */
  reason?: string;

  /**
   * True only when expiration is the reason the result is invalid.
   *
   * @remarks
   * A value of `true` indicates the underlying cryptographic checks succeeded
   * but `validUntil` has passed.
   */
  expired?: boolean;
}

/**
 * Result of verifying an envelope's seal hash.
 *
 * @remarks
 * Seal verification checks the envelope's seal integrity and does not replace
 * per-signer cryptographic verification. Call `verifyFile()` when you also need
 * to verify the individual signer records.
 */
export interface SealVerificationResult {
  /** Whether the stored seal hash matches the current envelope contents. */
  valid: boolean;
  /** Fingerprint of the signer recorded as the sealer, when available. */
  sealedBy?: MajikKeyFingerprint;
  /** ISO 8601 time at which the envelope was sealed, when available. */
  sealTimestamp?: string;
  /** Human-readable diagnostic when seal verification fails. */
  reason?: string;
}

/**
 * Seal metadata returned without performing cryptographic verification.
 *
 * @remarks
 * This is suitable for display or inspection when you only need to read seal
 * metadata. Use `verifySeal()` before treating the seal as cryptographically
 * intact.
 */
export interface SealInfo {
  /** SHA3-512 seal hash, hex-encoded (128 characters). */
  sealHash: string;
  /** ISO 8601 timestamp at which the seal was created. */
  sealTimestamp: ISODateString;
  /** Fingerprint of the issuer who applied the seal. */
  sealedBy: MajikKeyFingerprint;
}

/**
 * Expected-vs-actual status for one signatory in a restricted signing workflow.
 *
 * @remarks
 * This shape combines the allowlisted public-key identity with whether that
 * identity has already produced a signature. It is intended for progress and
 * signing-status UIs, not as a substitute for cryptographic verification.
 */
export interface SignatoryInfo {
  /** MajikKey fingerprint used to identify the expected signer. */
  signerId: MajikKeyFingerprint;
  /** Base64-encoded Ed25519 public key from the allowlist. */
  edPublicKey: string;
  /** Base64-encoded ML-DSA-87 public key from the allowlist. */
  mlDsaPublicKey: string;
  /** True when this signer already has a signature in the envelope. */
  hasSigned: boolean;
  /** ISO 8601 timestamp of the signer's actual signature, when `hasSigned` is true. */
  signedAt?: ISODateString;
}

/**
 * Complete signatory-status breakdown for a restricted multi-signature envelope.
 *
 * @remarks
 * All three arrays are always returned by the public `getSignatories()` family
 * of APIs. Use `filter` to populate the UI slice you need without changing the
 * result shape.
 */
export interface SignatoriesResult {
  /** Every expected signer, including those who are still pending. */
  all: SignatoryInfo[];
  /** Expected signers who have already signed. */
  signed: SignatoryInfo[];
  /** Expected signers who have not signed yet. */
  pending: SignatoryInfo[];
}

/**
 * Supported signatory-status filters for `getSignatories()` and its aliases.
 */
export type SignatoriesFilter = "all" | "signed" | "pending";

/**
 * Aggregated envelope state intended for a signing-status UI.
 *
 * @remarks
 * `getEnvelopeInfo()` gathers these values in one file read so callers do not
 * need to manually inspect the raw envelope for common UI states.
 */
export interface EnvelopeInfo {
  /**
   * True when the file uses a restricted multi-signature allowlist.
   *
   * @remarks
   * This is false for unsigned files, open-signing envelopes, and signatures
   * without a multi-signer restriction.
   */
  isMultiSig: boolean;

  /**
   * True when multiple signatures are present or multiple expected signers are allowlisted.
   *
   * @remarks
   * This flag describes the number of signatory participants represented by
   * the envelope, not merely whether two signatures have already been added.
   */
  hasMultipleSignatories: boolean;

  /** Whether the envelope has a seal and therefore rejects further signing. */
  isSealed: boolean;

  /** Seal metadata when `isSealed` is true. */
  sealInfo?: SealInfo;

  /**
   * The issuer who established the allowlist, or the first signer for open-signing files.
   *
   * `null` means no applicable signer/issuer exists.
   */
  issuer: SignatoryInfo | null;

  /**
   * Signatory breakdown when an allowlist exists; otherwise `null`.
   *
   * @remarks
   * Open-signing files have no fixed expected signer set, so the all/signed/
   * pending model is not applicable.
   */
  signatories: SignatoriesResult | null;

  /** Raw allowlist when restricted; `null` for open-signing files. */
  allowlist: ExpectedSigner[] | null;

  /** Number of per-signer signature records currently present in the envelope. */
  signatureCount: number;
}

// ─── Embed Options ─────────────────────────────────────────────────────────────

/**
 * Options controlling how a signature is embedded into a file.
 *
 * @remarks
 * In normal operation Majik Signature auto-detects a suitable handler from the
 * file bytes and MIME type. These options are overrides for callers that need
 * deterministic handler selection or MIME-type correction.
 */
export interface EmbedOptions {
  /**
   * Explicit MIME type used during handler selection.
   *
   * @remarks
   * Useful when the input `Blob` has an empty or misleading `type`, or when a
   * caller already knows the intended media type.
   */
  mimeType?: string;

  /**
   * Force the universal Tier-2 trailer fallback even when a native handler exists.
   *
   * @remarks
   * Primarily useful for testing fallback behavior or for compatibility cases
   * where the caller deliberately does not want native metadata embedding.
   */
  forceFallback?: boolean;
}

/**
 * Options for extracting a signature from an embedded file.
 *
 * @remarks
 * MIME type is normally inferred automatically; provide it only when automatic
 * detection needs an override.
 */
export interface ExtractOptions {
  /** Explicit MIME type override used during handler selection. */
  mimeType?: string;
}

/**
 * Options for verifying an embedded signature while extracting it.
 *
 * @remarks
 * Extends {@link ExtractOptions} so MIME type selection can be overridden in the
 * same call that performs signer-specific verification.
 */
export interface VerifyEmbeddedOptions extends ExtractOptions {
  /**
   * Optional signer fingerprint to require in the extracted envelope.
   *
   * @remarks
   * This is an additional identity check; cryptographic verification still
   * requires the supplied public-key material to validate the signature.
   */
  expectedSignerId?: string;
}

// ─── Handler Interface ────────────────────────────────────────────────────────

/**
 * Low-level contract implemented by each file-format embedding handler.
 *
 * @remarks
 * Handlers operate exclusively on raw `Uint8Array` bytes so the embedding
 * layer stays independent of browser `Blob` semantics. A handler is responsible
 * for recognizing its format, embedding/extracting the serialized envelope,
 * and restoring the exact unsigned bytes from the signed representation.
 */
export interface FormatHandler {
  /** Stable internal name used for diagnostics and returned file metadata. */
  readonly name: string;

  /** MIME types the handler can process when MIME-aware selection is used. */
  readonly supportedMimeTypes: readonly string[];

  /**
   * Determine whether this handler can process the supplied bytes.
   *
   * @param bytes Raw file bytes to inspect.
   * @param mimeType Optional caller-supplied MIME type hint.
   */
  canHandle(bytes: Uint8Array, mimeType?: string): boolean;

  /**
   * Embed serialized signature JSON into the file bytes.
   *
   * @param bytes Original file bytes without a signature envelope.
   * @param signatureJson Serialized envelope to embed.
   */
  embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array>;

  /**
   * Extract the serialized signature JSON from the file.
   *
   * @returns The embedded JSON string, or `null` when no envelope is present.
   */
  extract(bytes: Uint8Array): Promise<string | null>;

  /**
   * Remove the embedded signature and restore the unsigned file representation.
   *
   * @remarks
   * The returned bytes are the bytes the signature is intended to cover.
   */
  strip(bytes: Uint8Array): Promise<Uint8Array>;

  /**
   * Explain why a probable signature marker could not be parsed.
   *
   * @remarks
   * This is optional and is used for better diagnostics when bytes look like
   * they may contain a signature but no well-formed signature block can be read.
   */
  diagnose?(bytes: Uint8Array): string | null;
}

// ─── Embed / Extract Results ──────────────────────────────────────────────────

/**
 * Result returned after embedding a signature into a file.
 *
 * @remarks
 * `blob` contains the signed file. `handler` identifies the embedding handler
 * that produced it, and `mimeType` is the effective type used for the operation.
 */
export interface EmbedResult {
  /** Signed file containing the embedded envelope. */
  blob: Blob;
  /** Name of the file-format handler used for embedding. */
  handler: string;
  /** Effective MIME type used by the embedding operation. */
  mimeType: string;
}

/**
 * Result returned when extracting an embedded envelope from a file.
 */
export interface ExtractResult {
  /** Behavior-rich immutable envelope reconstructed from the embedded JSON. */
  envelope: MajikSignatureEnvelope;
  /** Name of the handler that extracted the envelope. */
  handler: string;
}

/**
 * Detached signature entry for one file inside a {@link MjksMapJSON} batch manifest.
 *
 * @remarks
 * Entries are keyed by normalized `path`, not by content hash. Duplicate-content
 * files are valid and therefore must remain distinct entries even when their
 * `contentHash` values are identical.
 */
export interface MjksMapEntry {
  /**
   * Relative POSIX-normalized path within the signed batch.
   *
   * @remarks
   * Paths use `/` separators, have no leading slash, and do not contain a
   * Windows drive prefix. The path is the primary lookup key in the manifest.
   */
  path: string;

  /**
   * Base64-encoded SHA-256 digest of the original unsigned file bytes.
   *
   * @remarks
   * Used to confirm that a file found at `path` is unchanged and as the content
   * lookup key when a file has been moved or renamed.
   */
  contentHash: string;

  /**
   * Optional original file size in bytes.
   *
   * @remarks
   * This is convenience metadata for display and diagnostics; verification is
   * based on content hashes and signatures, not on this field alone.
   */
  size?: number;

  /** Optional MIME type recorded for convenience. */
  mimeType?: string;

  /** Full detached multi-signature envelope for this specific file. */
  envelope: MajikSignatureEnvelopeJSON;
}

/**
 * Serialized `.mjksmap` batch-manifest shape.
 *
 * @remarks
 * The behavior-rich runtime counterpart is `MajikSignatureMap`. Each entry
 * carries the detached envelope for exactly one batch path.
 */
export interface MjksMapJSON {
  /** Manifest format version; currently fixed to `1`. */
  version: 1;
  /** ISO 8601 time when the manifest was created. */
  createdAt: ISODateString;
  /** Per-path detached signature entries. */
  entries: MjksMapEntry[];
}

/**
 * Result of looking up an entry by its expected path.
 *
 * @remarks
 * `found` answers whether a manifest entry exists for the path. When it does,
 * `hashMatches` independently tells whether the supplied file bytes still
 * match the recorded content hash.
 */
export interface MjksMapFindResult {
  /** Whether a manifest entry exists at the requested path. */
  found: boolean;
  /** Matching manifest entry when `found` is true. */
  entry?: MjksMapEntry;
  /**
   * Whether the supplied file content matches the entry's stored hash.
   *
   * @remarks
   * This is meaningful only when `found === true`. A false value means the
   * path exists in the manifest but the file content has changed.
   */
  hashMatches?: boolean;
}

// ─── Batch signing ────────────────────────────────────────────────────────────

/**
 * One input file supplied to a batch-signing operation.
 */
export interface BatchFileInput {
  /**
   * Relative path within the batch.
   *
   * @remarks
   * Paths must be unique within the batch and should follow the same normalized
   * POSIX path conventions used by {@link MjksMapEntry.path}.
   */
  path: string;
  /** File contents to sign. */
  blob: Blob;
}

/**
 * Options for `MajikSignature.signBatchDetached()`.
 *
 * @remarks
 * Signing options such as `contentType`, `timestamp`, `expectedSigners`, and
 * `validUntil` are applied uniformly to each file in the batch.
 */
export interface BatchSignOptions {
  /** Advisory content type applied to each generated signature. */
  contentType?: string;
  /** Optional fixed ISO 8601 timestamp applied to every signature. */
  timestamp?: ISODateString;
  /** Optional allowlist applied when establishing the first signature of each file. */
  expectedSigners?: ExpectedSigner[];
  /**
   * Optional ISO 8601 expiry applied to every generated signature.
   *
   * @remarks
   * Omit to create non-expiring signatures, matching `SignOptions.validUntil`.
   */
  validUntil?: ISODateString;
  /**
   * Batch output mode.
   *
   * `"map"` is the default and produces one {@link MajikSignatureMap} plus a
   * `.mjksmap` Blob. `"separate"` produces one `.mjksig` Blob per file.
   */
  mode?: "map" | "separate";
  /**
   * Whether to continue signing after an individual file fails.
   *
   * @default false
   * @remarks
   * When false, the operation stops on the first failure. When true, successful
   * files are retained and failures are returned in the `failures` array.
   */
  continueOnError?: boolean;
}

/**
 * Per-file failure captured by a batch-signing operation when continuation is enabled.
 */
export interface BatchSignFailure {
  /** Path of the file that could not be signed. */
  path: string;
  /** Human-readable description of the signing failure. */
  error: string;
}

/**
 * Discriminated result returned by `MajikSignature.signBatchDetached()`.
 *
 * @remarks
 * Narrow on `mode` before accessing `map`/`mapBlob` or `signatures`. The
 * `failures` array is present in both modes so callers can render partial
 * success without losing the per-file error information.
 */
export type BatchSignResult =
  | {
      /** Indicates manifest output mode. */
      mode: "map";
      /** Immutable batch-manifest instance covering the signed files. */
      map: import("./mjksmap").MajikSignatureMap;
      /** Ready-to-store `.mjksmap` Blob. */
      mapBlob: Blob;
      /** Files that failed when `continueOnError` allowed processing to continue. */
      failures: BatchSignFailure[];
    }
  | {
      /** Indicates one-container-per-file output mode. */
      mode: "separate";
      /** Signed `.mjksig` blobs paired with their original batch paths. */
      signatures: { path: string; blob: Blob }[];
      /** Files that failed when `continueOnError` allowed processing to continue. */
      failures: BatchSignFailure[];
    };

// ─── Batch verification ───────────────────────────────────────────────────────

/**
 * One file supplied to a batch-verification operation.
 */
export interface BatchVerifyInput {
  /** Relative path at which the caller expects the file to occur. */
  path: string;
  /** File contents to resolve and verify against the manifest. */
  blob: Blob;
}

/**
 * Per-file batch verification outcome.
 *
 * @remarks
 * These values describe the relationship between the supplied file and the
 * manifest, including content integrity and cryptographic verification:
 *
 * - `verified` — path/hash matched and all signatures verified.
 * - `invalid` — path/hash matched but at least one signature failed.
 * - `tampered` — the path exists in the manifest but supplied content differs.
 * - `not_in_map` — no manifest entry exists at the supplied path (and no valid
 *   relocation match was found).
 */
export type FileVerifyStatus =
  | "verified"
  | "invalid"
  | "tampered"
  | "not_in_map";

/**
 * Detailed result for one file in batch verification.
 *
 * @remarks
 * In normal batch operation this is a reportable result, not an exception.
 * Use `status` as the machine-readable state and `reason` for UI/diagnostics.
 */
export interface FileVerifyResult {
  /** Path supplied for this verification item. */
  path: string;
  /** Classification of the file's relationship to the manifest and signatures. */
  status: FileVerifyStatus;
  /**
   * Per-signer verification results.
   *
   * @remarks
   * Present for `verified`, `invalid`, and `tampered`; omitted for `not_in_map`.
   */
  results?: VerificationResult[];
  /** Human-readable summary suitable for displaying in a UI. */
  reason?: string;
  /**
   * Original manifest path when the file was found by content hash after being moved or renamed.
   *
   * @remarks
   * Present only for relocation matches. When set, `path` is the caller-supplied
   * location and `relocatedFrom` is where the file was originally signed.
   */
  relocatedFrom?: string;
}

/**
 * Options controlling batch-verification strictness and time handling.
 */
export interface BatchVerifyOptions {
  /**
   * Verify only the signature belonging to this expected signer fingerprint.
   *
   * @remarks
   * Omit this to verify every signer present in each matched envelope.
   */
  expectedSignerId?: MajikKeyFingerprint;

  /**
   * Clock value used when evaluating `validUntil`.
   *
   * @default new Date()
   * @remarks
   * The same `Date` is used for every file in the batch, which makes tests and
   * batch-wide expiry decisions deterministic.
   */
  now?: Date;

  /**
   * Whether a missing manifest entry should abort the entire batch call.
   *
   * @default false
   * @remarks
   * When false, missing files are returned as `status: "not_in_map"`. When true,
   * the presence of any missing file is escalated to a thrown error.
   */
  requireAllPresent?: boolean;
}

/**
 * Aggregate counts for a set of {@link FileVerifyResult} values.
 */
export interface BatchVerifySummary {
  /** Number of files processed. */
  total: number;
  /** Number of files with `status === "verified"`. */
  verified: number;
  /** Number of files with `status === "invalid"`. */
  invalid: number;
  /** Number of files with `status === "tampered"`. */
  tampered: number;
  /** Number of files with `status === "not_in_map"`. */
  notInMap: number;
  /**
   * True only when every processed file is `verified`.
   *
   * @remarks
   * This is the intended one-glance batch pass/fail property; inspect individual
   * result objects when a more detailed explanation is needed.
   */
  allValid: boolean;
}

/**
 * How a file was resolved against a {@link MajikSignatureMap}.
 *
 * @remarks
 * Resolution is path-first and content-aware. If the expected path does not
 * yield an unchanged file, the map can fall back to locating the same content
 * elsewhere in the batch.
 */
export type MjksMapResolveStatus =
  | "path_match"
  | "path_tampered"
  | "relocated"
  | "not_found";

/**
 * Result of path/content resolution against a batch manifest.
 */
export interface MjksMapResolveResult {
  /** Final resolution classification. */
  status: MjksMapResolveStatus;
  /** Matching manifest entry when one was resolved. */
  entry?: MjksMapEntry;
  /**
   * Original signed path when `status === "relocated"`.
   *
   * @remarks
   * The requested/current path is the path passed by the caller; this value is
   * the manifest path where the content was originally signed.
   */
  originalPath?: string;
}

/**
 * One append-only revision commitment in a file-versioning chain.
 *
 * @remarks
 * A version is 1-indexed. Starting with version 2, `previousVersionHash`
 * commits to the complete previous entry, creating a hash-linked revision
 * history. `contentHash` identifies the stripped file bytes for this revision.
 */
export interface FileVersion {
  /** Sequential revision number; starts at `1`. */
  version: number;
  /** ISO 8601 time at which this revision entry was created. */
  timestamp: ISODateString;
  /** Base64-encoded SHA-256 digest of this revision's stripped file bytes. */
  contentHash: string;
  /**
   * Hash of the entire previous `FileVersion` entry.
   *
   * @remarks
   * Omitted only for version `1`, which has no predecessor.
   */
  previousVersionHash?: string;
  /** MajikKey fingerprint of the signer who created this revision, when available. */
  createdBy?: MajikKeyFingerprint;
  /** Optional human-readable note describing the revision. */
  message?: string;
}

/**
 * Verification result for a signer commitment when the original file bytes
 * are not required.
 *
 * @remarks
 * Extends {@link VerificationResult} with an explicit `commitmentOnly` marker.
 * This is the result used for historical revisions during Tier-1
 * `verifyFileChain()` checks.
 */
export interface RevisionCommitmentResult extends VerificationResult {
  /** Always `true`; marks this as commitment-only rather than full content verification. */
  commitmentOnly: true;
}

/**
 * Tier-1 verification result for a revision-aware multi-signature file.
 *
 * @remarks
 * The latest revision is fully verified against the current file bytes. Older
 * revisions are checked via their cryptographic commitments and the current
 * revision-chain hash, without requiring archived copies of the older files.
 */
export interface FileChainVerification {
  /** Full verification result for the latest signer/revision. */
  latest: VerificationResult;
  /** Commitment-only verification results for earlier revisions/signers. */
  history: RevisionCommitmentResult[];
  /** Whether the complete revision commitment chain is internally consistent. */
  chainValid: boolean;
}

/**
 * Accepted representations of a detached signature envelope.
 *
 * @remarks
 * High-level APIs normalize these inputs internally. This lets callers use the
 * representation they already have instead of manually converting JSON, a
 * `MajikSignatureEnvelope` instance, or `.mjksig` bytes into another form.
 */
export type EnvelopeInput =
  | MajikSignatureEnvelope
  | MajikSignatureEnvelopeJSON
  | FileLike;

/**
 * Binary/file-like inputs accepted by detached-envelope and revision APIs.
 *
 * @remarks
 * `Blob` covers both browser/Tauri file workflows and generic binary payloads;
 * `File` adds filesystem metadata where available; typed-array and
 * `ArrayBuffer` inputs are useful in Node.js and other binary-first runtimes.
 */
export type FileLike = Blob | File | Uint8Array | ArrayBuffer;

/**
 * Per-revision status returned by archive-assisted revision verification.
 *
 * @remarks
 *
 * - `verified` — supplied bytes matched the recorded revision and its signature verified.
 * - `unmatched` — no supplied file matched this revision's content hash.
 * - `chain_broken` — revision-chain metadata did not match the committed chain.
 * - `signature_invalid` — the content hash matched, but cryptographic verification failed.
 */
export type RevisionCheckStatus =
  | "verified"
  | "unmatched"
  | "chain_broken"
  | "signature_invalid";

/**
 * Verification outcome for one entry in a file-version history.
 */
export interface RevisionCheckResult {
  /** Revision number being checked. */
  version: number;
  /** Classification of the supplied revision against its chain commitment. */
  status: RevisionCheckStatus;
  /** Signer fingerprint when the revision could be associated with a signer. */
  signerId?: MajikKeyFingerprint;
  /** Human-readable diagnostic for the status, when one is available. */
  reason?: string;
}

/**
 * Tier-2 archive-assisted verification result for the complete revision set.
 *
 * @remarks
 * `allValid` means every manifest revision that was checked matched supplied
 * bytes and verified cryptographically. `isCompleteSet` additionally requires
 * that the supplied revision set covers the entire recorded chain without gaps.
 */
export interface RevisionSetVerification {
  /** True only when every recorded revision matched supplied bytes and verified. */
  allValid: boolean;
  /** True only when the supplied revision files cover the entire recorded chain. */
  isCompleteSet: boolean;
  /** Per-revision verification details in chain order. */
  results: RevisionCheckResult[];
}

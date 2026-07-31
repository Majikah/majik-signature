/**
 * types.ts
 * Public types for the MajikSignature library.
 */

import { MajikChainAnchor } from "../anchor/types";
import type { ContentType } from "./constants";

export type { ContentType };

export type MajikSignatureEnvelope = MultiSigEnvelope;

/**
 * The serializable per-signer signature envelope.
 * Everything a verifier needs — no private keys required.
 */
export interface MajikSignatureJSON {
  /** Envelope version — must equal MAJIK_SIGNATURE_VERSION */
  version: 1;

  /** MajikKey fingerprint (SHA-256 of X25519 public key, base64) */
  signerId: string;

  /** Ed25519 public key, base64 (32 bytes) */
  signerEdPublicKey: string;

  /** ML-DSA-87 public key, base64 (2592 bytes) */
  signerMlDsaPublicKey: string;

  /** SHA-256 hash of the original content, base64 (32 bytes → 44 chars) */
  contentHash: string;

  /** Advisory content type — e.g. "audio/wav", "application/pdf" */
  contentType?: string;

  /** ISO 8601 timestamp of when the signature was created */
  timestamp: string;

  /** Ed25519 signature over the canonical payload, base64 (64 bytes) */
  edSignature: string;

  /** ML-DSA-87 signature over the canonical payload, base64 (4595 bytes) */
  mlDsaSignature: string;

  /**
   * SHA-256 hash of the canonical allowlist JSON, base64 (44 chars).
   * Present only on the envelope of the signer who established the allowlist.
   * Included in the canonical signing payload so both Ed25519 and ML-DSA-87
   * cover it — tampering with the allowlist breaks this signer's verification.
   * Absent on all other signers and on any signature made before multi-sig support.
   */
  allowlistHash?: string;

  tsa?: MajikTimestamp;
}

export interface MajikTSAPayload {
  digest: {
    algorithm: "SHA-256";
    value: string;
  };
  nonce: string; // server-generated, base64 random bytes
  timestamp: string; // ISO 8601, server-authoritative
  tsa: {
    id: string; // stable TSA entity identifier e.g. "tsa.majikah.solutions"
    signerFingerprint: string; // MajikKey fingerprint of the key that signed
  };
}

export interface MajikTSARequest {
  digest: {
    algorithm: "SHA-256";
    value: string;
  };
}

export interface MajikTimestamp {
  version: 1;
  id: string; // UUID — unique per issuance
  payload: MajikTSAPayload; // the exact payload that was signed
  signature: MajikSignatureJSON; // full envelope, carries its own public keys
}

/**
 * Identifies a single permitted signer in an allowlist.
 * All three fields must match — fingerprint alone is not sufficient.
 */
export interface ExpectedSigner {
  /** MajikKey fingerprint (SHA-256 of X25519 public key, base64) */
  signerId: string;
  /** Ed25519 public key, base64 (32 bytes) */
  edPublicKey: string;
  /** ML-DSA-87 public key, base64 (2592 bytes) */
  mlDsaPublicKey: string;
}

/**
 * Top-level on-disk / in-file envelope for multi-sig support.
 *
 * Backward compat:
 *   Old files embed a bare MajikSignatureJSON object.
 *   parseEnvelope() in core/multi-sig.ts detects this and promotes it
 *   transparently to { version: 1, signatures: [thatObject] } — callers
 *   never see the old shape.
 */
export interface MultiSigEnvelope {
  /** Envelope wrapper version — must equal MAJIK_ENVELOPE_VERSION */
  version: 1;

  /**
   * When present, restricts signing to these keys only.
   * Enforced at signFile() time — non-listed signers are rejected before
   * any cryptographic operation.
   * Absent = open signing (any key may add a signature).
   */
  allowlist?: ExpectedSigner[];

  /**
   * Fingerprint of the signer who established the allowlist.
   * Their MajikSignatureJSON.allowlistHash cryptographically commits
   * to the allowlist contents — tampering with the allowlist breaks
   * their signature verification.
   * Absent when allowlist is absent.
   */
  allowlistSignerId?: string;

  /** All per-signer envelopes. One entry per signer, keyed logically by signerId. */
  signatures: MajikSignatureJSON[];

  /**
   * SHA3-512 hash of the canonical seal payload (all signatories + sealTimestamp).
   * Hex-encoded, 128 chars — matches SEAL_HASH_HEX_LEN.
   * Present only when the issuer has sealed the envelope.
   * A sealed envelope rejects all further signing attempts, including from the issuer.
   */
  sealHash?: string;

  /**
   * ISO 8601 timestamp of when the seal was applied.
   * Included in the seal hash input — changing this breaks the seal.
   */
  sealTimestamp?: string;

  /**
   * Fingerprint of the signer who applied the seal.
   * Must equal allowlistSignerId — only the issuer can seal.
   */
  sealedBy?: string;

  chainAnchors?: MajikChainAnchor[]; // NEW — array from day one, multi-chain-ready
}

/**
 * Public key material needed to verify a MajikSignature.
 * No private key fields — safe to pass around freely.
 */
export interface MajikSignerPublicKeys {
  /** MajikKey fingerprint */
  signerId: string;
  /** Ed25519 public key bytes (32 bytes) */
  edPublicKey: Uint8Array;
  /** ML-DSA-87 public key bytes (2592 bytes) */
  mlDsaPublicKey: Uint8Array;
}

/**
 * Options accepted by MajikSignature.sign()
 */
export interface SignOptions {
  /** Advisory content type label */
  contentType?: string;
  /** Override timestamp (useful for deterministic tests) */
  timestamp?: string;
  /**
   * Restrict future signers to these keys only.
   * Only honoured when this is the first signature on a file (no existing
   * envelope or empty signatures array). Silently ignored on subsequent
   * signFile() calls — the existing allowlist always wins.
   * Each entry must include signerId + edPublicKey + mlDsaPublicKey (base64).
   */
  expectedSigners?: ExpectedSigner[];
}

/**
 * Result returned by MajikSignature.verify() and all file-level verify methods.
 */
export interface VerificationResult {
  valid: boolean;
  signerId?: string;
  contentHash?: string;
  timestamp: string;
  contentType?: string;
  /** Present when result came from a file verify — which handler processed it */
  handler?: string;
  /** Present when valid is false — human-readable failure reason */
  reason?: string;
}

/**
 * Result returned by verifySeal().
 */
export interface SealVerificationResult {
  /** Whether the seal hash is valid and matches all current signatories */
  valid: boolean;
  /** Fingerprint of who sealed the envelope */
  sealedBy?: string;
  /** ISO 8601 timestamp of when the seal was applied */
  sealTimestamp?: string;
  /** Human-readable failure reason when valid is false */
  reason?: string;
}

/**
 * Metadata about the seal without performing cryptographic verification.
 * Returned by getSealInfo().
 */
export interface SealInfo {
  /** SHA3-512 hash of the canonical seal payload, hex-encoded (128 chars) */
  sealHash: string;
  /** ISO 8601 timestamp of when the seal was applied */
  sealTimestamp: string;
  /** Fingerprint of the issuer who applied the seal */
  sealedBy: string;
}

/**
 * Full information about a single signatory.
 * Combines allowlist metadata (expected) with signing status (actual).
 */
export interface SignatoryInfo {
  /** MajikKey fingerprint */
  signerId: string;
  /** Ed25519 public key, base64 */
  edPublicKey: string;
  /** ML-DSA-87 public key, base64 */
  mlDsaPublicKey: string;
  /** Whether this signatory has already signed */
  hasSigned: boolean;
  /** ISO 8601 timestamp of their signature — present only when hasSigned is true */
  signedAt?: string;
}

/**
 * Result returned by getSignatories() and its aliases.
 * All three arrays are always present — callers can use whichever they need.
 */
export interface SignatoriesResult {
  /** All expected signatories (from allowlist), with signing status */
  all: SignatoryInfo[];
  /** Signatories who have already signed */
  signed: SignatoryInfo[];
  /** Signatories who are expected but have not yet signed */
  pending: SignatoryInfo[];
}

/**
 * Filter options for getSignatories().
 */
export type SignatoriesFilter = "all" | "signed" | "pending";

/**
 * Full summary of a file's envelope state.
 * Returned by getEnvelopeInfo() — one file read, complete picture.
 */
export interface EnvelopeInfo {
  /**
   * True when the file has an allowlist (restricted multi-sig).
   * False for open-signing files or unsigned files.
   */
  isMultiSig: boolean;
  /**
   * True when there is more than one signature present,
   * OR when an allowlist with more than one entry exists.
   */
  hasMultipleSignatories: boolean;
  /** Whether the envelope has been sealed */
  isSealed: boolean;
  /** Seal metadata — present only when isSealed is true */
  sealInfo?: SealInfo;
  /**
   * The issuer who established the allowlist and controls sealing.
   * Null for open-signing files.
   */
  issuer: SignatoryInfo | null;
  /** Full signatories breakdown — only populated when allowlist is present */
  signatories: SignatoriesResult | null;
  /** The raw allowlist — null for open-signing files */
  allowlist: ExpectedSigner[] | null;
  /** Total number of signatures currently in the envelope */
  signatureCount: number;
}

// ─── Embed Options ─────────────────────────────────────────────────────────────

export interface EmbedOptions {
  /**
   * Override MIME type detection. Normally auto-detected from file bytes.
   * Useful when the Blob has type="" or an unknown extension.
   */
  mimeType?: string;

  /**
   * If true, use the Tier-2 trailer fallback even for formats that have a
   * native handler. Useful for testing or when you want maximum compatibility.
   */
  forceFallback?: boolean;
}

export interface ExtractOptions {
  /** Override MIME type detection */
  mimeType?: string;
}

export interface VerifyEmbeddedOptions extends ExtractOptions {
  /** If provided, also checks signerId matches */
  expectedSignerId?: string;
}

// ─── Handler Interface ────────────────────────────────────────────────────────

/**
 * Every format handler implements this interface.
 * All methods receive/return raw Uint8Array — no Blob coupling inside handlers.
 */
export interface FormatHandler {
  readonly name: string;
  readonly supportedMimeTypes: readonly string[];
  canHandle(bytes: Uint8Array, mimeType?: string): boolean;
  embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array>;
  extract(bytes: Uint8Array): Promise<string | null>;
  strip(bytes: Uint8Array): Promise<Uint8Array>;
}

// ─── Embed / Extract Results ──────────────────────────────────────────────────

export interface EmbedResult {
  blob: Blob;
  handler: string;
  mimeType: string;
}

export interface ExtractResult {
  /** The parsed MultiSigEnvelope extracted from the file */
  envelope: MultiSigEnvelope;
  handler: string;
}

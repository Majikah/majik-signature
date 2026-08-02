/**
 * types.ts
 * Public types for the MajikSignature library.
 */

import { ISODateString } from "@majikah/majik-key";
import { MajikChainAnchor } from "../anchor/types";
import type { ContentType } from "./constants";
import type { MajikSignatureEnvelope } from "./envelope";

export type { ContentType };

export type MajikSignatureEnvelopeJSON = MultiSigEnvelope;

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
  envelope: MajikSignatureEnvelope;
  handler: string;
}

/**
 * A single file's entry in a MajikSignatureMap.
 * Keyed by `path` (unique within a batch) — NOT by contentHash alone,
 * since duplicate-content files (identical boilerplate, empty templates)
 * are a real case and hash-as-primary-key would silently collide them.
 */
export interface MjksMapEntry {
  /** Relative path within the batch, POSIX-normalized: forward slashes,
   *  no leading slash, no drive letters. */
  path: string;
  /** SHA-256 of the file's original (unsigned) content, base64.
   *  Used as an integrity check on lookup-by-path, and as the index
   *  for lookup-by-hash. */
  contentHash: string;
  /** Optional cheap-to-show metadata, no need to open the file for it */
  size?: number;
  mimeType?: string;
  /** The full detached envelope for this specific file */
  envelope: MajikSignatureEnvelopeJSON;
}

export interface MjksMapJSON {
  version: 1;
  createdAt: ISODateString; // ISO 8601
  entries: MjksMapEntry[];
}

export interface MjksMapFindResult {
  found: boolean;
  entry?: MjksMapEntry;
  /** Only meaningful when found === true. False means the file at this
   *  path was modified after signing — same name, different content. */
  hashMatches?: boolean;
}

// ─── Batch signing ────────────────────────────────────────────────────────────

export interface BatchFileInput {
  /** Relative path within the batch — must be unique across the batch. */
  path: string;
  blob: Blob;
}

export interface BatchSignOptions {
  contentType?: string;
  timestamp?: string;
  expectedSigners?: ExpectedSigner[];
  /** "map" (default) produces one MajikSignatureMap covering the whole
   *  batch. "separate" produces one .mjksig Blob per file. */
  mode?: "map" | "separate";
  /**
   * If false (default), the batch aborts on the first file that fails to
   * sign — signing is security-sensitive, so silent partial failure is
   * worse than a loud abort. Set true to collect failures and continue,
   * useful for large batches where a handful of unreadable files
   * shouldn't block everything else.
   */
  continueOnError?: boolean;
}

export interface BatchSignFailure {
  path: string;
  error: string;
}

export type BatchSignResult =
  | {
      mode: "map";
      map: import("./mjksmap").MajikSignatureMap;
      mapBlob: Blob;
      failures: BatchSignFailure[];
    }
  | {
      mode: "separate";
      signatures: { path: string; blob: Blob }[];
      failures: BatchSignFailure[];
    };

// ─── Batch verification ───────────────────────────────────────────────────────

export interface BatchVerifyInput {
  path: string;
  blob: Blob;
}

export type FileVerifyStatus =
  | "verified" // found in map, hash matches, all signatures valid
  | "invalid" // found in map, hash matches, but a signature failed
  | "tampered" // found in map, but current content no longer matches
  | "not_in_map"; // path has no entry in the map at all

export interface FileVerifyResult {
  path: string;
  status: FileVerifyStatus;
  /** Present for "verified" / "invalid" / "tampered" — absent for "not_in_map" */
  results?: VerificationResult[];
  /** Human-readable summary — always present, safe to show directly in UI */
  reason?: string;
  /** Present only when the file was found by content match at a different
   *  path than requested — i.e. it moved after signing but is still valid. */
  relocatedFrom?: string;
}

export interface BatchVerifyOptions {
  expectedSignerId?: string;
  /**
   * If true, a file with status "not_in_map" is a hard error for the whole
   * batch call (throws). Default false — missing files are reported per-file
   * instead, since a batch verify is usually a "tell me what's wrong with
   * each file" operation, not an all-or-nothing gate.
   */
  requireAllPresent?: boolean;
}

export interface BatchVerifySummary {
  total: number;
  verified: number;
  invalid: number;
  tampered: number;
  notInMap: number;
  /** True only when every file is "verified" — the one-glance pass/fail check */
  allValid: boolean;
}

export type MjksMapResolveStatus =
  | "path_match" // found at the expected path, hash confirms it's unmodified
  | "path_tampered" // found at the expected path, but content no longer matches
  | "relocated" // not found at the given path, but found elsewhere by hash
  | "not_found"; // no entry matches this file by path or by content, anywhere

export interface MjksMapResolveResult {
  status: MjksMapResolveStatus;
  entry?: MjksMapEntry;
  /** Only set when status === "relocated" — where the file now lives
   *  vs. where the map says it was originally signed. */
  originalPath?: string;
}

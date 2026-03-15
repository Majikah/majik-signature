/**
 * types.ts
 * Public types for the MajikSignature library.
 */

import type { ContentType } from "./constants";

export type { ContentType };

/**
 * The serializable signature envelope.
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
}

/**
 * Result returned by MajikSignature.verify() when verification passes.
 * Gives the caller structured info rather than a bare boolean.
 */
export interface VerificationResult {
  valid: boolean;
  signerId: string;
  contentHash: string;
  timestamp: string;
  contentType?: string;
}

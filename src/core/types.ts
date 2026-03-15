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
  signerId?: string;
  contentHash?: string;
  timestamp: string;
  contentType?: string;
}

/**
 *  Core types for MajikSignatureEmbed
 */

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
  /** Human-readable name for this handler, e.g. "PDF", "WAV" */
  readonly name: string;

  /** MIME types this handler can process */
  readonly supportedMimeTypes: readonly string[];

  /**
   * Returns true if this handler can process the given bytes.
   * May inspect magic bytes / file headers.
   */
  canHandle(bytes: Uint8Array, mimeType?: string): boolean;

  /**
   * Embed a serialized MajikSignatureJSON string into the file bytes.
   * Must NOT alter the original content in any way that affects the hash.
   * Returns new bytes with the signature embedded.
   */
  embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array>;

  /**
   * Extract the serialized MajikSignatureJSON string from file bytes.
   * Returns null if no signature is found.
   */
  extract(bytes: Uint8Array): Promise<string | null>;

  /**
   * Return the original bytes with any embedded signature removed.
   * This is what was signed — must produce stable output.
   */
  strip(bytes: Uint8Array): Promise<Uint8Array>;
}

// ─── Embed Result ─────────────────────────────────────────────────────────────

export interface EmbedResult {
  /** The new file as a Blob, with the signature embedded */
  blob: Blob;
  /** Which handler processed the file */
  handler: string;
  /** The MIME type used */
  mimeType: string;
}

export interface ExtractResult {
  /** The raw JSON string extracted from the file */
  signatureJson: string;
  /** Which handler found it */
  handler: string;
}

// ─── Verification Result (extended) ──────────────────────────────────────────

export interface EmbedVerifyResult {
  valid: boolean;
  signerId?: string;
  contentHash?: string;
  timestamp: string;
  contentType?: string;
  handler?: string;
  reason?: string;
}

/**
 * types.ts — MajikImageSignature type definitions
 */

// ─── Stub (what lives inside the image) ──────────────────────────────────────

/**
 * The compact proof embedded into the image via DCT steganography.
 *
 * Intentionally minimal — must survive Q70 JPEG recompression.
 * Total raw size: 4 (magic) + 2 (version) + 8 (pHash) + 32 (edPubKey) +
 *                 8 (timestamp) + 32 (signerId) + 64 (edSig) = 150 bytes
 * With Reed-Solomon ECC (50% overhead, 75 parity bytes): 225 bytes encoded on disk
 */
export interface ImageSignatureStub {
  /** 64-bit perceptual hash of the image (dct-pHash, bigint as hex string) */
  pHash: string;
  /** Ed25519 public key of the signer, raw 32 bytes as hex */
  signerEdPublicKey: string;
  /** Ed25519 signature over the canonical image signing payload, 64 bytes as hex */
  edSignature: string;
  /** Signer identifier (fingerprint), stored for display only — not verified inline */
  signerId: string;
  /** ISO timestamp of when the image was signed */
  timestamp: string;
}

// ─── Canonical signing payload ────────────────────────────────────────────────

/**
 * The data that Ed25519 signs.
 * Encoded as: "majik-image-v1:" + JSON({ v, id, ts, pHash })
 */
export interface ImageSigningPayloadFields {
  signerId: string;
  timestamp: string;
  pHash: string;
}

// ─── Sign options ─────────────────────────────────────────────────────────────

export interface ImageSignOptions {
  /** Override timestamp (ISO string). Defaults to now. */
  timestamp?: string;
  /**
   * Target output MIME type. Defaults to image/png for lossless output.
   * The signature is embedded before any lossy encoding — output is always
   * the "canonical" form. Platforms will re-compress; that's expected.
   */
  outputMimeType?: "image/png" | "image/jpeg" | "image/webp";
  /**
   * JPEG quality when outputMimeType is image/jpeg (0–100). Default: 92.
   * Higher = more capacity preserved. Never go below 70.
   */
  jpegQuality?: number;
}

// ─── Verification result ──────────────────────────────────────────────────────

export interface ImageVerificationResult {
  /** True only if stub was extracted AND pHash matches AND Ed25519 verifies */
  valid: boolean;
  /** Why verification failed, if valid === false */
  reason?: string;
  /** Signer ID from the stub (unverified — display only) */
  signerId?: string;
  /** ISO timestamp from the stub */
  timestamp?: string;
  /** The pHash stored in the stub (hex) */
  storedPHash?: string;
  /** The pHash recomputed from the uploaded image (hex) */
  computedPHash?: string;
  /** Hamming distance between stored and computed pHash (lower = more similar) */
  hammingDistance?: number;
  /** Ed25519 public key recovered from the stub (hex) */
  signerEdPublicKey?: string;
}

// ─── DCT embedding internals ──────────────────────────────────────────────────

export interface DctEmbedResult {
  /** Modified pixel data (RGBA, width*height*4 bytes) */
  pixels: Uint8ClampedArray;
  width: number;
  height: number;
  /** How many bits were actually written */
  bitsWritten: number;
  /** How many usable coefficient slots were available */
  capacity: number;
}

export interface DctExtractResult {
  /** Raw bits extracted from DCT coefficients */
  bits: Uint8Array;
  /** Total usable coefficient slots scanned */
  capacity: number;
}

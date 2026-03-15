/**
 * constants.ts
 * MajikSignature protocol constants.
 */

/** Current envelope version. Increment when the signing payload format changes. */
export const MAJIK_SIGNATURE_VERSION = 1 as const;

/**
 * Domain separator prefix prepended to every canonical signing payload.
 * Prevents cross-protocol signature reuse against other systems.
 * MUST NOT change — changing it invalidates all existing signatures.
 */
export const MAJIK_SIGNATURE_DOMAIN = "majik-signature-v1:" as const;

/**
 * Supported content type hints.
 * These are advisory — verification does not enforce content type.
 * They exist so consumers can display meaningful UI and reject unexpected types.
 */
export const CONTENT_TYPES = {
  BINARY: "application/octet-stream",
  JSON: "application/json",
  TEXT: "text/plain",
  PDF: "application/pdf",
  WAV: "audio/wav",
  MP3: "audio/mpeg",
  FLAC: "audio/flac",
  PNG: "image/png",
  JPEG: "image/jpeg",
  WEBP: "image/webp",
} as const;

export type ContentType =
  | (typeof CONTENT_TYPES)[keyof typeof CONTENT_TYPES]
  | string;

/** Minimum base64 length sanity checks */
export const MIN_ED_PUBLIC_KEY_B64_LEN = 40; // 32 bytes → 44 chars; give 4 slack
export const MIN_DSA_PUBLIC_KEY_B64_LEN = 100; // 2592 bytes → 3456 chars; sanity floor
export const MIN_SIGNATURE_B64_LEN = 80; // 64-byte Ed sig → 88 chars; floor
export const CONTENT_HASH_B64_LEN = 44; // SHA-256 → always 44 chars base64

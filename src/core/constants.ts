/**
 * constants.ts
 * MajikSignature protocol constants.
 */

/** Current per-signer envelope version. Increment when the signing payload format changes. */
export const MAJIK_SIGNATURE_VERSION = 1 as const;

/**
 * Current multi-sig envelope wrapper version.
 * Increment when the MultiSigEnvelope structure changes.
 * Kept separate from MAJIK_SIGNATURE_VERSION so the two can evolve independently.
 */
export const MAJIK_ENVELOPE_VERSION = 1 as const;

/**
 * Domain separator prefix prepended to every canonical signing payload.
 * Prevents cross-protocol signature reuse against other systems.
 * MUST NOT change — changing it invalidates all existing signatures.
 */
export const MAJIK_SIGNATURE_DOMAIN = "majik-signature-v1:" as const;

/**
 * Domain separator for the seal hash payload.
 * Distinct from MAJIK_SIGNATURE_DOMAIN to prevent cross-protocol reuse.
 */
export const MAJIK_SEAL_DOMAIN = "majik-seal-v1:" as const;

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

/**
 * Allowlist hash is also a SHA-256 output — identical length to CONTENT_HASH_B64_LEN.
 * Defined separately for clarity at validation call sites.
 */
export const ALLOWLIST_HASH_B64_LEN = CONTENT_HASH_B64_LEN; // 44 chars

/**
 * Seal hash is SHA3-512 → 64 bytes → 128 hex chars (with padding).
 * Distinct from SHA-256 hashes — longer length makes tampering obvious at a glance.
 */
export const SEAL_HASH_HEX_LEN = 128; // rename to reflect actual encoding

export const MAJIK_TIMESTAMP_VERSION = 1 as const;
export const MAJIK_TSA_DOMAIN =
  `majikah-tsa-v-${MAJIK_TIMESTAMP_VERSION}:` as const;

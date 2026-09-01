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
export const ALLOWLIST_HASH_B64_LEN = 44; // 44 chars

/**
 * Seal hash is SHA3-512 → 64 bytes → 128 hex chars.
 * Distinct from SHA-256 hashes — longer length makes tampering obvious at a glance.
 * This is the encoding computeSealHash() actually returns and validateSeal() checks against.
 */
export const SEAL_HASH_HEX_LEN = 128;

export const MAJIK_TIMESTAMP_VERSION = 1 as const;
export const MAJIK_TSA_DOMAIN =
  `majikah-tsa-v-${MAJIK_TIMESTAMP_VERSION}:` as const;

export const MAJIK_NOTARY_VERSION = 1 as const;
export const MAJIK_NOTARY_MEMO_DOMAIN =
  `majik-notary-v-${MAJIK_NOTARY_VERSION}:` as const;


  // ─── MJKSIG binary format ───────────────────────────────────────────────────
//
// Layout: [magic(6)][version(1)][reserved(1)][payloadLen(4, BE u32)][payload JSON]
// Header length is fixed at 12 bytes regardless of version — only the
// payload shape may change between versions, never the header layout.
// This lets fromMJKSIG() always locate and validate the header before it
// needs to know anything about the payload's internal shape.

export const MJKSIG_MAGIC = [0x4d, 0x4a, 0x4b, 0x53, 0x49, 0x47]; // "MJKSIG"
export const MJKSIG_MAGIC_LEN = MJKSIG_MAGIC.length;
export const MJKSIG_VERSION = 0x01;
export const MJKSIG_SUPPORTED_VERSIONS = [MJKSIG_VERSION] as const;
export const MJKSIG_HEADER_LEN = MJKSIG_MAGIC_LEN + 1 + 1 + 4; // 12

/**
 * Proposed IANA media type / conventional file extension for this format.
 * Referenced here so both live in one place ahead of registration —
 * update if/when the registration settles on different values.
 */
export const MJKSIG_MEDIA_TYPE = "application/vnd.majikah.mjksig" as const;
export const MJKSIG_FILE_EXTENSION = ".mjksig" as const;


// ─── MJKSMAP binary format ───────────────────────────────────────────────────
//
// Layout: [magic(7)][version(1)][reserved(1)][payloadLen(4, BE u32)][payload JSON]
// A single manifest file mapping every file in a batch/zip to its detached
// MajikSignatureEnvelope — one file to track instead of N loose .mjksig files.
// Header layout mirrors MJKSIG deliberately; only the magic differs.

export const MJKSMAP_MAGIC = [0x4d, 0x4a, 0x4b, 0x53, 0x4d, 0x41, 0x50]; // "MJKSMAP"
export const MJKSMAP_MAGIC_LEN = MJKSMAP_MAGIC.length;
export const MJKSMAP_VERSION = 0x01;
export const MJKSMAP_SUPPORTED_VERSIONS = [MJKSMAP_VERSION] as const;
export const MJKSMAP_HEADER_LEN = MJKSMAP_MAGIC_LEN + 1 + 1 + 4; // 13

export const MJKSMAP_MEDIA_TYPE = "application/vnd.majikah.mjksmap";
export const MJKSMAP_FILE_EXTENSION = ".mjksmap";

/** Conventional name/location when packaged in a signed batch zip. */
export const MJKSMAP_DEFAULT_FILENAME = "signatures.mjksmap";
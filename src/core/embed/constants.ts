/**
 * constants.ts — Shared constants for all format handlers
 */

/** Magic bytes appended at end of Tier-2 trailer: ASCII "MAJIKSIG" */
export const TRAILER_MAGIC = new Uint8Array([
  0x4d, 0x41, 0x4a, 0x49, 0x4b, 0x53, 0x49, 0x47,
]);

/** Total trailer suffix length: payload_length (8 bytes LE) + magic (8 bytes) = 16 bytes */
export const TRAILER_SUFFIX_LENGTH = 16;

/** Key name used in all text-based metadata fields */
export const SIGNATURE_KEY = "majik-signature";

/** Namespace URI used in XMP / XML-based metadata */
export const MAJIK_NAMESPACE = "https://signature.majikah.solutions";

/** PNG chunk type for embedded signature */
export const PNG_CHUNK_TYPE = "iTXt";

/** PNG keyword for iTXt chunk */
export const PNG_KEYWORD = "majik-signature";

/** RIFF chunk FourCC for WAV/AVI embedding */
export const RIFF_CHUNK_FOURCC = "majk";

/** ID3 TXXX frame description */
export const ID3_TXXX_DESCRIPTION = "MAJIK-SIGNATURE";

/** ZIP entry name for Office formats (DOCX/XLSX/PPTX) */
export const OFFICE_ZIP_ENTRY = "majik-signature.json";

/** MP4/MOV box type for custom metadata */
export const MP4_BOX_TYPE = "majk";

/** Custom metadata key for MKV/WebM */
export const MKV_TAG_NAME = "MAJIK_SIGNATURE";

// fflate stamps each entry's DOS date/time from `mtime`, defaulting to
// "now" if omitted. Without pinning this, rezipping identical content
// at two different times produces two different byte streams — which
// breaks the hash comparison between sign-time and verify-time even
// after fixing the strip() asymmetry below.
export const CANONICAL_MTIME = new Date(0);

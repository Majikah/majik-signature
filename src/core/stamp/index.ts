/**
 * core/stamp/index.ts
 *
 * Barrel for the stamp subsystem — dual-layer compression-resistant image signing.
 *
 * Primary API (used via MajikSignature.stampImage / verifyStamp / etc.):
 *   These are convenience wrappers on MajikSignature itself. Import this barrel
 *   only when you need the lower-level MajikImageSignature class directly, or
 *   when you need advanced primitives (pHash, DCT, Reed-Solomon, pixel row).
 *
 * Folder structure (relative to majik-signature/src/):
 *   core/stamp/
 *     index.ts                ← this file
 *     image-signature.ts      ← MajikImageSignature class
 *     core/
 *       types.ts
 *       phash.ts
 *       dct-stego.ts
 *       reed-solomon.ts
 *       stub.ts
 *       payload.ts
 *       pixel-row.ts
 *       image-utils.ts
 *
 * @example Direct use (advanced)
 * ```ts
 * import { MajikImageSignature } from '@majikah/majik-signature';
 * // or from the subpath:
 * import { MajikImageSignature } from '@majikah/majik-signature/stamp';
 *
 * const { blob } = await MajikImageSignature.sign(imageBlob, key, MajikSignature);
 * ```
 */

// ── Primary class ─────────────────────────────────────────────────────────────

export {
  MajikImageSignature,
  MajikImageSignatureError,
  MajikImageCapacityError,
} from "./image-signature.js";

export type {
  ImageVerificationResult,
  VerificationLayer,
} from "./image-signature.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export type { ImageSignatureStub, ImageSignOptions } from "./core/types.js";

// ── Advanced / testing primitives ─────────────────────────────────────────────
//
// These are intentionally not re-exported from the main majik-signature index.
// Import from '@majikah/majik-signature/stamp' if you need them directly.

export { computePHash, hammingDistance, pHashMatches } from "./core/phash.js";

export { dctEmbed, dctExtract, dctCapacity } from "./core/dct-stego.js";

export {
  rsEncode,
  rsDecode,
  RS_DATA_BYTES,
  RS_ECC_BYTES,
  RS_TOTAL_BYTES,
} from "./core/reed-solomon.js";

export { serializeStub, deserializeStub, STUB_SIZE } from "./core/stub.js";

export { buildImageSigningPayload } from "./core/payload.js";

export {
  pixelRowEmbed,
  pixelRowExtract,
  pixelRowStrip,
  pixelRowHasSignature,
} from "./core/pixel-row.js";

export {
  decodeImage,
  encodeImage,
  padToMinimum,
  MIN_DIMENSION,
} from "./core/image-utils.js";

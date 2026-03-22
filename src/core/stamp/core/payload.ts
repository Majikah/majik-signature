/**
 * payload.ts — Canonical signing payload for image signatures
 *
 * The Ed25519 signature covers a deterministic byte string that binds:
 *   - The domain prefix (prevents cross-protocol attacks)
 *   - The signer's identity
 *   - The timestamp
 *   - The perceptual hash of the image
 *
 * Format:
 *   "majik-image-v1:" + JSON.stringify({ v, id, ts, pHash })
 *
 * The JSON object is sorted by key for determinism. The string is then
 * UTF-8 encoded to produce the final bytes that are signed.
 */

import type { ImageSigningPayloadFields } from "./types";

const DOMAIN_PREFIX = "majik-image-v1:";

/**
 * Build the canonical byte payload that Ed25519 signs.
 * Must be deterministic — same inputs always produce same bytes.
 */
export function buildImageSigningPayload(
  fields: ImageSigningPayloadFields,
): Uint8Array {
  // Sorted keys for determinism across JSON implementations
  const obj = {
    id: fields.signerId,
    pHash: fields.pHash,
    ts: fields.timestamp,
    v: 1,
  };

  const canonical = DOMAIN_PREFIX + JSON.stringify(obj);
  return new TextEncoder().encode(canonical);
}

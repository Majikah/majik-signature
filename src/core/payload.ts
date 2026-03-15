/**
 * payload.ts
 *
 * Canonical signing payload construction.
 *
 * Both Ed25519 and ML-DSA-87 sign the SAME payload bytes.
 * The payload encodes: version, signerId, timestamp, contentType, contentHash.
 *
 * Format:
 *   "majik-signature-v1:" + JSON.stringify({ v, id, ts, ct, hash })
 *
 * where:
 *   v    — envelope version (integer)
 *   id   — signer fingerprint (string)
 *   ts   — ISO 8601 timestamp (string)
 *   ct   — content type or null
 *   hash — SHA-256 of original content, base64 (string)
 *
 * The domain prefix prevents cross-protocol misuse.
 * JSON key order is fixed — same input always produces same bytes.
 */

import { MAJIK_SIGNATURE_DOMAIN, MAJIK_SIGNATURE_VERSION } from "./constants";

export interface PayloadFields {
  signerId: string;
  timestamp: string;
  contentHash: string;
  contentType?: string;
}

/**
 * Build the canonical byte payload that both algorithms sign and verify.
 * Deterministic: identical inputs always produce identical bytes.
 */
export function buildSigningPayload(fields: PayloadFields): Uint8Array {
  const meta = JSON.stringify({
    v: MAJIK_SIGNATURE_VERSION,
    id: fields.signerId,
    ts: fields.timestamp,
    ct: fields.contentType ?? null,
    hash: fields.contentHash,
  });
  const prefix = new TextEncoder().encode(MAJIK_SIGNATURE_DOMAIN);
  const body = new TextEncoder().encode(meta);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

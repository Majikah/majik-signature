/**
 * payload.ts
 *
 * Canonical signing payload construction.
 *
 * Both Ed25519 and ML-DSA-87 sign the SAME payload bytes.
 * The payload encodes: version, signerId, timestamp, contentType, contentHash,
 * and — when an allowlist is being established — allowlistHash.
 *
 * Format:
 *   "majik-signature-v1:" + JSON.stringify({ v, id, ts, ct, hash[, alh] })
 *
 * where:
 *   v    — envelope version (integer)
 *   id   — signer fingerprint (string)
 *   ts   — ISO 8601 timestamp (string)
 *   ct   — content type or null
 *   hash — SHA-256 of original content, base64 (string)
 *   alh  — SHA-256 of canonical allowlist JSON, base64 (string) — OMITTED when
 *           not set. Omitting preserves byte-identical payloads for all signatures
 *           made before allowlist support was introduced (backward compat).
 *
 * The domain prefix prevents cross-protocol misuse.
 * JSON key order is fixed — same input always produces same bytes.
 *
 * Backward compatibility rule:
 *   `alh` is only included in the JSON when allowlistHash is explicitly provided.
 *   When absent it is NOT defaulted to null — omitting it entirely keeps the
 *   payload bytes identical to what pre-multi-sig signers produced, so all
 *   existing signatures continue to verify correctly.
 */

import { MAJIK_SIGNATURE_DOMAIN, MAJIK_SIGNATURE_VERSION } from "./constants";

export interface PayloadFields {
  signerId: string;
  timestamp: string;
  contentHash: string;
  contentType?: string;
  /**
   * SHA-256 hash of the canonical allowlist JSON (base64).
   * Included in the payload only when the signer is establishing an allowlist.
   * Must be omitted entirely (not null) for all other signatures.
   */
  allowlistHash?: string;
}

/**
 * Build the canonical byte payload that both algorithms sign and verify.
 * Deterministic: identical inputs always produce identical bytes.
 *
 * `alh` is conditionally spread — present only when allowlistHash is provided.
 * This is the load-bearing backward-compat guarantee: old signatures never had
 * `alh` in their payload, so we must not add it (even as null) when verifying them.
 */
export function buildSigningPayload(fields: PayloadFields): Uint8Array {
  const meta = JSON.stringify({
    v: MAJIK_SIGNATURE_VERSION,
    id: fields.signerId,
    ts: fields.timestamp,
    ct: fields.contentType ?? null,
    hash: fields.contentHash,
    // Conditionally include alh — omitting it entirely preserves byte-identical
    // payloads for all pre-allowlist signatures (backward compat).
    ...(fields.allowlistHash !== undefined
      ? { alh: fields.allowlistHash }
      : {}),
  });
  const prefix = new TextEncoder().encode(MAJIK_SIGNATURE_DOMAIN);
  const body = new TextEncoder().encode(meta);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

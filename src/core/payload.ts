/**
 * payload.ts
 *
 * Canonical signing payload construction.
 *
 * Both Ed25519 and ML-DSA-87 sign the SAME payload bytes.
 * The payload encodes: version, signerId, timestamp, contentType, contentHash,
 * and — when an allowlist is being established — allowlistHash, and validUntil
 *
 */

import { ISODateString, MajikKeyFingerprint } from "@majikah/majik-key";
import {
  MAJIK_SIGNATURE_DOMAIN,
  MAJIK_SIGNATURE_VERSION,
  MAJIK_TSA_DOMAIN,
} from "./constants";
import { MajikTSAPayload } from "./types";

export interface PayloadFields {
  signerId: MajikKeyFingerprint;
  timestamp: ISODateString;
  contentHash: string;
  contentType?: string;
  /**
   * SHA-256 hash of the canonical allowlist JSON (base64).
   * Included in the payload only when the signer is establishing an allowlist.
   * Must be omitted entirely (not null) for all other signatures.
   */
  allowlistHash?: string;

  validUntil?: ISODateString;

  versionChainHash?: string;
}

/**
 * Build the canonical byte payload that both algorithms sign and verify.
 * Deterministic: identical inputs always produce identical bytes.
 *
 * `alh` and `vu` are conditionally spread — present only when allowlistHash /
 * validUntil are provided. This is the load-bearing backward-compat guarantee:
 * old signatures never had these keys in their payload, so we must not add
 * them (even as null) when verifying old signatures.
 */
export function buildSigningPayload(fields: PayloadFields): Uint8Array {
  const meta = JSON.stringify({
    v: MAJIK_SIGNATURE_VERSION,
    id: fields.signerId,
    ts: fields.timestamp,
    ct: fields.contentType ?? null,
    hash: fields.contentHash,
    ...(fields.allowlistHash !== undefined
      ? { alh: fields.allowlistHash }
      : {}),
    ...(fields.validUntil !== undefined ? { vu: fields.validUntil } : {}),
    ...(fields.versionChainHash !== undefined
      ? { vch: fields.versionChainHash }
      : {}),
  });
  const prefix = new TextEncoder().encode(MAJIK_SIGNATURE_DOMAIN);
  const body = new TextEncoder().encode(meta);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

export function buildTSACanonicalBytes(payload: MajikTSAPayload): Uint8Array {
  const meta = JSON.stringify({
    digest: payload.digest,
    nonce: payload.nonce,
    timestamp: payload.timestamp,
    tsa: payload.tsa,
  });
  const prefix = new TextEncoder().encode(MAJIK_TSA_DOMAIN);
  const body = new TextEncoder().encode(meta);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

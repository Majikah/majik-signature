/**
 * core/payload.ts
 *
 * Canonical signing-payload construction for Majik Signature.
 *
 * @remarks
 * This module is the single source of truth for the exact byte sequences used
 * by Majik Signature's cryptographic signing and verification operations.
 * Both Ed25519 and ML-DSA-87 operate on the **same canonical bytes** produced
 * here; changing the field names, field presence rules, JSON structure, domain
 * prefix, or encoding changes the signed message and therefore breaks
 * compatibility with previously generated signatures.
 *
 * The regular signature payload is domain-separated with `MAJIK_SIGNATURE_DOMAIN`
 * and binds the signer identity, signing timestamp, content digest, advisory
 * content type, and—when applicable—allowlist, expiry, and revision-chain
 * commitments.
 *
 * The TSA payload uses a separate domain (`MAJIK_TSA_DOMAIN`) so timestamp
 * attestations cannot be confused with ordinary content signatures.
 */

import { ISODateString, MajikKeyFingerprint } from "@majikah/majik-key";
import {
  MAJIK_SIGNATURE_DOMAIN,
  MAJIK_SIGNATURE_VERSION,
  MAJIK_TSA_DOMAIN,
} from "./constants";
import { MajikTSAPayload } from "./types";

/**
 * Fields used to construct a canonical Majik Signature signing payload.
 *
 * @remarks
 * These fields are serialized into the versioned, domain-separated payload
 * consumed by both Ed25519 and ML-DSA-87.
 *
 * Optional fields are intentionally **omitted** when `undefined`; they are not
 * serialized as `null`. This distinction is part of the compatibility contract
 * for signatures created before those fields existed.
 */
export interface PayloadFields {
  /**
   * Majik Key fingerprint identifying the signer.
   *
   * @remarks
   * This value is copied into the canonical payload as `id`, binding the
   * signature to the signer's Majik Key identity.
   */
  signerId: MajikKeyFingerprint;

  /**
   * ISO 8601 timestamp representing when the signature was created.
   *
   * @remarks
   * Serialized as `ts`. Because it is part of the signed payload, changing the
   * timestamp after signing invalidates both the Ed25519 and ML-DSA-87
   * signatures.
   */
  timestamp: ISODateString;

  /**
   * Base64-encoded SHA-256 digest of the original content being signed.
   *
   * @remarks
   * Serialized as `hash`. The content itself is never included in the signing
   * payload; only its digest is signed. This keeps the payload small and makes
   * the same signing model applicable to strings, documents, media, and raw
   * binary data.
   */
  contentHash: string;

  /**
   * Optional advisory content-type label, such as `application/pdf` or
   * `audio/wav`.
   *
   * @remarks
   * Serialized as `ct`. When omitted, the canonical payload explicitly uses
   * `null` for this field. The value is metadata, not a security boundary;
   * verification does not rely on the declared content type to establish
   * content integrity.
   */
  contentType?: string;

  /**
   * Base64-encoded SHA-256 hash of the canonical allowlist JSON.
   *
   * @remarks
   * Serialized as `alh` **only when defined**. It is used when a signature
   * establishes or recommits to a signing allowlist, cryptographically binding
   * the signer to the expected signer set.
   *
   * Do not pass `null` to represent absence. Omitting this property entirely is
   * required for signatures that do not carry an allowlist commitment and is
   * essential for backward compatibility with older signatures.
   */
  allowlistHash?: string;

  /**
   * Optional ISO 8601 expiry timestamp for the signature.
   *
   * @remarks
   * Serialized as `vu` only when defined. Verification treats the signature as
   * expired once the current verification time is past this value. Because the
   * expiry is part of the canonical payload, it cannot be changed, removed, or
   * extended without invalidating the signature.
   */
  validUntil?: ISODateString;

  /**
   * Optional base64-encoded SHA-256 commitment to the file revision chain.
   *
   * @remarks
   * Serialized as `vch` only when defined. In revision-aware multi-signature
   * workflows, this commits the signer to the exact revision-chain state that
   * existed when they signed, allowing later verification to detect rewritten
   * chain metadata.
   */
  versionChainHash?: string;
}

/**
 * Build the canonical byte payload signed by both Majik Signature algorithms.
 *
 * @remarks
 * The payload has two layers:
 *
 * 1. A domain-separation prefix from `MAJIK_SIGNATURE_DOMAIN`.
 * 2. A UTF-8 encoded JSON object containing the canonical signing metadata.
 *
 * The JSON field names are intentionally compact and stable:
 * `v`, `id`, `ts`, `ct`, `hash`, `alh`, `vu`, and `vch`.
 *
 * `alh`, `vu`, and `vch` are conditionally included only when their
 * corresponding properties are defined. They must not be introduced as
 * `null` placeholders because omission is part of the on-wire compatibility
 * contract. In particular, older signatures did not contain these fields and
 * must reconstruct the exact payload shape they originally signed.
 *
 * `JSON.stringify()` and `TextEncoder` are deliberately used here so that the
 * same deterministic serialization and UTF-8 encoding are used for signing and
 * verification. Callers should pass already-normalized values and should not
 * attempt to reconstruct the payload manually.
 *
 * @param fields - Canonical metadata describing the signature being created
 *   or verified.
 * @returns The exact UTF-8 byte sequence that both Ed25519 and ML-DSA-87 must
 *   sign or verify.
 *
 * @example
 * ```ts
 * const payload = buildSigningPayload({
 *   signerId,
 *   timestamp: "2026-01-01T00:00:00.000Z",
 *   contentHash,
 *   contentType: "application/pdf",
 * });
 *
 * // Pass `payload` directly to the signing/verification primitives.
 * ```
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

/**
 * Build the canonical byte payload signed by a Trusted Timestamp Authority.
 *
 * @remarks
 * TSA payloads are domain-separated from ordinary Majik Signatures using
 * `MAJIK_TSA_DOMAIN`. The canonical JSON payload contains exactly four values:
 *
 * - `digest` — the SHA-256 digest being attested
 * - `nonce` — the server-generated nonce for the TSA issuance
 * - `timestamp` — the server-authoritative timestamp
 * - `tsa` — the TSA identity metadata
 *
 * The resulting bytes are what the TSA-controlled Majik Key signs with the
 * same Ed25519 + ML-DSA-87 hybrid mechanism used elsewhere in the library.
 * Keeping this construction centralized prevents clients and TSA servers from
 * accidentally signing different byte representations of the same timestamp
 * request.
 *
 * @param payload - Complete TSA payload to serialize into the canonical,
 *   domain-separated byte representation.
 * @returns The exact UTF-8 byte sequence that the TSA signer must sign or that
 *   a verifier must reconstruct before checking the TSA signature.
 *
 * @example
 * ```ts
 * const tsaBytes = buildTSACanonicalBytes({
 *   digest: { algorithm: "SHA-256", value: contentHash },
 *   nonce,
 *   timestamp,
 *   tsa: {
 *     id: "tsa.majikah.solutions",
 *     signerFingerprint: tsaKey.fingerprint,
 *   },
 * });
 * ```
 */
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

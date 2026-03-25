/**
 * core/multi-sig.ts
 *
 * Pure utility functions for multi-signature envelope handling.
 *
 * Responsibilities:
 *   - Normalize old single-sig and new multi-sig on-disk formats (parseEnvelope)
 *   - Upsert a signature into an envelope by signerId (upsertSignature)
 *   - Check whether a signer is permitted by an allowlist (checkAllowlist)
 *   - Produce a deterministic hash of an allowlist (hashAllowlist)
 *   - Produce a deterministic SHA3-512 seal hash (computeSealHash)
 *   - Build a structured SignatoriesResult from an envelope (buildSignatoriesResult)
 *
 * No classes, no side effects — safe to import anywhere.
 *
 * Backward compatibility:
 *   Old files embed a bare MajikSignatureJSON object (has `edSignature` field).
 *   parseEnvelope detects this shape and silently promotes it to a
 *   single-item MultiSigEnvelope with no allowlist. All callers always
 *   receive MultiSigEnvelope — the old shape is an implementation detail
 *   of this module only.
 */

import type { MajikKey } from "@majikah/majik-key";
import { sha3_512 } from "@noble/hashes/sha3.js";

import { MAJIK_ENVELOPE_VERSION, MAJIK_SEAL_DOMAIN } from "./constants";
import { MajikSignatureSerializationError } from "./errors";
import { hashContent, bytesToBase64 } from "./hash";
import type {
  ExpectedSigner,
  MajikSignatureJSON,
  MultiSigEnvelope,
  SignatoryInfo,
  SignatoriesResult,
} from "./types";
import { bytesToHex } from "@noble/hashes/utils.js";

// ─── Allowlist check result ───────────────────────────────────────────────────

export type AllowlistCheckResult =
  | { permitted: true; entry: ExpectedSigner | null } // null = open signing
  | { permitted: false; entry: null }; // not on allowlist

// ─── Envelope parsing ─────────────────────────────────────────────────────────

/**
 * Parse a raw JSON string extracted from a file into a MultiSigEnvelope.
 *
 * Handles three on-disk shapes gracefully:
 *
 *   1. NEW — MultiSigEnvelope: { version, signatures: [...], allowlist?: [...] }
 *      Passed through as-is after basic shape validation.
 *
 *   2. OLD — bare MajikSignatureJSON: { version, edSignature, signerId, ... }
 *      Promoted silently to { version: 1, signatures: [thatObject] }.
 *      No allowlist is set — the file is treated as open signing.
 *
 *   3. Anything else — throws MajikSignatureSerializationError.
 *
 * This is the ONLY place in the codebase that knows about the old format.
 * Everything above this function always works with MultiSigEnvelope.
 */
export function parseEnvelope(raw: string): MultiSigEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new MajikSignatureSerializationError(
      "Embedded signature payload is not valid JSON",
      err,
    );
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new MajikSignatureSerializationError(
      "Embedded signature payload must be a JSON object",
    );
  }

  const obj = parsed as Record<string, unknown>;

  // ── NEW format: MultiSigEnvelope ──────────────────────────────────────────
  // Discriminator: has a `signatures` array at the root.
  if (Array.isArray(obj.signatures)) {
    return obj as unknown as MultiSigEnvelope;
  }

  // ── OLD format: bare MajikSignatureJSON ───────────────────────────────────
  // Discriminator: has `edSignature` string — only individual envelopes have this.
  // Promote silently to a single-item MultiSigEnvelope with no allowlist.
  if (typeof obj.edSignature === "string") {
    return {
      version: MAJIK_ENVELOPE_VERSION,
      signatures: [obj as unknown as MajikSignatureJSON],
    };
  }

  throw new MajikSignatureSerializationError(
    "Unrecognised signature envelope format — expected MultiSigEnvelope or MajikSignatureJSON",
  );
}

// ─── Signature upsert ─────────────────────────────────────────────────────────

/**
 * Upsert a MajikSignatureJSON into a MultiSigEnvelope by signerId.
 *
 * - If the signer already has an entry, it is replaced (re-sign).
 * - If the signer is new, their entry is appended.
 * - The envelope's allowlist, allowlistSignerId, and seal fields are preserved.
 * - Returns a new envelope object — the input is not mutated.
 */
export function upsertSignature(
  envelope: MultiSigEnvelope,
  sig: MajikSignatureJSON,
): MultiSigEnvelope {
  const sigs = [...envelope.signatures];
  const idx = sigs.findIndex((s) => s.signerId === sig.signerId);
  if (idx >= 0) {
    sigs[idx] = sig;
  } else {
    sigs.push(sig);
  }
  return { ...envelope, signatures: sigs };
}

// ─── Allowlist enforcement ────────────────────────────────────────────────────

/**
 * Check whether a MajikKey is permitted to sign according to the envelope's allowlist.
 *
 * Return values:
 *   { permitted: true,  entry: null }          — no allowlist, open signing
 *   { permitted: true,  entry: ExpectedSigner } — signer is on the allowlist
 *   { permitted: false, entry: null }           — allowlist exists, signer not on it
 *
 * All three fields must match: signerId (fingerprint), edPublicKey, mlDsaPublicKey.
 * This prevents a signer from spoofing allowlist membership with a different key
 * that happens to share a fingerprint.
 */
export function checkAllowlist(
  envelope: MultiSigEnvelope,
  key: MajikKey,
): AllowlistCheckResult {
  // No allowlist — open signing, any signer permitted
  if (!envelope.allowlist || envelope.allowlist.length === 0) {
    return { permitted: true, entry: null };
  }

  const edPub = bytesToBase64(key.edPublicKey!);
  const mlPub = bytesToBase64(key.mlDsaPublicKey!);

  const match = envelope.allowlist.find(
    (e) =>
      e.signerId === key.fingerprint &&
      e.edPublicKey === edPub &&
      e.mlDsaPublicKey === mlPub,
  );

  if (match === undefined) {
    // Allowlist present but signer not found
    return { permitted: false, entry: null };
  }

  // Signer found on allowlist
  return { permitted: true, entry: match };
}

// ─── Allowlist hashing ────────────────────────────────────────────────────────

/**
 * Produce a deterministic SHA-256 hash of an allowlist.
 * Entries are sorted by signerId before serialization — order-independent.
 */
export function hashAllowlist(allowlist: ExpectedSigner[]): string {
  const sorted = [...allowlist].sort((a, b) =>
    a.signerId.localeCompare(b.signerId),
  );
  const canonical = JSON.stringify(sorted);
  return bytesToBase64(hashContent(canonical));
}

// ─── Seal hash ────────────────────────────────────────────────────────────────

/**
 * Compute the SHA3-512 seal hash over all current signatories and the seal timestamp.
 *
 * Canonical input:
 *   MAJIK_SEAL_DOMAIN + JSON({ ts, signatories: [{ signerId, edPublicKey, mlDsaPublicKey }] })
 *
 * Signatories are sorted by signerId for determinism.
 * The domain prefix prevents cross-protocol reuse of the seal hash.
 *
 * Using SHA3-512 (not SHA-256) so the seal hash is visually and structurally
 * distinct from other hashes in the envelope — different algorithm, different length.
 */
export function computeSealHash(
  signatures: MajikSignatureJSON[],
  sealTimestamp: string,
): string {
  const signatories = [...signatures]
    .sort((a, b) => a.signerId.localeCompare(b.signerId))
    .map((s) => ({
      signerId: s.signerId,
      edPublicKey: s.signerEdPublicKey,
      mlDsaPublicKey: s.signerMlDsaPublicKey,
    }));

  const body = JSON.stringify({ ts: sealTimestamp, signatories });
  const domainBytes = new TextEncoder().encode(MAJIK_SEAL_DOMAIN);
  const bodyBytes = new TextEncoder().encode(body);

  const input = new Uint8Array(domainBytes.length + bodyBytes.length);
  input.set(domainBytes, 0);
  input.set(bodyBytes, domainBytes.length);

  // SHA3-512 returns 64 bytes → 88 base64 chars
  const hashBytes = sha3_512(input);
  return bytesToHex(hashBytes);
}

// ─── Signatories result builder ───────────────────────────────────────────────

/**
 * Build a SignatoriesResult from a MultiSigEnvelope.
 *
 * When an allowlist is present, the result is built from the allowlist
 * (expected signatories) cross-referenced against actual signatures.
 *
 * When no allowlist is present, the result is built from actual signatures
 * only — every signer is "signed", pending is empty.
 *
 * Returns null when the envelope has no allowlist AND no signatures.
 */
// Inside multi-sig.ts

export function buildSignatoriesResult(
  envelope: MultiSigEnvelope,
): SignatoriesResult | null {
  const signedMap = new Map<string, MajikSignatureJSON>(
    envelope.signatures.map((s) => [s.signerId, s]),
  );

  if (envelope.allowlist && envelope.allowlist.length > 0) {
    const allMap = new Map<string, SignatoryInfo>();

    // 1. Add everyone from the allowlist (Expected)
    for (const entry of envelope.allowlist) {
      const sig = signedMap.get(entry.signerId);
      allMap.set(entry.signerId, {
        signerId: entry.signerId,
        edPublicKey: entry.edPublicKey,
        mlDsaPublicKey: entry.mlDsaPublicKey,
        hasSigned: sig !== undefined,
        signedAt: sig?.timestamp,
      });
    }

    // 2. Add actual signers who might not be in the allowlist (e.g., the Issuer)
    for (const sig of envelope.signatures) {
      if (!allMap.has(sig.signerId)) {
        allMap.set(sig.signerId, {
          signerId: sig.signerId,
          edPublicKey: sig.signerEdPublicKey,
          mlDsaPublicKey: sig.signerMlDsaPublicKey,
          hasSigned: true,
          signedAt: sig.timestamp,
        });
      }
    }

    const all = Array.from(allMap.values());
    return {
      all,
      signed: all.filter((s) => s.hasSigned),
      pending: all.filter((s) => !s.hasSigned),
    };
  }

  // Without allowlist: actual signatures only
  if (envelope.signatures.length === 0) return null;

  const all: SignatoryInfo[] = envelope.signatures.map((sig) => ({
    signerId: sig.signerId,
    edPublicKey: sig.signerEdPublicKey,
    mlDsaPublicKey: sig.signerMlDsaPublicKey,
    hasSigned: true,
    signedAt: sig.timestamp,
  }));

  return {
    all,
    signed: all,
    pending: [],
  };
}

// ─── Allowlist construction helper ───────────────────────────────────────────

/**
 * Build an ExpectedSigner entry from a MajikKey.
 * Extracts all three required fields (fingerprint + both public keys) in base64.
 * The key does not need to be unlocked — only public fields are read.
 */
export function expectedSignerFromKey(key: MajikKey): ExpectedSigner {
  return {
    signerId: key.fingerprint,
    edPublicKey: bytesToBase64(key.edPublicKey!),
    mlDsaPublicKey: bytesToBase64(key.mlDsaPublicKey!),
  };
}

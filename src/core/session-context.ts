/**
 * Canonical SignRoom session-context commitment helpers.
 */
import { bytesToBase64, base64ToBytes, sha256Bytes } from "./hash.js";

/** Authoritative session, one-time challenge, and immutable policy identifiers committed by a SignRoom participant. */
export interface MajikSessionSigningContext {
  /** Stable session identifier assigned by the session service. */
  sessionId: string;
  /** Single-use challenge identifier issued for this signing attempt. */
  challengeId: string;
  /** Base64-encoded SHA-256 hash of the immutable session policy snapshot. */
  policyHash: string;
}

/** Domain separator for the version-1 SignRoom session-context hash. Changing it breaks existing session-bound signatures. */
export const MAJIK_SESSION_CONTEXT_DOMAIN =
  "majik-signature-session-context-v1:" as const;

function validateIdentifier(
  value: unknown,
  field: string,
): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    value.trim() !== value
  ) {
    throw new TypeError(
      `${field} must be a non-empty string of at most 256 characters without surrounding whitespace`,
    );
  }
}

function validatePolicyHash(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length !== 44) {
    throw new TypeError("policyHash must be a base64-encoded SHA-256 digest");
  }
  try {
    const decoded = base64ToBytes(value);
    if (decoded.length !== 32 || bytesToBase64(decoded) !== value) {
      throw new TypeError("non-canonical digest");
    }
  } catch {
    throw new TypeError(
      "policyHash must be a canonical base64-encoded SHA-256 digest",
    );
  }
}

/**
 * Build the base64 SHA-256 commitment signed by each SignRoom participant.
 * Use this helper on both the signing client and the server; the prefix and
 * canonical property order are protocol constants.
 */
export function buildSessionContextHash(
  context: MajikSessionSigningContext,
): string {
  if (!context || typeof context !== "object") {
    throw new TypeError("session signing context must be an object");
  }
  validateIdentifier(context.sessionId, "sessionId");
  validateIdentifier(context.challengeId, "challengeId");
  validatePolicyHash(context.policyHash);

  const canonical = JSON.stringify({
    v: 1,
    sessionId: context.sessionId,
    challengeId: context.challengeId,
    policyHash: context.policyHash,
  });
  const prefix = new TextEncoder().encode(MAJIK_SESSION_CONTEXT_DOMAIN);
  const body = new TextEncoder().encode(canonical);
  const bytes = new Uint8Array(prefix.length + body.length);
  bytes.set(prefix, 0);
  bytes.set(body, prefix.length);
  return bytesToBase64(sha256Bytes(bytes));
}

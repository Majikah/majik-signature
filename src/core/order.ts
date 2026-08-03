/**
 * core/order.ts
 *
 * Chronological signing-order verification.
 *
 * Pure /structural, like envelope.ts — no MajikSig-specific imports beyond a
 * caller-supplied verify callback, so this has zero circular-dependency risk
 * with majik-signature.ts or majik-embed.ts.
 *
 * Trust model:
 *   - tsa.payload.timestamp is server-attested (a TSA stamped a nonce) —
 *     preferred whenever present.
 *   - The bare `timestamp` field is self-reported by the signer's local
 *     clock. It's tamper-evident (covered by the signature) but NOT
 *     independently attested — a signer could set their clock to anything.
 *   - Every result surfaces `usesUnattestedTimestamp` so callers can show
 *     a caveat when order was decided using a self-reported clock.
 */

import type { MajikKey } from "@majikah/majik-key";
import {
  MajikSignatureKeyError,
  MajikSignatureValidationError,
} from "./errors";
import { base64ToBytes, bytesToBase64 } from "./hash";
import type { MajikSignatureEnvelope } from "./envelope";
import type {
  ExpectedSigner,
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  VerificationResult,
} from "./types";

// ─── Public types ──────────────────────────────────────────────────────────

export type TimestampSource = "tsa" | "self-reported";

export interface SignerOrderStatus {
  signerId: string;
  expectedPosition: number;
  hasSigned: boolean;
  /** Present only when hasSigned is true */
  valid?: boolean;
  /** Present only when hasSigned && !valid */
  reason?: string;
  effectiveTimestamp?: string;
  timestampSource?: TimestampSource;
}

export interface OrderViolation {
  /** signerId expected to have signed earlier */
  earlier: string;
  /** signerId expected to have signed later */
  later: string;
  earlierTimestamp: string;
  laterTimestamp: string;
}

export interface SoftTieWarning {
  a: string;
  b: string;
  timestamp: string;
}

export interface SignatureOrderResult {
  /** True only when everyone expected signed, every signature is valid,
   *  the order was respected, AND (in strict mode) no extra signers exist. */
  valid: boolean;
  allExpectedSigned: boolean;
  allValid: boolean;
  orderRespected: boolean;
  strict: boolean;
  /** Only populated when strict === true */
  unexpectedSigners: string[];
  pendingSigners: string[];
  invalidSigners: string[];
  violations: OrderViolation[];
  /** True if any timestamp used in a comparison was self-reported rather
   *  than TSA-attested — order in that case is a claim, not a proof. */
  usesUnattestedTimestamp: boolean;
  /** Two signers landed on the identical instant — order between them is
   *  indistinguishable. Doesn't fail `valid`, just a note. */
  softTieWarnings: SoftTieWarning[];
  signers: SignerOrderStatus[];
  reason?: string;
}

export interface VerifySignatureOrderOptions {
  /** When true, any signer present in the envelope but absent from
   *  expectedOrder is reported and fails the overall result. */
  strict?: boolean;
}

/** Minimal shape the order verifier needs to check one signature's crypto. */
export type OrderVerifyFn = (
  content: Uint8Array,
  signature: MajikSignatureJSON,
  publicKeys: MajikSignerPublicKeys,
) => VerificationResult;

// ─── Normalization ─────────────────────────────────────────────────────────

function isExpectedSignerShape(
  v: MajikKey | ExpectedSigner,
): v is ExpectedSigner {
  return typeof (v as ExpectedSigner).edPublicKey === "string";
}

function toExpectedSigner(input: MajikKey | ExpectedSigner): ExpectedSigner {
  if (isExpectedSignerShape(input)) return input;

  const key = input as MajikKey;
  if (!key.hasSigningKeys) {
    throw new MajikSignatureKeyError(
      "MajikKey has no signing public keys — cannot build expected order entry.",
    );
  }
  return {
    signerId: key.fingerprint,
    edPublicKey: bytesToBase64(key.edPublicKey!),
    mlDsaPublicKey: bytesToBase64(key.mlDsaPublicKey!),
  };
}

/**
 * Normalize a mixed array of MajikKey instances and/or ExpectedSigner
 * objects into a plain ExpectedSigner[]. Order-preserving — position in
 * the input array IS the expected signing position.
 */
export function normalizeExpectedOrder(
  input: readonly (MajikKey | ExpectedSigner)[],
): ExpectedSigner[] {
  return input.map(toExpectedSigner);
}

// ─── Timestamp resolution ───────────────────────────────────────────────────

export function resolveEffectiveTimestamp(sig: MajikSignatureJSON): {
  timestamp: string;
  source: TimestampSource;
} {
  if (sig.tsa?.payload?.timestamp) {
    return { timestamp: sig.tsa.payload.timestamp, source: "tsa" };
  }
  return { timestamp: sig.timestamp, source: "self-reported" };
}

// ─── Core verification ───────────────────────────────────────────────────────

/**
 * Verify that an envelope's signatures were produced in the sequence given
 * by expectedOrder (array position == expected chronological position).
 *
 * Each expected signer is verified against THEIR OWN publicly-known keys
 * (as supplied in expectedOrder), not the self-asserted keys embedded in
 * their own envelope entry — this ties identity to a key you actually
 * trust, rather than trusting whatever key a signature claims to be signed
 * with.
 *
 * Only signers who (a) signed and (b) verified valid are compared for
 * order — an invalid signature's timestamp isn't trustworthy, so it's
 * excluded from ordering but still reported via invalidSigners.
 */
export function verifySignatureOrder(
  envelope: MajikSignatureEnvelope,
  originalBytes: Uint8Array,
  expectedOrder: readonly (MajikKey | ExpectedSigner)[],
  verifyFn: OrderVerifyFn,
  options?: VerifySignatureOrderOptions,
): SignatureOrderResult {
  const strict = options?.strict ?? false;
  const normalizedExpected = normalizeExpectedOrder(expectedOrder);

  if (normalizedExpected.length === 0) {
    throw new MajikSignatureValidationError(
      "expectedOrder must contain at least one signer.",
      "expectedOrder",
    );
  }

  const seenIds = new Set<string>();
  for (const e of normalizedExpected) {
    if (seenIds.has(e.signerId)) {
      throw new MajikSignatureValidationError(
        `Duplicate signerId in expectedOrder: "${e.signerId}"`,
        "expectedOrder",
      );
    }
    seenIds.add(e.signerId);
  }

  const sigsById = new Map(envelope.signatures.map((s) => [s.signerId, s]));

  const signers: SignerOrderStatus[] = [];
  const pendingSigners: string[] = [];
  const invalidSigners: string[] = [];
  let usesUnattestedTimestamp = false;

  // Only expected signers who signed AND verified valid are eligible for
  // order comparison — their timestamps are the only trustworthy ones.
  const considered: {
    signerId: string;
    timestamp: string;
    timeMs: number;
  }[] = [];

  for (let i = 0; i < normalizedExpected.length; i++) {
    const expected = normalizedExpected[i];
    const sig = sigsById.get(expected.signerId);

    if (!sig) {
      pendingSigners.push(expected.signerId);
      signers.push({
        signerId: expected.signerId,
        expectedPosition: i,
        hasSigned: false,
      });
      continue;
    }

    const publicKeys: MajikSignerPublicKeys = {
      signerId: expected.signerId,
      edPublicKey: base64ToBytes(expected.edPublicKey),
      mlDsaPublicKey: base64ToBytes(expected.mlDsaPublicKey),
    };

    const result = verifyFn(originalBytes, sig, publicKeys);
    const { timestamp, source } = resolveEffectiveTimestamp(sig);

    if (!result.valid) {
      invalidSigners.push(expected.signerId);
      signers.push({
        signerId: expected.signerId,
        expectedPosition: i,
        hasSigned: true,
        valid: false,
        reason: result.reason,
        effectiveTimestamp: timestamp,
        timestampSource: source,
      });
      continue;
    }

    if (source === "self-reported") usesUnattestedTimestamp = true;

    signers.push({
      signerId: expected.signerId,
      expectedPosition: i,
      hasSigned: true,
      valid: true,
      effectiveTimestamp: timestamp,
      timestampSource: source,
    });

    considered.push({
      signerId: expected.signerId,
      timestamp,
      timeMs: Date.parse(timestamp),
    });
  }

  // ── Order check — every pair among considered signers, not just neighbors ──
  const violations: OrderViolation[] = [];
  const softTieWarnings: SoftTieWarning[] = [];

  for (let i = 0; i < considered.length; i++) {
    for (let j = i + 1; j < considered.length; j++) {
      const a = considered[i]; // expected earlier
      const b = considered[j]; // expected later

      if (a.timeMs > b.timeMs) {
        violations.push({
          earlier: a.signerId,
          later: b.signerId,
          earlierTimestamp: a.timestamp,
          laterTimestamp: b.timestamp,
        });
      } else if (a.timeMs === b.timeMs) {
        softTieWarnings.push({
          a: a.signerId,
          b: b.signerId,
          timestamp: a.timestamp,
        });
      }
    }
  }

  // ── Strict mode: any actual signer absent from expectedOrder ────────────
  const unexpectedSigners: string[] = [];
  if (strict) {
    for (const sig of envelope.signatures) {
      if (!seenIds.has(sig.signerId)) unexpectedSigners.push(sig.signerId);
    }
  }

  const allExpectedSigned = pendingSigners.length === 0;
  const allValid = invalidSigners.length === 0;
  const orderRespected = violations.length === 0;
  const strictSatisfied = !strict || unexpectedSigners.length === 0;

  const valid =
    allExpectedSigned && allValid && orderRespected && strictSatisfied;

  let reason: string | undefined;
  if (!allExpectedSigned) {
    reason = `Missing signature(s) from: ${pendingSigners.join(", ")}`;
  } else if (!allValid) {
    reason = `Invalid signature(s) from: ${invalidSigners.join(", ")}`;
  } else if (!strictSatisfied) {
    reason = `Unexpected signer(s) present (strict mode): ${unexpectedSigners.join(", ")}`;
  } else if (!orderRespected) {
    reason = `Signing order violated: ${violations
      .map(
        (v) => `"${v.earlier}" expected before "${v.later}" but signed after`,
      )
      .join("; ")}`;
  } else if (softTieWarnings.length > 0) {
    reason = `All signatures valid and in order, but ${softTieWarnings.length} pair(s) share an identical timestamp — order cannot be distinguished for: ${softTieWarnings
      .map((w) => `"${w.a}"/"${w.b}"`)
      .join(", ")}`;
  }

  return {
    valid,
    allExpectedSigned,
    allValid,
    orderRespected,
    strict,
    unexpectedSigners,
    pendingSigners,
    invalidSigners,
    violations,
    usesUnattestedTimestamp,
    softTieWarnings,
    signers,
    reason,
  };
}

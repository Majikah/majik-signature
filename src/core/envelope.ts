/**
 * core/envelope.ts
 *
 * MajikSignatureEnvelope — encapsulated multi-signature envelope.
 *
 * Replaces the free-function toolkit in multi-sig.ts with a single class that
 * owns parsing, validation, upserts, allowlist enforcement, seal computation,
 * and signatory/issuer resolution.
 *
 * Design constraints:
 *   - Pure/structural only. No crypto, no signing, no verifying signatures —
 *     that stays in MajikSignature / MajikSignatureEmbed to avoid the
 *     majik-signature ⇄ majik-embed circular dependency.
 *   - Immutable. Every "with*" method returns a new instance; the receiver
 *     is never mutated.
 *   - MajikSignatureEnvelopeJSON (alias of MultiSigEnvelope, see types.ts)
 *     is the on-the-wire shape. This class is the in-memory, behavior-rich
 *     counterpart — same relationship as MajikSignatureJSON / MajikSignature.
 */

import type { MajikKey } from "@majikah/majik-key";
import { sha3_512 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import {
  MAJIK_ENVELOPE_VERSION,
  MAJIK_SEAL_DOMAIN,
  MJKSIG_HEADER_LEN,
  MJKSIG_MAGIC,
  MJKSIG_MAGIC_LEN,
  MJKSIG_MEDIA_TYPE,
  MJKSIG_SUPPORTED_VERSIONS,
  MJKSIG_VERSION,
} from "./constants";
import {
  MajikSignatureAllowlistError,
  MajikSignatureError,
  MajikSignatureKeyError,
  MajikSignatureSerializationError,
  MajikSignatureValidationError,
} from "./errors";
import { hashContent, bytesToBase64 } from "./hash";
import type {
  EnvelopeInfo,
  EnvelopeInput,
  ExpectedSigner,
  FileLike,
  FileVersion,
  MajikSignatureEnvelopeJSON,
  MajikSignatureJSON,
  SealInfo,
  SealVerificationResult,
  SignatoriesFilter,
  SignatoriesResult,
  SignatoryInfo,
} from "./types";
import type { MajikChainAnchor } from "../anchor/types";
import { normalizeToBytes } from "./embed/utils";

// ─── Allowlist check result ───────────────────────────────────────────────────

/**
 * Result of checking whether a key matches the envelope's signing allowlist.
 *
 * @remarks
 * This type represents the allowlist check only. It does not account for
 * whether the envelope is already sealed, and it does not apply the issuer
 * bypass used by {@link MajikSignatureEnvelope.assertCanSign}.
 *
 * When the envelope has no allowlist, the check succeeds with `entry: null`,
 * indicating that the envelope is open for signing.
 *
 * When an allowlist exists, membership requires all three signer properties
 * to match the supplied key:
 *
 * - `signerId`
 * - Ed25519 public key
 * - ML-DSA-87 public key
 */
export type AllowlistCheckResult =
  | {
      /**
       * `true` when the supplied key may sign according to the allowlist.
       *
       * When no allowlist exists, `entry` is `null` because the envelope is
       * open-signing rather than matching a specific allowlist entry.
       */
      permitted: true;
      /** Matching expected signer entry, or `null` for open signing. */
      entry: ExpectedSigner | null;
    }
  | {
      /** `false` when the supplied key is not present in the allowlist. */
      permitted: false;
      /** Always `null` when permission is denied. */
      entry: null;
    };

/**
 * Non-throwing result describing whether a key may add a signature.
 *
 * @remarks
 * Returned by {@link MajikSignatureEnvelope.canSign}. Use this shape for
 * UI-facing permission checks where a boolean plus a human-readable reason
 * is more useful than catching an exception.
 */
export interface CanSignResult {
  /** Whether the supplied key is currently permitted to add a signature. */
  permitted: boolean;

  /**
   * Human-readable explanation when `permitted` is `false`.
   *
   * @remarks
   * Treat this as presentation/diagnostic text rather than a stable machine
   * error code.
   */
  reason?: string;
}

/**
 * Non-throwing result describing whether the envelope is eligible for
 * chain-anchor registration.
 *
 * @remarks
 * Anchoring is structurally permitted only after the envelope has been
 * sealed. This check does not submit anything to a blockchain and does not
 * verify an external transaction.
 */
export interface CanAnchorResult {
  /** Whether the envelope is structurally eligible for chain anchoring. */
  permitted: boolean;

  /**
   * Human-readable reason when anchoring is not currently permitted.
   *
   * @remarks
   * Treat this as presentation/diagnostic text rather than a stable machine
   * error code.
   */
  reason?: string;
}

// ─── MajikSignatureEnvelope ────────────────────────────────────────────────────

/**
 * Immutable, behavior-rich representation of a Majik Signature multi-signer
 * envelope.
 *
 * @remarks
 * `MajikSignatureEnvelope` is the in-memory counterpart to the serialized
 * {@link MajikSignatureEnvelopeJSON} / `MultiSigEnvelope` shape. It owns
 * parsing, structural validation, allowlist enforcement, seal computation,
 * revision-chain bookkeeping, and signatory/issuer resolution.
 *
 * This class is deliberately **structural only**:
 *
 * - It does not create cryptographic signatures.
 * - It does not verify signer signatures.
 * - It does not require private signing keys for its envelope operations.
 *
 * Cryptographic signing and verification remain in the higher-level
 * `MajikSignature` APIs.
 *
 * Instances are immutable. Every `with*()` builder returns a new envelope;
 * the original instance is never mutated. Getter arrays are exposed as
 * read-only views, and serialization returns fresh data.
 *
 * @example
 * ```ts
 * const envelope = MajikSignatureEnvelope.empty()
 *   .withSignature(signature);
 *
 * const next = envelope.withSeal(signerId);
 *
 * console.log(envelope.isSealed()); // false
 * console.log(next.isSealed());     // true
 * ```
 */
export class MajikSignatureEnvelope {
  private readonly _version: 1;
  private readonly _signatures: readonly MajikSignatureJSON[];
  private readonly _allowlist?: readonly ExpectedSigner[];
  private readonly _allowlistSignerId?: string;
  private readonly _sealHash?: string;
  private readonly _sealTimestamp?: string;
  private readonly _sealedBy?: string;
  private readonly _chainAnchors?: readonly MajikChainAnchor[];
  private readonly _fileVersions?: readonly FileVersion[];

  private constructor(data: MajikSignatureEnvelopeJSON) {
    this._version = data.version;
    this._signatures = data.signatures;
    this._allowlist = data.allowlist;
    this._allowlistSignerId = data.allowlistSignerId;
    this._sealHash = data.sealHash;
    this._sealTimestamp = data.sealTimestamp;
    this._sealedBy = data.sealedBy;
    this._chainAnchors = data.chainAnchors;
    this._fileVersions = data.fileVersions;
  }

  // ── Getters ─────────────────────────────────────────────────────────────────

  /**
   * Envelope schema version.
   *
   * @remarks
   * The current public envelope version is always `1`. This is the
   * application-level envelope version, distinct from the MJKSIG binary
   * container version exposed by {@link MajikSignatureEnvelope.getMJKSIGVersion}.
   */
  get version(): 1 {
    return this._version;
  }
  /**
   * Per-signer signature envelopes currently contained in this envelope.
   *
   * @remarks
   * Each entry is logically identified by `signerId`. Use
   * {@link MajikSignatureEnvelope.findSignature} for a direct lookup.
   *
   * The returned array is read-only from the type system; use
   * {@link MajikSignatureEnvelope.withSignature} to replace or append an
   * entry without mutating this instance.
   */
  get signatures(): readonly MajikSignatureJSON[] {
    return this._signatures;
  }
  /**
   * Expected signer entries restricting who may sign the envelope.
   *
   * @returns The immutable allowlist when one has been established, or
   * `undefined` for an open-signing envelope.
   *
   * @remarks
   * An allowlist can only be established once and is tied to
   * {@link MajikSignatureEnvelope.allowlistSignerId}. Use
   * {@link MajikSignatureEnvelope.withAllowlist} to create a new envelope
   * with an allowlist.
   */
  get allowlist(): readonly ExpectedSigner[] | undefined {
    return this._allowlist;
  }
  /**
   * Fingerprint of the signer who established the allowlist.
   *
   * @remarks
   * When an allowlist exists, this identifies the issuer and the signer
   * authorized to seal the envelope. It is an identifier lookup only; use
   * cryptographic verification elsewhere when authenticity of the signer
   * itself matters.
   */
  get allowlistSignerId(): string | undefined {
    return this._allowlistSignerId;
  }
  /**
   * SHA3-512 seal digest, hex-encoded, when the envelope is sealed.
   *
   * @remarks
   * The digest covers the current signatories and the seal timestamp.
   * Presence of this field is the structural indication that the envelope
   * has been sealed.
   */
  get sealHash(): string | undefined {
    return this._sealHash;
  }
  /**
   * ISO 8601 timestamp captured when the envelope was sealed.
   *
   * @remarks
   * The timestamp is included in the seal-hash input, so changing it would
   * invalidate the stored seal hash.
   */
  get sealTimestamp(): string | undefined {
    return this._sealTimestamp;
  }
  /**
   * Signer fingerprint recorded as the actor who applied the seal.
   *
   * @remarks
   * For a restricted envelope this is required to be the allowlist issuer.
   * This value identifies the recorded sealer; it is not by itself a
   * cryptographic verification result.
   */
  get sealedBy(): string | undefined {
    return this._sealedBy;
  }
  /**
   * Confirmed external chain anchors registered on this envelope.
   *
   * @remarks
   * Anchors are metadata records only. This class does not submit
   * transactions or query a blockchain. Use {@link MajikSignatureEnvelope.withChainAnchor}
   * to immutably add or replace an anchor by `id`.
   */
  get chainAnchors(): readonly MajikChainAnchor[] {
    return this._chainAnchors ?? [];
  }

  /**
   * Append-only revision history associated with this envelope.
   *
   * @remarks
   * Each revision is linked to its predecessor through
   * `previousVersionHash`. Envelopes created before revision support may
   * have no entries and are represented here as an empty array.
   */
  get fileVersions(): readonly FileVersion[] {
    return this._fileVersions ?? [];
  }
  /**
   * Most recent file-revision entry, if a revision chain exists.
   *
   * @returns The last `FileVersion`, or `undefined` when no revisions have
   * been recorded.
   */
  get lastFileVersion(): FileVersion | undefined {
    return this._fileVersions?.[this._fileVersions.length - 1];
  }

  // ── Version chain hashing ────────────────────────────────────────────────

  /**
   * Hash a single {@link FileVersion} entry for use as the next revision's
   * `previousVersionHash`.
   *
   * @param entry Revision entry to hash.
   * @returns Base64-encoded SHA-256 digest of the JSON representation of
   * the supplied entry.
   *
   * @remarks
   * This is a structural commitment helper. It does not verify any signer
   * signature or prove that the referenced file bytes exist.
   */
  static hashFileVersionEntry(entry: FileVersion): string {
    return bytesToBase64(hashContent(JSON.stringify(entry)));
  }

  /**
   * Hash an entire revision chain as a single canonical commitment.
   *
   * @param chain Ordered revision entries, starting at version `1`.
   * @returns Base64-encoded SHA-256 digest of the JSON representation of
   * the supplied chain.
   *
   * @remarks
   * The helper is deterministic for the same ordered array contents and is
   * used by signatures to commit to the chain state at signing time.
   */
  static hashFileVersionChain(chain: readonly FileVersion[]): string {
    return bytesToBase64(hashContent(JSON.stringify(chain)));
  }

  /**
   * Append a new revision entry. Immutable. Validates the entry chains
   * correctly onto the current last entry (sequential version number,
   * previousVersionHash matching the prior entry's hash) before accepting
   * it — a broken chain fails loudly here, not silently later.
   */
  withFileVersion(entry: FileVersion): MajikSignatureEnvelope {
    if (this.isSealed()) {
      throw new MajikSignatureError(
        "Cannot add a file version to a sealed envelope.",
      );
    }

    const chain = this._fileVersions ?? [];
    const last = chain[chain.length - 1];
    const expectedVersion = last ? last.version + 1 : 1;

    if (entry.version !== expectedVersion) {
      throw new MajikSignatureValidationError(
        `FileVersion.version must be ${expectedVersion}, got ${entry.version}`,
        "version",
      );
    }

    const expectedPrevHash = last
      ? MajikSignatureEnvelope.hashFileVersionEntry(last)
      : undefined;
    if (entry.previousVersionHash !== expectedPrevHash) {
      throw new MajikSignatureValidationError(
        "FileVersion.previousVersionHash does not chain onto the current last entry.",
        "previousVersionHash",
      );
    }

    return new MajikSignatureEnvelope({
      ...this.toJSON(),
      fileVersions: [...chain, entry],
    });
  }

  /** Structural chain-linkage check — does not touch any signature. */
  /**
   * Check structural linkage of the local `fileVersions` chain.
   *
   * @returns An object with `valid: true` when the chain is structurally
   * consistent; otherwise `valid: false` with a diagnostic `reason`.
   *
   * @remarks
   * This method checks sequential version numbers and
   * `previousVersionHash` links only. It does **not** verify any
   * Ed25519/ML-DSA signature, content hash, or archived revision bytes.
   */
  verifyVersionChainIntegrity(): { valid: boolean; reason?: string } {
    const chain = this._fileVersions;
    if (!chain || chain.length === 0) return { valid: true };

    for (let i = 0; i < chain.length; i++) {
      const entry = chain[i];
      if (entry.version !== i + 1) {
        return {
          valid: false,
          reason: `fileVersions[${i}].version is ${entry.version}, expected ${i + 1}`,
        };
      }
      if (i === 0) {
        if (entry.previousVersionHash !== undefined) {
          return {
            valid: false,
            reason: "fileVersions[0] must not have a previousVersionHash",
          };
        }
        continue;
      }
      const expectedPrev = MajikSignatureEnvelope.hashFileVersionEntry(
        chain[i - 1],
      );
      if (entry.previousVersionHash !== expectedPrev) {
        return {
          valid: false,
          reason: `fileVersions[${i}].previousVersionHash mismatch`,
        };
      }
    }
    return { valid: true };
  }

  // ── State predicates ─────────────────────────────────────────────────────────

  /**
   * Determine whether the envelope has been structurally sealed.
   *
   * @returns `true` when seal metadata is present; otherwise `false`.
   *
   * @remarks
   * This is a structural predicate, not a cryptographic verification.
   * Use {@link MajikSignatureEnvelope.verifySeal} to validate the stored
   * seal hash against the current signatories and timestamp.
   */
  isSealed(): boolean {
    return this._sealHash !== undefined;
  }

  /**
   * Determine whether a non-empty signing allowlist exists.
   *
   * @returns `true` when restricted signer metadata is present; otherwise
   * `false` for open-signing envelopes.
   */
  hasAllowlist(): boolean {
    return !!this._allowlist && this._allowlist.length > 0;
  }

  /**
   * Determine whether the envelope currently contains no signatures.
   *
   * @returns `true` when this envelope is unsigned.
   *
   * @remarks
   * This is primarily useful when deciding whether first-signer-only
   * operations such as allowlist establishment are still eligible.
   */
  isFirstSigner(): boolean {
    return this._signatures.length === 0;
  }

  /**
   * True when the envelope has an allowlist naming more than one signer.
   * False for unsigned, open-signing, or single-signer files.
   */
  /**
   * Determine whether the envelope represents restricted multi-party signing.
   *
   * @returns `true` when an allowlist exists with more than one expected
   * signer; otherwise `false`.
   *
   * @remarks
   * This predicate describes the envelope's allowlist state. An open-signing
   * envelope may contain multiple signatures while still returning `false`.
   */
  isMultiSig(): boolean {
    return this.hasAllowlist() && this._allowlist!.length > 1;
  }

  /**
   * Determine whether more than one signature is currently present.
   *
   * @returns `true` when two or more signer envelopes exist.
   *
   * @remarks
   * Unlike {@link MajikSignatureEnvelope.isMultiSig}, this predicate does not
   * require an allowlist.
   */
  hasMultipleSignatories(): boolean {
    return this._signatures.length > 1;
  }

  /**
   * Find the stored signature envelope for a signer fingerprint.
   *
   * @param signerId MajikKey fingerprint to look up.
   * @returns The matching signature envelope, or `undefined` when that signer
   * has not signed this envelope.
   *
   * @remarks
   * This is a lookup only. It does not verify the returned signature or
   * public-key ownership.
   */
  findSignature(signerId: string): MajikSignatureJSON | undefined {
    return this._signatures.find((s) => s.signerId === signerId);
  }

  /** Fingerprint match only — does not verify key material. Use for quick checks. */
  /**
   * Check whether a key or fingerprint matches the recorded allowlist issuer.
   *
   * @param keyOrFingerprint A `MajikKey` whose fingerprint will be read, or
   * a fingerprint string to compare directly.
   * @returns `true` when the supplied fingerprint equals
   * `allowlistSignerId`; otherwise `false`.
   *
   * @remarks
   * This performs an identifier comparison only. It does not verify the
   * issuer's cryptographic signature or public keys.
   */
  isIssuer(keyOrFingerprint: MajikKey | string): boolean {
    const fingerprint =
      typeof keyOrFingerprint === "string"
        ? keyOrFingerprint
        : keyOrFingerprint.fingerprint;
    return !!this._allowlistSignerId && this._allowlistSignerId === fingerprint;
  }

  // ── Allowlist enforcement ────────────────────────────────────────────────────

  /**
   * Check whether a MajikKey is permitted to sign, per the allowlist alone
   * (does not account for seal status or issuer bypass — use assertCanSign()
   * or canSign() for the full three-field, seal-aware check).
   *
   * All three fields must match: signerId (fingerprint), edPublicKey, mlDsaPublicKey.
   * Prevents a signer from spoofing allowlist membership with a different key
   * that happens to share a fingerprint.
   */
  /**
   * Check allowlist membership for a signing key.
   *
   * @param key Key whose fingerprint and public signing keys should be
   * compared with the expected signer entries.
   * @returns A discriminated result containing the matching
   * {@link ExpectedSigner}, or `entry: null` for open signing / no match.
   *
   * @remarks
   * The comparison uses all three signer fields (`signerId`, Ed25519 public
   * key, and ML-DSA-87 public key). This method intentionally does not check
   * whether the envelope is sealed and does not apply the issuer bypass.
   * Use {@link MajikSignatureEnvelope.assertCanSign} or
   * {@link MajikSignatureEnvelope.canSign} for the complete signing gate.
   */
  checkAllowlist(key: MajikKey): AllowlistCheckResult {
    if (!this.hasAllowlist()) return { permitted: true, entry: null };

    const edPub = bytesToBase64(key.edPublicKey!);
    const mlPub = bytesToBase64(key.mlDsaPublicKey!);

    const match = this._allowlist!.find(
      (e) =>
        e.signerId === key.fingerprint &&
        e.edPublicKey === edPub &&
        e.mlDsaPublicKey === mlPub,
    );

    return match === undefined
      ? { permitted: false, entry: null }
      : { permitted: true, entry: match };
  }

  /**
   * Full signing-eligibility gate: sealed check + issuer bypass + allowlist check.
   * Throws MajikSignatureError (sealed) or MajikSignatureAllowlistError (not permitted).
   *
   * This is the single source of truth for "may this key sign this envelope" —
   * previously duplicated across signAndEmbed() and signDetached() in majik-embed.ts.
   */
  /**
   * Enforce the complete signing-permission policy for this envelope.
   *
   * @param key Key attempting to add a signature.
   * @throws {@link MajikSignatureError} When the envelope is sealed.
   * @throws {@link MajikSignatureAllowlistError} When the key is not
   * permitted by the allowlist.
   *
   * @remarks
   * This is the throwing counterpart to {@link MajikSignatureEnvelope.canSign}
   * and is the single structural gate for "may this key sign?".
   *
   * When an issuer fingerprint is recorded, the issuer bypasses the
   * allowlist-membership check but still cannot sign a sealed envelope.
   */
  assertCanSign(key: MajikKey): void {
    if (this.isSealed()) {
      throw new MajikSignatureError(
        "Cannot sign a sealed envelope. The issuer has locked this file against further signatures.",
      );
    }

    if (this.isIssuer(key)) return; // issuer always bypasses the allowlist

    const check = this.checkAllowlist(key);
    if (!check.permitted) {
      throw new MajikSignatureAllowlistError(
        `Signer "${key.fingerprint}" is not permitted to sign this file. ` +
          `The file has a signing allowlist established by "${this._allowlistSignerId}".`,
        key.fingerprint,
      );
    }
  }

  /** Non-throwing counterpart of assertCanSign(), for UI-facing checks. */
  /**
   * Check signing eligibility without throwing.
   *
   * @param key Key that would attempt to add a signature.
   * @returns `{ permitted: true }` when signing is allowed; otherwise
   * `{ permitted: false, reason }` with a human-readable explanation.
   *
   * @remarks
   * This method is intended for UI and preflight flows. It applies the same
   * sealed-envelope, issuer, and allowlist rules as
   * {@link MajikSignatureEnvelope.assertCanSign}.
   */
  canSign(key: MajikKey): CanSignResult {
    try {
      this.assertCanSign(key);
      return { permitted: true };
    } catch (err) {
      const reason =
        err instanceof Error
          ? err.message
          : "Signer is not permitted to sign this file.";
      return { permitted: false, reason };
    }
  }

  // ── Allowlist hashing ────────────────────────────────────────────────────────

  /**
   * Compute the canonical SHA-256 commitment for an allowlist.
   *
   * @param allowlist Expected signer entries to commit to.
   * @returns Base64-encoded SHA-256 digest of the normalized allowlist.
   *
   * @remarks
   * Entries are sorted by `signerId` before hashing, making the commitment
   * independent of the caller's input order.
   */
  static hashAllowlist(allowlist: readonly ExpectedSigner[]): string {
    const sorted = [...allowlist].sort((a, b) =>
      a.signerId.localeCompare(b.signerId),
    );
    return bytesToBase64(hashContent(JSON.stringify(sorted)));
  }

  /** SHA-256 hash of this envelope's own allowlist, or undefined if none is set. */
  /**
   * Compute the current envelope allowlist's integrity hash.
   *
   * @returns The deterministic base64 SHA-256 commitment when an allowlist
   * exists, otherwise `undefined`.
   *
   * @remarks
   * This is calculated from the current in-memory allowlist; it is not the
   * `allowlistHash` stored inside any signer's signature payload.
   */
  get computedAllowlistHash(): string | undefined {
    return this.hasAllowlist()
      ? MajikSignatureEnvelope.hashAllowlist(this._allowlist!)
      : undefined;
  }

  /**
   * Resolve the allowlistHash a given signer's canonical payload should include —
   * present when establishing a new allowlist (first signer + expectedSigners
   * provided), or when the issuer is re-signing an already-established allowlist
   * (keeps it present in their payload so the integrity check keeps passing).
   * Undefined in every other case.
   *
   * Consolidates logic previously duplicated between signAndEmbed() and
   * signDetached() in majik-embed.ts.
   */
  /**
   * Resolve the allowlist commitment that should be bound to a signer's
   * canonical signing payload.
   *
   * @param key Signer key that is about to sign.
   * @param expectedSigners Optional allowlist supplied during first-signature
   * creation.
   * @returns The allowlist hash when this signer is establishing an allowlist
   * or re-signing as the existing issuer; otherwise `undefined`.
   *
   * @remarks
   * This preserves the canonical-payload semantics used by the higher-level
   * signing APIs. It does not itself mutate the envelope or create a
   * signature.
   */
  resolveAllowlistHashFor(
    key: MajikKey,
    expectedSigners?: readonly ExpectedSigner[],
  ): string | undefined {
    const establishing =
      this.isFirstSigner() && !!expectedSigners && expectedSigners.length > 0;
    if (establishing)
      return MajikSignatureEnvelope.hashAllowlist(expectedSigners!);

    const issuerResigning =
      !this.isFirstSigner() && this.isIssuer(key) && this.hasAllowlist();
    if (issuerResigning) return this.computedAllowlistHash;

    return undefined;
  }

  /**
   * Verify that the allowlist establisher's stored allowlistHash still matches
   * the current allowlist — catches post-hoc tampering with the allowlist array.
   * Returns { valid: true } trivially when there is no allowlist.
   */
  /**
   * Check that the current allowlist still matches the commitment recorded
   * by the allowlist establisher's signature.
   *
   * @returns `valid: true` when there is no allowlist or when the stored
   * commitment matches; otherwise `valid: false` with a diagnostic reason.
   *
   * @remarks
   * This detects post-hoc changes to the allowlist array. It does not verify
   * the establisher's Ed25519/ML-DSA-87 signatures.
   */
  verifyAllowlistIntegrity(): { valid: boolean; reason?: string } {
    if (!this.hasAllowlist() || !this._allowlistSignerId)
      return { valid: true };

    const establisherSig = this.findSignature(this._allowlistSignerId);
    if (!establisherSig) {
      return {
        valid: false,
        reason: `Allowlist establisher "${this._allowlistSignerId}" has no signature in this envelope`,
      };
    }

    if (establisherSig.allowlistHash !== this.computedAllowlistHash) {
      return {
        valid: false,
        reason:
          "Allowlist integrity check failed — allowlist may have been tampered with",
      };
    }

    return { valid: true };
  }

  // ── Builders (immutable — each returns a new instance) ──────────────────────

  /**
   * Upsert a signature by signerId. Replaces an existing entry (re-sign) or
   * appends a new one. Refuses on a sealed envelope — sealing is meant to be
   * a hard lock, so this is enforced here rather than left to callers.
   */
  /**
   * Return a new envelope containing the supplied signer signature.
   *
   * @param sig Signature envelope to add.
   * @returns A new immutable envelope with the signer entry appended or
   * replaced by `signerId`.
   * @throws {@link MajikSignatureError} If the envelope is already sealed.
   *
   * @remarks
   * This is an upsert operation: an existing signature with the same
   * `signerId` is replaced. The current instance is never mutated.
   */
  withSignature(sig: MajikSignatureJSON): MajikSignatureEnvelope {
    if (this.isSealed()) {
      throw new MajikSignatureError(
        "Cannot add a signature to a sealed envelope.",
      );
    }

    const idx = this._signatures.findIndex((s) => s.signerId === sig.signerId);
    const nextSignatures =
      idx >= 0
        ? this._signatures.map((s, i) => (i === idx ? sig : s))
        : [...this._signatures, sig];

    return new MajikSignatureEnvelope({
      ...this.toJSON(),
      signatures: nextSignatures,
    });
  }

  /**
   * Establish the allowlist. Only permitted once, on an envelope with no
   * existing allowlist and no prior signatures (i.e. by the very first signer) —
   * enforced here rather than silently ignored, so misuse fails loudly.
   */
  /**
   * Return a new envelope with its signing allowlist established.
   *
   * @param allowlist Non-empty set of permitted signer identities.
   * @param signerId Fingerprint of the signer establishing the allowlist.
   * @returns A new envelope containing the allowlist and issuer fingerprint.
   * @throws {@link MajikSignatureError} If an allowlist already exists or the
   * envelope already contains a signature.
   * @throws {@link MajikSignatureValidationError} If the allowlist is empty.
   *
   * @remarks
   * The allowlist is a first-signer-only operation and cannot later be
   * replaced through this builder.
   */
  withAllowlist(
    allowlist: readonly ExpectedSigner[],
    signerId: string,
  ): MajikSignatureEnvelope {
    if (this.hasAllowlist()) {
      throw new MajikSignatureError(
        "This envelope already has an established allowlist. It cannot be replaced.",
      );
    }
    if (!this.isFirstSigner()) {
      throw new MajikSignatureError(
        "An allowlist can only be established by the first signer on a file.",
      );
    }
    if (!allowlist || allowlist.length === 0) {
      throw new MajikSignatureValidationError(
        "Allowlist must contain at least one entry.",
        "allowlist",
      );
    }

    return new MajikSignatureEnvelope({
      ...this.toJSON(),
      allowlist: [...allowlist],
      allowlistSignerId: signerId,
    });
  }

  /**
   * Seal the envelope, preventing any further signatures. Only the issuer may
   * seal when an allowlist is present; open-signing envelopes may be sealed
   * by whoever calls this (matches existing seal() behavior in majik-embed.ts).
   */
  /**
   * Return a new envelope with a cryptographic seal commitment.
   *
   * @param sealedBy Fingerprint of the signer applying the seal.
   * @param sealTimestamp Optional ISO 8601 timestamp. Defaults to the
   * current time when omitted.
   * @returns A new sealed envelope.
   * @throws {@link MajikSignatureError} If the envelope is already sealed.
   * @throws {@link MajikSignatureKeyError} If a restricted envelope is being
   * sealed by someone other than its issuer.
   *
   * @remarks
   * The seal is a SHA3-512 integrity commitment over the current signatories
   * and timestamp. It is not a replacement for verifying the individual
   * signer signatures.
   *
   * Once sealed, subsequent signature and revision builders are rejected.
   */
  withSeal(sealedBy: string, sealTimestamp?: string): MajikSignatureEnvelope {
    if (this.isSealed()) {
      throw new MajikSignatureError("This envelope is already sealed.");
    }
    if (this.hasAllowlist() && this._allowlistSignerId !== sealedBy) {
      throw new MajikSignatureKeyError(
        `Only the issuer ("${this._allowlistSignerId}") may seal this file. ` +
          `Provided fingerprint: "${sealedBy}".`,
      );
    }

    const ts = sealTimestamp ?? new Date().toISOString();
    const sealHash = this.computeSealHash(ts);

    return new MajikSignatureEnvelope({
      ...this.toJSON(),
      sealHash,
      sealTimestamp: ts,
      sealedBy,
    });
  }

  /**
   * Embed an already-confirmed chain anchor. Requires the envelope to be
   * sealed, and the anchor's digest must match the current seal hash — guards
   * against embedding an anchor computed against a stale seal. Upserts by
   * anchor.id so a retried call doesn't produce duplicate entries.
   */
  /**
   * Return a new envelope with an already-confirmed external chain anchor.
   *
   * @param anchor Anchor record whose digest must reference this envelope's
   * current seal hash.
   * @returns A new envelope containing the anchor, replacing any existing
   * anchor with the same `id`.
   * @throws {@link MajikSignatureError} If the envelope is not sealed or the
   * anchor digest does not match the current seal hash.
   *
   * @remarks
   * This method only records anchor metadata. It does not submit or confirm
   * a blockchain transaction.
   */
  withChainAnchor(anchor: MajikChainAnchor): MajikSignatureEnvelope {
    if (!this.isSealed()) {
      throw new MajikSignatureError(
        "Cannot register a chain anchor — envelope must be sealed first.",
      );
    }
    if (anchor.payload.digest.value !== this._sealHash) {
      throw new MajikSignatureError(
        "Chain anchor digest does not match the envelope's current seal hash.",
      );
    }

    const existing = this.chainAnchors;
    const nextAnchors = existing.some((a) => a.id === anchor.id)
      ? existing.map((a) => (a.id === anchor.id ? anchor : a))
      : [...existing, anchor];

    return new MajikSignatureEnvelope({
      ...this.toJSON(),
      chainAnchors: nextAnchors,
    });
  }

  // ── Seal queries ─────────────────────────────────────────────────────────────

  private computeSealHash(sealTimestamp: string): string {
    const signatories = [...this._signatures]
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

    return bytesToHex(sha3_512(input));
  }

  /**
   * Verify the envelope's stored seal commitment.
   *
   * @returns A structured seal-verification result. `valid: true` means the
   * stored seal hash matches the current signatories and seal timestamp.
   *
   * @remarks
   * This validates the seal commitment only. It does not verify the
   * individual signer signatures; use the higher-level file/content
   * verification APIs for that.
   */
  verifySeal(): SealVerificationResult {
    if (!this._sealHash || !this._sealTimestamp || !this._sealedBy) {
      return { valid: false, reason: "Envelope is not sealed" };
    }

    const recomputed = this.computeSealHash(this._sealTimestamp);
    if (recomputed !== this._sealHash) {
      return {
        valid: false,
        sealedBy: this._sealedBy,
        sealTimestamp: this._sealTimestamp,
        reason:
          "Seal hash does not match — signatories or timestamp may have been tampered with",
      };
    }

    return {
      valid: true,
      sealedBy: this._sealedBy,
      sealTimestamp: this._sealTimestamp,
    };
  }

  /**
   * Read seal metadata without recomputing or cryptographically validating it.
   *
   * @returns `{ sealHash, sealTimestamp, sealedBy }` when all seal fields are
   * present, otherwise `null`.
   *
   * @remarks
   * Use {@link MajikSignatureEnvelope.verifySeal} when the caller needs to
   * know whether the stored seal is internally consistent.
   */
  getSealInfo(): SealInfo | null {
    if (!this._sealHash || !this._sealTimestamp || !this._sealedBy) return null;
    return {
      sealHash: this._sealHash,
      sealTimestamp: this._sealTimestamp,
      sealedBy: this._sealedBy,
    };
  }

  /**
   * Check whether this envelope is structurally eligible for chain anchoring.
   *
   * @returns `{ permitted: true }` only when the envelope is sealed;
   * otherwise `{ permitted: false, reason }`.
   *
   * @remarks
   * Eligibility does not mean an external transaction has been submitted or
   * confirmed.
   */
  canAnchor(): CanAnchorResult {
    if (!this.isSealed()) {
      return {
        permitted: false,
        reason: "Envelope is not sealed. Anchoring requires a sealed envelope.",
      };
    }
    return { permitted: true };
  }

  // ── Issuer / signatories resolution ─────────────────────────────────────────

  /**
   * The issuer — the signer who established the allowlist and controls sealing.
   * Falls back to the first signer for open-signing envelopes. Null if unsigned.
   *
   * Consolidates logic previously duplicated between getIssuer() and
   * getEnvelopeInfo() in majik-embed.ts.
   */
  /**
   * Resolve the logical issuer/signing authority represented by this envelope.
   *
   * @returns The allowlist establisher when a restricted envelope has one;
   * otherwise the first signer for an open-signing envelope; `null` when the
   * envelope is unsigned.
   *
   * @remarks
   * The returned object combines expected-signer metadata with observed
   * signing status. It is a structural resolution and does not itself verify
   * the signer's cryptographic signature.
   */
  resolveIssuer(): SignatoryInfo | null {
    if (this._allowlistSignerId) {
      const issuerEntry = this._allowlist?.find(
        (e) => e.signerId === this._allowlistSignerId,
      );
      if (issuerEntry) {
        const issuerSig = this.findSignature(this._allowlistSignerId);
        return {
          signerId: issuerEntry.signerId,
          edPublicKey: issuerEntry.edPublicKey,
          mlDsaPublicKey: issuerEntry.mlDsaPublicKey,
          hasSigned: issuerSig !== undefined,
          signedAt: issuerSig?.timestamp,
        };
      }
    }

    if (this._signatures.length > 0) {
      const firstSig = this._signatures[0];
      return {
        signerId: firstSig.signerId,
        edPublicKey: firstSig.signerEdPublicKey,
        mlDsaPublicKey: firstSig.signerMlDsaPublicKey,
        hasSigned: true,
        signedAt: firstSig.timestamp,
      };
    }

    return null;
  }

  /**
   * Core signatories method. Returns all/signed/pending — always the full
   * shape; `filter` narrows which array is the "requested" one without
   * dropping the others, matching the original alias methods' contract.
   * Returns null when there is neither an allowlist nor any signatures.
   */
  /**
   * Resolve expected and actual signatories into a UI-friendly status model.
   *
   * @param filter Optional status selector. The returned object always
   * contains `all`, `signed`, and `pending` arrays.
   * @returns A complete {@link SignatoriesResult}, or `null` when the
   * envelope is unsigned and has no allowlist.
   *
   * @remarks
   * For restricted envelopes, allowlisted signers are included even before
   * they sign. Actual signers not present in the allowlist are also retained
   * in `all` so the result accurately reflects the envelope contents.
   */
  getSignatories(filter?: SignatoriesFilter): SignatoriesResult | null {
    const signedMap = new Map<string, MajikSignatureJSON>(
      this._signatures.map((s) => [s.signerId, s]),
    );

    let all: SignatoryInfo[];

    if (this.hasAllowlist()) {
      const byId = new Map<string, SignatoryInfo>();

      for (const entry of this._allowlist!) {
        const sig = signedMap.get(entry.signerId);
        byId.set(entry.signerId, {
          signerId: entry.signerId,
          edPublicKey: entry.edPublicKey,
          mlDsaPublicKey: entry.mlDsaPublicKey,
          hasSigned: sig !== undefined,
          signedAt: sig?.timestamp,
        });
      }

      // Actual signers not on the allowlist (e.g. the issuer) still count
      for (const sig of this._signatures) {
        if (!byId.has(sig.signerId)) {
          byId.set(sig.signerId, {
            signerId: sig.signerId,
            edPublicKey: sig.signerEdPublicKey,
            mlDsaPublicKey: sig.signerMlDsaPublicKey,
            hasSigned: true,
            signedAt: sig.timestamp,
          });
        }
      }

      all = Array.from(byId.values());
    } else {
      if (this._signatures.length === 0) return null;
      all = this._signatures.map((sig) => ({
        signerId: sig.signerId,
        edPublicKey: sig.signerEdPublicKey,
        mlDsaPublicKey: sig.signerMlDsaPublicKey,
        hasSigned: true,
        signedAt: sig.timestamp,
      }));
    }

    const signed = all.filter((s) => s.hasSigned);
    const pending = all.filter((s) => !s.hasSigned);

    if (!filter || filter === "all") return { all, signed, pending };

    // Preserve full shape even when narrowing — matches original contract
    return {
      all,
      signed: filter === "signed" ? signed : signed,
      pending: filter === "pending" ? pending : pending,
    };
  }

  /**
   * Full summary of envelope state in one call — used to render signing-status
   * UI without multiple separate lookups.
   */
  /**
   * Build a complete summary of the envelope's signing state.
   *
   * @returns Aggregated envelope metadata suitable for rendering signing
   * status without repeatedly querying individual properties.
   *
   * @remarks
   * The summary includes seal state, issuer resolution, signatory status,
   * allowlist contents, and the current signature count.
   */
  getEnvelopeInfo(): EnvelopeInfo {
    return {
      isMultiSig: this.hasAllowlist() || this.hasMultipleSignatories(),
      hasMultipleSignatories: this.hasMultipleSignatories(),
      isSealed: this.isSealed(),
      sealInfo: this.getSealInfo() ?? undefined,
      issuer: this.resolveIssuer(),
      signatories: this.getSignatories(),
      allowlist: this._allowlist ? [...this._allowlist] : null,
      signatureCount: this._signatures.length,
    };
  }

  // ── Serialization ─────────────────────────────────────────────────────────────

  /**
   * Convert the immutable instance to its plain JSON/wire representation.
   *
   * @returns A fresh `MajikSignatureEnvelopeJSON` object containing only the
   * serializable envelope state.
   *
   * @remarks
   * Optional sections such as the allowlist, seal metadata, chain anchors,
   * and revision history are omitted when they are not present.
   */
  toJSON(): MajikSignatureEnvelopeJSON {
    return {
      version: this._version,
      signatures: [...this._signatures],
      ...(this._allowlist ? { allowlist: [...this._allowlist] } : {}),
      ...(this._allowlistSignerId
        ? { allowlistSignerId: this._allowlistSignerId }
        : {}),
      ...(this._sealHash ? { sealHash: this._sealHash } : {}),
      ...(this._sealTimestamp ? { sealTimestamp: this._sealTimestamp } : {}),
      ...(this._sealedBy ? { sealedBy: this._sealedBy } : {}),
      ...(this._chainAnchors ? { chainAnchors: [...this._chainAnchors] } : {}),
      ...(this._fileVersions ? { fileVersions: [...this._fileVersions] } : {}),
    };
  }

  /**
   * Serialize the envelope as base64-encoded UTF-8 JSON.
   *
   * @returns Base64 transport representation of {@link MajikSignatureEnvelope.toJSON}.
   * @throws {@link MajikSignatureSerializationError} If encoding fails.
   *
   * @remarks
   * This is the lightweight transport format and has **no MJKSIG binary
   * header**. Use {@link MajikSignatureEnvelope.toMJKSIG} when a
   * self-identifying on-disk container is preferred.
   */
  serialize(): string {
    try {
      const bytes = new TextEncoder().encode(JSON.stringify(this.toJSON()));
      let binary = "";
      for (let i = 0; i < bytes.length; i++)
        binary += String.fromCharCode(bytes[i]);
      return btoa(binary);
    } catch (err) {
      throw new MajikSignatureSerializationError(
        "Failed to serialize envelope",
        err,
      );
    }
  }

  /**
   * Reconstruct an envelope from the base64 format produced by
   * {@link MajikSignatureEnvelope.serialize}.
   *
   * @param base64 Base64-encoded UTF-8 JSON envelope.
   * @returns A validated immutable envelope instance.
   * @throws {@link MajikSignatureSerializationError} When the base64 or JSON
   * payload cannot be decoded.
   * @throws {@link MajikSignatureValidationError} When the decoded object
   * has an invalid envelope shape.
   */
  static deserialize(base64: string): MajikSignatureEnvelope {
    try {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return MajikSignatureEnvelope.fromJSON(new TextDecoder().decode(bytes));
    } catch (err) {
      if (err instanceof MajikSignatureError) throw err;
      throw new MajikSignatureSerializationError(
        "Failed to deserialize envelope from base64",
        err,
      );
    }
  }

  // ── MJKSIG binary format ─────────────────────────────────────────────────
  //
  // A dedicated, versioned, self-identifying binary container for a detached
  // envelope — distinct from serialize()/deserialize() (plain base64 of the
  // JSON, no header) which remains for lightweight in-app round-tripping.
  // MJKSIG is the wire/on-disk format intended for out-of-band travel,
  // storage, and eventual IANA registration.

  // ── MJKSIG binary format ─────────────────────────────────────────────────
  //
  // A dedicated, versioned, self-identifying binary container for a detached
  // envelope — distinct from serialize()/deserialize() (plain base64 of the
  // JSON, no header) which remains for lightweight in-app round-tripping.
  // MJKSIG is the wire/on-disk format intended for out-of-band travel,
  // storage, and eventual IANA registration.

  /**
   * Raw MJKSIG bytes, no Blob wrapper. Exposed as a public escape hatch for
   * non-browser contexts (Node scripts, tests, direct fs writes) where
   * wrapping in a Blob just to immediately unwrap it again is pure overhead.
   * toMJKSIG() is the primary API for anything Blob-facing.
   */
  /**
   * Encode the envelope as raw MJKSIG binary bytes.
   *
   * @returns A self-describing `.mjksig` byte sequence as `Uint8Array`.
   *
   * @remarks
   * The container includes the MJKSIG magic bytes, format version,
   * reserved byte, big-endian payload length, and UTF-8 JSON payload.
   * This method is convenient for Node.js, filesystem, and low-level binary
   * workflows where wrapping the result in a `Blob` would add unnecessary
   * overhead.
   */
  toMJKSIGBytes(): Uint8Array {
    const payloadJson = new TextEncoder().encode(JSON.stringify(this.toJSON()));
    const out = new Uint8Array(MJKSIG_HEADER_LEN + payloadJson.length);

    out.set(MJKSIG_MAGIC, 0);
    out[MJKSIG_MAGIC_LEN] = MJKSIG_VERSION;
    out[MJKSIG_MAGIC_LEN + 1] = 0x00; // reserved — always 0 in v1

    const lenOffset = MJKSIG_MAGIC_LEN + 2;
    out[lenOffset] = (payloadJson.length >>> 24) & 0xff;
    out[lenOffset + 1] = (payloadJson.length >>> 16) & 0xff;
    out[lenOffset + 2] = (payloadJson.length >>> 8) & 0xff;
    out[lenOffset + 3] = payloadJson.length & 0xff;

    out.set(payloadJson, MJKSIG_HEADER_LEN);
    return out;
  }

  /**
   * Encode this envelope as an MJKSIG file Blob.
   * Always writes the current MJKSIG_VERSION — encoding an old payload
   * shape under an old version tag is not supported; old versions only
   * ever appear when *reading* pre-existing MJKSIG binaries.
   */
  /**
   * Encode the envelope as an MJKSIG `Blob`.
   *
   * @returns A Blob using the registered Majik Signature media type.
   *
   * @remarks
   * This is the browser-friendly counterpart to
   * {@link MajikSignatureEnvelope.toMJKSIGBytes} and is suitable for
   * downloads, file storage, and packaging into archives.
   */
  toMJKSIG(): Blob {
    const bytes = this.toMJKSIGBytes();
    return new Blob([bytes as BlobPart], {
      type: MJKSIG_MEDIA_TYPE,
    });
  }

  /**
   * Decode MJKSIG bytes back into a MajikSignatureEnvelope.
   * Validates magic bytes, version, and declared payload length before
   * attempting to parse — a truncated or corrupted buffer fails fast with
   * a clear reason rather than an obscure JSON.parse error.
   *
   * Accepts either a Blob (as produced by toMJKSIG()) or raw Uint8Array
   * (as produced by toMJKSIGBytes(), or read directly off disk) — mirrors
   * the same "accept either shape" pattern as from(). Reading a Blob
   * requires awaiting its bytes, which is why this method is async.
   */
  /**
   * Parse a `.mjksig` binary container into an immutable envelope.
   *
   * @param input Raw MJKSIG bytes or a `Blob`/`File` containing them.
   * @returns A fully parsed and structurally validated envelope.
   * @throws {@link MajikSignatureSerializationError} When magic bytes,
   * container version, declared payload length, or JSON framing is invalid.
   * @throws {@link MajikSignatureValidationError} When the decoded envelope
   * shape is invalid.
   *
   * @remarks
   * Container framing is checked before JSON parsing so truncated or
   * corrupted binary inputs fail with a format-specific error.
   */
  static async fromMJKSIG(
    input: FileLike, // Changed from Blob | Uint8Array
  ): Promise<MajikSignatureEnvelope> {
    // Replaces the manual `input instanceof Blob` check
    const raw = await normalizeToBytes(input);

    return MajikSignatureEnvelope.#parseMJKSIGBytes(raw);
  }

  /** Core MJKSIG byte parser — shared by fromMJKSIG() after Blob resolution. */
  static #parseMJKSIGBytes(raw: Uint8Array): MajikSignatureEnvelope {
    if (raw.length < MJKSIG_HEADER_LEN + 1) {
      // +1 == at least one byte of payload JSON
      throw new MajikSignatureSerializationError(
        "Malformed MJKSIG: too short to contain a valid header",
      );
    }

    for (let i = 0; i < MJKSIG_MAGIC_LEN; i++) {
      if (raw[i] !== MJKSIG_MAGIC[i]) {
        throw new MajikSignatureSerializationError(
          'Malformed MJKSIG: missing "MJKSIG" magic bytes',
        );
      }
    }

    const version = raw[MJKSIG_MAGIC_LEN];
    if (!(MJKSIG_SUPPORTED_VERSIONS as readonly number[]).includes(version)) {
      throw new MajikSignatureSerializationError(
        `Unsupported MJKSIG version: ${version} (supported: ${MJKSIG_SUPPORTED_VERSIONS.join(", ")})`,
      );
    }

    const lenOffset = MJKSIG_MAGIC_LEN + 2;
    const payloadLen =
      (raw[lenOffset] << 24) |
      (raw[lenOffset + 1] << 16) |
      (raw[lenOffset + 2] << 8) |
      raw[lenOffset + 3];

    if (payloadLen <= 0) {
      throw new MajikSignatureSerializationError(
        "Malformed MJKSIG: invalid payload length",
      );
    }

    const payloadStart = MJKSIG_HEADER_LEN;
    const payloadEnd = payloadStart + payloadLen;
    if (payloadEnd > raw.length) {
      throw new MajikSignatureSerializationError(
        "Malformed MJKSIG: declared payload length exceeds buffer",
      );
    }

    const json = new TextDecoder().decode(raw.slice(payloadStart, payloadEnd));
    // fromJSON() runs full #validateShape() — MJKSIG framing validity does
    // NOT imply envelope validity, so this is not a redundant check.
    return MajikSignatureEnvelope.fromJSON(json);
  }

  /**
   * Cheap structural sniff — checks magic bytes only, does not parse or
   * validate the payload. For a Blob, slices only the header bytes rather
   * than reading the whole file, so this stays cheap even on large inputs.
   */
  /**
   * Perform a cheap MJKSIG magic-byte sniff.
   *
   * @param input Binary input to inspect.
   * @returns `true` when the input begins with the MJKSIG magic bytes;
   * otherwise `false`.
   *
   * @remarks
   * This method does not parse JSON, validate the envelope, or verify any
   * signatures. For `Blob`/`File` inputs, only the header bytes are read.
   * Use this as a fast format guard before calling
   * {@link MajikSignatureEnvelope.fromMJKSIG}.
   */
  static async isMJKSIG(input: FileLike): Promise<boolean> {
    // If it's a Blob/File, slice safely to avoid loading massive files into memory
    const header =
      input instanceof Blob
        ? new Uint8Array(await input.slice(0, MJKSIG_MAGIC_LEN).arrayBuffer())
        : (await normalizeToBytes(input)).slice(0, MJKSIG_MAGIC_LEN); // Handles Uint8Array/ArrayBuffer

    if (header.length < MJKSIG_MAGIC_LEN) return false;
    for (let i = 0; i < MJKSIG_MAGIC_LEN; i++) {
      if (header[i] !== MJKSIG_MAGIC[i]) return false;
    }
    return true;
  }

  /**
   * Read just the version byte without parsing the payload.
   * Returns null if the input isn't MJKSIG-shaped at all.
   */
  /**
   * Read the MJKSIG binary-container version without parsing its payload.
   *
   * @param input Binary MJKSIG candidate.
   * @returns The encoded container version, or `null` when the input is not
   * recognizably MJKSIG-shaped.
   *
   * @remarks
   * This is a lightweight header inspection helper. It does not establish
   * that the payload itself is valid or supported beyond exposing the stored
   * version byte.
   */
  static async getMJKSIGVersion(
    input: FileLike, // Changed from Blob | Uint8Array
  ): Promise<number | null> {
    const header =
      input instanceof Blob
        ? new Uint8Array(
            await input.slice(0, MJKSIG_MAGIC_LEN + 1).arrayBuffer(),
          )
        : (await normalizeToBytes(input)).slice(0, MJKSIG_MAGIC_LEN + 1);

    if (!(await MajikSignatureEnvelope.isMJKSIG(header))) return null;
    if (header.length < MJKSIG_MAGIC_LEN + 1) return null;
    return header[MJKSIG_MAGIC_LEN];
  }

  // ── Creation / parsing ───────────────────────────────────────────────────────

  /**
   * Create a new empty, version-1 envelope.
   *
   * @returns An immutable envelope with no signatures and no optional
   * metadata.
   *
   * @example
   * ```ts
   * const envelope = MajikSignatureEnvelope.empty();
   * console.log(envelope.isFirstSigner()); // true
   * ```
   */
  static empty(): MajikSignatureEnvelope {
    return new MajikSignatureEnvelope({
      version: MAJIK_ENVELOPE_VERSION,
      signatures: [],
    });
  }

  /**
   * Parse a raw string or plain object into a MajikSignatureEnvelope.
   *
   * Handles three shapes:
   *   1. NEW  — MajikSignatureEnvelopeJSON: { version, signatures: [...], ... }
   *   2. OLD  — bare MajikSignatureJSON (has a string `edSignature`): promoted
   *      silently to a single-item envelope with no allowlist.
   *   3. Anything else — throws MajikSignatureSerializationError.
   *
   * This is the only place that knows about the legacy on-disk shape.
   */
  /**
   * Parse JSON into a validated `MajikSignatureEnvelope` instance.
   *
   * @param json A `MajikSignatureEnvelopeJSON`, legacy bare
   * `MajikSignatureJSON`, or JSON string containing either shape.
   * @returns A normalized immutable envelope instance.
   * @throws {@link MajikSignatureSerializationError} When the JSON is
   * malformed or the input shape is unrecognized.
   * @throws {@link MajikSignatureValidationError} When the recognized object
   * violates envelope structural rules.
   *
   * @remarks
   * Legacy single-signature JSON is transparently promoted to a version-1
   * envelope containing one signature. Callers therefore receive one modern
   * envelope abstraction regardless of whether the source file used the
   * pre-multi-signature format.
   */
  static fromJSON(
    json: MajikSignatureEnvelopeJSON | MajikSignatureJSON | string,
  ): MajikSignatureEnvelope {
    let parsed: unknown;
    try {
      parsed = typeof json === "string" ? JSON.parse(json) : json;
    } catch (err) {
      throw new MajikSignatureSerializationError(
        "Embedded signature payload is not valid JSON",
        err,
      );
    }

    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      throw new MajikSignatureSerializationError(
        "Embedded signature payload must be a JSON object",
      );
    }

    const obj = parsed as Record<string, unknown>;

    // Legacy bare-envelope promotion — discriminator: has string `edSignature`
    const promoted: Record<string, unknown> = Array.isArray(obj.signatures)
      ? obj
      : typeof obj.edSignature === "string"
        ? { version: MAJIK_ENVELOPE_VERSION, signatures: [obj] }
        : (() => {
            throw new MajikSignatureSerializationError(
              "Unrecognised signature envelope format — expected MajikSignatureEnvelopeJSON or MajikSignatureJSON",
            );
          })();

    MajikSignatureEnvelope.#validateShape(promoted);
    return new MajikSignatureEnvelope(
      promoted as unknown as MajikSignatureEnvelopeJSON,
    );
  }

  /**
   * Accepts an instance, its JSON shape, or MJKSIG bytes/Blob — normalizes to
   * an instance. This is the single entry point that lets every downstream
   * caller (verifyDetached, verifyDetachedWithKey, signDetached's
   * existingEnvelope option) transparently accept a detached envelope
   * regardless of which form it arrived in.
   *
   * Now async: resolving a Blob input requires awaiting its bytes. Every
   * existing call site is already inside an async method, so this only
   * costs an added `await` at each call site — no structural changes.
   */
  /**
   * Normalize any supported detached-envelope representation into an
   * immutable `MajikSignatureEnvelope`.
   *
   * @param input Existing envelope instance, plain JSON envelope,
   * MJKSIG bytes, or a Blob/File containing MJKSIG data.
   * @returns A normalized envelope instance.
   * @throws {@link MajikSignatureSerializationError} When a binary or JSON
   * representation cannot be decoded.
   * @throws {@link MajikSignatureValidationError} When the decoded envelope
   * is structurally invalid.
   *
   * @remarks
   * This is the universal normalization entry point used by detached-signing
   * and detached-verification workflows, allowing callers to pass whichever
   * supported representation they already have.
   */
  static async from(input: EnvelopeInput): Promise<MajikSignatureEnvelope> {
    if (input instanceof MajikSignatureEnvelope) return input;

    // Distinguish FileLike (binary/Blob) from MajikSignatureEnvelopeJSON (plain object)
    // A simple check: if it has the required JSON shape, parse it as JSON.
    const isPlainJson =
      typeof input === "object" &&
      input !== null &&
      "signatures" in input &&
      !("arrayBuffer" in input) && // Exclude Blob/File
      !(input instanceof Uint8Array) &&
      !(input instanceof ArrayBuffer);

    if (isPlainJson) {
      return MajikSignatureEnvelope.fromJSON(
        input as MajikSignatureEnvelopeJSON,
      );
    }

    // Otherwise, treat as FileLike MJKSIG binary
    return MajikSignatureEnvelope.fromMJKSIG(input as FileLike);
  }

  /**
   * Validate the current envelope's structural shape.
   *
   * @throws {@link MajikSignatureValidationError} When any required field,
   * version, paired optional fields, or nested signature/allowlist entry is
   * structurally invalid.
   *
   * @remarks
   * This is intentionally a structural check. It does not verify Ed25519,
   * ML-DSA-87, TSA, or blockchain signatures/claims.
   */
  validate(): void {
    MajikSignatureEnvelope.#validateShape(
      this.toJSON() as unknown as Record<string, unknown>,
    );
  }

  /**
   * Non-throwing structural validity check.
   *
   * @returns `true` when {@link MajikSignatureEnvelope.validate} succeeds;
   * otherwise `false`.
   *
   * @remarks
   * This is useful when validating untrusted serialized data without using
   * exceptions for normal control flow.
   */
  isValid(): boolean {
    try {
      this.validate();
      return true;
    } catch {
      return false;
    }
  }

  // ── Private validation ───────────────────────────────────────────────────────

  static #validateShape(obj: Record<string, unknown>): void {
    if (obj.version !== MAJIK_ENVELOPE_VERSION) {
      throw new MajikSignatureValidationError(
        `Unsupported envelope version: ${String(obj.version)}`,
        "version",
      );
    }

    if (!Array.isArray(obj.signatures)) {
      throw new MajikSignatureValidationError(
        "Envelope.signatures must be an array",
        "signatures",
      );
    }

    for (const [i, sig] of (obj.signatures as unknown[]).entries()) {
      MajikSignatureEnvelope.#validateSignatureEntry(sig, i);
    }

    const hasAllowlist = obj.allowlist !== undefined;
    const hasAllowlistSignerId = obj.allowlistSignerId !== undefined;

    if (hasAllowlist !== hasAllowlistSignerId) {
      throw new MajikSignatureValidationError(
        "allowlist and allowlistSignerId must be set together",
        "allowlist",
      );
    }

    if (hasAllowlist) {
      if (
        !Array.isArray(obj.allowlist) ||
        (obj.allowlist as unknown[]).length === 0
      ) {
        throw new MajikSignatureValidationError(
          "allowlist must be a non-empty array when present",
          "allowlist",
        );
      }
      for (const [i, entry] of (obj.allowlist as unknown[]).entries()) {
        MajikSignatureEnvelope.#validateExpectedSignerEntry(entry, i);
      }
      if (
        typeof obj.allowlistSignerId !== "string" ||
        !obj.allowlistSignerId.trim()
      ) {
        throw new MajikSignatureValidationError(
          "allowlistSignerId must be a non-empty string when allowlist is set",
          "allowlistSignerId",
        );
      }
    }

    const sealFields = ["sealHash", "sealTimestamp", "sealedBy"] as const;
    const presentSealFields = sealFields.filter((f) => obj[f] !== undefined);
    if (
      presentSealFields.length > 0 &&
      presentSealFields.length < sealFields.length
    ) {
      throw new MajikSignatureValidationError(
        "sealHash, sealTimestamp, and sealedBy must all be present together, or all absent",
        "sealHash",
      );
    }

    if (obj.chainAnchors !== undefined && !Array.isArray(obj.chainAnchors)) {
      throw new MajikSignatureValidationError(
        "chainAnchors must be an array when present",
        "chainAnchors",
      );
    }

    const hasFileVersions = obj.fileVersions !== undefined;

    if (hasFileVersions) {
      const typedFileVersion = obj.fileVersions as FileVersion[];
      if (!Array.isArray(typedFileVersion)) {
        throw new MajikSignatureValidationError(
          "fileVersions must be an array when present",
          "fileVersions",
        );
      }
    }
  }

  static #validateSignatureEntry(sig: unknown, index: number): void {
    if (sig === null || typeof sig !== "object") {
      throw new MajikSignatureValidationError(
        `signatures[${index}] must be an object`,
        "signatures",
      );
    }
    const requiredStringFields = [
      "signerId",
      "signerEdPublicKey",
      "signerMlDsaPublicKey",
      "contentHash",
      "timestamp",
      "edSignature",
      "mlDsaSignature",
    ];
    const obj = sig as Record<string, unknown>;
    for (const field of requiredStringFields) {
      if (typeof obj[field] !== "string" || !(obj[field] as string).length) {
        throw new MajikSignatureValidationError(
          `signatures[${index}].${field} must be a non-empty string`,
          field,
        );
      }
    }
  }

  static #validateExpectedSignerEntry(entry: unknown, index: number): void {
    if (entry === null || typeof entry !== "object") {
      throw new MajikSignatureValidationError(
        `allowlist[${index}] must be an object`,
        "allowlist",
      );
    }
    const obj = entry as Record<string, unknown>;
    for (const field of ["signerId", "edPublicKey", "mlDsaPublicKey"]) {
      if (typeof obj[field] !== "string" || !(obj[field] as string).length) {
        throw new MajikSignatureValidationError(
          `allowlist[${index}].${field} must be a non-empty string`,
          field,
        );
      }
    }
  }
}

// Freeze static methods
Object.freeze(MajikSignatureEnvelope);

// Freeze instance methods
Object.freeze(MajikSignatureEnvelope.prototype);

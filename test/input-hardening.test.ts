import { beforeAll, describe, expect, it } from "vitest";
import type { MajikKey } from "@majikah/majik-key";
import { getTestKey } from "./helpers/crypto";
import { MajikSignature } from "../src/majik-signature";
import { MajikSignatureValidator } from "../src/core/validator";
import { MajikSignatureEnvelope } from "../src/core/envelope";
import {
  MAX_ALLOWLIST_ENTRIES,
  MAX_SIGNATURES_PER_ENVELOPE,
  MAX_ENVELOPE_BYTES,
} from "../src/core/constants";
import { base64ToBytes, bytesToBase64 } from "../src/core/hash";

const ED25519_L = new Uint8Array([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
]);

describe("untrusted signature input hardening", () => {
  let key: MajikKey;
  let json: ReturnType<MajikSignature["toJSON"]>;

  beforeAll(async () => {
    key = await getTestKey();
    json = (await MajikSignature.sign("hardening fixture", key)).toJSON();
  }, 120000);

  it("rejects non-canonical or incorrectly sized cryptographic base64", () => {
    expect(() => MajikSignatureValidator.validateJSON({
      ...json,
      signerEdPublicKey: "A".repeat(44),
    })).toThrow(/canonical base64/i);

    expect(() => MajikSignatureValidator.validateJSON({
      ...json,
      mlDsaSignature: "A".repeat(6176),
    })).toThrow(/canonical base64/i);

    expect(() => MajikSignatureValidator.validateJSON({
      ...json,
      contentHash: "!".repeat(44),
    })).toThrow(/canonical base64/i);
  });

  it("rejects oversized identity and metadata strings and control characters", () => {
    expect(() => MajikSignatureValidator.validateJSON({
      ...json,
      signerId: "x".repeat(257),
    })).toThrow(/canonical base64/i);

    expect(() => MajikSignatureValidator.validateJSON({
      ...json,
      contentType: "text/plain\r\nInjected: value",
    })).toThrow(/contentType/i);

    expect(() => MajikSignatureValidator.validateJSON({
      ...json,
      timestamp: "2".repeat(65),
    })).toThrow(/timestamp/i);
  });

  it("validates optional digest commitments instead of accepting arbitrary strings", () => {
    expect(() => MajikSignatureValidator.validateJSON({
      ...json,
      versionChainHash: "not-a-digest",
    })).toThrow(/versionChainHash/i);

    expect(() => MajikSignatureValidator.validateJSON({
      ...json,
      allowlistHash: "A".repeat(50000),
    })).toThrow(/allowlistHash/i);
  });

  it("bounds multi-signature and allowlist collections on both validators", () => {
    const tooManySignatures = {
      version: 1,
      signatures: Array.from(
        { length: MAX_SIGNATURES_PER_ENVELOPE + 1 },
        () => json,
      ),
    };
    expect(() => MajikSignatureValidator.validateMultiSigEnvelope(
      tooManySignatures,
    )).toThrow(/signatures exceeds/i);
    expect(() => MajikSignatureEnvelope.fromJSON(tooManySignatures)).toThrow(/signatures exceeds/i);

    const signer = MajikSignature.expectedSignerFromKey(key);
    const tooManyAllowlistEntries = {
      version: 1,
      signatures: [json],
      allowlist: Array.from(
        { length: MAX_ALLOWLIST_ENTRIES + 1 },
        () => signer,
      ),
      allowlistSignerId: key.fingerprint,
    };
    expect(() => MajikSignatureValidator.validateMultiSigEnvelope(
      tooManyAllowlistEntries,
    )).toThrow(/allowlist exceeds/i);
    expect(() => MajikSignatureEnvelope.fromJSON(tooManyAllowlistEntries)).toThrow(/allowlist exceeds/i);
  });

  it("rejects non-hex seal hashes", () => {
    expect(() => MajikSignatureValidator.validateSealHash(
      "z".repeat(128),
    )).toThrow(/hex/i);
  });
  it("rejects invalid TSA nonce and signer fingerprint encodings", () => {
    expect(() => MajikSignatureValidator.validateMajikTSAPayload({
      digest: { algorithm: "SHA-256", value: json.contentHash },
      nonce: "A".repeat(40),
      timestamp: json.timestamp,
      tsa: { id: "test-tsa", signerFingerprint: "A".repeat(44) },
    })).toThrow(/canonical base64/i);
  });

  it("bounds nested TSA signature recursion", () => {
    let nested: Record<string, unknown> = { ...json };
    for (let i = 0; i < 10; i++) {
      nested = {
        ...json,
        tsa: {
          version: 1,
          id: "nested-tsa",
          payload: {
            digest: { algorithm: "SHA-256", value: json.contentHash },
            nonce: bytesToBase64(new Uint8Array(32)),
            timestamp: json.timestamp,
            tsa: { id: "test-tsa", signerFingerprint: json.signerId },
          },
          signature: nested,
        },
      };
    }
    expect(() => MajikSignatureValidator.validateJSON(nested)).toThrow(/nesting/i);
  });


  it("rejects encoded envelopes that exceed the parser byte ceiling", () => {
    expect(() => MajikSignatureEnvelope.fromJSON(
      "\u0800".repeat(Math.floor(MAX_ENVELOPE_BYTES / 3) + 1),
    )).toThrow(/maximum supported size/i);
    expect(() => MajikSignatureEnvelope.fromCBOR(
      new Uint8Array(MAX_ENVELOPE_BYTES + 1),
    )).toThrow(/maximum supported size/i);
  });

  it("rejects oversized in-memory envelopes and base64 before decoding", () => {
    const oversizedObject = {
      version: 1,
      signatures: [],
      untrustedPadding: "x".repeat(MAX_ENVELOPE_BYTES + 1),
    };
    expect(() => MajikSignatureEnvelope.fromJSON(oversizedObject as any)).toThrow(
      /maximum supported size/i,
    );

    const maxEncodedLength = Math.ceil(MAX_ENVELOPE_BYTES / 3) * 4;
    expect(() => MajikSignatureEnvelope.deserialize("A".repeat(maxEncodedLength + 1))).toThrow(
      /maximum supported encoded size/i,
    );
  });

  it("bounds builder-supplied allowlists and seal metadata before processing", () => {
    const signer = MajikSignature.expectedSignerFromKey(key);
    const oversizedAllowlist = Array.from(
      { length: MAX_ALLOWLIST_ENTRIES + 1 },
      () => signer,
    );
    expect(() =>
      MajikSignatureEnvelope.empty().withAllowlist(
        oversizedAllowlist,
        key.fingerprint,
      ),
    ).toThrow(/allowlist exceeds/i);
    expect(() =>
      MajikSignatureEnvelope.empty().withSeal("x".repeat(257)),
    ).toThrow(/sealedBy/i);
  });

  it("validates builder-supplied revision metadata and snapshots nested inputs", () => {
    expect(() => MajikSignatureEnvelope.empty().withFileVersion({
      version: 1,
      timestamp: json.timestamp,
      contentHash: json.contentHash,
      message: "x".repeat(4_097),
    })).toThrow(/message exceeds/i);

    const signatureInput = { ...json };
    const envelope = MajikSignatureEnvelope.empty().withSignature(signatureInput);
    signatureInput.contentType = "application/x-mutated-after-build";
    expect(envelope.signatures[0]?.contentType).not.toBe(
      "application/x-mutated-after-build",
    );
  });

  it("rejects Ed25519 scalar-malleated signatures", () => {
    const mutated = json.edSignature;
    const bytes = base64ToBytes(mutated);
    let carry = 0;
    for (let i = 0; i < 32; i++) {
      const sum = bytes[32 + i] + ED25519_L[i] + carry;
      bytes[32 + i] = sum & 0xff;
      carry = sum >>> 8;
    }
    expect(carry).toBe(0);

    const altered = { ...json, edSignature: bytesToBase64(bytes) };
    const publicKeys = MajikSignature.publicKeysFromMajikKey(key);
    const verified = MajikSignature.verify(
      new TextEncoder().encode("hardening fixture"),
      altered,
      publicKeys,
    );
    expect(verified.valid).toBe(false);
  });
});

import { beforeAll, describe, expect, it } from "vitest";
import type { MajikKey } from "@majikah/majik-key";
import { getTestKey } from "./helpers/crypto";
import { MajikSignature } from "../src/majik-signature";
import { MajikSignatureValidator } from "../src/core/validator";
import { MAX_ALLOWLIST_ENTRIES, MAX_SIGNATURES_PER_ENVELOPE } from "../src/core/constants";

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
    })).toThrow(/signerId/i);

    expect(() => MajikSignatureValidator.validateJSON({
      ...json,
      contentType: "text/plain\\r\\nInjected: value",
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

  it("bounds multi-signature and allowlist collections", () => {
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
  });

  it("rejects non-hex seal hashes", () => {
    expect(() => MajikSignatureValidator.validateSealHash(
      "z".repeat(128),
    )).toThrow(/hex/i);
  });
});

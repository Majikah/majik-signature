import { beforeAll, describe, expect, it } from "vitest";
import type { MajikKey } from "@majikah/majik-key";

import { getTestKey } from "./helpers/crypto";
import { MajikSignature } from "../src/majik-signature";
import { MajikSignatureEnvelope } from "../src/core/envelope";
import { encodeCBOR, decodeCBOR } from "../src/core/cbor";
import {
  envelopeFromCBOR,
  envelopeToCBOR,
  signatureFromCBOR,
  signatureToCBOR,
} from "../src/core/cbor/cbor-wire";
import { base64ToBytes, bytesToBase64, hashContent } from "../src/core/hash";
import type {
  MajikSignatureJSON,
  MajikSignatureEnvelopeJSON,
  MajikTimestamp,
} from "../src/core/types";
import type { MajikChainAnchor } from "../src/anchor/types";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { MajikSignatureEmbed } from "../src/core/embed/majik-embed";
import {
  MJKSIG_CBOR_VERSION,
  MJKSIG_HEADER_LEN,
  MJKSIG_JSON_VERSION,
  MJKSIG_MAGIC,
  MJKSIG_MAGIC_LEN,
  MJKSIG_MEDIA_TYPE,
} from "../src/core/constants";

const CONTENT = new TextEncoder().encode(
  "Majik Signature CBOR round-trip fixture — signed bytes must remain identical.",
);
const CONTENT_TYPE = "application/octet-stream";
const SIGNED_AT = "2026-10-14T01:02:03.000Z";
const SECOND_SIGNED_AT = "2026-10-14T01:05:06.000Z";
const TSA_AT = "2026-10-14T01:06:07.000Z";
const SEAL_AT = "2026-10-14T01:07:08.000Z";
const VALID_UNTIL = "2099-01-01T00:00:00.000Z";
const VERIFY_AT = new Date("2026-10-14T02:00:00.000Z");

// Final FIPS 204 ML-DSA-87 sizes. Keep this explicit so an incorrect adapter
// constant (for example, the pre-standard 4,595-byte signature length) fails.
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
const ML_DSA_87_SIGNATURE_BYTES = 4627;
const SHA256_BYTES = 32;
const SHA3_512_BYTES = 64;

function deepJsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function makeAnchor(sealHash: string): MajikChainAnchor {
  return {
    version: 1,
    id: "cbor-test-anchor-0001",
    payload: {
      chain: "solana",
      network: "mainnet-beta",
      digest: { algorithm: "SHA3-512", value: sealHash },
    },
    memo: `majik-notary-v-1:${sealHash}`,
    txSignature: "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4f1zLh2m7xJ",
    slot: 345678901,
    blockTime: 1791939600,
    confirmedAt: "2026-10-14T01:08:00.000Z",
    status: "confirmed",
  };
}

function expectByteString(
  value: unknown,
  length?: number,
): asserts value is Uint8Array {
  expect(value).toBeInstanceOf(Uint8Array);
  if (length !== undefined)
    expect((value as Uint8Array).byteLength).toBe(length);
}

function expectOptionalFieldsOmitted(
  value: Record<string, unknown>,
  fields: readonly string[],
): void {
  for (const field of fields) {
    expect(Object.prototype.hasOwnProperty.call(value, field)).toBe(false);
  }
}

const __currentDir = dirname(fileURLToPath(import.meta.url));

const FIXTURES_DIR = join(__currentDir, "fixtures", "compat");

function loadFixture(filename: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURES_DIR, filename)));
}

/**
 * Reconstructs the legacy MJKSIG v1 binary container.
 *
 * Version 1 stores a UTF-8 JSON payload.
 * Version 2 stores a CBOR payload.
 *
 * Intentionally does not call toMJKSIGBytes(), because that method
 * should now generate version 2 containers.
 */
function makeLegacyV1MJKSIG(envelope: MajikSignatureEnvelope): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify(envelope.toJSON()));

  if (payload.byteLength === 0) {
    throw new Error("Legacy MJKSIG payload must not be empty");
  }

  const out = new Uint8Array(MJKSIG_HEADER_LEN + payload.byteLength);

  // Magic: "MJKSIG"
  out.set(MJKSIG_MAGIC, 0);

  // Legacy JSON container version.
  out[MJKSIG_MAGIC_LEN] = MJKSIG_JSON_VERSION;

  // Reserved byte must remain zero.
  out[MJKSIG_MAGIC_LEN + 1] = 0x00;

  // Four-byte unsigned big-endian payload length.
  const lengthOffset = MJKSIG_MAGIC_LEN + 2;
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);

  view.setUint32(lengthOffset, payload.byteLength, false);

  // Payload starts immediately after the fixed header.
  out.set(payload, MJKSIG_HEADER_LEN);

  return out;
}

describe("CBOR serialization — Majik Signature", () => {
  let keyA: MajikKey;
  let keyB: MajikKey;
  let tsaKey: MajikKey;
  let expectedSigners: ReturnType<
    typeof MajikSignature.expectedSignerFromKey
  >[];
  let fullSignature: MajikSignature;
  let minimalSignature: MajikSignature;
  let tsa: MajikTimestamp;
  let complexEnvelope: MajikSignatureEnvelope;
  let minimalEnvelope: MajikSignatureEnvelope;

  beforeAll(async () => {
    [keyA, keyB, tsaKey] = await Promise.all([
      getTestKey(),
      getTestKey(),
      getTestKey(),
    ]);

    expectedSigners = [
      MajikSignature.expectedSignerFromKey(keyA),
      MajikSignature.expectedSignerFromKey(keyB),
    ];

    const contentHash = bytesToBase64(hashContent(CONTENT));
    const previousVersion: import("../src/core/types").FileVersion = {
      version: 1,
      timestamp: "2026-10-13T09:00:00.000Z",
      contentHash: bytesToBase64(hashContent("previous revision bytes")),
      createdBy: keyB.fingerprint,
      message: "Previous revision for CBOR coverage",
    };
    const currentVersion: import("../src/core/types").FileVersion = {
      version: 2,
      timestamp: SIGNED_AT,
      contentHash,
      previousVersionHash:
        MajikSignatureEnvelope.hashFileVersionEntry(previousVersion),
      createdBy: keyA.fingerprint,
      message: "Current revision with CBOR metadata",
    };
    const versionChainHash = MajikSignatureEnvelope.hashFileVersionChain([
      previousVersion,
      currentVersion,
    ]);
    const allowlistHash = MajikSignatureEnvelope.hashAllowlist(expectedSigners);

    fullSignature = await MajikSignature.sign(CONTENT, keyA, {
      contentType: CONTENT_TYPE,
      timestamp: SIGNED_AT,
      validUntil: VALID_UNTIL,
      allowlistHash,
      versionChainHash,
    });

    tsa = await MajikSignature.signTSA(
      fullSignature.buildTSARequestPayload(),
      tsaKey,
      {
        id: "tsa.majikah.solutions",
        signerFingerprint: tsaKey.fingerprint,
      },
      { timestamp: TSA_AT },
    );
    fullSignature.addTSA(tsa);

    minimalSignature = await MajikSignature.sign(CONTENT, keyB, {
      timestamp: SECOND_SIGNED_AT,
    });

    // Construct a representative envelope containing optional sections and
    // nested binary fields. The signatureA commitments match the actual data.
    let envelope = MajikSignatureEnvelope.empty()
      .withAllowlist(expectedSigners, keyA.fingerprint)
      .withFileVersion(previousVersion)
      .withFileVersion(currentVersion)
      .withSignature(fullSignature.toJSON())
      .withSignature(minimalSignature.toJSON())
      .withSeal(keyA.fingerprint, SEAL_AT);

    const anchor = makeAnchor(envelope.sealHash!);
    envelope = envelope.withChainAnchor(anchor);
    complexEnvelope = envelope;
    minimalEnvelope = MajikSignatureEnvelope.empty();
  }, 120000);

  // ── Encoder / decoder primitives ──────────────────────────────────────────

  describe("core/cbor encoder and decoder", () => {
    it("encodes to Uint8Array and decodes primitive CBOR values", () => {
      const input = {
        text: "Majik Signature",
        version: 1,
        enabled: true,
        nothing: null,
        bytes: new Uint8Array([0, 1, 2, 127, 255]),
        values: [1, "two", false],
      };

      const encoded = encodeCBOR(input);
      expect(encoded).toBeInstanceOf(Uint8Array);
      expect(encoded.byteLength).toBeGreaterThan(0);
      expect(decodeCBOR(encoded)).toEqual(input);
    });

    it("accepts ArrayBuffer input", () => {
      const encoded = encodeCBOR({
        version: 1,
        bytes: new Uint8Array([1, 2, 3]),
      });
      const restored = decodeCBOR(
        Uint8Array.from(encoded).buffer as ArrayBuffer,
      );
      expect(restored).toEqual({
        version: 1,
        bytes: new Uint8Array([1, 2, 3]),
      });
    });

    it("rejects empty input", () => {
      expect(() => decodeCBOR(new Uint8Array())).toThrow(/must not be empty/i);
    });

    it("rejects malformed CBOR bytes", () => {
      expect(() => decodeCBOR(new Uint8Array([0xff]))).toThrow();
    });
  });

  // ── Single signature ──────────────────────────────────────────────────────

  describe("MajikSignature toCBOR / fromCBOR", () => {
    it("round-trips a full signature back to an identical JSON representation", () => {
      const before = fullSignature.toJSON();
      const bytes = fullSignature.toCBOR();
      const restored = MajikSignature.fromCBOR(bytes);

      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(restored).toBeInstanceOf(MajikSignature);
      expect(restored.toJSON()).toEqual(before);
      expect(restored.toJSON()).toEqual(
        MajikSignature.fromJSON(before).toJSON(),
      );
    });

    it("round-trips the CBOR-native adapter map to the existing JSON interface", () => {
      const json = fullSignature.toJSON();
      const cborShape = signatureToCBOR(json);
      const restoredJson = signatureFromCBOR(cborShape);

      expect(restoredJson).toEqual(json);
      expectByteString(cborShape.signerId, SHA256_BYTES);
      expectByteString(cborShape.signerEdPublicKey, ED25519_PUBLIC_KEY_BYTES);
      expectByteString(
        cborShape.signerMlDsaPublicKey,
        ML_DSA_87_PUBLIC_KEY_BYTES,
      );
      expectByteString(cborShape.contentHash, SHA256_BYTES);
      expectByteString(cborShape.edSignature, ED25519_SIGNATURE_BYTES);
      expectByteString(cborShape.mlDsaSignature, ML_DSA_87_SIGNATURE_BYTES);
      expectByteString(cborShape.allowlistHash, SHA256_BYTES);
      expectByteString(cborShape.versionChainHash, SHA256_BYTES);
      expectByteString(cborShape.tsa?.payload.digest.value, SHA256_BYTES);
      expectByteString(cborShape.tsa?.payload.nonce, 32);
      expectByteString(
        cborShape.tsa?.payload.tsa.signerFingerprint,
        SHA256_BYTES,
      );
    });

    it("uses real CBOR byte strings instead of Base64 strings for cryptographic fields", () => {
      const encoded = fullSignature.toCBOR();
      const decoded = decodeCBOR(encoded) as Record<string, unknown>;

      expectByteString(decoded.signerId, SHA256_BYTES);
      expectByteString(decoded.signerEdPublicKey, ED25519_PUBLIC_KEY_BYTES);
      expectByteString(
        decoded.signerMlDsaPublicKey,
        ML_DSA_87_PUBLIC_KEY_BYTES,
      );
      expectByteString(decoded.contentHash, SHA256_BYTES);
      expectByteString(decoded.edSignature, ED25519_SIGNATURE_BYTES);
      expectByteString(decoded.mlDsaSignature, ML_DSA_87_SIGNATURE_BYTES);
      expect(typeof decoded.timestamp).toBe("string");
      expect(decoded.version).toBe(1);
    });

    it("preserves valid cryptographic verification after CBOR round-trip", () => {
      const restored = MajikSignature.fromCBOR(fullSignature.toCBOR());
      const result = MajikSignature.verify(
        CONTENT,
        restored,
        MajikSignature.publicKeysFromMajikKey(keyA),
        VERIFY_AT,
      );

      expect(result.valid).toBe(true);
      expect(result.signerId).toBe(keyA.fingerprint);
      expect(restored.verifyTSA().valid).toBe(true);
    });

    it("supports JSON → CBOR → JSON and JSON → instance → CBOR → instance", () => {
      const originalJson = fullSignature.toJSON();
      const fromJson = MajikSignature.fromJSON(originalJson);
      const fromCbor = MajikSignature.fromCBOR(fromJson.toCBOR());
      const roundTripJson = fromCbor.toJSON();

      expect(roundTripJson).toEqual(originalJson);
      expect(MajikSignature.fromJSON(roundTripJson).toJSON()).toEqual(
        originalJson,
      );
    });

    it("preserves omitted optional fields instead of converting them to null", () => {
      const json = minimalSignature.toJSON();
      const restored = MajikSignature.fromCBOR(minimalSignature.toCBOR());

      expect(restored.toJSON()).toEqual(json);
      expectOptionalFieldsOmitted(
        restored.toJSON() as unknown as Record<string, unknown>,
        [
          "contentType",
          "allowlistHash",
          "validUntil",
          "tsa",
          "versionChainHash",
        ],
      );
    });

    it("preserves optional TSA, expiry, allowlist, and revision commitments", () => {
      const restored = MajikSignature.fromCBOR(fullSignature.toCBOR());
      expect(restored.toJSON().contentType).toBe(CONTENT_TYPE);
      expect(restored.toJSON().validUntil).toBe(VALID_UNTIL);
      expect(restored.toJSON().allowlistHash).toBe(
        fullSignature.toJSON().allowlistHash,
      );
      expect(restored.toJSON().versionChainHash).toBe(
        fullSignature.toJSON().versionChainHash,
      );
      expect(restored.toJSON().tsa).toEqual(tsa);
    });

    it("does not mutate the signature instance while encoding", () => {
      const before = deepJsonClone(fullSignature.toJSON());
      fullSignature.toCBOR();
      expect(fullSignature.toJSON()).toEqual(before);
    });

    it("produces a smaller payload than JSON for a full signature", () => {
      const jsonBytes = new TextEncoder().encode(
        JSON.stringify(fullSignature.toJSON()),
      ).byteLength;
      const cborBytes = fullSignature.toCBOR().byteLength;

      expect(cborBytes).toBeLessThan(jsonBytes);
    });

    it("rejects empty and malformed CBOR through fromCBOR", () => {
      expect(() => MajikSignature.fromCBOR(new Uint8Array())).toThrow(/CBOR/i);
      expect(() => MajikSignature.fromCBOR(new Uint8Array([0xff]))).toThrow();
    });

    it("rejects a valid CBOR value that is not a signature map", () => {
      expect(() => MajikSignature.fromCBOR(encodeCBOR([1, 2, 3]))).toThrow();
      expect(() => MajikSignature.fromCBOR(encodeCBOR({}))).toThrow();
    });

    it("rejects unsupported signature versions", () => {
      const wire = signatureToCBOR(fullSignature.toJSON());
      expect(() => signatureFromCBOR({ ...wire, version: 2 })).toThrow(
        /version/i,
      );
    });

    it("rejects cryptographic fields represented as strings instead of byte strings", () => {
      const wire = signatureToCBOR(fullSignature.toJSON());
      expect(() =>
        signatureFromCBOR({ ...wire, contentHash: "not-a-byte-string" }),
      ).toThrow(/byte string/i);
    });

    it("rejects incorrect Ed25519 public-key length", () => {
      const wire = signatureToCBOR(fullSignature.toJSON());
      expect(() =>
        signatureFromCBOR({
          ...wire,
          signerEdPublicKey: new Uint8Array(31),
        }),
      ).toThrow(/signerEdPublicKey must be 32 bytes/i);
    });

    it("rejects incorrect ML-DSA-87 signature length", () => {
      const wire = signatureToCBOR(fullSignature.toJSON());
      expect(() =>
        signatureFromCBOR({
          ...wire,
          mlDsaSignature: new Uint8Array(ML_DSA_87_SIGNATURE_BYTES - 1),
        }),
      ).toThrow(/mlDsaSignature must be 4627 bytes/i);
    });

    it("rejects malformed nested TSA byte fields", () => {
      const wire = signatureToCBOR(fullSignature.toJSON());
      expect(wire.tsa).toBeDefined();
      const badTsa = {
        ...wire.tsa!,
        payload: {
          ...wire.tsa!.payload,
          nonce: new Uint8Array(31),
        },
      };

      expect(() => signatureFromCBOR({ ...wire, tsa: badTsa })).toThrow(
        /nonce must be 32 bytes/i,
      );
    });
  });

  // ── Multi-signature envelope ──────────────────────────────────────────────

  describe("MajikSignatureEnvelope toCBOR / fromCBOR", () => {
    it("round-trips a complex envelope to an identical JSON representation", () => {
      const before = complexEnvelope.toJSON();
      const encoded = complexEnvelope.toCBOR();
      const restored = MajikSignatureEnvelope.fromCBOR(encoded);

      expect(encoded).toBeInstanceOf(Uint8Array);
      expect(restored).toBeInstanceOf(MajikSignatureEnvelope);
      expect(restored.toJSON()).toEqual(before);
      expect(restored.toJSON()).toEqual(
        MajikSignatureEnvelope.fromJSON(before).toJSON(),
      );
    });

    it("round-trips the CBOR-native envelope adapter map to JSON", () => {
      const json = complexEnvelope.toJSON();
      const cborShape = envelopeToCBOR(json);
      const restoredJson = envelopeFromCBOR(cborShape);

      expect(restoredJson).toEqual(json);
      expect(cborShape.version).toBe(1);
      expect(cborShape.signatures).toHaveLength(2);
      expectByteString(cborShape.allowlistSignerId, SHA256_BYTES);
      expectByteString(cborShape.sealHash, SHA3_512_BYTES);
      expectByteString(cborShape.sealedBy, SHA256_BYTES);
      expectByteString(cborShape.allowlist?.[0].signerId, SHA256_BYTES);
      expectByteString(
        cborShape.allowlist?.[0].edPublicKey,
        ED25519_PUBLIC_KEY_BYTES,
      );
      expectByteString(
        cborShape.allowlist?.[0].mlDsaPublicKey,
        ML_DSA_87_PUBLIC_KEY_BYTES,
      );
      expectByteString(cborShape.fileVersions?.[0].contentHash, SHA256_BYTES);
      expectByteString(
        cborShape.fileVersions?.[1].previousVersionHash,
        SHA256_BYTES,
      );
      expectByteString(cborShape.fileVersions?.[1].createdBy, SHA256_BYTES);
      expectByteString(
        cborShape.chainAnchors?.[0].payload.digest.value,
        SHA3_512_BYTES,
      );
    });

    it("preserves real CBOR byte strings throughout the nested envelope", () => {
      const decoded = decodeCBOR(complexEnvelope.toCBOR()) as Record<
        string,
        unknown
      >;
      const signatures = decoded.signatures as Record<string, unknown>[];
      const allowlist = decoded.allowlist as Record<string, unknown>[];
      const versions = decoded.fileVersions as Record<string, unknown>[];
      const anchors = decoded.chainAnchors as Record<string, unknown>[];
      const anchorPayload = anchors[0].payload as Record<string, unknown>;
      const digest = anchorPayload.digest as Record<string, unknown>;

      expectByteString(decoded.sealHash, SHA3_512_BYTES);
      expectByteString(decoded.sealedBy, SHA256_BYTES);
      expectByteString(allowlist[0].signerId, SHA256_BYTES);
      expectByteString(signatures[0].mlDsaSignature, ML_DSA_87_SIGNATURE_BYTES);
      expectByteString(versions[1].previousVersionHash, SHA256_BYTES);
      expectByteString(digest.value, SHA3_512_BYTES);
      expect(typeof anchors[0].memo).toBe("string");
      expect(typeof anchors[0].txSignature).toBe("string");
    });

    it("preserves seal, allowlist, revision-chain integrity, and TSA after round-trip", () => {
      const restored = MajikSignatureEnvelope.fromCBOR(
        complexEnvelope.toCBOR(),
      );

      expect(restored.isValid()).toBe(true);
      expect(restored.isSealed()).toBe(true);
      expect(restored.verifySeal().valid).toBe(true);
      expect(restored.verifyAllowlistIntegrity().valid).toBe(true);
      expect(restored.verifyVersionChainIntegrity().valid).toBe(true);
      expect(restored.signatures).toHaveLength(2);
      expect(restored.allowlist).toHaveLength(2);

      const restoredA = MajikSignature.fromJSON(
        restored.findSignature(keyA.fingerprint)!,
      );
      expect(restoredA.verifyTSA().valid).toBe(true);

      const verifyA = MajikSignature.verify(
        CONTENT,
        restoredA,
        MajikSignature.publicKeysFromMajikKey(keyA),
        VERIFY_AT,
      );
      expect(verifyA.valid).toBe(true);
    });

    it("preserves chain-anchor values exactly across CBOR → JSON round-trip", () => {
      const restored = MajikSignatureEnvelope.fromCBOR(
        complexEnvelope.toCBOR(),
      );
      expect(restored.chainAnchors).toEqual(complexEnvelope.chainAnchors);
      expect(restored.chainAnchors[0].payload.digest.value).toBe(
        complexEnvelope.chainAnchors[0].payload.digest.value,
      );
      expect(restored.chainAnchors[0].memo).toBe(
        complexEnvelope.chainAnchors[0].memo,
      );
      expect(restored.chainAnchors[0].txSignature).toBe(
        complexEnvelope.chainAnchors[0].txSignature,
      );
    });

    it("round-trips an empty/minimal envelope and omits optional sections", () => {
      const before = minimalEnvelope.toJSON();
      const restored = MajikSignatureEnvelope.fromCBOR(
        minimalEnvelope.toCBOR(),
      );

      expect(restored.toJSON()).toEqual(before);
      expect(restored.signatures).toEqual([]);
      expectOptionalFieldsOmitted(
        restored.toJSON() as unknown as Record<string, unknown>,
        [
          "allowlist",
          "allowlistSignerId",
          "sealHash",
          "sealTimestamp",
          "sealedBy",
          "chainAnchors",
          "fileVersions",
        ],
      );
    });

    it("supports JSON → CBOR → JSON in both directions", () => {
      const json = complexEnvelope.toJSON();
      const fromJson = MajikSignatureEnvelope.fromJSON(json);
      const fromCbor = MajikSignatureEnvelope.fromCBOR(fromJson.toCBOR());
      const finalJson = fromCbor.toJSON();

      expect(finalJson).toEqual(json);
      expect(MajikSignatureEnvelope.fromJSON(finalJson).toJSON()).toEqual(json);
    });

    it("does not mutate an envelope when encoding it", () => {
      const before = deepJsonClone(complexEnvelope.toJSON());
      complexEnvelope.toCBOR();
      expect(complexEnvelope.toJSON()).toEqual(before);
    });

    it("produces a smaller payload than JSON for the complex envelope", () => {
      const jsonBytes = new TextEncoder().encode(
        JSON.stringify(complexEnvelope.toJSON()),
      ).byteLength;
      const cborBytes = complexEnvelope.toCBOR().byteLength;

      expect(cborBytes).toBeLessThan(jsonBytes);
    });

    it("rejects empty, malformed, and non-map CBOR inputs", () => {
      expect(() => MajikSignatureEnvelope.fromCBOR(new Uint8Array())).toThrow(
        /CBOR/i,
      );
      expect(() =>
        MajikSignatureEnvelope.fromCBOR(new Uint8Array([0xff])),
      ).toThrow();
      expect(() =>
        MajikSignatureEnvelope.fromCBOR(encodeCBOR([1, 2, 3])),
      ).toThrow();
    });

    it("rejects unsupported envelope versions", () => {
      const wire = envelopeToCBOR(complexEnvelope.toJSON());
      expect(() => envelopeFromCBOR({ ...wire, version: 99 })).toThrow(
        /version/i,
      );
    });

    it("rejects invalid envelope collection types", () => {
      const wire = envelopeToCBOR(complexEnvelope.toJSON());
      expect(() =>
        envelopeFromCBOR({ ...wire, signatures: "not-an-array" }),
      ).toThrow(/signatures must be an array/i);
      expect(() =>
        envelopeFromCBOR({ ...wire, allowlist: "not-an-array" }),
      ).toThrow(/allowlist must be an array/i);
      expect(() =>
        envelopeFromCBOR({ ...wire, chainAnchors: "not-an-array" }),
      ).toThrow(/chainAnchors must be an array/i);
      expect(() =>
        envelopeFromCBOR({ ...wire, fileVersions: "not-an-array" }),
      ).toThrow(/fileVersions must be an array/i);
    });

    it("rejects malformed seal hash length", () => {
      const wire = envelopeToCBOR(complexEnvelope.toJSON());
      expect(() =>
        envelopeFromCBOR({ ...wire, sealHash: new Uint8Array(63) }),
      ).toThrow(/64 bytes/i);
    });

    it("rejects malformed chain-anchor digest length", () => {
      const wire = envelopeToCBOR(complexEnvelope.toJSON());
      const anchor = wire.chainAnchors![0];
      const badAnchor = {
        ...anchor,
        payload: {
          ...anchor.payload,
          digest: { algorithm: "SHA3-512" as const, value: new Uint8Array(63) },
        },
      };

      expect(() =>
        envelopeFromCBOR({
          ...wire,
          chainAnchors: [badAnchor],
        }),
      ).toThrow(/64 bytes/i);
    });

    it("rejects malformed nested signature fields", () => {
      const wire = envelopeToCBOR(complexEnvelope.toJSON());
      const first = wire.signatures[0];
      const badFirst = {
        ...first,
        signerMlDsaPublicKey: new Uint8Array(2591),
      };

      expect(() =>
        envelopeFromCBOR({
          ...wire,
          signatures: [badFirst, wire.signatures[1]],
        }),
      ).toThrow(/signerMlDsaPublicKey must be 2592 bytes/i);
    });
  });

  // ── MJKSIG container compatibility ─────────────────────────────────────────

  describe("MJKSIG container compatibility — JSON v1 / CBOR v2", () => {
    it("writes new MJKSIG containers using version 2 CBOR", async () => {
      const bytes = complexEnvelope.toMJKSIGBytes();

      // The writer must use the new container version.
      expect(bytes[MJKSIG_MAGIC_LEN]).toBe(MJKSIG_CBOR_VERSION);

      // Validate the unchanged reserved byte.
      expect(bytes[MJKSIG_MAGIC_LEN + 1]).toBe(0x00);

      // Confirm that the payload is actually CBOR, not JSON text.
      const payload = bytes.subarray(MJKSIG_HEADER_LEN);
      const decoded = decodeCBOR(payload) as Record<string, unknown>;

      expect(decoded.version).toBe(1);
      expect(decoded.signatures).toBeDefined();

      const signatures = decoded.signatures as Record<string, unknown>[];
      expect(signatures).toHaveLength(2);

      // Cryptographic fields should use native CBOR byte strings.
      expectByteString(signatures[0].signerId, SHA256_BYTES);
      expectByteString(signatures[0].mlDsaSignature, ML_DSA_87_SIGNATURE_BYTES);

      // Current reader can immediately reload its newly written container.
      const restored = await MajikSignatureEnvelope.fromMJKSIG(bytes);

      expect(restored).toBeInstanceOf(MajikSignatureEnvelope);
      expect(restored.toJSON()).toEqual(complexEnvelope.toJSON());
      expect(restored.verifySeal().valid).toBe(true);
    });

    it("preserves the MJKSIG MIME type for the CBOR container", () => {
      const blob = complexEnvelope.toMJKSIG();

      expect(blob).toBeInstanceOf(Blob);
      expect(blob.type).toBe(MJKSIG_MEDIA_TYPE);
    });

    it("continues reading legacy version 1 JSON containers", async () => {
      const legacyBytes = makeLegacyV1MJKSIG(complexEnvelope);

      expect(legacyBytes[MJKSIG_MAGIC_LEN]).toBe(MJKSIG_JSON_VERSION);

      // Prove that the old format genuinely contains UTF-8 JSON.
      const legacyPayload = new TextDecoder("utf-8", {
        fatal: true,
      }).decode(legacyBytes.subarray(MJKSIG_HEADER_LEN));

      expect(() => JSON.parse(legacyPayload)).not.toThrow();

      const restored = await MajikSignatureEnvelope.fromMJKSIG(legacyBytes);

      expect(restored).toBeInstanceOf(MajikSignatureEnvelope);
      expect(restored.toJSON()).toEqual(complexEnvelope.toJSON());

      // Important envelope integrity checks survive legacy deserialization.
      expect(restored.isValid()).toBe(true);
      expect(restored.isSealed()).toBe(true);
      expect(restored.verifySeal().valid).toBe(true);
      expect(restored.verifyAllowlistIntegrity().valid).toBe(true);
      expect(restored.verifyVersionChainIntegrity().valid).toBe(true);
    });

    it("rejects unsupported MJKSIG container versions", async () => {
      const bytes = complexEnvelope.toMJKSIGBytes();
      bytes[MJKSIG_MAGIC_LEN] = 0x7f;

      await expect(MajikSignatureEnvelope.fromMJKSIG(bytes)).rejects.toThrow(
        /unsupported.*version/i,
      );
    });
  });

  // ── Cross-format regression checks ────────────────────────────────────────

  describe("JSON/CBOR interoperability and regression checks", () => {
    it("normalizes a CBOR signature into a JSON instance that still verifies", () => {
      const cbor = fullSignature.toCBOR();
      const cborDecodedToJson: MajikSignatureJSON = signatureFromCBOR(
        decodeCBOR(cbor),
      );
      const normalized = MajikSignature.fromJSON(cborDecodedToJson);
      const result = MajikSignature.verify(
        CONTENT,
        normalized,
        MajikSignature.publicKeysFromMajikKey(keyA),
        VERIFY_AT,
      );

      expect(normalized.toJSON()).toEqual(fullSignature.toJSON());
      expect(result.valid).toBe(true);
    });

    it("normalizes a CBOR envelope into the existing JSON envelope schema", () => {
      const decoded = decodeCBOR(complexEnvelope.toCBOR());
      const json: MajikSignatureEnvelopeJSON = envelopeFromCBOR(decoded);
      const normalized = MajikSignatureEnvelope.fromJSON(json);

      expect(normalized.toJSON()).toEqual(complexEnvelope.toJSON());
      expect(normalized.verifySeal().valid).toBe(true);
      expect(normalized.verifyAllowlistIntegrity().valid).toBe(true);
    });

    it("does not alter existing JSON serialization output", () => {
      const beforeSignature = fullSignature.toJSON();
      const beforeEnvelope = complexEnvelope.toJSON();

      // Exercise CBOR without replacing or mutating the established JSON API.
      MajikSignature.fromCBOR(fullSignature.toCBOR());
      MajikSignatureEnvelope.fromCBOR(complexEnvelope.toCBOR());

      expect(fullSignature.toJSON()).toEqual(beforeSignature);
      expect(complexEnvelope.toJSON()).toEqual(beforeEnvelope);
      expect(fullSignature.serialize()).toBe(
        btoa(
          Array.from(
            new TextEncoder().encode(JSON.stringify(beforeSignature)),
            (byte) => String.fromCharCode(byte),
          ).join(""),
        ),
      );
    });

    it("confirms Base64-backed cryptographic values are converted without changing their bytes", () => {
      const json = fullSignature.toJSON();
      const wire = signatureToCBOR(json);

      expect(wire.signerId).toEqual(base64ToBytes(json.signerId));
      expect(wire.signerEdPublicKey).toEqual(
        base64ToBytes(json.signerEdPublicKey),
      );
      expect(wire.signerMlDsaPublicKey).toEqual(
        base64ToBytes(json.signerMlDsaPublicKey),
      );
      expect(wire.edSignature).toEqual(base64ToBytes(json.edSignature));
      expect(wire.mlDsaSignature).toEqual(base64ToBytes(json.mlDsaSignature));
      expect(wire.contentHash).toEqual(base64ToBytes(json.contentHash));
    });
  });

  // ── Legacy embedded-file compatibility ─────────────────────────────────────

  describe("Legacy embedded-file compatibility — previous JSON signatures", () => {
    const legacyFiles = [
      {
        filename: "compat.pdf",
        mimeType: "application/pdf",
      },
      {
        filename: "compat.jpg",
        mimeType: "image/jpeg",
      },
      {
        filename: "compat.wav",
        mimeType: "audio/wav",
      },
    ] as const;

    it.each(legacyFiles)(
      "loads and verifies the legacy embedded signature in $filename",
      async ({ filename, mimeType }) => {
        const bytes = loadFixture(filename);

        // Step 1: The historical embedded JSON envelope must still parse.
        const extracted = await MajikSignatureEmbed.extract(bytes, {
          mimeType,
        });

        expect(
          extracted,
          `${filename} should contain a readable legacy signature envelope`,
        ).not.toBeNull();

        const envelope = extracted!.envelope;

        expect(envelope).toBeInstanceOf(MajikSignatureEnvelope);
        expect(envelope.isValid()).toBe(true);
        expect(envelope.signatures.length).toBeGreaterThan(0);

        // Step 2: Verify each historical signature against the original file.
        //
        // These public keys are read from the signatures embedded in the
        // fixed fixtures. No new key or signature is generated here.
        for (const signatureJSON of envelope.signatures) {
          const signature = MajikSignature.fromJSON(signatureJSON);
          const publicKeys = signature.extractPublicKeys();

          const results = await MajikSignature.verifyFile(bytes, publicKeys, {
            mimeType,
            expectedSignerId: signature.signerId,
          });

          expect(
            results.some((result) => result.valid),
            [
              `Legacy signature verification failed for ${filename}.`,
              `Signer: ${signature.signerId}`,
              `Results: ${JSON.stringify(results)}`,
            ].join("\n"),
          ).toBe(true);
        }
      },
    );
  });
});

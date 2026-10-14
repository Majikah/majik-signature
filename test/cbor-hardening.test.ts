
import { beforeAll, describe, expect, it } from "vitest";
import type { MajikKey } from "@majikah/majik-key";

import { getTestKey } from "./helpers/crypto";
import { MajikSignature } from "../src/majik-signature";
import { MajikSignatureEnvelope } from "../src/core/envelope";
import { encodeCBOR, decodeCBOR } from "../src/core/cbor";
import {
  signatureFromCBOR,
  signatureToCBOR,
} from "../src/core/cbor/cbor-wire";
import {
  MJKSIG_CBOR_VERSION,
  MJKSIG_HEADER_LEN,
  MJKSIG_JSON_VERSION,
  MJKSIG_MAGIC,
  MJKSIG_MAGIC_LEN,
  MJKSIG_MEDIA_TYPE,
} from "../src/core/constants";

const CONTENT = new TextEncoder().encode(
  "Majik Signature CBOR hardening regression fixture.",
);

const SIGNED_AT = "2026-10-14T01:02:03.000Z";
const VERIFY_AT = new Date("2026-10-14T02:00:00.000Z");

const SHA256_BYTES = 32;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
const ML_DSA_87_SIGNATURE_BYTES = 4627;
const SHA3_512_BYTES = 64;

type ContainerOptions = {
  reserved?: number;
  declaredLength?: number;
};

/**
 * Builds an MJKSIG container without using the production writer.
 * This allows malformed headers and payload lengths to be tested
 * independently from toMJKSIGBytes().
 */
function makeMJKSIGContainer(
  version: number,
  payload: Uint8Array,
  options: ContainerOptions = {},
): Uint8Array {
  const out = new Uint8Array(
    MJKSIG_HEADER_LEN + payload.byteLength,
  );

  out.set(MJKSIG_MAGIC, 0);
  out[MJKSIG_MAGIC_LEN] = version & 0xff;
  out[MJKSIG_MAGIC_LEN + 1] = options.reserved ?? 0;

  const lengthOffset = MJKSIG_MAGIC_LEN + 2;
  const view = new DataView(
    out.buffer,
    out.byteOffset,
    out.byteLength,
  );

  view.setUint32(
    lengthOffset,
    options.declaredLength ?? payload.byteLength,
    false,
  );

  out.set(payload, MJKSIG_HEADER_LEN);
  return out;
}

/**
 * Creates a legacy v1 container using UTF-8 JSON.
 * Do not replace this with the current production writer.
 */
function makeLegacyV1Container(
  envelope: MajikSignatureEnvelope,
): Uint8Array {
  const json = new TextEncoder().encode(
    JSON.stringify(envelope.toJSON()),
  );

  return makeMJKSIGContainer(MJKSIG_JSON_VERSION, json);
}

function appendBytes(
  input: Uint8Array,
  suffix: Uint8Array,
): Uint8Array {
  const result = new Uint8Array(input.byteLength + suffix.byteLength);
  result.set(input, 0);
  result.set(suffix, input.byteLength);
  return result;
}

function expectByteString(
  value: unknown,
  expectedLength?: number,
): asserts value is Uint8Array {
  expect(value).toBeInstanceOf(Uint8Array);

  if (expectedLength !== undefined) {
    expect((value as Uint8Array).byteLength).toBe(expectedLength);
  }
}

describe("CBOR hardening and backward compatibility", () => {
  let key: MajikKey;
  let signature: MajikSignature;
  let envelope: MajikSignatureEnvelope;

  beforeAll(async () => {
    key = await getTestKey();

    signature = await MajikSignature.sign(CONTENT, key, {
      timestamp: SIGNED_AT,
      contentType: "application/octet-stream",
    });

    envelope = MajikSignatureEnvelope.empty().withSignature(
      signature.toJSON(),
    );
  }, 120000);

  // ── Decoder input validation ─────────────────────────────────────────────

  describe("CBOR decoder input validation", () => {
    it("rejects empty input", () => {
      expect(() => decodeCBOR(new Uint8Array())).toThrow();
    });

    it.each([
      {
        label: "top-level break code",
        bytes: [0xff],
      },
      {
        label: "truncated byte string",
        bytes: [0x45, 0x01, 0x02],
      },
      {
        label: "truncated array",
        bytes: [0x82, 0x01],
      },
      {
        label: "truncated map",
        bytes: [0xa1, 0x01],
      },
      {
        label: "truncated unsigned integer",
        bytes: [0x19, 0x01],
      },
      {
        label: "reserved additional-information value",
        bytes: [0x1c],
      },
    ])("rejects $label", ({ bytes }) => {
      expect(() => decodeCBOR(new Uint8Array(bytes))).toThrow();
    });

    it("reads only the selected Uint8Array view, not adjacent buffer data", () => {
      const encoded = encodeCBOR({
        message: "correct view",
        binary: new Uint8Array([1, 2, 3]),
      });

      const backing = new Uint8Array(encoded.byteLength + 8);
      backing.fill(0xff);
      backing.set(encoded, 4);

      const view = backing.subarray(4, 4 + encoded.byteLength);

      expect(decodeCBOR(view)).toEqual({
        message: "correct view",
        binary: new Uint8Array([1, 2, 3]),
      });
    });

    it("rejects trailing data after a valid CBOR item", () => {
      const encoded = encodeCBOR({ valid: true });
      const trailing = appendBytes(
        encoded,
        new Uint8Array([0x00]),
      );

      // The payload contract requires exactly one CBOR data item.
      expect(() => decodeCBOR(trailing)).toThrow();
    });

    it("rejects trailing data after a CBOR envelope", () => {
      const encoded = envelope.toCBOR();
      const trailing = appendBytes(
        encoded,
        new Uint8Array([0x00]),
      );

      expect(() =>
        MajikSignatureEnvelope.fromCBOR(trailing),
      ).toThrow();
    });

    it("rejects CBOR values that are not envelope maps", () => {
      expect(() =>
        MajikSignatureEnvelope.fromCBOR(encodeCBOR([1, 2, 3])),
      ).toThrow();

      expect(() =>
        MajikSignatureEnvelope.fromCBOR(encodeCBOR("not an envelope")),
      ).toThrow();

      expect(() =>
        MajikSignatureEnvelope.fromCBOR(encodeCBOR(null)),
      ).toThrow();

      expect(() =>
        MajikSignatureEnvelope.fromCBOR(encodeCBOR({})),
      ).toThrow();
    });

    it("accepts ArrayBuffer input for a valid envelope", () => {
      const encoded = envelope.toCBOR();
      const buffer = Uint8Array.from(encoded).buffer as ArrayBuffer;

      const restored = MajikSignatureEnvelope.fromCBOR(buffer);

      expect(restored.toJSON()).toEqual(envelope.toJSON());
    });

    it("handles a Uint8Array view with a nonzero byte offset", () => {
      const encoded = envelope.toCBOR();
      const backing = new Uint8Array(encoded.byteLength + 12);

      backing.set(encoded, 6);

      const view = backing.subarray(6, 6 + encoded.byteLength);
      const restored = MajikSignatureEnvelope.fromCBOR(view);

      expect(restored.toJSON()).toEqual(envelope.toJSON());
    });
  });

  // ── Signature field validation ───────────────────────────────────────────

  describe("CBOR signature schema validation", () => {
    it("uses native byte strings for fixed-length cryptographic fields", () => {
      const wire = signatureToCBOR(signature.toJSON());

      expectByteString(wire.signerId, SHA256_BYTES);
      expectByteString(
        wire.signerEdPublicKey,
        ED25519_PUBLIC_KEY_BYTES,
      );
      expectByteString(
        wire.signerMlDsaPublicKey,
        ML_DSA_87_PUBLIC_KEY_BYTES,
      );
      expectByteString(wire.contentHash, SHA256_BYTES);
      expectByteString(wire.edSignature, ED25519_SIGNATURE_BYTES);
      expectByteString(
        wire.mlDsaSignature,
        ML_DSA_87_SIGNATURE_BYTES,
      );

      expect(signatureFromCBOR(wire)).toEqual(signature.toJSON());
    });

    it("rejects a signature encoded with an unsupported schema version", () => {
      const wire = signatureToCBOR(signature.toJSON());

      expect(() =>
        signatureFromCBOR({ ...wire, version: 99 }),
      ).toThrow(/version/i);
    });

    it("rejects Base64 strings where CBOR byte strings are required", () => {
      const wire = signatureToCBOR(signature.toJSON());

      expect(() =>
        signatureFromCBOR({
          ...wire,
          contentHash: "not-a-byte-string",
        }),
      ).toThrow(/byte string/i);
    });

    it.each([
      {
        field: "signerId",
        value: new Uint8Array(SHA256_BYTES - 1),
      },
      {
        field: "signerEdPublicKey",
        value: new Uint8Array(ED25519_PUBLIC_KEY_BYTES - 1),
      },
      {
        field: "signerMlDsaPublicKey",
        value: new Uint8Array(ML_DSA_87_PUBLIC_KEY_BYTES - 1),
      },
      {
        field: "contentHash",
        value: new Uint8Array(SHA256_BYTES - 1),
      },
      {
        field: "edSignature",
        value: new Uint8Array(ED25519_SIGNATURE_BYTES - 1),
      },
      {
        field: "mlDsaSignature",
        value: new Uint8Array(ML_DSA_87_SIGNATURE_BYTES - 1),
      },
    ])("rejects an invalid byte length for $field", ({ field, value }) => {
      const wire = signatureToCBOR(signature.toJSON());

      expect(() =>
        signatureFromCBOR({
          ...wire,
          [field]: value,
        }),
      ).toThrow();
    });

    it("rejects malformed CBOR passed to the signature deserializer", () => {
      expect(() =>
        MajikSignature.fromCBOR(new Uint8Array()),
      ).toThrow();

      expect(() =>
        MajikSignature.fromCBOR(new Uint8Array([0xff])),
      ).toThrow();

      expect(() =>
        MajikSignature.fromCBOR(encodeCBOR([1, 2, 3])),
      ).toThrow();

      expect(() =>
        MajikSignature.fromCBOR(encodeCBOR({})),
      ).toThrow();
    });

    it("retains valid signature verification after CBOR decoding", () => {
      const restored = MajikSignature.fromCBOR(signature.toCBOR());

      const result = MajikSignature.verify(
        CONTENT,
        restored,
        MajikSignature.publicKeysFromMajikKey(key),
        VERIFY_AT,
      );

      expect(result.valid).toBe(true);
      expect(result.signerId).toBe(key.fingerprint);
    });
  });

  // ── MJKSIG framing and parser hardening ───────────────────────────────────

  describe("MJKSIG container framing", () => {
    it("writes v2 CBOR with the correct header and exact length", async () => {
      const bytes = envelope.toMJKSIGBytes();

      expect(bytes.byteLength).toBeGreaterThan(MJKSIG_HEADER_LEN);
      expect(Array.from(bytes.subarray(0, MJKSIG_MAGIC_LEN))).toEqual(
        Array.from(MJKSIG_MAGIC),
      );

      expect(bytes[MJKSIG_MAGIC_LEN]).toBe(MJKSIG_CBOR_VERSION);
      expect(bytes[MJKSIG_MAGIC_LEN + 1]).toBe(0x00);

      const declaredLength = new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      ).getUint32(MJKSIG_MAGIC_LEN + 2, false);

      expect(declaredLength).toBe(
        bytes.byteLength - MJKSIG_HEADER_LEN,
      );

      const payload = bytes.subarray(MJKSIG_HEADER_LEN);
      const restored = await MajikSignatureEnvelope.fromMJKSIG(bytes);

      expect(restored.toJSON()).toEqual(envelope.toJSON());
      expect(decodeCBOR(payload)).toBeDefined();
    });

    it("keeps the registered MIME type for generated MJKSIG blobs", async () => {
      const blob = envelope.toMJKSIG();

      expect(blob).toBeInstanceOf(Blob);
      expect(blob.type).toBe(MJKSIG_MEDIA_TYPE);

      const restored = await MajikSignatureEnvelope.fromMJKSIG(blob);

      expect(restored.toJSON()).toEqual(envelope.toJSON());
    });

    it("continues loading legacy v1 JSON containers", async () => {
      const legacy = makeLegacyV1Container(envelope);

      expect(legacy[MJKSIG_MAGIC_LEN]).toBe(MJKSIG_JSON_VERSION);

      const payload = new TextDecoder("utf-8", {
        fatal: true,
      }).decode(legacy.subarray(MJKSIG_HEADER_LEN));

      expect(() => JSON.parse(payload)).not.toThrow();

      const restored = await MajikSignatureEnvelope.fromMJKSIG(legacy);

      expect(restored.toJSON()).toEqual(envelope.toJSON());

      const restoredSignature = MajikSignature.fromJSON(
        restored.signatures[0],
      );

      const verification = MajikSignature.verify(
        CONTENT,
        restoredSignature,
        MajikSignature.publicKeysFromMajikKey(key),
        VERIFY_AT,
      );

      expect(verification.valid).toBe(true);
    });

    it("rejects truncated headers", async () => {
      const valid = envelope.toMJKSIGBytes();

      const inputs = [
        new Uint8Array(),
        valid.subarray(0, 1),
        valid.subarray(0, MJKSIG_MAGIC_LEN - 1),
        valid.subarray(0, MJKSIG_HEADER_LEN - 1),
      ];

      for (const input of inputs) {
        await expect(
          MajikSignatureEnvelope.fromMJKSIG(input),
        ).rejects.toThrow();
      }
    });

    it("rejects incorrect magic bytes", async () => {
      const bytes = envelope.toMJKSIGBytes();
      bytes[0] ^= 0xff;

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow(/magic/i);
    });

    it("rejects a nonzero reserved header byte", async () => {
      const bytes = envelope.toMJKSIGBytes();
      bytes[MJKSIG_MAGIC_LEN + 1] = 0x01;

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow(/reserved/i);
    });

    it("rejects unsupported container versions", async () => {
      const bytes = envelope.toMJKSIGBytes();
      bytes[MJKSIG_MAGIC_LEN] = 0x7f;

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow(/version/i);
    });

    it("rejects empty payloads", async () => {
      const bytes = makeMJKSIGContainer(
        MJKSIG_CBOR_VERSION,
        new Uint8Array(),
      );

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow();
    });

    it("rejects a declared payload length larger than the buffer", async () => {
      const payload = envelope.toCBOR();

      const bytes = makeMJKSIGContainer(
        MJKSIG_CBOR_VERSION,
        payload,
        { declaredLength: payload.byteLength + 1 },
      );

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow(/length|payload|buffer/i);
    });

    it("rejects a declared payload length larger than available data, including UINT32_MAX", async () => {
      const payload = envelope.toCBOR();

      const bytes = makeMJKSIGContainer(
        MJKSIG_CBOR_VERSION,
        payload,
        { declaredLength: 0xffff_ffff },
      );

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow();
    });

    it("rejects a declared payload length shorter than the actual payload", async () => {
      const payload = envelope.toCBOR();

      const bytes = makeMJKSIGContainer(
        MJKSIG_CBOR_VERSION,
        payload,
        { declaredLength: payload.byteLength - 1 },
      );

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow(/trailing|length|payload/i);
    });

    it("rejects bytes appended outside the declared container payload", async () => {
      const valid = envelope.toMJKSIGBytes();
      const modified = appendBytes(valid, new Uint8Array([0x00]));

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(modified),
      ).rejects.toThrow(/trailing|length|payload/i);
    });

    it("rejects invalid UTF-8 in a legacy v1 container", async () => {
      const bytes = makeMJKSIGContainer(
        MJKSIG_JSON_VERSION,
        new Uint8Array([0xff, 0xfe]),
      );

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow();
    });

    it("rejects malformed JSON in a legacy v1 container", async () => {
      const bytes = makeMJKSIGContainer(
        MJKSIG_JSON_VERSION,
        new TextEncoder().encode("{"),
      );

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow();
    });

    it("rejects malformed CBOR in a v2 container", async () => {
      const bytes = makeMJKSIGContainer(
        MJKSIG_CBOR_VERSION,
        new Uint8Array([0xff]),
      );

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow();
    });

    it("rejects a valid CBOR value of the wrong envelope shape", async () => {
      const bytes = makeMJKSIGContainer(
        MJKSIG_CBOR_VERSION,
        encodeCBOR([1, 2, 3]),
      );

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow();
    });

    it("rejects a v2 payload containing a valid envelope plus another CBOR item", async () => {
      const payload = appendBytes(
        envelope.toCBOR(),
        new Uint8Array([0x00]),
      );

      const bytes = makeMJKSIGContainer(
        MJKSIG_CBOR_VERSION,
        payload,
      );

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(bytes),
      ).rejects.toThrow();
    });
  });

  // ── Non-mutation guarantees ───────────────────────────────────────────────

  describe("Serialization and verification must not mutate caller data", () => {
    it("does not mutate the signature when serializing to CBOR", () => {
      const before = JSON.stringify(signature.toJSON());

      signature.toCBOR();

      expect(JSON.stringify(signature.toJSON())).toBe(before);
    });

    it("does not mutate the envelope when serializing to CBOR or MJKSIG", () => {
      const before = JSON.stringify(envelope.toJSON());

      envelope.toCBOR();
      envelope.toMJKSIGBytes();

      expect(JSON.stringify(envelope.toJSON())).toBe(before);
    });

    it("does not mutate input bytes while decoding a CBOR envelope", () => {
      const bytes = envelope.toCBOR();
      const before = new Uint8Array(bytes);

      MajikSignatureEnvelope.fromCBOR(bytes);

      expect(bytes).toEqual(before);
    });

    it("preserves the existing JSON representation after CBOR operations", () => {
      const signatureBefore = signature.toJSON();
      const envelopeBefore = envelope.toJSON();

      const restoredSignature = MajikSignature.fromCBOR(
        signature.toCBOR(),
      );
      const restoredEnvelope = MajikSignatureEnvelope.fromCBOR(
        envelope.toCBOR(),
      );

      expect(restoredSignature.toJSON()).toEqual(signatureBefore);
      expect(restoredEnvelope.toJSON()).toEqual(envelopeBefore);
      expect(signature.toJSON()).toEqual(signatureBefore);
      expect(envelope.toJSON()).toEqual(envelopeBefore);
    });
  });
});

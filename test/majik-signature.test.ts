import { describe, it, expect, vi, beforeAll } from "vitest";
import { MajikSignature } from "../src/majik-signature";
import { getTestKey } from "./helpers/crypto";
import { MajikKey } from "@majikah/majik-key";

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __currentDir = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__currentDir, "fixtures");

interface FileFixture {
  label: string;
  file: string;
  contentType: string;
}

const FILE_FIXTURES: FileFixture[] = [
  { label: "Plain Text", file: "sample.txt", contentType: "text/plain" },
  { label: "MP4 Video", file: "sample.mp4", contentType: "video/mp4" },
  { label: "WAV Audio", file: "sample.wav", contentType: "audio/wav" },
  {
    label: "Word Document",
    file: "sample.docx",
    contentType:
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  },
  {
    label: "Excel Spreadsheet",
    file: "sample.xlsx",
    contentType:
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  },
  { label: "CSV File", file: "sample.csv", contentType: "text/csv" },
  { label: "PDF Document", file: "sample.pdf", contentType: "application/pdf" },
];

function loadFixture(filename: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURES_DIR, filename)));
}

/** Flips the first byte so the hash changes, without assuming text content. */
function tamperBytes(bytes: Uint8Array): Uint8Array {
  const tampered = new Uint8Array(bytes);
  if (tampered.length > 0) {
    tampered[0] = tampered[0] ^ 0xff;
  } else {
    return new Uint8Array([1]); // edge case: empty fixture file
  }
  return tampered;
}

// ─── 1. MOCK DEPENDENCIES ──────────────────────────────────────────────────

// Mock the crypto algorithms to return predictable values for fast test evaluation,
// while retaining underlying setup helpers like generateKeyPairFromSeed for MajikKey.
vi.mock("@stablelib/ed25519", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@stablelib/ed25519")>();
  return {
    ...actual,
    sign: vi.fn().mockReturnValue(new Uint8Array(64).fill(1)), // ← 64 bytes, not 4
    verify: vi.fn().mockReturnValue(true),
  };
});

vi.mock("@noble/post-quantum/ml-dsa.js", () => ({
  ml_dsa87: {
    sign: vi.fn().mockReturnValue(new Uint8Array(4595).fill(5)), // ← 4595 bytes, not 4
    verify: vi.fn().mockReturnValue(true),
  },
}));

// Mock the file embedding sub-module delegation
vi.mock("../src/core/embed/majik-embed", () => ({
  MajikSignatureEmbed: {
    signAndEmbed: vi.fn().mockResolvedValue({
      blob: {},
      signature: {},
      handler: "test",
      mimeType: "text/plain",
    }),
    verifyWithKey: vi.fn().mockResolvedValue([]),
    verify: vi.fn().mockResolvedValue([]),
    embed: vi.fn().mockResolvedValue({ blob: {} }),
    extract: vi.fn().mockResolvedValue({ envelope: { signatures: [] } }),
    strip: vi.fn().mockResolvedValue({}),
    hasSignature: vi.fn().mockResolvedValue(true),
    getAllowlist: vi.fn().mockResolvedValue([]),
    seal: vi.fn().mockResolvedValue({}),
    verifySeal: vi.fn().mockResolvedValue({ valid: true }),
    getSealInfo: vi.fn().mockResolvedValue({}),
    isSealed: vi.fn().mockResolvedValue(false),
    isMultiSig: vi.fn().mockResolvedValue(false),
    canSign: vi.fn().mockResolvedValue({ permitted: true }),
    getSignatories: vi
      .fn()
      .mockResolvedValue({ all: [], signed: [], pending: [] }),
    getIssuer: vi.fn().mockResolvedValue(null),
    getEnvelopeInfo: vi.fn().mockResolvedValue({}),
  },
}));

// // Mock the image stamping sub-module delegation
// vi.mock("../src/core/stamp/image-signature", () => ({
//   MajikImageSignature: {
//     sign: vi.fn().mockResolvedValue({ blob: {}, stub: {}, fullEnvelope: {} }),
//     verify: vi.fn().mockResolvedValue({ valid: true }),
//     inspect: vi.fn().mockResolvedValue({ hasPixelRow: true, hasDct: true }),
//     isSigned: vi.fn().mockResolvedValue(true),
//   },
// }));

// ─── 2. TEST SUITE ──────────────────────────────────────────────────────────

describe("MajikSignature Class Unit Tests", () => {
  let mockKey: MajikKey;
  const dummyContent = "Hello, post-quantum world!";

  beforeAll(async () => {
    vi.clearAllMocks();
    mockKey = await getTestKey();
  }, 30000); // ← timeout in ms as the 2nd arg to beforeAll

  // ── SIGNING TESTS ─────────────────────────────────────────────────────────

  describe("Signing Content (.sign)", () => {
    it("should successfully generate a MajikSignature instance with valid arguments", async () => {
      const signature = await MajikSignature.sign(dummyContent, mockKey, {
        contentType: "text/plain",
      });

      expect(signature).toBeInstanceOf(MajikSignature);
      expect(signature.version).toBe(1);
      expect(signature.signerId).toBe(mockKey.fingerprint);
      expect(signature.contentType).toBe("text/plain");
      expect(signature.contentHash).toBeDefined();
      expect(signature.edSignature).toBeDefined();
      expect(signature.mlDsaSignature).toBeDefined();
    });

    describe("File type signing", () => {
      it.each(FILE_FIXTURES)(
        "should sign $label ($file) content correctly",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const signature = await MajikSignature.sign(fileContent, mockKey, {
            contentType,
          });

          expect(signature).toBeInstanceOf(MajikSignature);
          expect(signature.version).toBe(1);
          expect(signature.signerId).toBe(mockKey.fingerprint);
          expect(signature.contentType).toBe(contentType);
          expect(signature.contentHash).toBeDefined();
          expect(signature.edSignature).toBeDefined();
          expect(signature.mlDsaSignature).toBeDefined();
        },
      );
    });
  });

  // ── VERIFICATION TESTS ────────────────────────────────────────────────────
  describe("Verification (.verify)", () => {
    it("should return a validation true object if cryptographic checks pass", async () => {
      const signature = await MajikSignature.sign(dummyContent, mockKey);
      const publicKeys = MajikSignature.publicKeysFromMajikKey(mockKey);

      const result = MajikSignature.verify(dummyContent, signature, publicKeys);

      expect(result.valid).toBe(true);
      expect(result.signerId).toBe(mockKey.fingerprint);
    });

    it("should return valid false if the verified content hash does not match original signature", async () => {
      const signature = await MajikSignature.sign(dummyContent, mockKey);
      const publicKeys = MajikSignature.publicKeysFromMajikKey(mockKey);

      const result = MajikSignature.verify(
        "Tampered content!",
        signature,
        publicKeys,
      );

      expect(result.valid).toBe(false);
    });

    it("should allow verification directly using an instance of a MajikKey (.verifyWithKey)", async () => {
      const signature = await MajikSignature.sign(dummyContent, mockKey);
      const result = MajikSignature.verifyWithKey(
        dummyContent,
        signature,
        mockKey,
      );

      expect(result.valid).toBe(true);
    });

    describe("File type verification", () => {
      it.each(FILE_FIXTURES)(
        "should verify $label ($file) content correctly",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const signature = await MajikSignature.sign(fileContent, mockKey, {
            contentType,
          });
          const publicKeys = MajikSignature.publicKeysFromMajikKey(mockKey);

          const result = MajikSignature.verify(
            fileContent,
            signature,
            publicKeys,
          );

          expect(result.valid).toBe(true);
          expect(result.signerId).toBe(mockKey.fingerprint);
        },
      );

      it.each(FILE_FIXTURES)(
        "should reject tampered $label ($file) content",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const signature = await MajikSignature.sign(fileContent, mockKey, {
            contentType,
          });
          const publicKeys = MajikSignature.publicKeysFromMajikKey(mockKey);

          const tampered = tamperBytes(fileContent);
          const result = MajikSignature.verify(tampered, signature, publicKeys);

          expect(result.valid).toBe(false);
        },
      );

      it.each(FILE_FIXTURES)(
        "should verify $label ($file) directly via verifyWithKey",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const signature = await MajikSignature.sign(fileContent, mockKey, {
            contentType,
          });

          const result = MajikSignature.verifyWithKey(
            fileContent,
            signature,
            mockKey,
          );

          expect(result.valid).toBe(true);
        },
      );
    });
  });

  // ── SERIALIZATION TESTS ───────────────────────────────────────────────────
  describe("Serialization and Parsing", () => {
    it("should cleanly execute string round-trips via serialize and deserialize", async () => {
      const signature = await MajikSignature.sign(dummyContent, mockKey);

      const serializedBase64 = signature.serialize();
      expect(typeof serializedBase64).toBe("string");

      const deserializedInstance = MajikSignature.deserialize(serializedBase64);
      expect(deserializedInstance).toBeInstanceOf(MajikSignature);
      expect(deserializedInstance.signerId).toBe(signature.signerId);
      expect(deserializedInstance.contentHash).toBe(signature.contentHash);
    });

    it("should cleanly compile JSON primitives via toJSON and fromJSON", async () => {
      const signature = await MajikSignature.sign(dummyContent, mockKey);
      const jsonOutput = signature.toJSON();

      expect(jsonOutput.version).toBe(1);
      expect(jsonOutput.signerId).toBe(signature.signerId);

      const instantiatedFromJson = MajikSignature.fromJSON(jsonOutput);
      expect(instantiatedFromJson.signerId).toBe(signature.signerId);
    });
  });

  // ── HELPER & COMPLIANCE METHODS ───────────────────────────────────────────
  describe("Instance Compliance & Key Helpers", () => {
    it("should accurately handle validation flags", async () => {
      const signature = await MajikSignature.sign(dummyContent, mockKey);
      expect(signature.isValid()).toBe(true);
    });

    it("should successfully slice out public key components into independent objects", async () => {
      const signature = await MajikSignature.sign(dummyContent, mockKey);
      const keys = signature.extractPublicKeys();

      expect(keys.signerId).toBe(mockKey.fingerprint);
      expect(keys.edPublicKey).toBeInstanceOf(Uint8Array);
      expect(keys.mlDsaPublicKey).toBeInstanceOf(Uint8Array);
    });

    it("should correctly format expected signer profiles from raw key structures", () => {
      const profile = MajikSignature.expectedSignerFromKey(mockKey);

      expect(profile.signerId).toBe(mockKey.fingerprint);

      // We add the '!' to satisfy TypeScript that edPublicKey is not undefined
      expect(profile.edPublicKey).toBe(
        btoa(String.fromCharCode(...mockKey.edPublicKey!)),
      );

      // We assert the post-quantum key was extracted and encoded as a string,
      // but avoid spreading its 2592 bytes to prevent call stack overflows!
      expect(typeof profile.mlDsaPublicKey).toBe("string");
      expect(profile.mlDsaPublicKey.length).toBeGreaterThan(0);
    });
  });

  // ── DELEGATION METRIC CHECK (Integration Contracts) ──────────────────────
  describe("Sub-module Framework Redirection Contracts", () => {
    it("should redirect file-signing assertions to MajikSignatureEmbed", async () => {
      const dummyBlob = new Blob([""], { type: "text/plain" });
      const result = await MajikSignature.signFile(dummyBlob, mockKey);

      expect(result).toBeDefined();
    });

    // it("should redirect image stamping capabilities to MajikImageSignature", async () => {
    //   const dummyImageBlob = new Blob([""], { type: "image/jpeg" });
    //   const result = await MajikSignature.stampImage(dummyImageBlob, mockKey);

    //   expect(result).toBeDefined();
    // });
  });
});

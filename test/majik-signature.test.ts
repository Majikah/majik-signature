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

/** Simulates data corruption on an embedded Blob (modifies original content, keeping envelope parsing intact if appended) */
async function corruptBlob(blob: Blob): Promise<Blob> {
  const buffer = await blob.arrayBuffer();
  const view = new Uint8Array(buffer);
  if (view.length > 0) {
    // Flip a byte to break the content hash validation
    view[0] = view[0] ^ 0xff;
  }
  return new Blob([view], { type: blob.type });
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

// ─── 2. TEST SUITE ──────────────────────────────────────────────────────────

describe("MajikSignature Class Unit Tests", () => {
  let mockKey: MajikKey;
  const dummyContent = "Hello, post-quantum world!";

  beforeAll(async () => {
    vi.clearAllMocks();
    mockKey = await getTestKey();
  }, 60000); // ← timeout in ms as the 2nd arg to beforeAll

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

  // ── DELEGATION METRIC CHECK ───────────────────────────────────────────────
  describe("Sub-module Framework Redirection Contracts", () => {
    it("should redirect file-signing assertions to MajikSignatureEmbed", async () => {
      const dummyBlob = new Blob(["test"], { type: "text/plain" });
      const result = await MajikSignature.signFile(dummyBlob, mockKey);
      expect(result).toBeDefined();
    });
  });

  // ── MULTI-PARTY SIGNING (OPEN & RESTRICTED) ────────────────────────────────
  describe("Multi-Party File Signing Workflow", () => {
    let issuerKey: MajikKey;
    let allowedKey1: MajikKey;
    let allowedKey2: MajikKey;
    let intruderKey: MajikKey;
    let baseBlob: Blob;

    beforeAll(async () => {
      console.log("Creating Test Keys");
      issuerKey = await getTestKey();
      console.log("[majik-key] Issuer Key Created");

      allowedKey1 = await getTestKey();
      console.log("[majik-key] Allowed Key 1 Created");

      allowedKey2 = await getTestKey();
      console.log("[majik-key] Allowed Key 2 Created");

      intruderKey = await getTestKey();
      console.log("[majik-key] Intruder Key Created");

      baseBlob = new Blob(["Majik Multi-sig test data"], {
        type: "text/plain",
      });
    }, 120000); // ← timeout in ms as the 2nd arg to beforeAll

    describe("Open Signing (No Allowlist)", () => {
      it("should permit multiple signatures sequentially from different keys", async () => {
        // Signer 1
        const { blob: sig1Blob } = await MajikSignature.signFile(
          baseBlob,
          allowedKey1,
        );
        // Signer 2 appends to envelope
        const { blob: sig2Blob } = await MajikSignature.signFile(
          sig1Blob,
          allowedKey2,
        );

        const info = await MajikSignature.getEnvelopeInfo(sig2Blob);
        expect(info?.signatureCount).toBe(2);
        expect(info?.isMultiSig).toBe(false); // No allowlist established

        const results = await MajikSignature.verifyFile(sig2Blob, allowedKey2);
        expect(results.some((r) => r.valid)).toBe(true);
      });
    });

    describe("Restricted Multi-Sig (Allowlist)", () => {
      let restrictedBlob: Blob;

      it("should successfully establish an allowlist on first sign", async () => {
        const expectedSigners = [
          MajikSignature.expectedSignerFromKey(issuerKey),
          MajikSignature.expectedSignerFromKey(allowedKey1),
          MajikSignature.expectedSignerFromKey(allowedKey2),
        ];

        const { blob } = await MajikSignature.signFile(baseBlob, issuerKey, {
          expectedSigners,
        });
        restrictedBlob = blob;

        const info = await MajikSignature.getEnvelopeInfo(restrictedBlob);
        expect(info?.isMultiSig).toBe(true);
        expect(info?.issuer?.signerId).toBe(issuerKey.fingerprint);
        expect(info?.allowlist?.length).toBe(3);
      });

      it("should permit a signature from an allowlisted key", async () => {
        const { blob: doubleSignedBlob } = await MajikSignature.signFile(
          restrictedBlob,
          allowedKey1,
        );

        const info = await MajikSignature.getEnvelopeInfo(doubleSignedBlob);
        expect(info?.signatureCount).toBe(2);
        expect(
          info?.signatories?.signed.some(
            (s) => s.signerId === allowedKey1.fingerprint,
          ),
        ).toBe(true);
      });

      it("should reject a signature attempt from a key not on the allowlist", async () => {
        await expect(
          MajikSignature.signFile(restrictedBlob, intruderKey),
        ).rejects.toThrow(/not permitted to sign this file/);
      });

      it("should accurately reflect pending signatories", async () => {
        const signatories =
          await MajikSignature.getPendingSignatories(restrictedBlob);
        expect(
          signatories?.pending.some(
            (s) => s.signerId === allowedKey2.fingerprint,
          ),
        ).toBe(true);
        expect(
          signatories?.pending.some(
            (s) => s.signerId === intruderKey.fingerprint,
          ),
        ).toBe(false);
      });
    });

    // ── ENVELOPE SEALING ─────────────────────────────────────────────────────
    describe("Envelope Sealing Capabilities", () => {
      let sealedBlob: Blob;
      let readyToSealBlob: Blob;

      beforeAll(async () => {
        // Setup a restricted file with signatures
        const expectedSigners = [
          MajikSignature.expectedSignerFromKey(issuerKey),
          MajikSignature.expectedSignerFromKey(allowedKey1),
        ];
        const { blob: step1 } = await MajikSignature.signFile(
          baseBlob,
          issuerKey,
          { expectedSigners },
        );
        const { blob: step2 } = await MajikSignature.signFile(
          step1,
          allowedKey1,
        );
        readyToSealBlob = step2;
      });

      it("should reject sealing attempts from non-issuers", async () => {
        await expect(
          MajikSignature.seal(readyToSealBlob, allowedKey1),
        ).rejects.toThrow(/Only the issuer.*may seal this file/);
      });

      it("should allow the issuer to seal the multi-sig envelope", async () => {
        const { blob, sealInfo } = await MajikSignature.seal(
          readyToSealBlob,
          issuerKey,
        );
        sealedBlob = blob;

        expect(sealInfo.sealedBy).toBe(issuerKey.fingerprint);

        const isSealed = await MajikSignature.isSealed(sealedBlob);
        expect(isSealed).toBe(true);
      });

      it("should successfully verify an intact seal", async () => {
        const result = await MajikSignature.verifySeal(sealedBlob);
        expect(result.valid).toBe(true);
        expect(result.sealedBy).toBe(issuerKey.fingerprint);
      });

      it("should strictly reject any new signatures once the envelope is sealed", async () => {
        // Even the issuer shouldn't be able to re-sign a sealed file
        await expect(
          MajikSignature.signFile(sealedBlob, issuerKey),
        ).rejects.toThrow(/Cannot sign a sealed envelope/);
      });
    });

    // ── DATA INTEGRITY & TAMPERING ───────────────────────────────────────────
    describe("Data Integrity & Tampering Checks", () => {
      it("should flag validation as false if a signed file's raw bytes are modified over the wire", async () => {
        // Sign a file normally
        const { blob: originalSignedBlob } = await MajikSignature.signFile(
          baseBlob,
          issuerKey,
        );

        // Simulate a corrupted payload (bit rot, man-in-the-middle, formatting issue)
        const tamperedBlob = await corruptBlob(originalSignedBlob);

        // Verification must fail because the reconstructed payload contentHash will mismatch
        const verifyResults = await MajikSignature.verifyFile(
          tamperedBlob,
          issuerKey,
        );

        // Ensure at least one result processed and returned valid = false
        expect(verifyResults.length).toBeGreaterThan(0);
        expect(verifyResults[0].valid).toBe(false);
      });
    });
  });
});

import { describe, it, expect, vi, beforeAll } from "vitest";
import { MajikSignature } from "../src/majik-signature";
import { getTestKey } from "./helpers/crypto";
import { MajikKey } from "@majikah/majik-key";

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { MajikChainAnchor } from "../src/anchor/types";

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
          const blob = new Blob([fileContent as BlobPart], {
            type: contentType,
          });
          const { signature } = await MajikSignature.signFile(blob, mockKey, {
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
          const blob = new Blob([fileContent as BlobPart], {
            type: contentType,
          });
          const { signature, blob: signedBlob } = await MajikSignature.signFile(
            blob,
            mockKey,
            {
              contentType,
            },
          );

          // Recover what was actually signed, not the raw pre-strip fixture
          const strippedBlob = await MajikSignature.stripFrom(signedBlob, {
            mimeType: contentType,
          });
          const strippedBytes = new Uint8Array(
            await strippedBlob.arrayBuffer(),
          );

          const result = MajikSignature.verifyWithKey(
            strippedBytes,
            signature,
            mockKey,
          );
          expect(result.valid).toBe(true);
        },
      );

      it.each(FILE_FIXTURES)(
        "should verify $label ($file) directly via verifyFile",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const blob = new Blob([fileContent as BlobPart], {
            type: contentType,
          });
          const { blob: signedBlob } = await MajikSignature.signFile(
            blob,
            mockKey,
            {
              contentType,
            },
          );

          const results = await MajikSignature.verifyFile(signedBlob, mockKey);
          expect(results[0].valid).toBe(true);
        },
      );
    });

    it("MP4 strip() should be idempotent on its own output", async () => {
      const fileContent = loadFixture("sample.mp4");
      const blob = new Blob([fileContent as BlobPart], { type: "video/mp4" });
      const once = new Uint8Array(
        await (await MajikSignature.stripFrom(blob)).arrayBuffer(),
      );
      const twice = new Uint8Array(
        await (await MajikSignature.stripFrom(new Blob([once]))).arrayBuffer(),
      );
      expect(once).toEqual(twice);
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
        expect(info?.isMultiSig).toBe(true);

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

    // ── CHAIN ANCHORING CAPABILITIES ─────────────────────────────────────────
    describe("Chain Anchoring Capabilities", () => {
      let sealedBlob: Blob;
      let readyToSealBlob: Blob;

      beforeAll(async () => {
        // Build a fresh unsealed and sealed file for anchoring checks
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

        const { blob: step3 } = await MajikSignature.seal(
          readyToSealBlob,
          issuerKey,
        );
        sealedBlob = step3;
      });

      it("should reject anchoring eligibility checks on unsigned files", async () => {
        const result = await MajikSignature.canAnchor(baseBlob);
        expect(result.permitted).toBe(false);
        expect(result.reason).toContain("no envelope found");
      });

      it("should reject anchoring eligibility checks on signed but unsealed files", async () => {
        const result = await MajikSignature.canAnchor(readyToSealBlob);
        expect(result.permitted).toBe(false);
        expect(result.reason).toContain("File is not sealed");
      });

      it("should permit anchoring on a sealed file", async () => {
        const result = await MajikSignature.canAnchor(sealedBlob);
        expect(result.permitted).toBe(true);
      });

      it("should throw when trying to register an anchor on an unsigned file", async () => {
        const dummyAnchor: MajikChainAnchor = {
          version: 1,
          id: "anchor-1",
          payload: {
            chain: "solana",
            network: "mainnet-beta",
            digest: {
              algorithm: "SHA3-512",
              value: "dummy-seal-hash",
            },
          },
          memo: "majik-notary-v1:dummy-seal-hash",
          txSignature: "dummy-tx-signature",
          slot: 12345,
          blockTime: 1700000000,
          confirmedAt: "2026-07-16T02:18:20.000Z",
          status: "confirmed",
        };

        await expect(
          MajikSignature.registerChainAnchor(baseBlob, dummyAnchor),
        ).rejects.toThrow(/no envelope found/);
      });

      it("should throw when trying to register an anchor on an unsealed file", async () => {
        const sealInfo = await MajikSignature.getSealInfo(sealedBlob);
        const dummyAnchor: MajikChainAnchor = {
          version: 1,
          id: "anchor-1",
          payload: {
            chain: "solana",
            network: "mainnet-beta",
            digest: {
              algorithm: "SHA3-512",
              value: sealInfo!.sealHash,
            },
          },
          memo: `majik-notary-v1:${sealInfo!.sealHash}`,
          txSignature: "dummy-tx-signature",
          slot: 12345,
          blockTime: 1700000000,
          confirmedAt: "2026-07-16T02:18:20.000Z",
          status: "confirmed",
        };

        await expect(
          MajikSignature.registerChainAnchor(readyToSealBlob, dummyAnchor),
        ).rejects.toThrow(/file must be sealed first/);
      });

      it("should throw when the anchor digest doesn't match the envelope's seal hash", async () => {
        const dummyAnchor: MajikChainAnchor = {
          version: 1,
          id: "anchor-1",
          payload: {
            chain: "solana",
            network: "mainnet-beta",
            digest: {
              algorithm: "SHA3-512",
              value: "mismatched-hash-value-000000000000000000000000000000000",
            },
          },
          memo: "majik-notary-v1:mismatched-hash-value",
          txSignature: "dummy-tx-signature",
          slot: 12345,
          blockTime: 1700000000,
          confirmedAt: "2026-07-16T02:18:20.000Z",
          status: "confirmed",
        };

        await expect(
          MajikSignature.registerChainAnchor(sealedBlob, dummyAnchor),
        ).rejects.toThrow(
          /digest does not match the envelope's current seal hash/,
        );
      });

      it("should successfully register and retrieve chain anchors on a sealed file", async () => {
        const sealInfo = await MajikSignature.getSealInfo(sealedBlob);
        expect(sealInfo).not.toBeNull();

        const anchor: MajikChainAnchor = {
          version: 1,
          id: "anchor-uuid-777",
          payload: {
            chain: "solana",
            network: "mainnet-beta",
            digest: {
              algorithm: "SHA3-512",
              value: sealInfo!.sealHash,
            },
          },
          memo: `majik-notary-v1:${sealInfo!.sealHash}`,
          txSignature: "52GgP8F9abcdefghijklmnopqrstuvwxyz",
          slot: 9876543,
          blockTime: 1700000000,
          confirmedAt: "2026-07-16T02:18:20.000Z",
          status: "confirmed",
        };

        // Assert initially empty list of anchors
        let anchors = await MajikSignature.getChainAnchors(sealedBlob);
        expect(anchors).toEqual([]);

        // Register the anchor record
        const anchoredBlob = await MajikSignature.registerChainAnchor(
          sealedBlob,
          anchor,
        );

        // Retrieve and assert correctly updated anchor payload
        anchors = await MajikSignature.getChainAnchors(anchoredBlob);
        expect(anchors).toHaveLength(1);
        expect(anchors[0]).toEqual(anchor);
      });

      it("should upsert instead of duplicate when registering the same anchor ID twice", async () => {
        const sealInfo = await MajikSignature.getSealInfo(sealedBlob);
        const anchorId = "anchor-uuid-dup-check";

        const anchor: MajikChainAnchor = {
          version: 1,
          id: anchorId,
          payload: {
            chain: "solana",
            network: "mainnet-beta",
            digest: {
              algorithm: "SHA3-512",
              value: sealInfo!.sealHash,
            },
          },
          memo: `majik-notary-v1:${sealInfo!.sealHash}`,
          txSignature: "original-tx-sig",
          slot: 9876543,
          blockTime: 1700000000,
          confirmedAt: "2026-07-16T02:18:20.000Z",
          status: "pending",
        };

        // Register first time
        const anchoredBlob1 = await MajikSignature.registerChainAnchor(
          sealedBlob,
          anchor,
        );

        // Update transaction status parameters for the duplicate register check
        const updatedAnchor: MajikChainAnchor = {
          ...anchor,
          txSignature: "finalized-tx-sig",
          status: "confirmed",
        };

        // Register a second time with modified properties but identical anchor ID
        const anchoredBlob2 = await MajikSignature.registerChainAnchor(
          anchoredBlob1,
          updatedAnchor,
        );

        const anchors = await MajikSignature.getChainAnchors(anchoredBlob2);
        expect(anchors).toHaveLength(1); // Length is still 1 (the record was upserted)
        expect(anchors[0].status).toBe("confirmed");
        expect(anchors[0].txSignature).toBe("finalized-tx-sig");
      });
    });
  });

  // ── DETACHED SIGNING & VERIFICATION FLOW (FULL FLOW) ──────────────────────
  describe("Detached File Signing & Verification (Full Flow)", () => {
    let activeKey1: MajikKey;
    let activeKey2: MajikKey;
    let baseBlob: Blob;

    beforeAll(async () => {
      // Generate genuine keys for full cryptographic flow testing (no mocks)
      console.log("[majik-key] Generating activeKey1 for detached flow...");
      activeKey1 = await getTestKey();

      console.log("[majik-key] Generating activeKey2 for detached flow...");
      activeKey2 = await getTestKey();

      const fileContent = loadFixture("sample.txt");
      baseBlob = new Blob([fileContent as BlobPart], { type: "text/plain" });
    }, 120000);

    it("should successfully sign and verify a file using the detached flow", async () => {
      // 1. Sign Detached
      const { blob: strippedBlob, envelope: detachedEnvelope } =
        await MajikSignature.signFileDetached(baseBlob, activeKey1, {
          contentType: "text/plain",
        });

      expect(detachedEnvelope).toBeDefined();
      expect(detachedEnvelope.signatures.length).toBe(1);

      // 2. Verify Detached against the stripped file
      const results = await MajikSignature.verifyFileDetached(
        strippedBlob,
        detachedEnvelope,
        activeKey1,
      );

      expect(results).toHaveLength(1);
      expect(results[0].valid).toBe(true);
      expect(results[0].signerId).toBe(activeKey1.fingerprint);
    });

    it("should support passing an existing envelope out-of-band for multi-sig", async () => {
      // 1. First signer generates the initial detached envelope
      const { blob: stripped1, envelope: env1 } =
        await MajikSignature.signFileDetached(baseBlob, activeKey1, {
          contentType: "text/plain",
        });

      // 2. Second signer adds their signature to the existing envelope
      const { blob: stripped2, envelope: env2 } =
        await MajikSignature.signFileDetached(stripped1, activeKey2, {
          existingEnvelope: env1,
          contentType: "text/plain",
        });

      expect(env2.signatures.length).toBe(2);

      // 3. Verify Signer 1 independently
      const results1 = await MajikSignature.verifyFileDetached(
        stripped2,
        env2,
        activeKey1,
        { expectedSignerId: activeKey1.fingerprint },
      );
      expect(results1).toHaveLength(1);
      expect(results1[0].valid).toBe(true);
      expect(results1[0].signerId).toBe(activeKey1.fingerprint);

      // 4. Verify Signer 2 independently
      const results2 = await MajikSignature.verifyFileDetached(
        stripped2,
        env2,
        activeKey2,
        { expectedSignerId: activeKey2.fingerprint },
      );
      expect(results2).toHaveLength(1);
      expect(results2[0].valid).toBe(true);
      expect(results2[0].signerId).toBe(activeKey2.fingerprint);
    });

    it("should reject verification if the detached file bytes are tampered with", async () => {
      // 1. Generate valid detached signature
      const { blob: strippedBlob, envelope: detachedEnvelope } =
        await MajikSignature.signFileDetached(baseBlob, activeKey1, {
          contentType: "text/plain",
        });

      // 2. Simulate data corruption on the raw file
      const tamperedBlob = await corruptBlob(strippedBlob);

      // 3. Attempt verification against the tampered data
      const results = await MajikSignature.verifyFileDetached(
        tamperedBlob,
        detachedEnvelope,
        activeKey1,
      );

      expect(results.length).toBeGreaterThan(0);
      expect(results[0].valid).toBe(false);
    });

    it("should reject verification when evaluated against mismatched public keys", async () => {
      const { blob: strippedBlob, envelope: detachedEnvelope } =
        await MajikSignature.signFileDetached(baseBlob, activeKey1, {
          contentType: "text/plain",
        });

      // Verify the envelope signed by activeKey1 using activeKey2's context
      const results = await MajikSignature.verifyFileDetached(
        strippedBlob,
        detachedEnvelope,
        activeKey2,
      );

      // Verification should fail because the cryptographic validation checks won't match
      expect(results.some((r) => r.valid)).toBe(false);
    });
  });
});

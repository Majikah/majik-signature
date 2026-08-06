import { describe, it, expect, beforeAll } from "vitest";
import { MajikSignature } from "../src/majik-signature";

import { MajikKey } from "@majikah/majik-key";

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { MajikChainAnchor } from "../src/anchor/types";
import { getTestKey } from "./helpers/crypto";
import { MajikSignatureEnvelope } from "../src/core/envelope";
import { MajikSignatureMap } from "../src/core/mjksmap";
import type { MajikTimestamp } from "../src/core/types";

const __currentDir = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__currentDir, "fixtures");

interface FileFixture {
  label: string;
  file: string;
  contentType: string;
}

const FILE_FIXTURES: FileFixture[] = [
  { label: "Plain Text", file: "sample.txt", contentType: "text/plain" },
  { label: "WEBP Image", file: "sample.webp", contentType: "image/webp" },
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

/** Simulates data corruption on an embedded/detached Blob's raw bytes. */
async function corruptBlob(blob: Blob): Promise<Blob> {
  const buffer = await blob.arrayBuffer();
  const view = new Uint8Array(buffer);
  if (view.length > 0) {
    view[0] = view[0] ^ 0xff;
  }
  return new Blob([view], { type: blob.type });
}

// ─── TEST SUITE ──────────────────────────────────────────────────────────────

describe("MajikSignature Class Unit Tests", () => {
  const dummyContent = "Hello, post-quantum world!";

  // ── SHARED KEY POOL ─────────────────────────────────────────────────────
  //
  // Created ONCE, in parallel, at the very top of the suite. Every describe
  // block below reuses these instead of minting a fresh MajikKey — key
  // generation is the expensive part of these tests (ML-KEM/ML-DSA
  // keygen), and nothing about signing/verifying mutates key state in a
  // way that would make reuse across tests unsafe.
  //
  // Roles are assigned semantically so test bodies stay readable:
  //   keyA   — primary signer / issuer in multi-sig & batch tests
  //   keyB   — second signer
  //   keyC   — third signer (used where a distinct third party matters,
  //            e.g. allowlists with >2 members)
  //   keyD   — the "intruder" / unauthorized signer in negative tests
  //   tsaKey — a dedicated authority key, kept separate from signer keys
  //            since it plays a structurally different role (timestamping
  //            authority, not a file signer)
  let keyA: MajikKey;
  let keyB: MajikKey;
  let keyC: MajikKey;
  let keyD: MajikKey;
  let tsaKey: MajikKey;

  beforeAll(async () => {
    console.log("[majik-key] Generating shared key pool (5 keys, parallel)...");
    [keyA, keyB, keyC, keyD, tsaKey] = await Promise.all([
      getTestKey(),
      getTestKey(),
      getTestKey(),
      getTestKey(),
      getTestKey(),
    ]);
    console.log("[majik-key] Shared key pool ready.");
  }, 120000);

  // ── SIGNING TESTS ─────────────────────────────────────────────────────────

  describe("Signing Content (.sign)", () => {
    it("should successfully generate a MajikSignature instance with valid arguments", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA, {
        contentType: "text/plain",
      });

      expect(signature).toBeInstanceOf(MajikSignature);
      expect(signature.version).toBe(1);
      expect(signature.signerId).toBe(keyA.fingerprint);
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
          const { signature } = await MajikSignature.signFile(blob, keyA, {
            contentType,
          });

          expect(signature).toBeInstanceOf(MajikSignature);
          expect(signature.version).toBe(1);
          expect(signature.signerId).toBe(keyA.fingerprint);
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
      const signature = await MajikSignature.sign(dummyContent, keyA);
      const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);

      const result = MajikSignature.verify(dummyContent, signature, publicKeys);

      expect(result.valid).toBe(true);
      expect(result.signerId).toBe(keyA.fingerprint);
    });

    it("should return valid false if the verified content hash does not match original signature", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA);
      const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);

      const result = MajikSignature.verify(
        "Tampered content!",
        signature,
        publicKeys,
      );

      expect(result.valid).toBe(false);
    });

    it("should allow verification directly using an instance of a MajikKey (.verifyWithKey)", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA);
      const result = MajikSignature.verifyWithKey(
        dummyContent,
        signature,
        keyA,
      );

      expect(result.valid).toBe(true);
    });

    describe("File type verification", () => {
      it.each(FILE_FIXTURES)(
        "should verify $label ($file) content correctly",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const signature = await MajikSignature.sign(fileContent, keyA, {
            contentType,
          });
          const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);

          const result = MajikSignature.verify(
            fileContent,
            signature,
            publicKeys,
          );

          expect(result.valid).toBe(true);
          expect(result.signerId).toBe(keyA.fingerprint);
        },
      );

      it.each(FILE_FIXTURES)(
        "should reject tampered $label ($file) content",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const signature = await MajikSignature.sign(fileContent, keyA, {
            contentType,
          });
          const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);

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
            keyA,
            { contentType },
          );

          const strippedBlob = await MajikSignature.stripFrom(signedBlob, {
            mimeType: contentType,
          });
          const strippedBytes = new Uint8Array(
            await strippedBlob.arrayBuffer(),
          );

          const result = MajikSignature.verifyWithKey(
            strippedBytes,
            signature,
            keyA,
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
            keyA,
            { contentType },
          );

          const results = await MajikSignature.verifyFile(signedBlob, keyA);
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
      const signature = await MajikSignature.sign(dummyContent, keyA);

      const serializedBase64 = signature.serialize();
      expect(typeof serializedBase64).toBe("string");

      const deserializedInstance = MajikSignature.deserialize(serializedBase64);
      expect(deserializedInstance).toBeInstanceOf(MajikSignature);
      expect(deserializedInstance.signerId).toBe(signature.signerId);
      expect(deserializedInstance.contentHash).toBe(signature.contentHash);
    });

    it("should cleanly compile JSON primitives via toJSON and fromJSON", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA);
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
      const signature = await MajikSignature.sign(dummyContent, keyA);
      expect(signature.isValid()).toBe(true);
    });

    it("should successfully slice out public key components into independent objects", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA);
      const keys = signature.extractPublicKeys();

      expect(keys.signerId).toBe(keyA.fingerprint);
      expect(keys.edPublicKey).toBeInstanceOf(Uint8Array);
      expect(keys.mlDsaPublicKey).toBeInstanceOf(Uint8Array);
    });

    it("should correctly format expected signer profiles from raw key structures", () => {
      const profile = MajikSignature.expectedSignerFromKey(keyA);

      expect(profile.signerId).toBe(keyA.fingerprint);
      expect(profile.edPublicKey).toBe(
        btoa(String.fromCharCode(...keyA.edPublicKey!)),
      );
      expect(typeof profile.mlDsaPublicKey).toBe("string");
      expect(profile.mlDsaPublicKey.length).toBeGreaterThan(0);
    });
  });

  // ── DELEGATION METRIC CHECK ───────────────────────────────────────────────
  describe("Sub-module Framework Redirection Contracts", () => {
    it("should redirect file-signing assertions to MajikSignatureEmbed", async () => {
      const dummyBlob = new Blob(["test"], { type: "text/plain" });
      const result = await MajikSignature.signFile(dummyBlob, keyA);
      expect(result).toBeDefined();
    });
  });

  // ── MULTI-PARTY SIGNING (OPEN & RESTRICTED) ────────────────────────────────
  describe("Multi-Party File Signing Workflow", () => {
    let baseBlob: Blob;

    beforeAll(() => {
      baseBlob = new Blob(["Majik Multi-sig test data"], {
        type: "text/plain",
      });
    });

    describe("Open Signing (No Allowlist)", () => {
      it("should permit multiple signatures sequentially from different keys", async () => {
        const { blob: sig1Blob } = await MajikSignature.signFile(
          baseBlob,
          keyB,
        );
        const { blob: sig2Blob } = await MajikSignature.signFile(
          sig1Blob,
          keyC,
        );

        const info = await MajikSignature.getEnvelopeInfo(sig2Blob);
        expect(info?.signatureCount).toBe(2);
        expect(info?.isMultiSig).toBe(true);

        const results = await MajikSignature.verifyFile(sig2Blob, keyC);
        expect(results.some((r) => r.valid)).toBe(true);
      });
    });

    describe("Restricted Multi-Sig (Allowlist)", () => {
      let restrictedBlob: Blob;

      it("should successfully establish an allowlist on first sign", async () => {
        const expectedSigners = [
          MajikSignature.expectedSignerFromKey(keyA),
          MajikSignature.expectedSignerFromKey(keyB),
          MajikSignature.expectedSignerFromKey(keyC),
        ];

        const { blob } = await MajikSignature.signFile(baseBlob, keyA, {
          expectedSigners,
        });
        restrictedBlob = blob;

        const info = await MajikSignature.getEnvelopeInfo(restrictedBlob);
        expect(info?.isMultiSig).toBe(true);
        expect(info?.issuer?.signerId).toBe(keyA.fingerprint);
        expect(info?.allowlist?.length).toBe(3);
      });

      it("should permit a signature from an allowlisted key", async () => {
        const { blob: doubleSignedBlob } = await MajikSignature.signFile(
          restrictedBlob,
          keyB,
        );

        const info = await MajikSignature.getEnvelopeInfo(doubleSignedBlob);
        expect(info?.signatureCount).toBe(2);
        expect(
          info?.signatories?.signed.some(
            (s) => s.signerId === keyB.fingerprint,
          ),
        ).toBe(true);
      });

      it("should reject a signature attempt from a key not on the allowlist", async () => {
        await expect(
          MajikSignature.signFile(restrictedBlob, keyD),
        ).rejects.toThrow(/not permitted to sign this file/);
      });

      it("should accurately reflect pending signatories", async () => {
        const signatories =
          await MajikSignature.getPendingSignatories(restrictedBlob);
        expect(
          signatories?.pending.some((s) => s.signerId === keyC.fingerprint),
        ).toBe(true);
        expect(
          signatories?.pending.some((s) => s.signerId === keyD.fingerprint),
        ).toBe(false);
      });
    });

    // ── ENVELOPE SEALING ─────────────────────────────────────────────────────
    describe("Envelope Sealing Capabilities", () => {
      let sealedBlob: Blob;
      let readyToSealBlob: Blob;

      beforeAll(async () => {
        const expectedSigners = [
          MajikSignature.expectedSignerFromKey(keyA),
          MajikSignature.expectedSignerFromKey(keyB),
        ];
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyA, {
          expectedSigners,
        });
        const { blob: step2 } = await MajikSignature.signFile(step1, keyB);
        readyToSealBlob = step2;
      });

      it("should reject sealing attempts from non-issuers", async () => {
        await expect(
          MajikSignature.seal(readyToSealBlob, keyB),
        ).rejects.toThrow(/Only the issuer.*may seal this file/);
      });

      it("should allow the issuer to seal the multi-sig envelope", async () => {
        const { blob, sealInfo } = await MajikSignature.seal(
          readyToSealBlob,
          keyA,
        );
        sealedBlob = blob;

        expect(sealInfo.sealedBy).toBe(keyA.fingerprint);

        const isSealed = await MajikSignature.isSealed(sealedBlob);
        expect(isSealed).toBe(true);
      });

      it("should successfully verify an intact seal", async () => {
        const result = await MajikSignature.verifySeal(sealedBlob);
        expect(result.valid).toBe(true);
        expect(result.sealedBy).toBe(keyA.fingerprint);
      });

      it("should strictly reject any new signatures once the envelope is sealed", async () => {
        await expect(MajikSignature.signFile(sealedBlob, keyA)).rejects.toThrow(
          /Cannot sign a sealed envelope/,
        );
      });
    });

    // ── DATA INTEGRITY & TAMPERING ───────────────────────────────────────────
    describe("Data Integrity & Tampering Checks", () => {
      it("should flag validation as false if a signed file's raw bytes are modified over the wire", async () => {
        const { blob: originalSignedBlob } = await MajikSignature.signFile(
          baseBlob,
          keyA,
        );

        const tamperedBlob = await corruptBlob(originalSignedBlob);

        const verifyResults = await MajikSignature.verifyFile(
          tamperedBlob,
          keyA,
        );

        expect(verifyResults.length).toBeGreaterThan(0);
        expect(verifyResults[0].valid).toBe(false);
      });
    });

    // ── CHAIN ANCHORING CAPABILITIES ─────────────────────────────────────────
    describe("Chain Anchoring Capabilities", () => {
      let sealedBlob: Blob;
      let readyToSealBlob: Blob;

      beforeAll(async () => {
        const expectedSigners = [
          MajikSignature.expectedSignerFromKey(keyA),
          MajikSignature.expectedSignerFromKey(keyB),
        ];
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyA, {
          expectedSigners,
        });
        const { blob: step2 } = await MajikSignature.signFile(step1, keyB);
        readyToSealBlob = step2;

        const { blob: step3 } = await MajikSignature.seal(
          readyToSealBlob,
          keyA,
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
        expect(result.reason).toContain("Envelope is not sealed");
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
            digest: { algorithm: "SHA3-512", value: "dummy-seal-hash" },
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
            digest: { algorithm: "SHA3-512", value: sealInfo!.sealHash },
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
        ).rejects.toThrow(/envelope must be sealed first/);
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
            digest: { algorithm: "SHA3-512", value: sealInfo!.sealHash },
          },
          memo: `majik-notary-v1:${sealInfo!.sealHash}`,
          txSignature: "52GgP8F9abcdefghijklmnopqrstuvwxyz",
          slot: 9876543,
          blockTime: 1700000000,
          confirmedAt: "2026-07-16T02:18:20.000Z",
          status: "confirmed",
        };

        let anchors = await MajikSignature.getChainAnchors(sealedBlob);
        expect(anchors).toEqual([]);

        const anchoredBlob = await MajikSignature.registerChainAnchor(
          sealedBlob,
          anchor,
        );

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
            digest: { algorithm: "SHA3-512", value: sealInfo!.sealHash },
          },
          memo: `majik-notary-v1:${sealInfo!.sealHash}`,
          txSignature: "original-tx-sig",
          slot: 9876543,
          blockTime: 1700000000,
          confirmedAt: "2026-07-16T02:18:20.000Z",
          status: "pending",
        };

        const anchoredBlob1 = await MajikSignature.registerChainAnchor(
          sealedBlob,
          anchor,
        );

        const updatedAnchor: MajikChainAnchor = {
          ...anchor,
          txSignature: "finalized-tx-sig",
          status: "confirmed",
        };

        const anchoredBlob2 = await MajikSignature.registerChainAnchor(
          anchoredBlob1,
          updatedAnchor,
        );

        const anchors = await MajikSignature.getChainAnchors(anchoredBlob2);
        expect(anchors).toHaveLength(1);
        expect(anchors[0].status).toBe("confirmed");
        expect(anchors[0].txSignature).toBe("finalized-tx-sig");
      });
    });
  });

  // ── DETACHED SIGNING & VERIFICATION FLOW (FULL FLOW) ──────────────────────
  describe("Detached File Signing & Verification (Full Flow)", () => {
    let baseBlob: Blob;

    beforeAll(() => {
      const fileContent = loadFixture("sample.txt");
      baseBlob = new Blob([fileContent as BlobPart], { type: "text/plain" });
    });

    it("should successfully sign and verify a file using the detached flow, returning both envelope and signature", async () => {
      const {
        blob: strippedBlob,
        envelope: detachedEnvelope,
        signature,
      } = await MajikSignature.signFileDetached(baseBlob, keyA, {
        contentType: "text/plain",
      });

      expect(detachedEnvelope).toBeDefined();
      expect(detachedEnvelope.signatures.length).toBe(1);

      // The most recent signature is returned directly — no need to
      // re-extract it from the envelope via findSignature().
      expect(signature).toBeInstanceOf(MajikSignature);
      expect(signature.signerId).toBe(keyA.fingerprint);

      const results = await MajikSignature.verifyFileDetached(
        strippedBlob,
        detachedEnvelope,
        keyA,
      );

      expect(results).toHaveLength(1);
      expect(results[0].valid).toBe(true);
      expect(results[0].signerId).toBe(keyA.fingerprint);
    });

    it("should support passing an existing envelope out-of-band for multi-sig", async () => {
      const { blob: stripped1, envelope: env1 } =
        await MajikSignature.signFileDetached(baseBlob, keyA, {
          contentType: "text/plain",
        });

      const { blob: stripped2, envelope: env2 } =
        await MajikSignature.signFileDetached(stripped1, keyB, {
          existingEnvelope: env1,
          contentType: "text/plain",
        });

      expect(env2.signatures.length).toBe(2);

      const results1 = await MajikSignature.verifyFileDetached(
        stripped2,
        env2,
        keyA,
        { expectedSignerId: keyA.fingerprint },
      );
      expect(results1).toHaveLength(1);
      expect(results1[0].valid).toBe(true);
      expect(results1[0].signerId).toBe(keyA.fingerprint);

      const results2 = await MajikSignature.verifyFileDetached(
        stripped2,
        env2,
        keyB,
        { expectedSignerId: keyB.fingerprint },
      );
      expect(results2).toHaveLength(1);
      expect(results2[0].valid).toBe(true);
      expect(results2[0].signerId).toBe(keyB.fingerprint);
    });

    it("should reject verification if the detached file bytes are tampered with", async () => {
      const { blob: strippedBlob, envelope: detachedEnvelope } =
        await MajikSignature.signFileDetached(baseBlob, keyA, {
          contentType: "text/plain",
        });

      const tamperedBlob = await corruptBlob(strippedBlob);

      const results = await MajikSignature.verifyFileDetached(
        tamperedBlob,
        detachedEnvelope,
        keyA,
      );

      expect(results.length).toBeGreaterThan(0);
      expect(results[0].valid).toBe(false);
    });

    it("should reject verification when evaluated against mismatched public keys", async () => {
      const { blob: strippedBlob, envelope: detachedEnvelope } =
        await MajikSignature.signFileDetached(baseBlob, keyA, {
          contentType: "text/plain",
        });

      const results = await MajikSignature.verifyFileDetached(
        strippedBlob,
        detachedEnvelope,
        keyB,
      );

      expect(results.some((r) => r.valid)).toBe(false);
    });
  });

  // ─── DETACHED SIGNATURES & MJKSIG FEATURE TESTS ──────────────────────────────

  describe("Detached Signatures & MJKSIG Features", () => {
    describe("Detached File Signing and Verification (.signFileDetached & .verifyFileDetached)", () => {
      it.each(FILE_FIXTURES)(
        "should sign $label ($file) detached and verify successfully",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const originalBlob = new Blob([fileContent as BlobPart], {
            type: contentType,
          });

          const { blob: strippedBlob, envelope } =
            await MajikSignature.signFileDetached(originalBlob, keyA, {
              contentType,
            });

          expect(envelope).toBeInstanceOf(MajikSignatureEnvelope);
          expect(envelope.signatures.length).toBe(1);
          expect(envelope.signatures[0].signerId).toBe(keyA.fingerprint);

          const results = await MajikSignature.verifyFileDetached(
            strippedBlob,
            envelope,
            keyA,
          );

          expect(results).toHaveLength(1);
          expect(results[0].valid).toBe(true);
          expect(results[0].signerId).toBe(keyA.fingerprint);
        },
      );

      it.each(FILE_FIXTURES)(
        "should reject detached verification on corrupted $label ($file) content",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const originalBlob = new Blob([fileContent as BlobPart], {
            type: contentType,
          });

          const { blob: strippedBlob, envelope } =
            await MajikSignature.signFileDetached(originalBlob, keyA, {
              contentType,
            });

          const corruptedBlob = await corruptBlob(strippedBlob);

          const results = await MajikSignature.verifyFileDetached(
            corruptedBlob,
            envelope,
            keyA,
          );

          expect(results).toHaveLength(1);
          expect(results[0].valid).toBe(false);
        },
      );
    });

    describe("MJKSIG Binary Format Conversions & Verification", () => {
      it.each(FILE_FIXTURES)(
        "should convert detached envelope for $label ($file) to MJKSIG binary and verify back",
        async ({ file, contentType }) => {
          const fileContent = loadFixture(file);
          const originalBlob = new Blob([fileContent as BlobPart], {
            type: contentType,
          });

          const { blob: strippedBlob, envelope } =
            await MajikSignature.signFileDetached(originalBlob, keyA, {
              contentType,
            });

          const mjksigBlob = envelope.toMJKSIG();
          const bytes = envelope.toMJKSIGBytes();
          expect(mjksigBlob).toBeInstanceOf(Blob);
          expect(bytes.length).toBeGreaterThan(12);

          expect(await MajikSignatureEnvelope.isMJKSIG(mjksigBlob)).toBe(true);
          expect(
            await MajikSignatureEnvelope.getMJKSIGVersion(mjksigBlob),
          ).toBe(1);

          const directVerifyResults = await MajikSignature.verifyFileDetached(
            strippedBlob,
            mjksigBlob,
            keyA,
          );

          expect(directVerifyResults).toHaveLength(1);
          expect(directVerifyResults[0].valid).toBe(true);
          expect(directVerifyResults[0].signerId).toBe(keyA.fingerprint);

          const decodedEnvelope =
            await MajikSignatureEnvelope.fromMJKSIG(mjksigBlob);

          expect(decodedEnvelope).toBeInstanceOf(MajikSignatureEnvelope);
          expect(decodedEnvelope.isValid()).toBe(true);
          expect(decodedEnvelope.signatures[0].contentHash).toBe(
            envelope.signatures[0].contentHash,
          );

          const restoredVerifyResults = await MajikSignature.verifyFileDetached(
            strippedBlob,
            decodedEnvelope,
            keyA,
          );

          expect(restoredVerifyResults[0].valid).toBe(true);
        },
      );

      describe("MJKSIG Sniffing and Error Handling", () => {
        it("should return false for isMJKSIG on non-MJKSIG bytes", async () => {
          const dummyBytes = new TextEncoder().encode(
            "Hello World, Not MJKSIG!",
          );
          const isMJKSIG = await MajikSignatureEnvelope.isMJKSIG(dummyBytes);
          expect(isMJKSIG).toBe(false);
          expect(
            await MajikSignatureEnvelope.getMJKSIGVersion(dummyBytes),
          ).toBeNull();
        });

        it("should throw when decoding corrupted or truncated MJKSIG bytes", async () => {
          const shortBuffer = new Uint8Array([0x4d, 0x4a, 0x4b]); // "MJK"
          await expect(
            MajikSignatureEnvelope.fromMJKSIG(shortBuffer),
          ).rejects.toThrow(
            "Malformed MJKSIG: too short to contain a valid header",
          );

          const badMagic = new Uint8Array(32);
          await expect(
            MajikSignatureEnvelope.fromMJKSIG(badMagic),
          ).rejects.toThrow('Malformed MJKSIG: missing "MJKSIG" magic bytes');
        });
      });
    });
  });

  // ─── TRUSTED TIMESTAMPS (TSA) ─────────────────────────────────────────────────

  describe("Trusted Timestamps (TSA)", () => {
    async function issueTsaFor(
      signature: MajikSignature,
    ): Promise<MajikTimestamp> {
      const request = signature.buildTSARequestPayload();
      return MajikSignature.signTSA(request, tsaKey, {
        id: "tsa.majikah.solutions",
        signerFingerprint: tsaKey.fingerprint,
      });
    }

    it("should sign a TSA payload and produce a valid MajikTimestamp", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA);
      const ts = await issueTsaFor(signature);

      expect(ts.version).toBe(1);
      expect(ts.payload.digest.value).toBe(signature.contentHash);
      expect(ts.payload.tsa.signerFingerprint).toBe(tsaKey.fingerprint);
    });

    it("should attach a TSA to a signature via addTSA and successfully re-verify it", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA);
      const ts = await issueTsaFor(signature);

      signature.addTSA(ts);
      expect(signature.hasTSA).toBe(true);

      const result = signature.verifyTSA();
      expect(result.valid).toBe(true);
    });

    it("should reject addTSA if the TSA digest does not match this signature's contentHash", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA);
      const otherSignature = await MajikSignature.sign(
        "a completely different payload",
        keyB,
      );
      const mismatchedTsa = await issueTsaFor(otherSignature);

      expect(() => signature.addTSA(mismatchedTsa)).toThrow(
        /TSA digest does not match signature contentHash/,
      );
    });

    it("should reject attaching a second TSA once one is already set", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA);
      const ts = await issueTsaFor(signature);

      signature.addTSA(ts);
      expect(() => signature.addTSA(ts)).toThrow(
        /TSA is already set and cannot be replaced/,
      );
    });

    it("should carry the TSA through a toJSON/fromJSON round-trip", async () => {
      const signature = await MajikSignature.sign(dummyContent, keyA);
      const ts = await issueTsaFor(signature);
      signature.addTSA(ts);

      const restored = MajikSignature.fromJSON(signature.toJSON());
      expect(restored.hasTSA).toBe(true);
      expect(restored.verifyTSA().valid).toBe(true);
    });

    describe("signFileDetached with options.tsa", () => {
      it("should attach a TSA during detached signing when options.tsa is provided", async () => {
        const fileContent = loadFixture("sample.txt");
        const blob = new Blob([fileContent as BlobPart], {
          type: "text/plain",
        });

        // Content hash only depends on bytes, not on timestamp — signing
        // the same content twice (once here to obtain a contentHash for the
        // TSA request, once for real inside signFileDetached) yields the
        // same contentHash both times, so the TSA's digest still matches.
        const precomputed = await MajikSignature.sign(fileContent, keyA, {
          contentType: "text/plain",
        });
        const ts = await issueTsaFor(precomputed);

        const { envelope, signature } = await MajikSignature.signFileDetached(
          blob,
          keyA,
          { contentType: "text/plain", tsa: ts },
        );

        expect(signature.hasTSA).toBe(true);
        expect(envelope.signatures[0].tsa).toBeDefined();
        expect(envelope.signatures[0].tsa?.payload.digest.value).toBe(
          signature.contentHash,
        );
      });

      it("should reject options.tsa whose digest doesn't match the file actually being signed", async () => {
        const blobA = new Blob(["file A content"], { type: "text/plain" });
        const blobB = new Blob(["completely different file B content"], {
          type: "text/plain",
        });

        const sigForB = await MajikSignature.sign(
          new Uint8Array(await blobB.arrayBuffer()),
          keyA,
          { contentType: "text/plain" },
        );
        const tsaForB = await issueTsaFor(sigForB);

        await expect(
          MajikSignature.signFileDetached(blobA, keyA, {
            contentType: "text/plain",
            tsa: tsaForB,
          }),
        ).rejects.toThrow(/TSA digest does not match signature contentHash/);
      });
    });
  });

  // ─── MJKSMAP & BATCH SIGNING / VERIFICATION ──────────────────────────────────

  describe("MajikSignatureMap (.mjksmap) & Batch Signing", () => {
    describe("Core Map Operations", () => {
      it("creates an empty map and adds entries immutably", async () => {
        const map0 = MajikSignatureMap.empty();
        expect(map0.size).toBe(0);

        const fileContent = loadFixture("sample.txt");
        const blob = new Blob([fileContent as BlobPart], {
          type: "text/plain",
        });
        const { envelope } = await MajikSignature.signFileDetached(blob, keyA, {
          contentType: "text/plain",
        });

        const map1 = map0.withEntry({
          path: "docs/report.txt",
          contentHash: envelope.signatures[0].contentHash,
          size: blob.size,
          mimeType: "text/plain",
          envelope: envelope.toJSON(),
        });

        expect(map0.size).toBe(0); // original untouched — immutable builder
        expect(map1.size).toBe(1);
        expect(map1.getEntry("docs/report.txt")).toBeDefined();
      });

      it("normalizes backslash paths and drive letters to the same key", () => {
        const map = MajikSignatureMap.empty().withEntry({
          path: "C:\\docs\\a.pdf",
          contentHash: "deadbeef",
          envelope: { version: 1, signatures: [] } as any,
        });

        expect(map.getEntry("docs/a.pdf")).toBeDefined();
        expect(map.hasEntry("docs\\a.pdf")).toBe(true);
      });

      it("replaces an entry on re-add at the same path (withEntry upsert)", () => {
        let map = MajikSignatureMap.empty().withEntry({
          path: "a.txt",
          contentHash: "hash1",
          envelope: { version: 1, signatures: [] } as any,
        });
        map = map.withEntry({
          path: "a.txt",
          contentHash: "hash2",
          envelope: { version: 1, signatures: [] } as any,
        });

        expect(map.size).toBe(1);
        expect(map.getEntry("a.txt")?.contentHash).toBe("hash2");
      });

      it("removes an entry via withoutEntry", () => {
        let map = MajikSignatureMap.empty().withEntry({
          path: "a.txt",
          contentHash: "hash1",
          envelope: { version: 1, signatures: [] } as any,
        });
        map = map.withoutEntry("a.txt");
        expect(map.size).toBe(0);
      });
    });

    describe("MJKSMAP Serialization Round-Trip", () => {
      it("round-trips through toJSON/fromJSON", async () => {
        const fileContent = loadFixture("sample.txt");
        const blob = new Blob([fileContent as BlobPart], {
          type: "text/plain",
        });
        const { envelope } = await MajikSignature.signFileDetached(blob, keyA, {
          contentType: "text/plain",
        });

        const map = MajikSignatureMap.empty().withEntry({
          path: "sample.txt",
          contentHash: envelope.signatures[0].contentHash,
          envelope: envelope.toJSON(),
        });

        const restored = MajikSignatureMap.fromJSON(map.toJSON());
        expect(restored.size).toBe(1);
        expect(restored.getEntry("sample.txt")?.contentHash).toBe(
          envelope.signatures[0].contentHash,
        );
      });

      it("round-trips through toMJKSMAP/fromMJKSMAP binary format", async () => {
        const fileContent = loadFixture("sample.txt");
        const blob = new Blob([fileContent as BlobPart], {
          type: "text/plain",
        });
        const { envelope } = await MajikSignature.signFileDetached(blob, keyA, {
          contentType: "text/plain",
        });

        const map = MajikSignatureMap.empty().withEntry({
          path: "sample.txt",
          contentHash: envelope.signatures[0].contentHash,
          envelope: envelope.toJSON(),
        });

        const mapBlob = map.toMJKSMAP();
        expect(mapBlob).toBeInstanceOf(Blob);
        expect(await MajikSignatureMap.isMJKSMAP(mapBlob)).toBe(true);

        const restored = await MajikSignatureMap.fromMJKSMAP(mapBlob);
        expect(restored).toBeInstanceOf(MajikSignatureMap);
        expect(restored.size).toBe(1);
        expect(restored.isValid()).toBe(true);
      });

      it("returns false for isMJKSMAP on unrelated bytes", async () => {
        const dummy = new TextEncoder().encode("not a map");
        expect(await MajikSignatureMap.isMJKSMAP(dummy)).toBe(false);
      });
    });

    describe("Lookup: getEntry / findEntry / findEntriesByHash / resolveEntry", () => {
      let map: MajikSignatureMap;
      let fileA: Blob;
      let fileB: Blob;
      let fileADup: Blob; // same content as fileA, different Blob instance

      beforeAll(async () => {
        const contentA = loadFixture("sample.txt");
        const contentB = loadFixture("sample.csv");

        fileA = new Blob([contentA as BlobPart], { type: "text/plain" });
        fileB = new Blob([contentB as BlobPart], { type: "text/csv" });
        fileADup = new Blob([contentA as BlobPart], { type: "text/plain" });

        const { envelope: envA } = await MajikSignature.signFileDetached(
          fileA,
          keyA,
          { contentType: "text/plain" },
        );
        const { envelope: envB } = await MajikSignature.signFileDetached(
          fileB,
          keyB,
          { contentType: "text/csv" },
        );

        map = MajikSignatureMap.empty()
          .withEntry({
            path: "docs/a.txt",
            contentHash: envA.signatures[0].contentHash,
            envelope: envA.toJSON(),
          })
          .withEntry({
            path: "docs/b.csv",
            contentHash: envB.signatures[0].contentHash,
            envelope: envB.toJSON(),
          });
      }, 60000);

      it("getEntry finds by exact normalized path", () => {
        expect(map.getEntry("docs/a.txt")).toBeDefined();
        expect(map.getEntry("docs\\a.txt")).toBeDefined();
        expect(map.getEntry("nope.txt")).toBeUndefined();
      });

      it("findEntry confirms hash match for unmodified content", async () => {
        const result = await map.findEntry("docs/a.txt", fileA);
        expect(result.found).toBe(true);
        expect(result.hashMatches).toBe(true);
      });

      it("findEntry flags hash mismatch for content modified under the same path", async () => {
        const tamperedBytes = tamperBytes(
          new Uint8Array(await fileA.arrayBuffer()),
        );
        const tamperedBlob = new Blob([tamperedBytes as BlobPart], {
          type: "text/plain",
        });

        const result = await map.findEntry("docs/a.txt", tamperedBlob);
        expect(result.found).toBe(true);
        expect(result.hashMatches).toBe(false);
      });

      it("findEntry reports not found for an unknown path", async () => {
        const result = await map.findEntry("unknown/path.txt", fileA);
        expect(result.found).toBe(false);
      });

      it("findEntriesByHash finds a file by content regardless of path", async () => {
        const entries = await map.findEntriesByHash(fileADup);
        expect(entries.length).toBe(1);
        expect(entries[0].path).toBe("docs/a.txt");
      });

      it("resolveEntry returns path_match for an unmodified file at its original path", async () => {
        const result = await map.resolveEntry("docs/a.txt", fileA);
        expect(result.status).toBe("path_match");
      });

      it("resolveEntry returns path_tampered when content no longer matches at the expected path", async () => {
        const tamperedBytes = tamperBytes(
          new Uint8Array(await fileA.arrayBuffer()),
        );
        const tamperedBlob = new Blob([tamperedBytes as BlobPart], {
          type: "text/plain",
        });

        const result = await map.resolveEntry("docs/a.txt", tamperedBlob);
        expect(result.status).toBe("path_tampered");
      });

      it("resolveEntry returns relocated when the file is found by content at a different path", async () => {
        const result = await map.resolveEntry(
          "moved/somewhere/a.txt",
          fileADup,
        );
        expect(result.status).toBe("relocated");
        expect(result.originalPath).toBe("docs/a.txt");
      });

      it("resolveEntry returns not_found when the file matches nothing at all", async () => {
        const unrelated = new Blob(["totally unrelated content"], {
          type: "text/plain",
        });
        const result = await map.resolveEntry("unknown.txt", unrelated);
        expect(result.status).toBe("not_found");
      });

      it("getEnvelope returns a rich MajikSignatureEnvelope instance for a known path", () => {
        const envelope = map.getEnvelope("docs/a.txt");
        expect(envelope).toBeInstanceOf(MajikSignatureEnvelope);
      });

      it("getEnvelope returns null for an unknown path", () => {
        expect(map.getEnvelope("nope.txt")).toBeNull();
      });

      it("getAllEnvelopes returns every entry paired with a rich envelope instance", () => {
        const all = map.getAllEnvelopes();
        expect(all.length).toBe(2);
        for (const { envelope } of all) {
          expect(envelope).toBeInstanceOf(MajikSignatureEnvelope);
        }
      });
    });

    describe("Batch Signing (.signBatchDetached)", () => {
      it("signs a batch in 'map' mode (default) and produces a valid MajikSignatureMap", async () => {
        const files = [
          {
            path: "docs/one.txt",
            blob: new Blob([loadFixture("sample.txt") as BlobPart], {
              type: "text/plain",
            }),
          },
          {
            path: "docs/two.csv",
            blob: new Blob([loadFixture("sample.csv") as BlobPart], {
              type: "text/csv",
            }),
          },
        ];

        const result = await MajikSignature.signBatchDetached(files, keyA);

        expect(result.mode).toBe("map");
        if (result.mode === "map") {
          expect(result.map.size).toBe(2);
          expect(result.map.hasEntry("docs/one.txt")).toBe(true);
          expect(result.map.hasEntry("docs/two.csv")).toBe(true);
          expect(result.mapBlob).toBeInstanceOf(Blob);
          expect(result.failures).toHaveLength(0);
        }
      });

      it("signs a batch in 'separate' mode and produces one .mjksig Blob per file", async () => {
        const files = [
          {
            path: "docs/one.txt",
            blob: new Blob([loadFixture("sample.txt") as BlobPart], {
              type: "text/plain",
            }),
          },
          {
            path: "docs/two.csv",
            blob: new Blob([loadFixture("sample.csv") as BlobPart], {
              type: "text/csv",
            }),
          },
        ];

        const result = await MajikSignature.signBatchDetached(files, keyA, {
          mode: "separate",
        });

        expect(result.mode).toBe("separate");
        if (result.mode === "separate") {
          expect(result.signatures).toHaveLength(2);
          for (const { blob } of result.signatures) {
            expect(blob).toBeInstanceOf(Blob);
          }
          expect(result.failures).toHaveLength(0);
        }
      });

      it("rejects a batch with duplicate paths before doing any signing", async () => {
        const files = [
          {
            path: "docs/dup.txt",
            blob: new Blob(["a"], { type: "text/plain" }),
          },
          {
            path: "docs/dup.txt",
            blob: new Blob(["b"], { type: "text/plain" }),
          },
        ];

        await expect(
          MajikSignature.signBatchDetached(files, keyA),
        ).rejects.toThrow(/Duplicate path in batch/);
      });

      it("rejects an empty batch", async () => {
        await expect(
          MajikSignature.signBatchDetached([], keyA),
        ).rejects.toThrow(/Batch must contain at least one file/);
      });

      it("establishes an allowlist on each file's envelope when expectedSigners is provided", async () => {
        const expectedSigners = [
          MajikSignature.expectedSignerFromKey(keyA),
          MajikSignature.expectedSignerFromKey(keyB),
        ];

        const files = [
          {
            path: "restricted/one.txt",
            blob: new Blob(["restricted content one"], { type: "text/plain" }),
          },
        ];

        const result = await MajikSignature.signBatchDetached(files, keyA, {
          expectedSigners,
        });

        expect(result.mode).toBe("map");
        if (result.mode === "map") {
          const envelope = result.map.getEnvelope("restricted/one.txt");
          expect(envelope?.hasAllowlist()).toBe(true);
          expect(envelope?.allowlistSignerId).toBe(keyA.fingerprint);
        }
      });

      describe("continueOnError behavior", () => {
        // "bad" blob deliberately omits arrayBuffer() to trigger a natural,
        // per-file failure inside signDetached — avoids needing to mock any
        // frozen static methods (MajikSignature is Object.freeze()'d).
        function badBlob(): Blob {
          return { size: 0, type: "text/plain" } as unknown as Blob;
        }

        it("aborts the whole batch on the first failure by default", async () => {
          const files = [
            { path: "bad.txt", blob: badBlob() },
            {
              path: "good.txt",
              blob: new Blob(["good content"], { type: "text/plain" }),
            },
          ];

          await expect(
            MajikSignature.signBatchDetached(files, keyA),
          ).rejects.toThrow(/Batch signing failed on "bad.txt"/);
        });

        it("collects failures and continues when continueOnError is true", async () => {
          const files = [
            { path: "bad.txt", blob: badBlob() },
            {
              path: "good.txt",
              blob: new Blob(["good content"], { type: "text/plain" }),
            },
          ];

          const result = await MajikSignature.signBatchDetached(files, keyA, {
            continueOnError: true,
          });

          expect(result.mode).toBe("map");
          if (result.mode === "map") {
            expect(result.failures).toHaveLength(1);
            expect(result.failures[0].path).toBe("bad.txt");
            expect(result.map.hasEntry("good.txt")).toBe(true);
            expect(result.map.hasEntry("bad.txt")).toBe(false);
          }
        });
      });
    });

    describe("Batch Verification (.verifyFilesFromMjksMap)", () => {
      let map: MajikSignatureMap;
      let signedFiles: { path: string; blob: Blob }[];

      beforeAll(async () => {
        signedFiles = [
          {
            path: "docs/one.txt",
            blob: new Blob([loadFixture("sample.txt") as BlobPart], {
              type: "text/plain",
            }),
          },
          {
            path: "docs/two.csv",
            blob: new Blob([loadFixture("sample.csv") as BlobPart], {
              type: "text/csv",
            }),
          },
        ];

        const result = await MajikSignature.signBatchDetached(
          signedFiles,
          keyA,
        );
        if (result.mode !== "map") throw new Error("expected map mode");
        map = result.map;
      }, 60000);

      it("reports 'verified' for every unmodified, correctly-placed file", async () => {
        const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);
        const results = await MajikSignature.verifyFilesFromMjksMap(
          map,
          signedFiles,
          publicKeys,
        );

        expect(results).toHaveLength(2);
        for (const r of results) {
          expect(r.status).toBe("verified");
          expect(r.results?.every((vr) => vr.valid)).toBe(true);
        }

        const summary = MajikSignature.summarizeBatchVerification(results);
        expect(summary.allValid).toBe(true);
        expect(summary.verified).toBe(2);
        expect(summary.total).toBe(2);
      });

      it("reports 'tampered' for a file whose content changed under its signed path", async () => {
        const tamperedBytes = tamperBytes(
          new Uint8Array(await signedFiles[0].blob.arrayBuffer()),
        );
        const tamperedFiles = [
          {
            path: "docs/one.txt",
            blob: new Blob([tamperedBytes as BlobPart], { type: "text/plain" }),
          },
          signedFiles[1],
        ];

        const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);
        const results = await MajikSignature.verifyFilesFromMjksMap(
          map,
          tamperedFiles,
          publicKeys,
        );

        const tamperedResult = results.find((r) => r.path === "docs/one.txt");
        expect(tamperedResult?.status).toBe("tampered");
      });

      it("reports 'not_in_map' for a file with no corresponding entry", async () => {
        const strayFile = [
          {
            path: "unrelated.txt",
            blob: new Blob(["stray"], { type: "text/plain" }),
          },
        ];
        const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);
        const results = await MajikSignature.verifyFilesFromMjksMap(
          map,
          strayFile,
          publicKeys,
        );

        expect(results[0].status).toBe("not_in_map");
      });

      it("throws when requireAllPresent is set and a file is missing", async () => {
        const strayFile = [
          {
            path: "unrelated.txt",
            blob: new Blob(["stray"], { type: "text/plain" }),
          },
        ];
        const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);

        await expect(
          MajikSignature.verifyFilesFromMjksMap(map, strayFile, publicKeys, {
            requireAllPresent: true,
          }),
        ).rejects.toThrow(/was not found in the signature map/);
      });

      it("reports 'verified' with relocatedFrom when a file moved to a different path", async () => {
        const relocatedFiles = [
          { path: "moved/one.txt", blob: signedFiles[0].blob },
          signedFiles[1],
        ];

        const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);
        const results = await MajikSignature.verifyFilesFromMjksMap(
          map,
          relocatedFiles,
          publicKeys,
        );

        const relocatedResult = results.find((r) => r.path === "moved/one.txt");
        expect(relocatedResult?.status).toBe("verified");
        expect(relocatedResult?.relocatedFrom).toBe("docs/one.txt");
      });

      it("verifyFilesFromMjksMapWithKey resolves public keys automatically from a MajikKey", async () => {
        const results = await MajikSignature.verifyFilesFromMjksMapWithKey(
          map,
          signedFiles,
          keyA,
        );
        expect(results.every((r) => r.status === "verified")).toBe(true);
      });
    });
  });

  // ─── CHRONOLOGICAL ORDER VERIFICATION (.verifyFileOrder & .verifyFileDetachedOrder) ───

  describe("Chronological Order Verification (.verifyFileOrder & .verifyFileDetachedOrder)", () => {
    const t1 = "2026-08-01T10:00:00.000Z";
    const t2 = "2026-08-01T10:05:00.000Z";
    const t3 = "2026-08-01T10:10:00.000Z";

    let baseBlob: Blob;

    beforeAll(() => {
      baseBlob = new Blob(["Order Verification Test Document"], {
        type: "text/plain",
      });
    });

    // ── NORMALIZATION ────────────────────────────────────────────────────────

    describe("normalizeExpectedOrder", () => {
      it("should accept mixed MajikKey instances and ExpectedSigner objects and normalize them", () => {
        const profileB = MajikSignature.expectedSignerFromKey(keyB);
        const normalized = MajikSignature.normalizeExpectedOrder([
          keyA,
          profileB,
        ]);

        expect(normalized).toHaveLength(2);
        expect(normalized[0].signerId).toBe(keyA.fingerprint);
        expect(normalized[1].signerId).toBe(keyB.fingerprint);
        expect(typeof normalized[0].edPublicKey).toBe("string");
        expect(typeof normalized[0].mlDsaPublicKey).toBe("string");
      });

      it("should throw a validation error if expectedOrder is empty", async () => {
        const { blob } = await MajikSignature.signFile(baseBlob, keyA);
        await expect(MajikSignature.verifyFileOrder(blob, [])).rejects.toThrow(
          /expectedOrder must contain at least one signer/,
        );
      });

      it("should throw a validation error if expectedOrder contains duplicates", async () => {
        const { blob } = await MajikSignature.signFile(baseBlob, keyA);
        await expect(
          MajikSignature.verifyFileOrder(blob, [keyA, keyA]),
        ).rejects.toThrow(/Duplicate signerId in expectedOrder/);
      });
    });

    // ── HAPPY PATH (CORRECT ORDER) ───────────────────────────────────────────

    describe("Valid Chronological Signing", () => {
      it("should return valid=true when all expected signers sign in the correct sequence (embedded)", async () => {
        // keyA @ t1 -> keyB @ t2 -> keyC @ t3
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyA, {
          timestamp: t1,
        });
        const { blob: step2 } = await MajikSignature.signFile(step1, keyB, {
          timestamp: t2,
        });
        const { blob: finalBlob } = await MajikSignature.signFile(step2, keyC, {
          timestamp: t3,
        });

        const result = await MajikSignature.verifyFileOrder(finalBlob, [
          keyA,
          keyB,
          keyC,
        ]);

        expect(result.valid).toBe(true);
        expect(result.allExpectedSigned).toBe(true);
        expect(result.allValid).toBe(true);
        expect(result.orderRespected).toBe(true);
        expect(result.pendingSigners).toHaveLength(0);
        expect(result.invalidSigners).toHaveLength(0);
        expect(result.violations).toHaveLength(0);
        expect(result.usesUnattestedTimestamp).toBe(true); // Self-reported local clocks used
      });

      it("should support mixed key types in expectedOrder (MajikKey + ExpectedSigner profile)", async () => {
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyA, {
          timestamp: t1,
        });
        const { blob: finalBlob } = await MajikSignature.signFile(step1, keyB, {
          timestamp: t2,
        });

        const expectedOrder = [
          keyA,
          MajikSignature.expectedSignerFromKey(keyB),
        ];

        const result = await MajikSignature.verifyFileOrder(
          finalBlob,
          expectedOrder,
        );

        expect(result.valid).toBe(true);
        expect(result.orderRespected).toBe(true);
      });

      it("should correctly verify order against detached envelope via verifyFileDetachedOrder", async () => {
        const { blob: stripped1, envelope: env1 } =
          await MajikSignature.signFileDetached(baseBlob, keyA, {
            timestamp: t1,
          });

        const { blob: stripped2, envelope: finalEnv } =
          await MajikSignature.signFileDetached(stripped1, keyB, {
            existingEnvelope: env1,
            timestamp: t2,
          });

        const result = await MajikSignature.verifyFileDetachedOrder(
          stripped2,
          finalEnv,
          [keyA, keyB],
        );

        expect(result.valid).toBe(true);
        expect(result.allExpectedSigned).toBe(true);
        expect(result.orderRespected).toBe(true);
      });
    });

    // ── ORDER VIOLATIONS (OUT OF ORDER) ──────────────────────────────────────

    describe("Out-of-Order Signing Violations", () => {
      it("should detect order violations when signers sign out of the expected sequence", async () => {
        // Expected order: keyA then keyB
        // Actual signing: keyB @ t1 then keyA @ t2
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyB, {
          timestamp: t1,
        });
        const { blob: finalBlob } = await MajikSignature.signFile(step1, keyA, {
          timestamp: t2,
        });

        const result = await MajikSignature.verifyFileOrder(finalBlob, [
          keyA,
          keyB,
        ]);

        expect(result.valid).toBe(false);
        expect(result.allExpectedSigned).toBe(true);
        expect(result.allValid).toBe(true);
        expect(result.orderRespected).toBe(false);
        expect(result.violations).toHaveLength(1);

        const violation = result.violations[0];
        expect(violation.earlier).toBe(keyA.fingerprint);
        expect(violation.later).toBe(keyB.fingerprint);
        expect(violation.earlierTimestamp).toBe(t2);
        expect(violation.laterTimestamp).toBe(t1);
      });
    });

    // ── PENDING SIGNERS (INCOMPLETE) ─────────────────────────────────────────

    describe("Pending / Missing Signers", () => {
      it("should flag allExpectedSigned=false and populate pendingSigners when expected signers are missing", async () => {
        // Expected: keyA -> keyB -> keyC, but only keyA and keyB signed
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyA, {
          timestamp: t1,
        });
        const { blob: finalBlob } = await MajikSignature.signFile(step1, keyB, {
          timestamp: t2,
        });

        const result = await MajikSignature.verifyFileOrder(finalBlob, [
          keyA,
          keyB,
          keyC,
        ]);

        expect(result.valid).toBe(false);
        expect(result.allExpectedSigned).toBe(false);
        expect(result.pendingSigners).toEqual([keyC.fingerprint]);
        expect(result.orderRespected).toBe(true); // Signatures present were in order
      });
    });

    // ── INVALID / TAMPERED SIGNATURES ────────────────────────────────────────

    describe("Invalid & Tampered Signatures in Sequence", () => {
      it("should flag allValid=false and populate invalidSigners when payload is corrupted", async () => {
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyA, {
          timestamp: t1,
        });
        const { blob: step2 } = await MajikSignature.signFile(step1, keyB, {
          timestamp: t2,
        });

        const tamperedBlob = await corruptBlob(step2);

        const result = await MajikSignature.verifyFileOrder(tamperedBlob, [
          keyA,
          keyB,
        ]);

        expect(result.valid).toBe(false);
        expect(result.allValid).toBe(false);
        expect(result.invalidSigners.length).toBeGreaterThan(0);
      });
    });

    // ── STRICT MODE & UNEXPECTED SIGNERS ────────────────────────────────────

    describe("Strict Mode Enforcement ({ strict: true })", () => {
      it("should allow unlisted signers in non-strict mode if expected order is valid", async () => {
        // Signed by keyA @ t1, keyB @ t2, and an extra keyD @ t3
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyA, {
          timestamp: t1,
        });
        const { blob: step2 } = await MajikSignature.signFile(step1, keyB, {
          timestamp: t2,
        });
        const { blob: finalBlob } = await MajikSignature.signFile(step2, keyD, {
          timestamp: t3,
        });

        const result = await MajikSignature.verifyFileOrder(
          finalBlob,
          [keyA, keyB],
          { strict: false },
        );

        expect(result.valid).toBe(true);
        expect(result.strict).toBe(false);
        // Since strict mode is false, the library doesn't compile unexpected signers.
        expect(result.unexpectedSigners).toEqual([]);
      });

      it("should reject and flag unexpectedSigners in strict mode", async () => {
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyA, {
          timestamp: t1,
        });
        const { blob: step2 } = await MajikSignature.signFile(step1, keyB, {
          timestamp: t2,
        });
        const { blob: finalBlob } = await MajikSignature.signFile(step2, keyD, {
          timestamp: t3,
        });

        const result = await MajikSignature.verifyFileOrder(
          finalBlob,
          [keyA, keyB],
          { strict: true },
        );

        expect(result.valid).toBe(false);
        expect(result.strict).toBe(true);
        expect(result.unexpectedSigners).toEqual([keyD.fingerprint]);
        expect(result.reason).toContain("Unexpected signer(s) present");
      });
    });

    // ── TSA VS. UNATTESTED TIMESTAMPS ────────────────────────────────────────

    describe("TSA vs Unattested Timestamp Detection", () => {
      it("should set usesUnattestedTimestamp=false when all signatures carry a TSA token", async () => {
        // Prepare TSA token for keyA
        const sigA = await MajikSignature.sign(
          new Uint8Array(await baseBlob.arrayBuffer()),
          keyA,
          { contentType: "text/plain", timestamp: t1 },
        );
        const tsaReqA = sigA.buildTSARequestPayload();
        const tsaTokenA = await MajikSignature.signTSA(tsaReqA, tsaKey, {
          id: "tsa.majikah.solutions",
          signerFingerprint: tsaKey.fingerprint,
        });

        const { blob: stripped, envelope } =
          await MajikSignature.signFileDetached(baseBlob, keyA, {
            contentType: "text/plain",
            timestamp: t1,
            tsa: tsaTokenA,
          });

        const result = await MajikSignature.verifyFileDetachedOrder(
          stripped,
          envelope,
          [keyA],
        );

        expect(result.valid).toBe(true);
        expect(result.usesUnattestedTimestamp).toBe(false); // TSA timestamp used
      });
    });

    // ── SOFT-TIE TIMESTAMP WARNINGS ─────────────────────────────────────────

    describe("Soft-Tie Timestamp Warnings", () => {
      it("should generate softTieWarnings when two signers have identical timestamps", async () => {
        // Both sign with identical timestamp t1
        const { blob: step1 } = await MajikSignature.signFile(baseBlob, keyA, {
          timestamp: t1,
        });
        const { blob: finalBlob } = await MajikSignature.signFile(step1, keyB, {
          timestamp: t1,
        });

        const result = await MajikSignature.verifyFileOrder(finalBlob, [
          keyA,
          keyB,
        ]);

        expect(result.valid).toBe(true);
        expect(result.softTieWarnings).toHaveLength(1);
        expect(result.softTieWarnings[0]).toEqual({
          a: keyA.fingerprint,
          b: keyB.fingerprint,
          timestamp: t1,
        });
      });
    });
  });
});

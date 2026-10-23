import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { MajikKey } from "@majikah/majik-key";

import { MajikSignature } from "../src/majik-signature";
import { MajikSignatureEnvelope } from "../src/core/envelope";
import { MajikSignatureMap } from "../src/core/mjksmap";
import { MJKSIG_VERSION } from "../src/core/constants";
import type { MajikTimestamp } from "../src/core/types";
import { getTestKey } from "./helpers/crypto";

const __currentDir = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__currentDir, "fixtures");

interface FileFixture {
  label: string;
  file: string;
  contentType: string;
}

/**
 * Keep this list aligned with the core file-signing suite. Detached signing
 * should work regardless of whether a format has a native embedding handler:
 * the envelope is stored separately from the signed content.
 */
const FILE_FIXTURES: FileFixture[] = [
  { label: "Plain Text", file: "sample.txt", contentType: "text/plain" },
  { label: "WEBP Image", file: "sample.webp", contentType: "image/webp" },
  { label: "PNG Image", file: "sample.png", contentType: "image/png" },
  { label: "JPEG Image", file: "sample.jpg", contentType: "image/jpeg" },
  { label: "MP4 Video", file: "sample.mp4", contentType: "video/mp4" },
  { label: "MOV Video", file: "sample.mov", contentType: "video/quicktime" },
  { label: "MKV Video", file: "sample.mkv", contentType: "video/x-matroska" },
  { label: "WAV Audio", file: "sample.wav", contentType: "audio/wav" },
  { label: "FLAC Audio", file: "sample.flac", contentType: "audio/flac" },
  { label: "MP3 Audio", file: "sample.mp3", contentType: "audio/mpeg" },
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
  {
    label: "Windows Executable",
    file: "sample.exe",
    contentType: "application/vnd.microsoft.portable-executable",
  },
  {
    label: "MSIX Package",
    file: "sample.msix",
    contentType: "application/msix",
  },
  {
    label: "Debian Package",
    file: "sample.deb",
    contentType: "application/vnd.debian.binary-package",
  },
  {
    label: "Windows Installer Package",
    file: "sample.msi",
    contentType: "application/x-msi",
  },
];

function loadFixture(filename: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURES_DIR, filename)));
}

/** Flip a byte without assuming the fixture is text. */
function tamperBytes(bytes: Uint8Array): Uint8Array {
  const tampered = new Uint8Array(bytes);
  if (tampered.length === 0) return new Uint8Array([1]);
  tampered[0] ^= 0xff;
  return tampered;
}

async function corruptBlob(blob: Blob): Promise<Blob> {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  return new Blob([tamperBytes(bytes) as BlobPart], { type: blob.type });
}

/**
 * Test-only simulation of a signer adding a visual stamp to a PDF revision.
 * We deterministically alter one payload byte instead of depending on a PDF
 * rendering/stamping library. Each call is based on the previous revision and
 * changes a different byte; the PDF header is left untouched for format
 * detection. This intentionally models changed document bytes, not a real
 * rendered appearance or a production PDF-stamping implementation.
 */
async function simulatePdfStamp(
  previousRevision: Blob,
  stampIndex: number,
): Promise<Blob> {
  const bytes = new Uint8Array(await previousRevision.arrayBuffer());
  if (bytes.length === 0) {
    return new Blob([new Uint8Array([0x25, 0x50, 0x44, 0x46, stampIndex])], {
      type: previousRevision.type || "application/pdf",
    });
  }

  const firstMutableIndex = Math.min(8, Math.max(0, bytes.length - 1));
  const targetIndex = Math.min(
    Math.max(firstMutableIndex, Math.floor(bytes.length / 2) + stampIndex),
    bytes.length - 1,
  );
  bytes[targetIndex] ^= 0xff;
  return new Blob([bytes as BlobPart], {
    type: previousRevision.type || "application/pdf",
  });
}

function asBlob(fixture: FileFixture): Blob {
  return new Blob([loadFixture(fixture.file) as BlobPart], {
    type: fixture.contentType,
  });
}

function signerProfile(key: MajikKey) {
  return MajikSignature.expectedSignerFromKey(key);
}

// ─── SHARED KEYS ─────────────────────────────────────────────────────────────

describe("Majik Signature — Detached Signing & Verification", () => {
  let keyA: MajikKey;
  let keyB: MajikKey;
  let keyC: MajikKey;
  let keyD: MajikKey;
  let keyE: MajikKey;
  let tsaKey: MajikKey;

  beforeAll(async () => {
    [keyA, keyB, keyC, keyD, keyE, tsaKey] = await Promise.all([
      getTestKey(),
      getTestKey(),
      getTestKey(),
      getTestKey(),
      getTestKey(),
      getTestKey(),
    ]);
  }, 120000);

  // ─── CORE DETACHED WORKFLOW ────────────────────────────────────────────────

  describe("Single-file detached signing and verification", () => {
    it("signs a file without embedding an envelope and returns its signature separately", async () => {
      const original = asBlob(
        FILE_FIXTURES.find((f) => f.file === "sample.txt")!,
      );
      const {
        blob: detachedFile,
        envelope,
        signature,
      } = await MajikSignature.signFileDetached(original, keyA, {
        contentType: "text/plain",
      });

      expect(detachedFile).toBeInstanceOf(Blob);
      expect(new Uint8Array(await detachedFile.arrayBuffer())).toEqual(
        new Uint8Array(await original.arrayBuffer()),
      );
      expect(envelope).toBeInstanceOf(MajikSignatureEnvelope);
      expect(envelope.signatures).toHaveLength(1);
      expect(signature.signerId).toBe(keyA.fingerprint);
      expect(envelope.signatures[0].signerId).toBe(keyA.fingerprint);

      const results = await MajikSignature.verifyFileDetached(
        detachedFile,
        envelope,
        keyA,
        { expectedSignerId: keyA.fingerprint },
      );
      expect(results).toHaveLength(1);
      expect(results[0].valid).toBe(true);
      expect(results[0].signerId).toBe(keyA.fingerprint);
    });

    it("supports passing an existing envelope out-of-band for multi-signer detached signing", async () => {
      const original = new Blob(["detached multi-signer content"], {
        type: "text/plain",
      });
      const first = await MajikSignature.signFileDetached(original, keyA, {
        contentType: "text/plain",
      });
      const second = await MajikSignature.signFileDetached(first.blob, keyB, {
        contentType: "text/plain",
        existingEnvelope: first.envelope,
      });

      expect(second.envelope.signatures).toHaveLength(2);

      const resultA = await MajikSignature.verifyFileDetached(
        second.blob,
        second.envelope,
        keyA,
        { expectedSignerId: keyA.fingerprint },
      );
      const resultB = await MajikSignature.verifyFileDetached(
        second.blob,
        second.envelope,
        keyB,
        { expectedSignerId: keyB.fingerprint },
      );
      expect(resultA[0].valid).toBe(true);
      expect(resultB[0].valid).toBe(true);
    });

    it("rejects an unauthorized signer when the issuer establishes an allowlist", async () => {
      const original = new Blob(["restricted detached content"], {
        type: "text/plain",
      });
      const first = await MajikSignature.signFileDetached(original, keyA, {
        contentType: "text/plain",
        expectedSigners: [signerProfile(keyA), signerProfile(keyB)],
      });

      expect(first.envelope.hasAllowlist()).toBe(true);
      await expect(
        MajikSignature.signFileDetached(first.blob, keyD, {
          contentType: "text/plain",
          existingEnvelope: first.envelope,
        }),
      ).rejects.toThrow(/not permitted to sign this file/i);
    });

    it("rejects detached verification when the supplied public keys belong to another signer", async () => {
      const original = new Blob(["public key mismatch"], {
        type: "text/plain",
      });
      const { blob, envelope } = await MajikSignature.signFileDetached(
        original,
        keyA,
        { contentType: "text/plain" },
      );

      const results = await MajikSignature.verifyFileDetached(
        blob,
        envelope,
        keyB,
        { expectedSignerId: keyA.fingerprint },
      );
      expect(results).toHaveLength(1);
      expect(results[0].valid).toBe(false);
    });

    it("rejects detached verification when the file bytes are modified", async () => {
      const original = new Blob(["tamper me"], { type: "text/plain" });
      const { blob, envelope } = await MajikSignature.signFileDetached(
        original,
        keyA,
        { contentType: "text/plain" },
      );
      const tampered = await corruptBlob(blob);

      const results = await MajikSignature.verifyFileDetached(
        tampered,
        envelope,
        keyA,
        { expectedSignerId: keyA.fingerprint },
      );
      expect(results).toHaveLength(1);
      expect(results[0].valid).toBe(false);
    });
  });

  // ─── EVERY AVAILABLE FILE FIXTURE ──────────────────────────────────────────

  describe("Detached signing and verification across every file fixture", () => {
    it.each(FILE_FIXTURES)(
      "signs and verifies $label ($file) using a detached envelope",
      async ({ file, contentType }) => {
        const original = new Blob([loadFixture(file) as BlobPart], {
          type: contentType,
        });
        const { blob: detachedFile, envelope } =
          await MajikSignature.signFileDetached(original, keyA, {
            contentType,
          });

        expect(envelope.signatures).toHaveLength(1);
        expect(envelope.signatures[0].signerId).toBe(keyA.fingerprint);

        const results = await MajikSignature.verifyFileDetached(
          detachedFile,
          envelope,
          keyA,
          { expectedSignerId: keyA.fingerprint },
        );
        expect(results).toHaveLength(1);
        expect(results[0].valid).toBe(true);
        expect(results[0].signerId).toBe(keyA.fingerprint);
      },
    );

    it.each(FILE_FIXTURES)(
      "rejects a tampered $label ($file) after detached signing",
      async ({ file, contentType }) => {
        const original = new Blob([loadFixture(file) as BlobPart], {
          type: contentType,
        });
        const { blob, envelope } = await MajikSignature.signFileDetached(
          original,
          keyA,
          { contentType },
        );
        const tampered = await corruptBlob(blob);

        const results = await MajikSignature.verifyFileDetached(
          tampered,
          envelope,
          keyA,
          { expectedSignerId: keyA.fingerprint },
        );
        expect(results).toHaveLength(1);
        expect(results[0].valid).toBe(false);
      },
    );
  });

  // ─── MJKSIG ENVELOPE TRANSPORT ─────────────────────────────────────────────

  describe("MJKSIG binary envelope conversion", () => {
    it("round-trips a detached envelope through MJKSIG bytes and verifies the file", async () => {
      const original = asBlob(
        FILE_FIXTURES.find((f) => f.file === "sample.pdf")!,
      );
      const { blob: detachedFile, envelope } =
        await MajikSignature.signFileDetached(original, keyA, {
          contentType: "application/pdf",
        });

      const mjksigBlob = envelope.toMJKSIG();
      const mjksigBytes = envelope.toMJKSIGBytes();
      expect(mjksigBlob).toBeInstanceOf(Blob);
      expect(mjksigBytes.length).toBeGreaterThan(12);
      expect(await MajikSignatureEnvelope.isMJKSIG(mjksigBlob)).toBe(true);
      expect(await MajikSignatureEnvelope.isMJKSIG(mjksigBytes)).toBe(true);
      expect(await MajikSignatureEnvelope.getMJKSIGVersion(mjksigBlob)).toBe(
        MJKSIG_VERSION,
      );

      const decoded = await MajikSignatureEnvelope.fromMJKSIG(mjksigBlob);
      expect(decoded).toBeInstanceOf(MajikSignatureEnvelope);
      expect(decoded.isValid()).toBe(true);
      expect(decoded.signatures[0].contentHash).toBe(
        envelope.signatures[0].contentHash,
      );

      const direct = await MajikSignature.verifyFileDetached(
        detachedFile,
        mjksigBlob,
        keyA,
        { expectedSignerId: keyA.fingerprint },
      );
      const restored = await MajikSignature.verifyFileDetached(
        detachedFile,
        decoded,
        keyA,
        { expectedSignerId: keyA.fingerprint },
      );
      expect(direct[0].valid).toBe(true);
      expect(restored[0].valid).toBe(true);
    });

    it("recognizes non-MJKSIG bytes as unrelated data and rejects malformed MJKSIG payloads", async () => {
      const unrelated = new TextEncoder().encode("not an MJKSIG envelope");
      expect(await MajikSignatureEnvelope.isMJKSIG(unrelated)).toBe(false);
      expect(
        await MajikSignatureEnvelope.getMJKSIGVersion(unrelated),
      ).toBeNull();

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(new Uint8Array([0x4d, 0x4a, 0x4b])),
      ).rejects.toThrow(/too short to contain a valid header/i);

      await expect(
        MajikSignatureEnvelope.fromMJKSIG(new Uint8Array(32)),
      ).rejects.toThrow(/missing .*MJKSIG.* magic bytes/i);
    });
  });

  // ─── TRUSTED TIMESTAMPS ON DETACHED SIGNATURES ──────────────────────────────

  describe("Trusted timestamps in detached signing", () => {
    async function issueTsaFor(
      signature: MajikSignature,
    ): Promise<MajikTimestamp> {
      return MajikSignature.signTSA(
        signature.buildTSARequestPayload(),
        tsaKey,
        {
          id: "tsa.majikah.solutions",
          signerFingerprint: tsaKey.fingerprint,
        },
      );
    }

    it("attaches and verifies a TSA token supplied through signFileDetached options", async () => {
      const original = new Blob(["detached TSA content"], {
        type: "text/plain",
      });
      const precomputed = await MajikSignature.sign(
        new Uint8Array(await original.arrayBuffer()),
        keyA,
        { contentType: "text/plain" },
      );
      const tsa = await issueTsaFor(precomputed);

      const { blob, envelope, signature } =
        await MajikSignature.signFileDetached(original, keyA, {
          contentType: "text/plain",
          tsa,
        });

      expect(signature.hasTSA).toBe(true);
      expect(signature.verifyTSA().valid).toBe(true);
      expect(envelope.signatures[0].tsa).toBeDefined();
      expect(envelope.signatures[0].tsa?.payload.digest.value).toBe(
        signature.contentHash,
      );

      const results = await MajikSignature.verifyFileDetached(
        blob,
        envelope,
        keyA,
        { expectedSignerId: keyA.fingerprint },
      );
      expect(results[0].valid).toBe(true);
    });

    it("rejects a TSA token whose digest belongs to different content", async () => {
      const fileA = new Blob(["file A"], { type: "text/plain" });
      const fileB = new Blob(["file B is different"], { type: "text/plain" });
      const signatureB = await MajikSignature.sign(
        new Uint8Array(await fileB.arrayBuffer()),
        keyA,
        { contentType: "text/plain" },
      );
      const tsaForB = await issueTsaFor(signatureB);

      await expect(
        MajikSignature.signFileDetached(fileA, keyA, {
          contentType: "text/plain",
          tsa: tsaForB,
        }),
      ).rejects.toThrow(/TSA digest does not match signature contentHash/i);
    });
  });

  // ─── BATCH DETACHED SIGNING / MJKSMAP VERIFICATION ──────────────────────────

  describe("Batch detached signing and signature-map verification", () => {
    const batchFiles = () => [
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

    it("packages a detached batch into a valid .mjksmap and verifies every file", async () => {
      const files = batchFiles();
      const signed = await MajikSignature.signBatchDetached(files, keyA);

      expect(signed.mode).toBe("map");
      if (signed.mode !== "map") throw new Error("Expected map mode");
      expect(signed.map).toBeInstanceOf(MajikSignatureMap);
      expect(signed.map.size).toBe(2);
      expect(await MajikSignatureMap.isMJKSMAP(signed.mapBlob)).toBe(true);
      expect(signed.failures).toHaveLength(0);

      const restoredMap = await MajikSignatureMap.fromMJKSMAP(signed.mapBlob);
      expect(restoredMap).toBeInstanceOf(MajikSignatureMap);
      expect(restoredMap.isValid()).toBe(true);

      const verified = await MajikSignature.verifyFilesFromMjksMap(
        restoredMap,
        files,
        MajikSignature.publicKeysFromMajikKey(keyA),
      );
      expect(verified).toHaveLength(2);
      expect(verified.every((r) => r.status === "verified")).toBe(true);
      expect(MajikSignature.summarizeBatchVerification(verified).allValid).toBe(
        true,
      );
    });

    it("supports separate .mjksig output for each batch file", async () => {
      const signed = await MajikSignature.signBatchDetached(
        batchFiles(),
        keyA,
        {
          mode: "separate",
        },
      );

      expect(signed.mode).toBe("separate");
      if (signed.mode !== "separate") throw new Error("Expected separate mode");
      expect(signed.signatures).toHaveLength(2);
      for (const item of signed.signatures) {
        expect(item.blob).toBeInstanceOf(Blob);
        expect(await MajikSignatureEnvelope.isMJKSIG(item.blob)).toBe(true);
      }
      expect(signed.failures).toHaveLength(0);
    });

    it("establishes an allowlist and applies validUntil to every file in a batch", async () => {
      const files = batchFiles();
      const validUntil = "2026-07-01T00:00:00.000Z";
      const signed = await MajikSignature.signBatchDetached(files, keyA, {
        expectedSigners: [signerProfile(keyA), signerProfile(keyB)],
        timestamp: "2026-06-01T00:00:00.000Z",
        validUntil,
      });

      expect(signed.mode).toBe("map");
      if (signed.mode !== "map") throw new Error("Expected map mode");
      for (const path of ["docs/one.txt", "docs/two.csv"]) {
        const envelope = signed.map.getEnvelope(path);
        expect(envelope?.hasAllowlist()).toBe(true);
        expect(envelope?.allowlistSignerId).toBe(keyA.fingerprint);
        expect(envelope?.signatures[0].validUntil).toBe(validUntil);
      }

      const publicKeys = MajikSignature.publicKeysFromMajikKey(keyA);
      const beforeExpiry = await MajikSignature.verifyFilesFromMjksMap(
        signed.map,
        files,
        publicKeys,
        { now: new Date("2026-06-15T00:00:00.000Z") },
      );
      expect(beforeExpiry.every((result) => result.status === "verified")).toBe(
        true,
      );

      const afterExpiry = await MajikSignature.verifyFilesFromMjksMap(
        signed.map,
        files,
        publicKeys,
        { now: new Date("2026-07-02T00:00:00.000Z") },
      );
      expect(afterExpiry.every((result) => result.status === "invalid")).toBe(
        true,
      );
      expect(
        afterExpiry.every((result) => result.results?.[0].expired === true),
      ).toBe(true);
    });

    it("reports tampered, relocated, and unmapped files during batch verification", async () => {
      const files = batchFiles();
      const signed = await MajikSignature.signBatchDetached(files, keyA);
      if (signed.mode !== "map") throw new Error("Expected map mode");

      const tamperedOne = await corruptBlob(files[0].blob);
      const candidates = [
        { path: "docs/one.txt", blob: tamperedOne },
        { path: "moved/two.csv", blob: files[1].blob },
        { path: "outside/unrelated.txt", blob: new Blob(["unmapped"]) },
      ];
      const results = await MajikSignature.verifyFilesFromMjksMap(
        signed.map,
        candidates,
        MajikSignature.publicKeysFromMajikKey(keyA),
      );

      expect(
        results.find((result) => result.path === "docs/one.txt")?.status,
      ).toBe("tampered");
      const relocated = results.find(
        (result) => result.path === "moved/two.csv",
      );
      expect(relocated?.status).toBe("verified");
      expect(relocated?.relocatedFrom).toBe("docs/two.csv");
      expect(
        results.find((result) => result.path === "outside/unrelated.txt")
          ?.status,
      ).toBe("not_in_map");
    });

    it("throws when requireAllPresent is enabled and an input file is not mapped", async () => {
      const signed = await MajikSignature.signBatchDetached(batchFiles(), keyA);
      if (signed.mode !== "map") throw new Error("Expected map mode");

      await expect(
        MajikSignature.verifyFilesFromMjksMap(
          signed.map,
          [{ path: "unknown.txt", blob: new Blob(["not mapped"]) }],
          MajikSignature.publicKeysFromMajikKey(keyA),
          { requireAllPresent: true },
        ),
      ).rejects.toThrow(/was not found in the signature map/i);
    });

    it("collects individual failures and continues when continueOnError is true", async () => {
      const badBlob = { size: 0, type: "text/plain" } as unknown as Blob;
      const files = [
        { path: "bad.txt", blob: badBlob },
        {
          path: "good.txt",
          blob: new Blob(["good content"], { type: "text/plain" }),
        },
      ];

      await expect(
        MajikSignature.signBatchDetached(files, keyA),
      ).rejects.toThrow(/Batch signing failed on "bad.txt"/i);

      const continued = await MajikSignature.signBatchDetached(files, keyA, {
        continueOnError: true,
      });
      expect(continued.mode).toBe("map");
      if (continued.mode !== "map") throw new Error("Expected map mode");
      expect(continued.failures).toHaveLength(1);
      expect(continued.failures[0].path).toBe("bad.txt");
      expect(continued.map.hasEntry("good.txt")).toBe(true);
      expect(continued.map.hasEntry("bad.txt")).toBe(false);
    });

    it("rejects empty and duplicate-path batches before signing", async () => {
      await expect(MajikSignature.signBatchDetached([], keyA)).rejects.toThrow(
        /Batch must contain at least one file/i,
      );

      await expect(
        MajikSignature.signBatchDetached(
          [
            { path: "duplicate.txt", blob: new Blob(["one"]) },
            { path: "duplicate.txt", blob: new Blob(["two"]) },
          ],
          keyA,
        ),
      ).rejects.toThrow(/Duplicate path in batch/i);
    });
  });

  // ─── DETACHED TIMESTAMP / EXPIRY / ORDER ────────────────────────────────────

  describe("Detached expiry and chronological order", () => {
    const SIGNED_AT = "2026-06-01T00:00:00.000Z";
    const BEFORE_EXPIRY = new Date("2026-06-15T00:00:00.000Z");
    const EXPIRY = "2026-07-01T00:00:00.000Z";
    const AFTER_EXPIRY = new Date("2026-07-02T00:00:00.000Z");

    it("honors validUntil before and after expiry during detached verification", async () => {
      const original = new Blob(["detached expiring content"], {
        type: "text/plain",
      });
      const { blob, envelope } = await MajikSignature.signFileDetached(
        original,
        keyA,
        { contentType: "text/plain", timestamp: SIGNED_AT, validUntil: EXPIRY },
      );

      const before = await MajikSignature.verifyFileDetached(
        blob,
        envelope,
        keyA,
        { expectedSignerId: keyA.fingerprint, now: BEFORE_EXPIRY },
      );
      const after = await MajikSignature.verifyFileDetached(
        blob,
        envelope,
        keyA,
        { expectedSignerId: keyA.fingerprint, now: AFTER_EXPIRY },
      );

      expect(before[0].valid).toBe(true);
      expect(after[0].valid).toBe(false);
      expect(after[0].expired).toBe(true);
    });

    it("verifies detached signer order when signatures are appended in the expected sequence", async () => {
      const original = new Blob(["detached order test"], {
        type: "text/plain",
      });
      const first = await MajikSignature.signFileDetached(original, keyA, {
        contentType: "text/plain",
        timestamp: "2026-08-01T10:00:00.000Z",
      });
      const second = await MajikSignature.signFileDetached(first.blob, keyB, {
        contentType: "text/plain",
        timestamp: "2026-08-01T10:05:00.000Z",
        existingEnvelope: first.envelope,
      });

      const order = await MajikSignature.verifyFileDetachedOrder(
        second.blob,
        second.envelope,
        [keyA, keyB],
      );
      expect(order.valid).toBe(true);
      expect(order.allExpectedSigned).toBe(true);
      expect(order.orderRespected).toBe(true);
    });
  });

  // ─── REVISION-AWARE DETACHED SIGNING: priorFile ─────────────────────────────

  describe("Detached revision chains with priorFile", () => {
    const t1 = "2026-08-01T10:00:00.000Z";
    const t2 = "2026-08-01T10:05:00.000Z";

    it("lets an issuer establish an expected signer, then verifies a second signer after a PDF stamp modification", async () => {
      const originalPdf = asBlob(
        FILE_FIXTURES.find((fixture) => fixture.file === "sample.pdf")!,
      );
      const expectedSigners = [signerProfile(keyA), signerProfile(keyB)];

      // V1: the issuer signs the original PDF and establishes the signer allowlist.
      const issuer = await MajikSignature.signFileDetached(originalPdf, keyA, {
        contentType: "application/pdf",
        timestamp: t1,
        expectedSigners,
        message: "Issuer signed the original PDF",
      });
      const revision1 = issuer.blob;
      expect(issuer.envelope.hasAllowlist()).toBe(true);
      expect(issuer.envelope.signatures).toHaveLength(1);

      // V2: the second signer applies a simulated stamp. priorFile is the exact
      // detached content corresponding to the existing envelope before stamping.
      const stampedRevision2 = await simulatePdfStamp(revision1, 1);
      const secondSigner = await MajikSignature.signFileDetached(
        stampedRevision2,
        keyB,
        {
          contentType: "application/pdf",
          timestamp: t2,
          existingEnvelope: issuer.envelope,
          priorFile: revision1,
          message: "Second signer added a stamp",
        },
      );

      expect(secondSigner.envelope.signatures).toHaveLength(2);
      expect(secondSigner.envelope.fileVersions).toHaveLength(2);
      expect(secondSigner.envelope.signatures[1].signerId).toBe(
        keyB.fingerprint,
      );
      expect(new Uint8Array(await secondSigner.blob.arrayBuffer())).not.toEqual(
        new Uint8Array(await revision1.arrayBuffer()),
      );

      // Verify the latest signature directly against V2, then verify the entire
      // detached chain. The issuer's historical signature is over V1 bytes, so
      // it is checked as a cryptographic commitment rather than against V2 bytes.
      const latestResult = await MajikSignature.verifyFileDetached(
        secondSigner.blob,
        secondSigner.envelope,
        keyB,
        { expectedSignerId: keyB.fingerprint },
      );
      expect(latestResult[0].valid).toBe(true);

      const chainResult = await MajikSignature.verifyFileDetachedChain(
        secondSigner.blob,
        secondSigner.envelope,
      );
      expect(chainResult.chainValid).toBe(true);
      expect(chainResult.latest.valid).toBe(true);
      expect(chainResult.latest.signerId).toBe(keyB.fingerprint);
      expect(chainResult.history).toHaveLength(1);
      expect(chainResult.history[0].valid).toBe(true);
      expect(chainResult.history[0].signerId).toBe(keyA.fingerprint);
    });

    it("supports up to five allowlisted signers, each modifying the PDF before signing, and verifies every revision", async () => {
      const signers = [keyA, keyB, keyC, keyD, keyE];
      const expectedSigners = signers.map(signerProfile);
      const originalPdf = asBlob(
        FILE_FIXTURES.find((fixture) => fixture.file === "sample.pdf")!,
      );

      // The issuer creates the initial detached signature and allowlist.
      const issuer = await MajikSignature.signFileDetached(
        originalPdf,
        signers[0],
        {
          contentType: "application/pdf",
          timestamp: "2026-08-01T10:00:00.000Z",
          expectedSigners,
          message: "Signer 1: issuer signature",
        },
      );

      let currentFile = issuer.blob;
      let currentEnvelope = issuer.envelope;
      expect(currentEnvelope.hasAllowlist()).toBe(true);

      // Each subsequent signer starts from the last revision, changes its bytes
      // to represent a stamp, and supplies the unmodified previous revision via
      // priorFile so the library can validate and extend the existing chain.
      for (let i = 1; i < signers.length; i++) {
        const previousFile = currentFile;
        const stampedFile = await simulatePdfStamp(previousFile, i);
        const minute = String(i * 5).padStart(2, "0");
        const result = await MajikSignature.signFileDetached(
          stampedFile,
          signers[i],
          {
            contentType: "application/pdf",
            timestamp: `2026-08-01T10:${minute}:00.000Z`,
            existingEnvelope: currentEnvelope,
            priorFile: previousFile,
            message: `Signer ${i + 1}: simulated stamp`,
          },
        );

        expect(result.envelope.signatures).toHaveLength(i + 1);
        expect(result.envelope.fileVersions).toHaveLength(i + 1);
        expect(
          result.envelope.signatures.some(
            (signature) => signature.signerId === signers[i].fingerprint,
          ),
        ).toBe(true);

        // Confirm each transition changed the file bytes and left a valid chain.
        expect(new Uint8Array(await result.blob.arrayBuffer())).not.toEqual(
          new Uint8Array(await previousFile.arrayBuffer()),
        );
        const chain = await MajikSignature.verifyFileDetachedChain(
          result.blob,
          result.envelope,
        );
        expect(chain.chainValid).toBe(true);
        expect(chain.latest.valid).toBe(true);
        expect(chain.latest.signerId).toBe(signers[i].fingerprint);
        expect(chain.history).toHaveLength(i);
        expect(chain.history.every((entry) => entry.valid)).toBe(true);

        currentFile = result.blob;
        currentEnvelope = result.envelope;
      }

      expect(currentEnvelope.signatures).toHaveLength(5);
      expect(currentEnvelope.fileVersions).toHaveLength(5);

      // A final full-chain check makes the end state explicit as well.
      const finalChain = await MajikSignature.verifyFileDetachedChain(
        currentFile,
        currentEnvelope,
      );
      expect(finalChain.chainValid).toBe(true);
      expect(finalChain.latest.valid).toBe(true);
      expect(finalChain.history).toHaveLength(4);
      expect(finalChain.history.every((entry) => entry.valid)).toBe(true);
    });

    it("rejects extending a detached revision chain when priorFile does not match the existing envelope", async () => {
      const originalPdf = asBlob(
        FILE_FIXTURES.find((fixture) => fixture.file === "sample.pdf")!,
      );
      const first = await MajikSignature.signFileDetached(originalPdf, keyA, {
        contentType: "application/pdf",
      });
      const unrelatedPriorFile = new Blob(["not the signed PDF revision"], {
        type: "application/pdf",
      });
      const stamped = await simulatePdfStamp(originalPdf, 1);

      await expect(
        MajikSignature.signFileDetached(stamped, keyB, {
          contentType: "application/pdf",
          existingEnvelope: first.envelope,
          priorFile: unrelatedPriorFile,
        }),
      ).rejects.toThrow(/Refusing to build on priorFile/i);
    });

    it("rejects priorFile without an existing detached envelope", async () => {
      const originalPdf = asBlob(
        FILE_FIXTURES.find((fixture) => fixture.file === "sample.pdf")!,
      );
      const stamped = await simulatePdfStamp(originalPdf, 1);

      await expect(
        MajikSignature.signFileDetached(stamped, keyB, {
          contentType: "application/pdf",
          priorFile: originalPdf,
        }),
      ).rejects.toThrow(/priorFile requires existingEnvelope/i);
    });

    it("detects detached revision-chain metadata tampering", async () => {
      const originalPdf = asBlob(
        FILE_FIXTURES.find((fixture) => fixture.file === "sample.pdf")!,
      );
      const first = await MajikSignature.signFileDetached(originalPdf, keyA, {
        contentType: "application/pdf",
        expectedSigners: [signerProfile(keyA), signerProfile(keyB)],
      });
      const revision2 = await simulatePdfStamp(first.blob, 1);
      const second = await MajikSignature.signFileDetached(revision2, keyB, {
        contentType: "application/pdf",
        existingEnvelope: first.envelope,
        priorFile: first.blob,
        message: "original audit note",
      });

      const originalJson = second.envelope.toJSON();
      const fileVersions = [...(originalJson.fileVersions ?? [])];
      expect(fileVersions.length).toBe(2);
      const firstVersion = fileVersions[0];
      if (!firstVersion) throw new Error("Expected the first file version");
      fileVersions[0] = { ...firstVersion, message: "forged audit note" };
      const tamperedEnvelope = MajikSignatureEnvelope.fromJSON({
        ...originalJson,
        fileVersions,
      });

      const verification = await MajikSignature.verifyFileDetachedChain(
        second.blob,
        tamperedEnvelope,
      );
      expect(verification.chainValid).toBe(false);
    });
  });
});

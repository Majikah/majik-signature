import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { MajikKey } from "@majikah/majik-key";

import { MajikSignature } from "../src/majik-signature";
import { MajikSignatureMap } from "../src/core/mjksmap";
import { MJKSMAP_MAGIC } from "../src/core/constants";

import { getTestKey } from "./helpers/crypto";

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const __currentDir = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__currentDir, "fixtures");

type FileFixture = {
  label: string;
  file: string;
  contentType: string;
};

type BatchFile = {
  path: string;
  blob: Blob;
};

/**
 * Real fixture corpus shared with the broader Majik Signature test suite.
 *
 * The .mjksmap format is intentionally file-type agnostic. This corpus gives
 * us coverage across text, images, audio, video, documents, executables, and
 * install/package formats.
 */
const FILE_FIXTURES: readonly FileFixture[] = [
  {
    label: "Plain Text",
    file: "sample.txt",
    contentType: "text/plain",
  },
  {
    label: "WEBP Image",
    file: "sample.webp",
    contentType: "image/webp",
  },
  {
    label: "PNG Image",
    file: "sample.png",
    contentType: "image/png",
  },
  {
    label: "JPEG Image",
    file: "sample.jpg",
    contentType: "image/jpeg",
  },
  {
    label: "MP4 Video",
    file: "sample.mp4",
    contentType: "video/mp4",
  },
  {
    label: "MOV Video",
    file: "sample.mov",
    contentType: "video/quicktime",
  },
  {
    label: "MKV Video",
    file: "sample.mkv",
    contentType: "video/x-matroska",
  },
  {
    label: "WAV Audio",
    file: "sample.wav",
    contentType: "audio/wav",
  },
  {
    label: "FLAC Audio",
    file: "sample.flac",
    contentType: "audio/flac",
  },
  {
    label: "MP3 Audio",
    file: "sample.mp3",
    contentType: "audio/mpeg",
  },
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
  {
    label: "CSV File",
    file: "sample.csv",
    contentType: "text/csv",
  },
  {
    label: "PDF Document",
    file: "sample.pdf",
    contentType: "application/pdf",
  },
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

// ─────────────────────────────────────────────────────────────────────────────
// Fixture Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Load a real fixture from test/fixtures as raw bytes.
 */
function loadFixture(filename: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURES_DIR, filename)));
}

/**
 * Build the canonical detached batch payload for every real fixture.
 *
 * Important:
 * signBatchDetached() signs handler.strip(bytes), not necessarily the raw
 * bytes supplied by the caller. Some handlers (notably MP3 and Office formats)
 * canonicalize unsigned files as well.
 *
 * Therefore the test batch must use the same canonical bytes that detached
 * signing hashes. This also mirrors the clean Blob returned by signFileDetached().
 */
async function createFixtureBatch(): Promise<BatchFile[]> {
  return Promise.all(
    FILE_FIXTURES.map(async (fixture) => {
      const rawBlob = new Blob([loadFixture(fixture.file) as BlobPart], {
        type: fixture.contentType,
      });

      const canonicalBlob = await MajikSignature.stripFrom(rawBlob, {
        mimeType: fixture.contentType,
      });

      return {
        path: fixturePath(fixture),
        blob: canonicalBlob,
      };
    }),
  );
}

/**
 * Return the logical path used by the .mjksmap for a fixture.
 */
function fixturePath(fixture: FileFixture): string {
  return `fixtures/${fixture.file}`;
}

/**
 * Read a Blob into mutable bytes.
 */
async function blobBytes(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

/**
 * Produce a deliberately corrupted .mjksmap payload by modifying its first
 * byte. This should invalidate the MJKSMAP magic header.
 */
async function corruptMagic(blob: Blob): Promise<Uint8Array> {
  const bytes = await blobBytes(blob);

  if (bytes.length === 0) {
    throw new Error("Cannot corrupt an empty MJKSMAP payload");
  }

  bytes[0] ^= 0xff;

  return bytes;
}

/**
 * Assert that an entry exists and contains the metadata expected for a real
 * fixture.
 */
function expectFixtureEntry(
  map: MajikSignatureMap,
  fixture: FileFixture,
  blob: Blob,
): void {
  const path = fixturePath(fixture);
  const entry = map.getEntry(path);

  expect(entry, `Expected .mjksmap entry for ${path}`).toBeDefined();

  expect(entry?.path).toBe(path);
  expect(entry?.size).toBe(blob.size);
  expect(entry?.mimeType).toBe(fixture.contentType);

  expect(entry?.contentHash).toEqual(expect.any(String));
  expect(entry?.contentHash?.length).toBeGreaterThan(0);

  expect(entry?.envelope).toBeDefined();
}

/**
 * Assert that every result is verified.
 *
 * This deliberately provides diagnostic information when the assertion fails.
 * A generic `every(...) === true` assertion hides the file that actually
 * failed verification, which is especially painful when testing a large real
 * fixture corpus.
 */
function expectAllVerified(results: Array<any>): void {
  const failures = results.filter((result) => result.status !== "verified");

  if (failures.length > 0) {
    const diagnostics = failures.map((result) => ({
      path: result.path,
      status: result.status,
      relocatedFrom: result.relocatedFrom,
      verificationResults: result.results,
    }));

    throw new Error(
      [
        "Expected every file to verify successfully.",
        `Failed entries: ${failures.length}`,
        JSON.stringify(diagnostics, null, 2),
      ].join("\n"),
    );
  }

  expect(failures).toHaveLength(0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Suite
// ─────────────────────────────────────────────────────────────────────────────

describe("MajikSignatureMap (.mjksmap)", () => {
  let releaseKey: MajikKey;
  let unauthorizedKey: MajikKey;

  /**
   * Shared real fixture batch.
   */
  let signedFiles: BatchFile[];

  /**
   * Shared map and serialized .mjksmap container.
   *
   * PQ signing is intentionally performed once in beforeAll() rather than
   * repeatedly in individual tests.
   */
  let signedMap: MajikSignatureMap;
  let signedMapBlob: Blob;

  beforeAll(async () => {
    [releaseKey, unauthorizedKey] = await Promise.all([
      getTestKey(),
      getTestKey(),
    ]);

    signedFiles = await createFixtureBatch();

    const result = await MajikSignature.signBatchDetached(
      signedFiles,
      releaseKey,
      {
        mode: "map",
        continueOnError: false,
      },
    );

    expect(result.mode).toBe("map");

    if (result.mode !== "map") {
      throw new Error("Expected signBatchDetached() to return map mode");
    }

    expect(result.failures).toHaveLength(0);

    signedMap = result.map;
    signedMapBlob = result.mapBlob;
  }, 120000);

  // ===========================================================================
  // Core Map Operations
  // ===========================================================================

  describe("Core Map Operations", () => {
    it("creates an empty immutable map", () => {
      const map = MajikSignatureMap.empty();

      expect(map).toBeInstanceOf(MajikSignatureMap);
      expect(map.size).toBe(0);
      expect(map.isValid()).toBe(true);
    });

    it("adds entries immutably without mutating the original map", async () => {
      const sourceBlob = new Blob(["immutable map test"], {
        type: "text/plain",
      });

      const { envelope } = await MajikSignature.signFileDetached(
        sourceBlob,
        releaseKey,
        {
          contentType: "text/plain",
        },
      );

      const map0 = MajikSignatureMap.empty();

      const map1 = map0.withEntry({
        path: "docs/report.txt",
        contentHash: envelope.signatures[0].contentHash,
        size: sourceBlob.size,
        mimeType: "text/plain",
        envelope: envelope.toJSON(),
      });

      expect(map0.size).toBe(0);
      expect(map1.size).toBe(1);

      expect(map0.getEntry("docs/report.txt")).toBeUndefined();

      expect(map1.getEntry("docs/report.txt")).toBeDefined();
    });

    it("upserts an entry when the normalized path already exists", () => {
      let map = MajikSignatureMap.empty().withEntry({
        path: "docs/report.txt",
        contentHash: "hash-1",
        envelope: {
          version: 1,
          signatures: [],
        } as any,
      });

      map = map.withEntry({
        path: "docs/report.txt",
        contentHash: "hash-2",
        envelope: {
          version: 1,
          signatures: [],
        } as any,
      });

      expect(map.size).toBe(1);
      expect(map.getEntry("docs/report.txt")?.contentHash).toBe("hash-2");
    });

    it("normalizes Windows drive letters and path separators", () => {
      const map = MajikSignatureMap.empty().withEntry({
        path: "C:\\docs\\reports\\report.pdf",
        contentHash: "deadbeef",
        envelope: {
          version: 1,
          signatures: [],
        } as any,
      });

      expect(map.getEntry("docs/reports/report.pdf")).toBeDefined();

      expect(map.getEntry("docs\\reports\\report.pdf")).toBeDefined();

      expect(map.hasEntry("C:\\docs\\reports\\report.pdf")).toBe(true);

      expect(map.size).toBe(1);
    });

    it("treats differently formatted versions of the same path as one key", () => {
      let map = MajikSignatureMap.empty().withEntry({
        path: "C:\\docs\\a.txt",
        contentHash: "hash-1",
        envelope: {
          version: 1,
          signatures: [],
        } as any,
      });

      map = map.withEntry({
        path: "docs/a.txt",
        contentHash: "hash-2",
        envelope: {
          version: 1,
          signatures: [],
        } as any,
      });

      expect(map.size).toBe(1);
      expect(map.getEntry("docs/a.txt")?.contentHash).toBe("hash-2");
    });

    it("removes an entry without affecting unrelated entries", () => {
      const map = MajikSignatureMap.empty()
        .withEntry({
          path: "a.txt",
          contentHash: "hash-a",
          envelope: {
            version: 1,
            signatures: [],
          } as any,
        })
        .withEntry({
          path: "b.txt",
          contentHash: "hash-b",
          envelope: {
            version: 1,
            signatures: [],
          } as any,
        });

      const derived = map.withoutEntry("a.txt");

      expect(map.size).toBe(2);
      expect(derived.size).toBe(1);

      expect(derived.hasEntry("a.txt")).toBe(false);
      expect(derived.hasEntry("b.txt")).toBe(true);

      // Original map remains untouched.
      expect(map.hasEntry("a.txt")).toBe(true);
      expect(map.hasEntry("b.txt")).toBe(true);
    });
  });

  // ===========================================================================
  // Real Fixture Coverage
  // ===========================================================================

  describe("Real Fixture Coverage", () => {
    it("contains one entry for every real fixture in the signed batch", () => {
      expect(signedMap.size).toBe(FILE_FIXTURES.length);

      for (let index = 0; index < FILE_FIXTURES.length; index += 1) {
        const fixture = FILE_FIXTURES[index];
        const file = signedFiles[index];

        expectFixtureEntry(signedMap, fixture, file.blob);
      }
    });

    it("preserves MIME type and byte size for every fixture", () => {
      for (let index = 0; index < FILE_FIXTURES.length; index += 1) {
        const fixture = FILE_FIXTURES[index];
        const file = signedFiles[index];

        const entry = signedMap.getEntry(file.path);

        expect(entry).toBeDefined();
        expect(entry?.size).toBe(file.blob.size);
        expect(entry?.mimeType).toBe(fixture.contentType);
      }
    });

    it("stores content hashes and signature envelopes for every fixture", () => {
      for (const fixture of FILE_FIXTURES) {
        const entry = signedMap.getEntry(fixturePath(fixture));

        expect(entry).toBeDefined();

        expect(entry?.contentHash).toEqual(expect.any(String));

        expect(entry?.contentHash.length).toBeGreaterThan(0);

        expect(entry?.envelope).toBeDefined();
      }
    });

    it("covers dedicated-handler and container formats without dropping them", () => {
      const dedicatedFormats = [
        "sample.docx",
        "sample.xlsx",
        "sample.pdf",
        "sample.exe",
        "sample.msix",
        "sample.deb",
        "sample.msi",
      ];

      for (const filename of dedicatedFormats) {
        expect(
          signedMap.hasEntry(`fixtures/${filename}`),
          `Missing .mjksmap entry for ${filename}`,
        ).toBe(true);
      }
    });
  });

  // ===========================================================================
  // Lookup & Resolution
  // ===========================================================================

  describe("Lookup & Resolution", () => {
    it("gets entries using normalized paths", () => {
      const fixture = FILE_FIXTURES[0];

      const logicalPath = fixturePath(fixture);
      const windowsPath = logicalPath.replaceAll("/", "\\");

      expect(signedMap.getEntry(logicalPath)).toBeDefined();

      expect(signedMap.getEntry(windowsPath)).toBeDefined();

      expect(signedMap.hasEntry(windowsPath)).toBe(true);
    });

    it("returns undefined and false for an unknown path", () => {
      const unknownPath = "fixtures/does-not-exist.bin";

      expect(signedMap.getEntry(unknownPath)).toBeUndefined();

      expect(signedMap.hasEntry(unknownPath)).toBe(false);
    });

    it("finds an entry and confirms the content hash for an unmodified file", async () => {
      const file = signedFiles[0];

      const result = await signedMap.findEntry(file.path, file.blob);

      expect(result.found).toBe(true);
      expect(result.hashMatches).toBe(true);
    });

    it("finds an entry but reports a hash mismatch for tampered content", async () => {
      const file = signedFiles[0];

      const bytes = await blobBytes(file.blob);

      bytes[0] ^= 0xff;

      const tamperedBlob = new Blob([bytes as BlobPart], {
        type: file.blob.type,
      });

      const result = await signedMap.findEntry(file.path, tamperedBlob);

      expect(result.found).toBe(true);
      expect(result.hashMatches).toBe(false);
    });

    it("reports not found when both path and content are unknown", async () => {
      const unrelated = new Blob(["totally unrelated content"], {
        type: "text/plain",
      });

      const result = await signedMap.findEntry(
        "fixtures/unknown.txt",
        unrelated,
      );

      expect(result.found).toBe(false);
    });

    it("resolves an unchanged file as path_match", async () => {
      const file = signedFiles[0];

      const result = await signedMap.resolveEntry(file.path, file.blob);

      expect(result.status).toBe("path_match");
    });

    it("resolves a relocated file by content", async () => {
      const file = signedFiles[0];

      const result = await signedMap.resolveEntry(
        "relocated/sample.txt",
        file.blob,
      );

      expect(result.status).toBe("relocated");
      expect(result.originalPath).toBe(file.path);
    });

    it("resolves same-path modified content as path_tampered", async () => {
      const file = signedFiles[0];

      const bytes = await blobBytes(file.blob);

      bytes[bytes.length - 1] ^= 0xff;

      const tamperedBlob = new Blob([bytes as BlobPart], {
        type: file.blob.type,
      });

      const result = await signedMap.resolveEntry(file.path, tamperedBlob);

      expect(result.status).toBe("path_tampered");
    });

    it("resolves an unrelated file as not_found", async () => {
      const unrelated = new Blob(["unrelated content for resolveEntry"], {
        type: "text/plain",
      });

      const result = await signedMap.resolveEntry(
        "unknown/location.txt",
        unrelated,
      );

      expect(result.status).toBe("not_found");
    });

    it("finds entries by content hash regardless of path", async () => {
      const original = signedFiles[0];

      const duplicateBlob = new Blob([await original.blob.arrayBuffer()], {
        type: original.blob.type,
      });

      const entries = await signedMap.findEntriesByHash(duplicateBlob);

      expect(entries).toHaveLength(1);
      expect(entries[0].path).toBe(original.path);
    });
  });

  // ===========================================================================
  // JSON Serialization
  // ===========================================================================

  describe("JSON Serialization", () => {
    it("round-trips through toJSON/fromJSON", () => {
      const json = signedMap.toJSON();

      const restored = MajikSignatureMap.fromJSON(json);

      expect(restored).toBeInstanceOf(MajikSignatureMap);

      expect(restored.size).toBe(signedMap.size);

      expect(restored.isValid()).toBe(true);
      expect(restored.toJSON()).toEqual(json);
    });

    it("preserves every signed entry through JSON serialization", () => {
      const restored = MajikSignatureMap.fromJSON(signedMap.toJSON());

      for (const fixture of FILE_FIXTURES) {
        const path = fixturePath(fixture);

        expect(restored.getEntry(path)).toEqual(signedMap.getEntry(path));
      }
    });
  });

  // ===========================================================================
  // Binary .mjksmap Serialization
  // ===========================================================================

  describe("Binary .mjksmap Serialization", () => {
    it("serializes to a non-empty Blob", () => {
      expect(signedMapBlob).toBeInstanceOf(Blob);

      expect(signedMapBlob.size).toBeGreaterThan(0);
    });

    it("starts with the canonical MJKSMAP magic bytes", async () => {
      const bytes = await blobBytes(signedMapBlob);

      expect(Array.from(bytes.slice(0, MJKSMAP_MAGIC.length))).toEqual(
        MJKSMAP_MAGIC,
      );
    });

    it("is recognized by isMJKSMAP() from both Blob and byte input", async () => {
      expect(await MajikSignatureMap.isMJKSMAP(signedMapBlob)).toBe(true);

      const bytes = await blobBytes(signedMapBlob);

      expect(await MajikSignatureMap.isMJKSMAP(bytes)).toBe(true);
    });

    it("rejects unrelated bytes as an .mjksmap container", async () => {
      const unrelated = new TextEncoder().encode(
        "this is not a majik signature map",
      );

      expect(await MajikSignatureMap.isMJKSMAP(unrelated)).toBe(false);
    });

    it("rejects a payload with an invalid magic header", async () => {
      const corrupted = await corruptMagic(signedMapBlob);

      expect(await MajikSignatureMap.isMJKSMAP(corrupted)).toBe(false);

      await expect(
        MajikSignatureMap.fromMJKSMAP(new Blob([corrupted as BlobPart])),
      ).rejects.toThrow();
    });

    it("round-trips the complete map through binary serialization", async () => {
      const restored = await MajikSignatureMap.fromMJKSMAP(signedMapBlob);

      expect(restored).toBeInstanceOf(MajikSignatureMap);

      expect(restored.size).toBe(signedMap.size);

      expect(restored.isValid()).toBe(true);

      for (const fixture of FILE_FIXTURES) {
        const path = fixturePath(fixture);

        const original = signedMap.getEntry(path);

        const restoredEntry = restored.getEntry(path);

        expect(restoredEntry).toBeDefined();

        expect(restoredEntry?.contentHash).toBe(original?.contentHash);
      }
    });

    it("preserves verification capability after binary round-trip", async () => {
      const restored = await MajikSignatureMap.fromMJKSMAP(signedMapBlob);

      const results = await MajikSignature.verifyFilesFromMjksMapWithKey(
        restored,
        signedFiles,
        releaseKey,
        {
          expectedSignerId: releaseKey.fingerprint,
          requireAllPresent: true,
        },
      );

      expect(results).toHaveLength(FILE_FIXTURES.length);

      expectAllVerified(results);

      const summary = MajikSignature.summarizeBatchVerification(results);

      expect(summary.allValid).toBe(true);
      expect(summary.verified).toBe(FILE_FIXTURES.length);
      expect(summary.invalid).toBe(0);
      expect(summary.tampered).toBe(0);
      expect(summary.total).toBe(FILE_FIXTURES.length);
    });

    it("throws when attempting to parse completely invalid binary data", async () => {
      const corruptBlob = new Blob([new Uint8Array([0x00, 0x11, 0x22, 0x33])]);

      await expect(
        MajikSignatureMap.fromMJKSMAP(corruptBlob),
      ).rejects.toThrow();
    });

    it("throws when parsing an empty blob", async () => {
      const emptyBlob = new Blob([]);

      expect(await MajikSignatureMap.isMJKSMAP(emptyBlob)).toBe(false);

      await expect(MajikSignatureMap.fromMJKSMAP(emptyBlob)).rejects.toThrow();
    });
  });

  // ===========================================================================
  // Batch Signing
  // ===========================================================================

  describe("Batch Signing", () => {
    it("signs the complete real fixture corpus in map mode", () => {
      expect(signedMap).toBeInstanceOf(MajikSignatureMap);

      expect(signedMap.size).toBe(FILE_FIXTURES.length);
    });

    it("creates a signed envelope for every map entry", () => {
      for (const fixture of FILE_FIXTURES) {
        const envelope = signedMap.getEnvelope(fixturePath(fixture));

        expect(envelope).not.toBeNull();
      }
    });

    it("does not silently drop dedicated-handler formats", () => {
      const handlerSensitiveFixtures = [
        "sample.docx",
        "sample.xlsx",
        "sample.pdf",
        "sample.exe",
        "sample.msix",
        "sample.deb",
        "sample.msi",
      ];

      for (const filename of handlerSensitiveFixtures) {
        expect(
          signedMap.hasEntry(`fixtures/${filename}`),
          `Missing map entry for ${filename}`,
        ).toBe(true);
      }
    });

    it("creates exactly one logical map entry for each signed input", () => {
      const paths = signedFiles.map((file) => file.path);

      const uniquePaths = new Set(paths);

      expect(uniquePaths.size).toBe(signedFiles.length);

      expect(signedMap.size).toBe(uniquePaths.size);
    });
  });

  // ===========================================================================
  // Batch Verification
  // ===========================================================================

  describe("Batch Verification", () => {
    it("verifies every unmodified file with the original signer", async () => {
      const results = await MajikSignature.verifyFilesFromMjksMapWithKey(
        signedMap,
        signedFiles,
        releaseKey,
        {
          expectedSignerId: releaseKey.fingerprint,
          requireAllPresent: true,
        },
      );

      expect(results).toHaveLength(FILE_FIXTURES.length);

      expectAllVerified(results);

      const summary = MajikSignature.summarizeBatchVerification(results);

      expect(summary.allValid).toBe(true);
      expect(summary.verified).toBe(FILE_FIXTURES.length);
      expect(summary.invalid).toBe(0);
      expect(summary.tampered).toBe(0);
      expect(summary.total).toBe(FILE_FIXTURES.length);
    });

    it("verifies correctly when public keys are resolved explicitly", async () => {
      const publicKeys = MajikSignature.publicKeysFromMajikKey(releaseKey);

      const results = await MajikSignature.verifyFilesFromMjksMap(
        signedMap,
        signedFiles,
        publicKeys,
      );

      expect(results).toHaveLength(FILE_FIXTURES.length);

      expectAllVerified(results);
    });

    it("detects tampering in one fixture while preserving verification of the others", async () => {
      const tamperedFiles = [...signedFiles];

      const targetIndex = tamperedFiles.findIndex(
        (file) => file.path === "fixtures/sample.pdf",
      );

      expect(targetIndex).toBeGreaterThanOrEqual(0);

      const target = tamperedFiles[targetIndex];

      const bytes = await blobBytes(target.blob);

      bytes[Math.floor(bytes.length / 2)] ^= 0xff;

      tamperedFiles[targetIndex] = {
        path: target.path,
        blob: new Blob([bytes as BlobPart], {
          type: target.blob.type,
        }),
      };

      const results = await MajikSignature.verifyFilesFromMjksMapWithKey(
        signedMap,
        tamperedFiles,
        releaseKey,
      );

      const tamperedResult = results.find(
        (result) => result.path === target.path,
      );

      expect(tamperedResult).toBeDefined();

      // This is the established batch-verification contract.
      expect(tamperedResult?.status).toBe("tampered");

      const verifiedOthers = results.filter(
        (result) => result.path !== target.path && result.status === "verified",
      );

      expect(verifiedOthers.length).toBe(FILE_FIXTURES.length - 1);

      const summary = MajikSignature.summarizeBatchVerification(results);

      expect(summary.allValid).toBe(false);
      expect(summary.tampered).toBe(1);
      expect(summary.verified).toBe(FILE_FIXTURES.length - 1);
      expect(summary.total).toBe(FILE_FIXTURES.length);
    });

    it("reports not_in_map for an extra file absent from the .mjksmap", async () => {
      const verifyFiles: BatchFile[] = [
        ...signedFiles,
        {
          path: "fixtures/untracked-extra.bin",
          blob: new Blob(["this file was never signed"], {
            type: "application/octet-stream",
          }),
        },
      ];

      const results = await MajikSignature.verifyFilesFromMjksMapWithKey(
        signedMap,
        verifyFiles,
        releaseKey,
      );

      const extraResult = results.find(
        (result) => result.path === "fixtures/untracked-extra.bin",
      );

      expect(extraResult).toBeDefined();

      // Established status in the main batch verification suite.
      expect(extraResult?.status).toBe("not_in_map");
    });
    it("throws when an input file is absent from the signature map and requireAllPresent is enabled", async () => {
      const extraFile: BatchFile = {
        path: "fixtures/untracked-extra.bin",
        blob: new Blob(["this file was never signed"], {
          type: "application/octet-stream",
        }),
      };

      await expect(
        MajikSignature.verifyFilesFromMjksMapWithKey(
          signedMap,
          [...signedFiles, extraFile],
          releaseKey,
          {
            requireAllPresent: true,
          },
        ),
      ).rejects.toThrow(/was not found in the signature map/);
    });

    it("verifies all supplied files when requireAllPresent is disabled and a map entry is omitted", async () => {
      const incompleteFiles = signedFiles.filter(
        (file) => file.path !== "fixtures/sample.msi",
      );

      const results = await MajikSignature.verifyFilesFromMjksMapWithKey(
        signedMap,
        incompleteFiles,
        releaseKey,
        {
          requireAllPresent: false,
        },
      );

      expect(results).toHaveLength(FILE_FIXTURES.length - 1);

      expectAllVerified(results);

      expect(
        results.some((result) => result.path === "fixtures/sample.msi"),
      ).toBe(false);
    });

    it("rejects verification against an unauthorized MajikKey", async () => {
      const results = await MajikSignature.verifyFilesFromMjksMapWithKey(
        signedMap,
        signedFiles,
        unauthorizedKey,
        {
          expectedSignerId: unauthorizedKey.fingerprint,
        },
      );

      const summary = MajikSignature.summarizeBatchVerification(results);

      expect(summary.allValid).toBe(false);
      expect(summary.verified).toBe(0);
    });
  });

  // ===========================================================================
  // Batch Verification & Relocation
  // ===========================================================================

  describe("Batch Verification & Relocation", () => {
    it("verifies a file after it moves to another logical path", async () => {
      const relocatedFiles: BatchFile[] = [
        {
          path: "relocated/sample.txt",
          blob: signedFiles[0].blob,
        },
        ...signedFiles.slice(1),
      ];

      const results = await MajikSignature.verifyFilesFromMjksMap(
        signedMap,
        relocatedFiles,
        MajikSignature.publicKeysFromMajikKey(releaseKey),
      );

      const relocatedResult = results.find(
        (result) => result.path === "relocated/sample.txt",
      );

      expect(relocatedResult?.status).toBe("verified");

      expect(relocatedResult?.relocatedFrom).toBe("fixtures/sample.txt");
    });

    it("resolves a relocated file against its original map entry", async () => {
      const original = signedFiles[0];

      const result = await signedMap.resolveEntry(
        "relocated/sample.txt",
        original.blob,
      );

      expect(result.status).toBe("relocated");

      expect(result.originalPath).toBe(original.path);
    });
  });

  // ===========================================================================
  // Map Integrity & Invariants
  // ===========================================================================

  describe("Map Integrity & Invariants", () => {
    it("is structurally valid immediately after signing", () => {
      expect(signedMap.isValid()).toBe(true);
    });

    it("contains one unique entry per logical path", () => {
      const paths = signedFiles.map((file) => file.path);

      const uniquePaths = new Set(paths);

      expect(uniquePaths.size).toBe(paths.length);

      expect(signedMap.size).toBe(uniquePaths.size);

      for (const path of uniquePaths) {
        expect(signedMap.hasEntry(path)).toBe(true);
      }
    });

    it("does not mutate when deriving a map without one entry", () => {
      const originalSize = signedMap.size;

      const derived = signedMap.withoutEntry("fixtures/sample.txt");

      expect(signedMap.size).toBe(originalSize);

      expect(derived.size).toBe(originalSize - 1);

      expect(signedMap.hasEntry("fixtures/sample.txt")).toBe(true);

      expect(derived.hasEntry("fixtures/sample.txt")).toBe(false);
    });

    it("can reconstruct every envelope from the map", () => {
      const envelopes = signedMap.getAllEnvelopes();

      expect(envelopes).toHaveLength(FILE_FIXTURES.length);

      for (const item of envelopes) {
        expect(item.path).toEqual(expect.any(String));

        expect(item.envelope).toBeDefined();
      }
    });
  });

  //   describe("Canonical Fixture Preparation", () => {
  //     it("uses canonical detached bytes for every fixture", async () => {
  //       const canonicalBatch = await createFixtureBatch();

  //       expect(canonicalBatch).toHaveLength(FILE_FIXTURES.length);

  //       for (let index = 0; index < FILE_FIXTURES.length; index += 1) {
  //         const fixture = FILE_FIXTURES[index];
  //         const canonical = canonicalBatch[index];

  //         const rawBlob = new Blob([loadFixture(fixture.file) as BlobPart], {
  //           type: fixture.contentType,
  //         });

  //         const expectedCanonical = await MajikSignature.stripFrom(rawBlob, {
  //           mimeType: fixture.contentType,
  //         });

  //         expect(canonical.path).toBe(fixturePath(fixture));

  //         expect(canonical.blob.size).toBe(expectedCanonical.size);

  //         expect(new Uint8Array(await canonical.blob.arrayBuffer())).toEqual(
  //           new Uint8Array(await expectedCanonical.arrayBuffer()),
  //         );
  //       }
  //     });
  //   });
});

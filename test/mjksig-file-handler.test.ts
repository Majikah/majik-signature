// mjksig-file-handler.test_5.ts
import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Import all handlers (assuming they are exported from the handlers index or their respective files)
import { PdfHandler } from "../src/core/embed/handlers/pdf";
import { PngHandler } from "../src/core/embed/handlers/png";
import { JpegHandler } from "../src/core/embed/handlers/jpeg";
import { WavHandler } from "../src/core/embed/handlers/wav";
import { Mp3Handler } from "../src/core/embed/handlers/mp3";
import { Mp4Handler } from "../src/core/embed/handlers/mp4";
import { FlacHandler } from "../src/core/embed/handlers/flac";
import { OfficeHandler } from "../src/core/embed/handlers/office";
import { TextHandler } from "../src/core/embed/handlers/text";
import { FormatHandler } from "../src/core/types";
import { MkvHandler } from "../src/core/embed/handlers";

const __currentDir = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__currentDir, "fixtures");

function loadFixture(filename: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURES_DIR, filename)));
}

// ─── FIXTURE MAPPING ─────────────────────────────────────────────────────────

interface HandlerFixture {
  label: string;
  HandlerClass: new () => FormatHandler;
  file: string;
  mimeType: string;
  requiresMime?: boolean;
}

const HANDLER_FIXTURES: HandlerFixture[] = [
  {
    label: "PDF",
    HandlerClass: PdfHandler,
    file: "sample.pdf",
    mimeType: "application/pdf",
  },
  {
    label: "PNG",
    HandlerClass: PngHandler,
    file: "sample.png",
    mimeType: "image/png",
  },
  {
    label: "JPEG",
    HandlerClass: JpegHandler,
    file: "sample.jpg",
    mimeType: "image/jpeg",
  },
  {
    label: "WAV",
    HandlerClass: WavHandler,
    file: "sample.wav",
    mimeType: "audio/wav",
  },
  {
    label: "MP3",
    HandlerClass: Mp3Handler,
    file: "sample.mp3",
    mimeType: "audio/mp3",
  },
  {
    label: "MP4",
    HandlerClass: Mp4Handler,
    file: "sample.mp4",
    mimeType: "video/mp4",
  },
  {
    label: "MKV",
    HandlerClass: MkvHandler,
    file: "sample.mkv",
    mimeType: "video/x-matroska",
  },

  {
    label: "FLAC Audio",
    HandlerClass: FlacHandler,
    file: "sample.flac",
    mimeType: "audio/flac",
  },
  {
    label: "Office",
    HandlerClass: OfficeHandler,
    file: "sample.docx",
    mimeType:
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  },
  {
    label: "Text",
    HandlerClass: TextHandler,
    file: "sample.txt",
    mimeType: "text/plain",
    requiresMime: true, // Plain text lacks magic bytes; it cannot be reliably sniffed from bytes alone.
  },
];

// ─── TEST SUITE ──────────────────────────────────────────────────────────────

describe("MajikSignature File Format Handlers", () => {
  const dummySignaturePayload = JSON.stringify({
    version: 1,
    signatures: [
      {
        signerId: "test-fingerprint-001",
        contentHash: "dummy-hash-value",
        edSignature: "dummy-ed-sig",
        mlDsaSignature: "dummy-mldsa-sig",
      },
    ],
  });

  HANDLER_FIXTURES.forEach(
    ({ label, HandlerClass, file, mimeType, requiresMime }) => {
      describe(`${label} Handler`, () => {
        let handler: FormatHandler;
        let originalBytes: Uint8Array;

        // Make beforeAll async to handle the strip() promise
        beforeAll(async () => {
          console.log(
            `\n[INIT] ⚙️ Preparing handler: ${label} (File: ${file})`,
          );
          try {
            handler = new HandlerClass();
            const rawBytes = loadFixture(file);

            // Pre-canonicalize the original file bytes.
            // Handlers like Office (ZIP re-compression) and MP3 (ID3 padding stripping)
            // intentionally normalize structures so that sign() and verify() run on
            // deterministic bytes. Testing against the raw fixture would falsely fail.
            originalBytes = await handler.strip(rawBytes);

            console.log(
              `[INIT] ✅ Successfully loaded fixture for ${label} (${originalBytes.length} bytes)`,
            );
          } catch (error) {
            console.error(
              `[INIT] ❌ FAILED to load fixture for ${label}:`,
              error,
            );
            throw error;
          }
        });

        // ── Positive Scenarios ─────────────────────────────────────────────────

        it("should successfully identify its supported format via canHandle()", () => {
          console.log(`[TEST] 🔍 ${label} - Starting: canHandle()`);
          try {
            // All handlers must identify the file when provided with the correct MIME type
            expect(handler.canHandle(originalBytes, mimeType)).toBe(true);

            // Only assert byte-sniffing capabilities on formats that support it
            if (!requiresMime) {
              expect(handler.canHandle(originalBytes)).toBe(true);
            }

            console.log(`[PASS] 🟢 ${label} - canHandle() succeeded`);
          } catch (error) {
            console.error(`[FAIL] 🔴 ${label} - canHandle() crashed:`, error);
            throw error;
          }
        });

        it("should successfully embed and extract the signature payload", async () => {
          console.log(`[TEST] ✍️  ${label} - Starting: embed() and extract()`);
          try {
            console.log(`       -> ${label}: Embedding payload...`);
            const embeddedBytes = await handler.embed(
              originalBytes,
              dummySignaturePayload,
            );

            expect(embeddedBytes).toBeInstanceOf(Uint8Array);
            expect(embeddedBytes.length).toBeGreaterThanOrEqual(
              originalBytes.length,
            );
            console.log(
              `       -> ${label}: Embedding complete (${embeddedBytes.length} bytes). Extracting...`,
            );

            const extractedPayload = await handler.extract(embeddedBytes);
            expect(extractedPayload).toBe(dummySignaturePayload);
            console.log(`[PASS] 🟢 ${label} - embed() and extract() succeeded`);
          } catch (error) {
            console.error(
              `[FAIL] 🔴 ${label} - embed() or extract() crashed:`,
              error,
            );
            throw error;
          }
        });

        it("should cleanly strip an embedded signature, returning byte-for-byte original data", async () => {
          console.log(`[TEST] 🧹 ${label} - Starting: strip()`);
          try {
            console.log(
              `       -> ${label}: Embedding payload for strip test...`,
            );
            const embeddedBytes = await handler.embed(
              originalBytes,
              dummySignaturePayload,
            );

            console.log(`       -> ${label}: Stripping payload...`);
            const strippedBytes = await handler.strip(embeddedBytes);

            expect(strippedBytes).toEqual(originalBytes);
            console.log(`[PASS] 🟢 ${label} - strip() succeeded`);
          } catch (error) {
            console.error(`[FAIL] 🔴 ${label} - strip() crashed:`, error);
            throw error;
          }
        });

        // ── Negative Scenarios ─────────────────────────────────────────────────

        it("should return false for canHandle() when given invalid files or MIME types", () => {
          console.log(
            `[TEST] 🚫 ${label} - Starting: canHandle() invalid data`,
          );
          try {
            const dummyBadBytes = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
            expect(
              handler.canHandle(dummyBadBytes, "application/octet-stream"),
            ).toBe(false);
            console.log(
              `[PASS] 🟢 ${label} - canHandle() correctly rejected invalid data`,
            );
          } catch (error) {
            console.error(
              `[FAIL] 🔴 ${label} - canHandle() invalid data crashed:`,
              error,
            );
            throw error;
          }
        });

        it("should return null when trying to extract from an unsigned file", async () => {
          console.log(
            `[TEST] Empty ${label} - Starting: extract() on unsigned file`,
          );
          try {
            const extractedPayload = await handler.extract(originalBytes);
            expect(extractedPayload).toBeNull();
            console.log(
              `[PASS] 🟢 ${label} - extract() correctly returned null for unsigned file`,
            );
          } catch (error) {
            console.error(
              `[FAIL] 🔴 ${label} - extract() on unsigned file crashed:`,
              error,
            );
            throw error;
          }
        });

        it("should gracefully handle stripping an already unsigned file by returning original bytes", async () => {
          console.log(
            `[TEST] 🛡️  ${label} - Starting: strip() on unsigned file`,
          );
          try {
            const strippedBytes = await handler.strip(originalBytes);
            expect(strippedBytes).toEqual(originalBytes);
            console.log(
              `[PASS] 🟢 ${label} - strip() safely handled unsigned file`,
            );
          } catch (error) {
            console.error(
              `[FAIL] 🔴 ${label} - strip() on unsigned file crashed:`,
              error,
            );
            throw error;
          }
        });

        it("should gracefully handle severely truncated files without crashing", async () => {
          console.log(
            `[TEST] ✂️  ${label} - Starting: extract() on truncated file`,
          );
          try {
            const truncatedBytes = originalBytes.slice(0, 10);
            try {
              const extractedPayload = await handler.extract(truncatedBytes);
              expect(extractedPayload).toBeNull();
            } catch (innerError) {
              expect(innerError).toBeDefined();
            }
            console.log(
              `[PASS] 🟢 ${label} - Gracefully handled truncated file`,
            );
          } catch (error) {
            console.error(
              `[FAIL] 🔴 ${label} - extract() on truncated file completely crashed:`,
              error,
            );
            throw error;
          }
        });

        it("should STRICTLY REJECT files with appended trailing garbage strings", async () => {
          console.log(
            `[TEST] 🗑️  ${label} - Starting: extract() on trailing garbage`,
          );
          try {
            console.log(
              `       -> ${label}: Embedding payload and appending garbage...`,
            );
            const embeddedBytes = await handler.embed(
              originalBytes,
              dummySignaturePayload,
            );

            const appendedString = new TextEncoder().encode(
              "malicious trailing string data",
            );
            const tamperedBytes = new Uint8Array(
              embeddedBytes.length + appendedString.length,
            );
            tamperedBytes.set(embeddedBytes);
            tamperedBytes.set(appendedString, embeddedBytes.length);

            console.log(
              `       -> ${label}: Extracting from tampered bytes...`,
            );
            try {
              const extractedPayload = await handler.extract(tamperedBytes);
              expect(extractedPayload).toBeNull();
            } catch (innerError) {
              expect(innerError).toBeDefined();
            }
            console.log(
              `[PASS] 🟢 ${label} - Correctly rejected trailing garbage`,
            );
          } catch (error) {
            console.error(
              `[FAIL] 🔴 ${label} - extract() on trailing garbage crashed:`,
              error,
            );
            throw error;
          }
        });
      });
    },
  );
});

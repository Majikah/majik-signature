import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_HASH_CHUNK_SIZE,
  MAX_HASH_CHUNK_SIZE,
  MIN_HASH_CHUNK_SIZE,
  validateHashChunkSize,
} from "../src/core/streaming/config.js";
import { hashSource } from "../src/core/streaming/sha256-stream.js";

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

function makePattern(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = (i * 31 + (i >>> 8) * 17 + 0x5a) & 0xff;
  }
  return bytes;
}

async function* repeatedSource(
  totalBytes: number,
  pattern: Uint8Array,
): AsyncGenerator<Uint8Array> {
  let remaining = totalBytes;
  while (remaining > 0) {
    const count = Math.min(remaining, pattern.byteLength);
    yield count === pattern.byteLength ? pattern : pattern.subarray(0, count);
    remaining -= count;
  }
}

function expectedDigest(totalBytes: number, pattern: Uint8Array): Uint8Array {
  const hash = createHash("sha256");
  let remaining = totalBytes;
  while (remaining > 0) {
    const count = Math.min(remaining, pattern.byteLength);
    hash.update(pattern.subarray(0, count));
    remaining -= count;
  }
  return new Uint8Array(hash.digest());
}

describe("streaming large-input stress and allocation boundaries", () => {
  it("keeps the shared defaults and supported chunk boundaries explicit", () => {
    expect(DEFAULT_HASH_CHUNK_SIZE).toBe(MiB);
    expect(MIN_HASH_CHUNK_SIZE).toBe(64 * 1024);
    expect(MAX_HASH_CHUNK_SIZE).toBe(64 * MiB);
    expect(() => validateHashChunkSize(MIN_HASH_CHUNK_SIZE)).not.toThrow();
    expect(() => validateHashChunkSize(MAX_HASH_CHUNK_SIZE)).not.toThrow();
    expect(() => validateHashChunkSize(MIN_HASH_CHUNK_SIZE - 1)).toThrow();
    expect(() => validateHashChunkSize(MAX_HASH_CHUNK_SIZE + 1)).toThrow();
    expect(() => validateHashChunkSize(Number.MAX_SAFE_INTEGER)).toThrow();
    expect(() => validateHashChunkSize(1.5)).toThrow();
    expect(() => validateHashChunkSize(Number.NaN)).toThrow();
  });

  it.each([64 * 1024, 256 * 1024, MiB, 4 * MiB, 16 * MiB])(
    "hashes a virtual 32 MiB + 37 byte source with chunkSize=%i without materializing it",
    async (chunkSize) => {
      const totalBytes = 32 * MiB + 37;
      const pattern = makePattern(MiB + 113);
      const expected = expectedDigest(totalBytes, pattern);
      let previousProgress = 0;

      const result = await hashSource(repeatedSource(totalBytes, pattern), {
        chunkSize,
        totalBytes,
        maxBytes: totalBytes,
        onProgress: ({ bytesProcessed, totalBytes: declared }) => {
          expect(bytesProcessed).toBeGreaterThan(previousProgress);
          expect(declared).toBe(totalBytes);
          expect(bytesProcessed).toBeLessThanOrEqual(totalBytes);
          previousProgress = bytesProcessed;
        },
      });

      expect(result.bytesProcessed).toBe(totalBytes);
      expect(result.totalBytes).toBe(totalBytes);
      expect(result.digest).toEqual(expected);
      expect(previousProgress).toBe(totalBytes);
    },
    120_000,
  );

  it("rejects invalid yielded chunks and cancels a failed ReadableStream cleanly", async () => {
    const invalid = {
      async *[Symbol.asyncIterator]() {
        yield "not-bytes" as unknown as Uint8Array;
      },
    };
    await expect(hashSource(invalid)).rejects.toThrow(/non-Uint8Array/i);

    let cancelCalled = false;
    let pullCount = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pullCount += 1;
        if (pullCount === 1) controller.enqueue(new Uint8Array(128 * 1024));
        else controller.error(new Error("synthetic read failure"));
      },
      cancel() {
        cancelCalled = true;
      },
    });

    await expect(hashSource(stream, { chunkSize: MIN_HASH_CHUNK_SIZE })).rejects.toThrow(
      /synthetic read failure/i,
    );
    expect(pullCount).toBeGreaterThanOrEqual(1);
    // A stream that has entered an errored state may reject cancel(); the
    // hashing code must still surface the original read failure without a hang.
    expect(cancelCalled).toBe(false);
  });

  it("actively cancels a ReadableStream after AbortSignal cancellation", async () => {
    const controller = new AbortController();
    let cancelCalled = false;
    let pulls = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(streamController) {
        pulls += 1;
        streamController.enqueue(new Uint8Array(128 * 1024, pulls & 0xff));
      },
      cancel() {
        cancelCalled = true;
      },
    });

    await expect(hashSource(stream, {
      chunkSize: MIN_HASH_CHUNK_SIZE,
      signal: controller.signal,
      onProgress: () => controller.abort("stress-test-cancel"),
    })).rejects.toThrow(/cancel/i);
    expect(pulls).toBeGreaterThanOrEqual(1);
    expect(cancelCalled).toBe(true);
  });

  const runLargeStress = process.env.MAJIK_RUN_LARGE_STRESS === "1";
  const largeStressBytes = Number(process.env.MAJIK_STRESS_BYTES ?? 10 * GiB);

  (runLargeStress ? it : it.skip)(
    "best-effort hashes a configurable virtual multi-gigabyte source (opt-in)",
    async () => {
      if (!Number.isSafeInteger(largeStressBytes) || largeStressBytes <= 0) {
        throw new Error("MAJIK_STRESS_BYTES must be a positive safe integer");
      }
      const pattern = makePattern(MiB);
      const expected = expectedDigest(largeStressBytes, pattern);
      const result = await hashSource(repeatedSource(largeStressBytes, pattern), {
        chunkSize: 8 * MiB,
        totalBytes: largeStressBytes,
        maxBytes: largeStressBytes,
      });
      expect(result.bytesProcessed).toBe(largeStressBytes);
      expect(result.digest).toEqual(expected);
    },
    30 * 60 * 1000,
  );
});

import { beforeAll, describe, expect, it } from "vitest";
import type { MajikKey } from "@majikah/majik-key";
import { getTestKey } from "./helpers/crypto.js";
import { MajikSignature } from "../src/majik-signature.js";
import { bytesToBase64, hashContent } from "../src/core/hash.js";
import {
  DEFAULT_HASH_CHUNK_SIZE,
  MAX_HASH_CHUNK_SIZE,
  MIN_HASH_CHUNK_SIZE,
  detectHashStrategy,
  hashSource,
} from "../src/core/streaming/index.js";

const MIB = 1024 * 1024;

async function* chunks(bytes: Uint8Array, size: number): AsyncGenerator<Uint8Array> {
  for (let offset = 0; offset < bytes.byteLength; offset += size) {
    yield bytes.subarray(offset, Math.min(offset + size, bytes.byteLength));
  }
}

describe("streaming SHA-256", () => {
  it("uses bounded chunk defaults", () => {
    expect(DEFAULT_HASH_CHUNK_SIZE).toBe(MIB);
    expect(MIN_HASH_CHUNK_SIZE).toBe(64 * 1024);
    expect(MAX_HASH_CHUNK_SIZE).toBe(64 * MIB);
  });

  it("selects buffered and streaming strategies from known sizes", () => {
    expect(detectHashStrategy(new Uint8Array(8 * MIB))).toBe("buffered");
    expect(detectHashStrategy(new Uint8Array(8 * MIB + 1))).toBe("streaming");
  });

  it.each([1, 63, 64, 65, 4093, MIB, 4 * MIB])(
    "produces the exact one-shot digest with %i-byte chunk boundaries",
    async (chunkSize) => {
      const bytes = new Uint8Array(2 * MIB + 137);
      for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 31 + 7) & 0xff;

      const streamed = await hashSource(chunks(bytes, chunkSize), {
        chunkSize: MIB,
      });
      expect(bytesToBase64(streamed.digest)).toBe(
        bytesToBase64(hashContent(bytes)),
      );
      expect(streamed.bytesProcessed).toBe(bytes.byteLength);
      expect(streamed.strategy).toBe("streaming");
    },
  );

  it("matches the historical digest for a 25 MiB buffer", async () => {
    const bytes = new Uint8Array(25 * MIB);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 17 + 19) & 0xff;

    const previous = bytesToBase64(hashContent(bytes));
    const current = await hashSource(bytes);
    expect(bytesToBase64(current.digest)).toBe(previous);
    expect(current.bytesProcessed).toBe(25 * MIB);
    expect(current.strategy).toBe("streaming");
  });

  it("honors maximum byte limits and cancellation", async () => {
    const bytes = new Uint8Array(1024);
    await expect(
      hashSource(chunks(bytes, 128), {
        maxBytes: 100,
      }),
    ).rejects.toThrow(/maximum/i);

    const controller = new AbortController();
    controller.abort("test cancellation");
    await expect(
      hashSource(chunks(bytes, 128), { signal: controller.signal }),
    ).rejects.toThrow(/cancel/i);
  });

  it("validates expected total bytes for unknown-length streams", async () => {
    const bytes = new Uint8Array(4097);
    const exact = await hashSource(chunks(bytes, 113), {
      totalBytes: bytes.byteLength,
    });
    expect(exact.bytesProcessed).toBe(bytes.byteLength);
    expect(exact.totalBytes).toBe(bytes.byteLength);

    await expect(
      hashSource(chunks(bytes, 113), { totalBytes: bytes.byteLength - 1 }),
    ).rejects.toThrow(/length mismatch/i);

    async function* truncated(): AsyncGenerator<Uint8Array> {
      yield bytes.subarray(0, 1000);
    }
    await expect(
      hashSource(truncated(), { totalBytes: bytes.byteLength }),
    ).rejects.toThrow(/length mismatch/i);
  });

  it("rejects a declared size that disagrees with a known source", async () => {
    const bytes = new Uint8Array(32);
    await expect(
      hashSource(bytes, { totalBytes: bytes.byteLength + 1 }),
    ).rejects.toThrow(/source length mismatch/i);
  });

  it("accepts the aligned maximum chunk-size override", async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const result = await hashSource(chunks(bytes, 2), {
      chunkSize: MAX_HASH_CHUNK_SIZE,
      totalBytes: bytes.byteLength,
    });
    expect(result.bytesProcessed).toBe(bytes.byteLength);
  });

  it("hashes Blob inputs incrementally when they exceed the threshold", async () => {
    const bytes = new Uint8Array(9 * MIB);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i & 0xff;
    const blob = new Blob([bytes]);
    const streamed = await hashSource(blob);
    expect(bytesToBase64(streamed.digest)).toBe(
      bytesToBase64(hashContent(bytes)),
    );
    expect(streamed.strategy).toBe("streaming");
  });
});

describe("streaming detached batch signing", () => {
  let key: MajikKey;

  beforeAll(async () => {
    key = await getTestKey();
  }, 120000);

  it("signs multiple streams into a compatible MJKSMAP manifest", async () => {
    const first = new TextEncoder().encode("first streamed batch file");
    const second = new TextEncoder().encode("second streamed batch file");
    const result = await MajikSignature.signBatchDetachedStream(
      [
        { path: "docs/first.txt", source: chunks(first, 3), totalBytes: first.length, mimeType: "text/plain" },
        { path: "docs/second.txt", source: chunks(second, 5), totalBytes: second.length, mimeType: "text/plain" },
      ],
      key,
      {
        mode: "map",
        onProgress: (progress) => {
          expect(progress.totalFiles).toBe(2);
          expect(progress.path.startsWith("docs/")).toBe(true);
        },
      },
    );

    expect(result.mode).toBe("map");
    if (result.mode !== "map") throw new Error("Expected map mode");
    expect(result.map.size).toBe(2);
    expect(result.map.getEntry("docs/first.txt")?.contentHash).toBe(
      bytesToBase64(hashContent(first)),
    );
    expect(result.map.getEntry("docs/second.txt")?.size).toBe(second.length);

    const signature = result.map.getEntry("docs/first.txt")!.envelope.signatures[0]!;
    const verified = await MajikSignature.verifyStream(
      chunks(first, 2),
      signature,
      MajikSignature.publicKeysFromMajikKey(key),
    );
    expect(verified.valid).toBe(true);

    const mapResults = await MajikSignature.verifyFilesFromMjksMapStream(
      result.map,
      [
        { path: "docs/first.txt", source: chunks(first, 4), totalBytes: first.length },
        { path: "moved/second.txt", source: chunks(second, 7), totalBytes: second.length },
      ],
      MajikSignature.publicKeysFromMajikKey(key),
    );
    expect(mapResults.map((item) => item.status)).toEqual(["verified", "verified"]);
    expect(mapResults[1]?.relocatedFrom).toBe("docs/second.txt");

    const modified = new TextEncoder().encode("modified content");
    const tampered = await MajikSignature.verifyFilesFromMjksMapStream(
      result.map,
      [{ path: "docs/first.txt", source: chunks(modified, 3), totalBytes: modified.length }],
      MajikSignature.publicKeysFromMajikKey(key),
    );
    expect(tampered[0]?.status).toBe("tampered");
  });

  it("emits separate MJKSIG blobs when requested", async () => {
    const first = new TextEncoder().encode("separate streamed result one");
    const second = new TextEncoder().encode("separate streamed result two");
    const result = await MajikSignature.signBatchDetachedStream(
      [
        { path: "one.txt", source: chunks(first, 4), totalBytes: first.length },
        { path: "two.txt", source: chunks(second, 6), totalBytes: second.length },
      ],
      key,
      { mode: "separate" },
    );

    expect(result.mode).toBe("separate");
    if (result.mode !== "separate") throw new Error("Expected separate mode");
    expect(result.signatures).toHaveLength(2);
    expect(result.signatures.map((item) => item.path)).toEqual(["one.txt", "two.txt"]);
    expect(result.signatures.every((item) => item.blob.size > 0)).toBe(true);
  });

  it("does not continue a batch after explicit cancellation", async () => {
    const controller = new AbortController();
    controller.abort();
    const bytes = new TextEncoder().encode("cancelled batch input");

    await expect(
      MajikSignature.signBatchDetachedStream(
        [{ path: "cancelled.txt", source: chunks(bytes, 3), totalBytes: bytes.length }],
        key,
        {
          continueOnError: true,
          streaming: { signal: controller.signal },
        },
      ),
    ).rejects.toThrow(/cancel/i);
  });

  it("continues after per-file failures when requested", async () => {
    const valid = new TextEncoder().encode("valid item");
    const invalid = new TextEncoder().encode("invalid length");
    const result = await MajikSignature.signBatchDetachedStream(
      [
        { path: "valid.txt", source: chunks(valid, 2), totalBytes: valid.length },
        { path: "invalid.txt", source: chunks(invalid, 2), totalBytes: invalid.length + 1 },
      ],
      key,
      { continueOnError: true },
    );

    expect(result.mode).toBe("map");
    if (result.mode !== "map") throw new Error("Expected map mode");
    expect(result.map.size).toBe(1);
    expect(result.failures).toHaveLength(1);
    expect(result.failures[0]?.path).toBe("invalid.txt");
  });
});

describe("MajikSignature streaming APIs", () => {
  let key: MajikKey;

  beforeAll(async () => {
    key = await getTestKey();
  }, 120000);

  it("creates a detached signature that verifies against the same streamed bytes", async () => {
    const input = new TextEncoder().encode("streamed signature input");
    const signature = await MajikSignature.signStream(chunks(input, 3), key, {
      contentType: "text/plain",
    });
    const publicKeys = MajikSignature.publicKeysFromMajikKey(key);
    const result = await MajikSignature.verifyStream(
      chunks(input, 2),
      signature,
      publicKeys,
    );

    expect(result.valid).toBe(true);
    expect(result.contentHash).toBe(bytesToBase64(hashContent(input)));
  });
});

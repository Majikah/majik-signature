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
    expect(MAX_HASH_CHUNK_SIZE).toBe(8 * MIB);
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

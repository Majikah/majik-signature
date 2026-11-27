import { SHA256 } from "@stablelib/sha256";
import { MajikSignatureError, MajikSignatureValidationError } from "../errors.js";
import {
  DEFAULT_HASH_CHUNK_SIZE,
  DEFAULT_HASH_STREAMING_THRESHOLD,
  validateHashChunkSize,
} from "./config.js";
import { detectHashStrategy, getKnownSourceSize } from "./strategy.js";
import type {
  StreamingByteSource,
  StreamingHashOptions,
  StreamingHashProgress,
  StreamingHashResult,
} from "./types.js";

/** Incremental SHA-256 state. Each update appends bytes to one logical message. */
export class Sha256Stream {
  private readonly hasher = new SHA256();
  private finalized = false;

  update(chunk: Uint8Array): void {
    if (this.finalized) {
      throw new MajikSignatureError("SHA-256 stream has already been finalized");
    }
    if (!(chunk instanceof Uint8Array)) {
      throw new MajikSignatureValidationError("Hash chunks must be Uint8Array values", "chunk");
    }
    if (chunk.byteLength > 0) this.hasher.update(chunk);
  }

  digest(): Uint8Array {
    if (this.finalized) {
      throw new MajikSignatureError("SHA-256 stream has already been finalized");
    }
    this.finalized = true;
    return this.hasher.digest();
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new MajikSignatureError("Streaming hash was cancelled", signal.reason);
  }
}

function validateOptions(options: StreamingHashOptions): {
  chunkSize: number;
  thresholdBytes: number;
  maxBytes?: number;
  totalBytes?: number;
} {
  if (
    typeof options !== "object" ||
    options === null ||
    Array.isArray(options)
  ) {
    throw new MajikSignatureValidationError(
      "options must be an object",
      "options",
    );
  }
  if (
    options.onProgress !== undefined &&
    typeof options.onProgress !== "function"
  ) {
    throw new MajikSignatureValidationError(
      "onProgress must be a function when provided",
      "onProgress",
    );
  }
  if (
    options.signal !== undefined &&
    (typeof options.signal !== "object" ||
      options.signal === null ||
      typeof options.signal.aborted !== "boolean")
  ) {
    throw new MajikSignatureValidationError(
      "signal must be an AbortSignal-like object when provided",
      "signal",
    );
  }

  const chunkSize = options.chunkSize ?? DEFAULT_HASH_CHUNK_SIZE;
  const thresholdBytes =
    options.thresholdBytes ?? DEFAULT_HASH_STREAMING_THRESHOLD;
  validateHashChunkSize(chunkSize);

  if (!Number.isSafeInteger(thresholdBytes) || thresholdBytes < 0) {
    throw new MajikSignatureValidationError(
      "thresholdBytes must be a non-negative safe integer",
      "thresholdBytes",
    );
  }
  if (
    options.maxBytes !== undefined &&
    (!Number.isSafeInteger(options.maxBytes) || options.maxBytes < 0)
  ) {
    throw new MajikSignatureValidationError(
      "maxBytes must be a non-negative safe integer",
      "maxBytes",
    );
  }
  if (
    options.totalBytes !== undefined &&
    (!Number.isSafeInteger(options.totalBytes) || options.totalBytes < 0)
  ) {
    throw new MajikSignatureValidationError(
      "totalBytes must be a non-negative safe integer",
      "totalBytes",
    );
  }
  if (
    options.totalBytes !== undefined &&
    options.maxBytes !== undefined &&
    options.totalBytes > options.maxBytes
  ) {
    throw new MajikSignatureValidationError(
      "totalBytes exceeds the configured maximum",
      "totalBytes",
    );
  }

  return {
    chunkSize,
    thresholdBytes,
    maxBytes: options.maxBytes,
    totalBytes: options.totalBytes,
  };
}

function asByteSource(source: StreamingByteSource): void {
  const isBlob = typeof Blob !== "undefined" && source instanceof Blob;
  const isReadable =
    typeof source === "object" &&
    source !== null &&
    typeof (source as ReadableStream<Uint8Array>).getReader === "function";
  const isAsyncIterable =
    typeof source === "object" &&
    source !== null &&
    Symbol.asyncIterator in source;

  if (
    !(source instanceof Uint8Array) &&
    !(source instanceof ArrayBuffer) &&
    !isBlob &&
    !isReadable &&
    !isAsyncIterable
  ) {
    throw new MajikSignatureValidationError(
      "source must be a Uint8Array, ArrayBuffer, Blob, ReadableStream, or AsyncIterable<Uint8Array>",
      "source",
    );
  }
}

/**
 * Hash a byte source without materializing a stream into one large allocation.
 *
 * Small in-memory inputs use one update. Large in-memory inputs are sliced
 * without copying. Blob, ReadableStream, and AsyncIterable sources are consumed
 * incrementally. The digest is exactly SHA-256(source bytes), with no
 * per-chunk framing or concatenated intermediate hashes.
 */
export async function hashSource(
  source: StreamingByteSource,
  options: StreamingHashOptions = {},
): Promise<StreamingHashResult> {
  asByteSource(source);
  const config = validateOptions(options);
  const strategy = detectHashStrategy(source, config.thresholdBytes);
  const sourceSize = getKnownSourceSize(source);
  if (
    config.totalBytes !== undefined &&
    sourceSize !== undefined &&
    sourceSize !== config.totalBytes
  ) {
    throw new MajikSignatureValidationError(
      `Source length mismatch: expected ${config.totalBytes} bytes, source reports ${sourceSize}`,
      "totalBytes",
    );
  }
  const expectedSize = config.totalBytes ?? sourceSize;

  if (
    expectedSize !== undefined &&
    config.maxBytes !== undefined &&
    expectedSize > config.maxBytes
  ) {
    throw new MajikSignatureValidationError(
      `Input exceeds the configured maximum of ${config.maxBytes} bytes`,
      "maxBytes",
    );
  }

  const stream = new Sha256Stream();
  let bytesProcessed = 0;

  const consume = async (chunk: Uint8Array): Promise<void> => {
    if (!(chunk instanceof Uint8Array)) {
      throw new MajikSignatureValidationError(
        "Stream yielded a non-Uint8Array chunk",
        "source",
      );
    }
    if (chunk.byteLength === 0) return;

    // A custom ReadableStream/AsyncIterable may yield a single very large
    // Uint8Array. Process that value in bounded slices without copying it.
    for (let offset = 0; offset < chunk.byteLength; offset += config.chunkSize) {
      throwIfAborted(options.signal);
      const part = chunk.subarray(offset, Math.min(offset + config.chunkSize, chunk.byteLength));
      const next = bytesProcessed + part.byteLength;
      if (!Number.isSafeInteger(next)) {
        throw new MajikSignatureValidationError(
          "Input byte count exceeds the safe integer range",
          "source",
        );
      }
      if (config.maxBytes !== undefined && next > config.maxBytes) {
        throw new MajikSignatureValidationError(
          `Input exceeds the configured maximum of ${config.maxBytes} bytes`,
          "maxBytes",
        );
      }
      if (expectedSize !== undefined && next > expectedSize) {
        throw new MajikSignatureValidationError(
          `Stream length mismatch: expected ${expectedSize} bytes, received at least ${next}`,
          "totalBytes",
        );
      }

      stream.update(part);
      bytesProcessed = next;
      options.onProgress?.({
        bytesProcessed,
        ...(expectedSize !== undefined ? { totalBytes: expectedSize } : {}),
      });

      // A custom iterable/stream can yield a single huge Uint8Array. Yield
      // between bounded slices so timers and cancellation events can run.
      if (offset + config.chunkSize < chunk.byteLength) {
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
      }
    }
  };

  const processBuffer = async (bytes: Uint8Array): Promise<void> => {
    if (strategy === "buffered") {
      await consume(bytes);
      return;
    }

    for (let offset = 0; offset < bytes.byteLength; offset += config.chunkSize) {
      await consume(
        bytes.subarray(offset, Math.min(offset + config.chunkSize, bytes.byteLength)),
      );
      // Yield so a large already-materialized buffer does not monopolize the UI thread.
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
  };

  throwIfAborted(options.signal);

  if (source instanceof Uint8Array) {
    await processBuffer(source);
  } else if (source instanceof ArrayBuffer) {
    await processBuffer(new Uint8Array(source));
  } else if (typeof Blob !== "undefined" && source instanceof Blob) {
    if (strategy === "buffered") {
      await processBuffer(new Uint8Array(await source.arrayBuffer()));
    } else {
      await consumeReadableStream(source.stream(), consume, options.signal);
    }
  } else if (
    typeof source === "object" &&
    source !== null &&
    typeof (source as ReadableStream<Uint8Array>).getReader === "function"
  ) {
    await consumeReadableStream(
      source as ReadableStream<Uint8Array>,
      consume,
      options.signal,
    );
  } else {
    for await (const chunk of source as AsyncIterable<Uint8Array>) {
      await consume(chunk);
    }
  }

  throwIfAborted(options.signal);
  if (expectedSize !== undefined && bytesProcessed !== expectedSize) {
    throw new MajikSignatureValidationError(
      `Stream length mismatch: expected ${expectedSize} bytes, read ${bytesProcessed}`,
      "totalBytes",
    );
  }
  return {
    digest: stream.digest(),
    bytesProcessed,
    strategy,
    ...(expectedSize !== undefined ? { totalBytes: expectedSize } : {}),
  };
}

async function consumeReadableStream(
  source: ReadableStream<Uint8Array>,
  consume: (chunk: Uint8Array) => Promise<void>,
  signal?: AbortSignal,
): Promise<void> {
  const reader = source.getReader();
  try {
    while (true) {
      throwIfAborted(signal);
      const result = await reader.read();
      if (result.done) break;
      await consume(result.value);
    }
  } catch (error) {
    try {
      await reader.cancel(error);
    } catch {
      // Preserve the original processing/cancellation error.
    }
    throw error;
  } finally {
    reader.releaseLock();
  }
}

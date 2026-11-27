import {
  DEFAULT_HASH_STREAMING_THRESHOLD,
} from "./config.js";
import type { HashStrategy, StreamingByteSource } from "./types.js";

/** Return the byte length for in-memory/Blob sources, or undefined for unknown-size streams. */
export function getKnownSourceSize(source: StreamingByteSource): number | undefined {
  if (source instanceof Uint8Array) return source.byteLength;
  if (source instanceof ArrayBuffer) return source.byteLength;
  if (typeof Blob !== "undefined" && source instanceof Blob) return source.size;
  return undefined;
}

/** Select the buffered path for known small sources and the streaming path for large or unknown-size sources. */
export function detectHashStrategy(
  source: StreamingByteSource,
  thresholdBytes = DEFAULT_HASH_STREAMING_THRESHOLD,
): HashStrategy {
  if (!Number.isSafeInteger(thresholdBytes) || thresholdBytes < 0) {
    throw new RangeError("thresholdBytes must be a non-negative safe integer");
  }

  const knownSize = getKnownSourceSize(source);
  if (knownSize === undefined) return "streaming";
  return knownSize > thresholdBytes ? "streaming" : "buffered";
}

import {
  DEFAULT_HASH_STREAMING_THRESHOLD,
} from "./config.js";
import type { HashStrategy, StreamingByteSource } from "./types.js";

export function getKnownSourceSize(source: StreamingByteSource): number | undefined {
  if (source instanceof Uint8Array) return source.byteLength;
  if (source instanceof ArrayBuffer) return source.byteLength;
  if (typeof Blob !== "undefined" && source instanceof Blob) return source.size;
  return undefined;
}

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

/** Tunable defaults for streaming content hashes. */
export const DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024;
/** Minimum permitted per-worker hash chunk size (64 KiB). */
export const MIN_HASH_CHUNK_SIZE = 64 * 1024;
/** Hard cap per hash worker to keep caller-controlled buffering bounded. */
export const MAX_HASH_CHUNK_SIZE = 64 * 1024 * 1024;
/** Known-size sources larger than this threshold default to the streaming path (8 MiB). */
export const DEFAULT_HASH_STREAMING_THRESHOLD = 8 * 1024 * 1024;

/** Validate a caller-supplied chunk size against the supported 64 KiB–64 MiB range. */
export function validateHashChunkSize(value: number): void {
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_HASH_CHUNK_SIZE ||
    value > MAX_HASH_CHUNK_SIZE
  ) {
    throw new RangeError(
      `chunkSize must be an integer between ${MIN_HASH_CHUNK_SIZE} and ${MAX_HASH_CHUNK_SIZE} bytes`,
    );
  }
}

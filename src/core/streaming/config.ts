/** Tunable defaults for streaming content hashes. */
export const DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024;
export const MIN_HASH_CHUNK_SIZE = 64 * 1024;
export const MAX_HASH_CHUNK_SIZE = 256 * 1024 * 1024;
export const DEFAULT_HASH_STREAMING_THRESHOLD = 8 * 1024 * 1024;

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

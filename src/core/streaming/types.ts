/** Shared types for bounded-memory SHA-256 processing. */
export type HashStrategy = "buffered" | "streaming";

/** Progress snapshot emitted after a non-empty chunk has been incorporated into the digest. */
export interface StreamingHashProgress {
  bytesProcessed: number;
  totalBytes?: number;
}

/**
 * Per-operation controls for bounded-memory SHA-256 hashing.
 * The optional maximum and expected length are distinct: maxBytes caps accepted
 * input, while totalBytes asserts the source's complete length.
 */
export interface StreamingHashOptions {
  /** Read/update granularity. Defaults to 1 MiB. */
  chunkSize?: number;
  /** Inputs at or below this size may use the one-shot path. Defaults to 8 MiB. */
  thresholdBytes?: number;
  /** Optional upper bound for untrusted or externally supplied streams. */
  maxBytes?: number;
  /** Expected complete source length; rejects truncated or overlong streams. */
  totalBytes?: number;
  /** Stops processing between chunks. */
  signal?: AbortSignal;
  /** Called after each non-empty chunk has been incorporated. */
  onProgress?: (progress: StreamingHashProgress) => void;
}

/** Byte source accepted by the cross-runtime streaming hash helper. */
export type StreamingByteSource =
  | Uint8Array
  | ArrayBuffer
  | Blob
  | ReadableStream<Uint8Array>
  | AsyncIterable<Uint8Array>;

/** Final digest and byte-count/strategy metadata returned by a completed hash operation. */
export interface StreamingHashResult {
  /** Raw 32-byte SHA-256 digest, byte-for-byte compatible with hashContent(). */
  digest: Uint8Array;
  bytesProcessed: number;
  strategy: HashStrategy;
  totalBytes?: number;
}

/** Shared types for bounded-memory SHA-256 processing. */
export type HashStrategy = "buffered" | "streaming";

export interface StreamingHashProgress {
  bytesProcessed: number;
  totalBytes?: number;
}

export interface StreamingHashOptions {
  /** Read/update granularity. Defaults to 1 MiB. */
  chunkSize?: number;
  /** Inputs at or below this size may use the one-shot path. Defaults to 8 MiB. */
  thresholdBytes?: number;
  /** Optional upper bound for untrusted or externally supplied streams. */
  maxBytes?: number;
  /** Stops processing between chunks. */
  signal?: AbortSignal;
  /** Called after each non-empty chunk has been incorporated. */
  onProgress?: (progress: StreamingHashProgress) => void;
}

export type StreamingByteSource =
  | Uint8Array
  | ArrayBuffer
  | Blob
  | ReadableStream<Uint8Array>
  | AsyncIterable<Uint8Array>;

export interface StreamingHashResult {
  /** Raw 32-byte SHA-256 digest, byte-for-byte compatible with hashContent(). */
  digest: Uint8Array;
  bytesProcessed: number;
  strategy: HashStrategy;
  totalBytes?: number;
}

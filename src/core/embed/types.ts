// ─── Handler Interface ────────────────────────────────────────────────────────

import { MajikSignatureEnvelope } from "../envelope.js";

/**
 * Low-level contract implemented by each file-format embedding handler.
 *
 * @remarks
 * Handlers operate exclusively on raw `Uint8Array` bytes so the embedding
 * layer stays independent of browser `Blob` semantics. A handler is responsible
 * for recognizing its format, embedding/extracting the serialized envelope,
 * and restoring the exact unsigned bytes from the signed representation.
 */
export interface FormatHandler {
  /** Stable internal name used for diagnostics and returned file metadata. */
  readonly name: string;

  /** MIME types the handler can process when MIME-aware selection is used. */
  readonly supportedMimeTypes: readonly string[];

  /**
   * Determine whether this handler can process the supplied bytes.
   *
   * @param bytes Raw file bytes to inspect.
   * @param mimeType Optional caller-supplied MIME type hint.
   */
  canHandle(bytes: Uint8Array, mimeType?: string): boolean;

  /**
   * Embed serialized signature JSON into the file bytes.
   *
   * @param bytes Original file bytes without a signature envelope.
   * @param signatureJson Serialized envelope to embed.
   */
  embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array>;

  /**
   * Extract the serialized signature JSON from the file.
   *
   * @returns The embedded JSON string, or `null` when no envelope is present.
   */
  extract(bytes: Uint8Array): Promise<string | null>;

  /**
   * Remove the embedded signature and restore the unsigned file representation.
   *
   * @remarks
   * The returned bytes are the bytes the signature is intended to cover.
   */
  strip(bytes: Uint8Array): Promise<Uint8Array>;

  /**
   * Explain why a probable signature marker could not be parsed.
   *
   * @remarks
   * This is optional and is used for better diagnostics when bytes look like
   * they may contain a signature but no well-formed signature block can be read.
   */
  diagnose?(bytes: Uint8Array): string | null;
}

// ─── Embed / Extract Results ──────────────────────────────────────────────────

/**
 * Result returned after embedding a signature into a file.
 *
 * @remarks
 * `blob` contains the signed file. `handler` identifies the embedding handler
 * that produced it, and `mimeType` is the effective type used for the operation.
 */
export interface EmbedResult {
  /** Signed file containing the embedded envelope. */
  blob: Blob;
  /** Name of the file-format handler used for embedding. */
  handler: string;
  /** Effective MIME type used by the embedding operation. */
  mimeType: string;
}

/**
 * Result returned when extracting an embedded envelope from a file.
 */
export interface ExtractResult {
  /** Behavior-rich immutable envelope reconstructed from the embedded JSON. */
  envelope: MajikSignatureEnvelope;
  /** Name of the handler that extracted the envelope. */
  handler: string;
}

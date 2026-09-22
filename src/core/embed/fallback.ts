/**
 * handlers/fallback.ts — Tier-2 universal trailer handler.
 *
 * The universal fallback is the final embedding strategy used when no
 * format-specific handler recognizes a file. It can therefore operate on
 * arbitrary binary content without needing to understand the file format.
 *
 * Trailer layout:
 *   [original bytes]
 *   [signature JSON encoded as UTF-8]
 *   [8-byte payload length, little-endian]
 *   [8-byte magic marker]
 *
 * @remarks
 * The handler intentionally treats the signature payload as opaque JSON text.
 * Format awareness, cryptographic signing, and signature verification remain
 * outside this handler.
 *
 * The fallback is designed for formats whose parsers tolerate trailing bytes.
 * That is a compatibility strategy, not a universal guarantee: some formats
 * or downstream tools may reject, rewrite, truncate, or otherwise normalize
 * trailing data. Prefer a native format handler when one is available and
 * durable cross-tool interoperability matters.
 *
 * Embedding is idempotent. Before writing a new trailer, any existing
 * universal trailer is removed so signatures do not accumulate back-to-back.
 */

import { FormatHandler } from "../types";
import { appendTrailer, extractTrailer } from "./utils";

/**
 * Last-resort {@link FormatHandler} that embeds signatures using the universal
 * binary trailer format.
 *
 * @remarks
 * `FallbackHandler` is intended to be registered after format-specific
 * handlers. Its {@link canHandle} method always returns `true`, making this
 * handler the universal catch-all for otherwise unsupported file types.
 *
 * The handler does not perform cryptographic operations itself. It only:
 * - appends a serialized signature payload,
 * - extracts that payload when the trailer is present, and
 * - removes the trailer to recover the original bytes.
 *
 * The trailer is self-describing through its terminating magic bytes and
 * length field, allowing extraction and stripping without knowing the file's
 * MIME type or format.
 *
 * @example
 * ```ts
 * const handler = new FallbackHandler();
 *
 * const signed = await handler.embed(bytes, signatureJson);
 * const extracted = await handler.extract(signed);
 * const original = await handler.strip(signed);
 * ```
 *
 * @see {@link FormatHandler}
 */
export class FallbackHandler implements FormatHandler {
  /**
   * Human-readable handler name used by the embedding pipeline and diagnostics.
   */
  readonly name = "Fallback (Universal Trailer)";

  /**
   * MIME types accepted by this handler.
   *
   * @remarks
   * Intentionally declares a catch-all rather than a concrete media
   * type. Actual selection is still governed by handler ordering and
   * `canHandle()`.
   */
  readonly supportedMimeTypes = ["*/*"] as const;

  /**
   * Determine whether this handler can process the supplied content.
   *
   * @remarks
   * This method always returns `true` because the universal trailer is the
   * Tier-2 last-resort embedding mechanism. It should therefore remain the
   * final handler in the handler-selection chain; placing it earlier would
   * prevent more format-aware handlers from being selected.
   *
   * The byte content and MIME type are intentionally ignored.
   *
   * @param _bytes File bytes to inspect. Ignored by the fallback handler.
   * @param _mimeType Optional MIME type hint. Ignored by the fallback handler.
   * @returns Always `true`.
   */
  canHandle(_bytes: Uint8Array, _mimeType?: string): boolean {
    // Always handles — it's the last resort
    return true;
  }

  /**
   * Embed a serialized signature payload using the universal trailer format.
   *
   * @remarks
   * Any existing universal trailer is stripped before the new payload is
   * appended. This makes repeated embedding idempotent: re-embedding replaces
   * the existing fallback signature rather than stacking multiple trailers.
   *
   * The supplied `signatureJson` is treated as already-serialized signature
   * data. This method does not parse, validate, or cryptographically verify
   * it.
   *
   * @param bytes Original or previously signed file bytes.
   * @param signatureJson Serialized signature envelope JSON to append.
   * @returns The file bytes with exactly one universal signature trailer.
   */
  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    // Strip any existing trailer first (idempotent)
    const stripped = await this.strip(bytes);
    return appendTrailer(stripped, signatureJson);
  }

  /**
   * Extract the serialized signature payload from a universal trailer.
   *
   * @remarks
   * Extraction is structural only. A non-null return value means a well-formed
   * universal trailer was found; it does not mean that the contained signature
   * is cryptographically valid or trusted.
   *
   * @param bytes File bytes that may contain a universal trailer.
   * @returns The serialized signature JSON when a valid trailer is present;
   * otherwise `null`.
   */
  async extract(bytes: Uint8Array): Promise<string | null> {
    const result = extractTrailer(bytes);
    return result ? result.signatureJson : null;
  }

  /**
   * Remove the universal trailer and recover the original file bytes.
   *
   * @remarks
   * If no recognizable universal trailer is present, the input bytes are
   * returned unchanged.
   *
   * This operation only removes the trailer produced by the universal
   * fallback format. It does not remove signatures embedded by native,
   * format-specific handlers.
   *
   * @param bytes File bytes that may contain a universal trailer.
   * @returns The original bytes when a trailer is found; otherwise the
   * unchanged input bytes.
   */
  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    const result = extractTrailer(bytes);
    return result ? result.original : bytes;
  }
}

// Freeze static methods
Object.freeze(FallbackHandler);

// Freeze instance methods
Object.freeze(FallbackHandler.prototype);

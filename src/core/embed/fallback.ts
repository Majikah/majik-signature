/**
 * handlers/fallback.ts — Tier-2 universal trailer handler
 *
 * Works on ANY file format. Appends a self-describing binary trailer:
 *   [original bytes][signature_json_utf8][8-byte length LE][8-byte magic]
 *
 * Files remain valid for their primary use — most parsers ignore trailing bytes.
 * The magic bytes allow detection and clean stripping from any file.
 */

import { FormatHandler } from "../types";
import { appendTrailer, extractTrailer } from "./utils";

export class FallbackHandler implements FormatHandler {
  readonly name = "Fallback (Universal Trailer)";
  readonly supportedMimeTypes = ["*/*"] as const;

  canHandle(_bytes: Uint8Array, _mimeType?: string): boolean {
    // Always handles — it's the last resort
    return true;
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    // Strip any existing trailer first (idempotent)
    const stripped = await this.strip(bytes);
    return appendTrailer(stripped, signatureJson);
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    const result = extractTrailer(bytes);
    return result ? result.signatureJson : null;
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    const result = extractTrailer(bytes);
    return result ? result.original : bytes;
  }
}

// Freeze static methods
Object.freeze(FallbackHandler);

// Freeze instance methods
Object.freeze(FallbackHandler.prototype);

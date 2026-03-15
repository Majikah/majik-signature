/**
 * handlers/mkv.ts — MKV / WebM handler (EBML-based)
 *
 * MKV and WebM use the Extensible Binary Meta Language (EBML) container.
 * We use the Tier-2 trailer approach for these formats since full EBML
 * parsing is complex and fragmented MP4/MKV files vary widely.
 *
 * The trailer approach is safe for MKV/WebM: the EBML spec does not prohibit
 * trailing bytes after the Segment element, and media players ignore them.
 *
 * If you need native MKV Tags element embedding, this handler can be extended
 * with a full EBML parser. For now, the Tier-2 trailer is the primary store.
 */

import { FormatHandler } from "../../types";
import { appendTrailer, extractTrailer } from "../utils";


const EBML_MAGIC = new Uint8Array([0x1a, 0x45, 0xdf, 0xa3]);

export class MkvHandler implements FormatHandler {
  readonly name = "MKV/WebM";
  readonly supportedMimeTypes = [
    "video/x-matroska",
    "video/webm",
    "audio/webm",
    "audio/x-matroska",
  ] as const;

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (this.supportedMimeTypes.includes(mimeType as any)) return true;
    return (
      bytes.length >= 4 &&
      bytes[0] === EBML_MAGIC[0] &&
      bytes[1] === EBML_MAGIC[1] &&
      bytes[2] === EBML_MAGIC[2] &&
      bytes[3] === EBML_MAGIC[3]
    );
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);
    return appendTrailer(clean, signatureJson);
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

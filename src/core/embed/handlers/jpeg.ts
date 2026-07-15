/**
 * handlers/jpeg.ts — JPEG handler
 *
 * Embeds the MajikSignature in a custom APP15 (0xFFEF) segment.
 * APP0–APP15 are all valid JPEG application marker segments.
 * APP1 is used by EXIF/XMP; we use APP15 to avoid collisions.
 *
 * Segment layout:
 *   0xFF 0xEF [2B length BE (includes the 2 length bytes)] [identifier "MAJIK\0"] [JSON UTF-8]
 *
 * Falls back to Tier-2 trailer if segment injection fails.
 */

import { FormatHandler } from "../../types";

import { concatBytes, textDecode, textEncode } from "../utils";

const JPEG_SOI = new Uint8Array([0xff, 0xd8]);
const APP15_MARKER = new Uint8Array([0xff, 0xef]);
const MAJIK_IDENTIFIER = textEncode("MAJIK\0");

export class JpegHandler implements FormatHandler {
  readonly name = "JPEG";
  readonly supportedMimeTypes = ["image/jpeg", "image/jpg"] as const;

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (mimeType === "image/jpeg" || mimeType === "image/jpg") return true;
    return (
      bytes.length >= 3 &&
      bytes[0] === 0xff &&
      bytes[1] === 0xd8 &&
      bytes[2] === 0xff
    );
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);

    // Build the APP15 segment
    const payload = textEncode(signatureJson);
    const segmentData = concatBytes(MAJIK_IDENTIFIER, payload);
    const length = segmentData.length + 2; // +2 for the length field itself

    if (length > 0xffff) {
      // Shouldn't happen for a signature, but guard anyway
      throw new Error("Signature too large for JPEG APP15 segment");
    }

    const lengthBytes = new Uint8Array([(length >> 8) & 0xff, length & 0xff]);
    const segment = concatBytes(APP15_MARKER, lengthBytes, segmentData);

    // Insert after SOI (0xFF 0xD8), before the first APP/SOF marker
    // SOI is always 2 bytes
    const rest = clean.slice(2);
    return concatBytes(JPEG_SOI, segment, rest);
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    if (!this.canHandle(bytes)) return null;
    try {
      return this._findApp15(bytes);
    } catch {
      return null;
    }
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    if (!this.canHandle(bytes)) return bytes;
    try {
      return this._removeApp15(bytes);
    } catch {
      return bytes;
    }
  }

  // ─── Marker Scanning ────────────────────────────────────────────────────────

  private _findApp15(bytes: Uint8Array): string | null {
    let offset = 2; // Skip SOI

    while (offset < bytes.length - 1) {
      if (bytes[offset] !== 0xff) break;

      const marker = bytes[offset + 1];
      if (marker === 0xd9) break; // EOI

      // Markers without a length field: RST0-RST7, SOI, EOI, TEM
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
        offset += 2;
        continue;
      }

      if (offset + 4 > bytes.length) break;
      const segLength = (bytes[offset + 2] << 8) | bytes[offset + 3]; // includes 2 length bytes
      const segDataStart = offset + 4;
      const segDataEnd = offset + 2 + segLength;

      // Check for our APP15 marker
      if (marker === 0xef) {
        const segData = bytes.slice(segDataStart, segDataEnd);
        // Check identifier
        if (segData.length > MAJIK_IDENTIFIER.length) {
          const ident = segData.slice(0, MAJIK_IDENTIFIER.length);
          const isOurs = MAJIK_IDENTIFIER.every((b, i) => ident[i] === b);
          if (isOurs) {
            return textDecode(segData.slice(MAJIK_IDENTIFIER.length));
          }
        }
      }

      offset = segDataEnd;
    }

    return null;
  }

  private _removeApp15(bytes: Uint8Array): Uint8Array {
    const parts: Uint8Array[] = [JPEG_SOI];
    let offset = 2; // Skip SOI

    while (offset < bytes.length - 1) {
      if (bytes[offset] !== 0xff) {
        // Remaining entropy-coded data
        parts.push(bytes.slice(offset));
        break;
      }

      const marker = bytes[offset + 1];
      if (marker === 0xd9) {
        // EOI — include and stop
        parts.push(bytes.slice(offset));
        break;
      }

      // Markers without length
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
        parts.push(bytes.slice(offset, offset + 2));
        offset += 2;
        continue;
      }

      if (offset + 4 > bytes.length) {
        parts.push(bytes.slice(offset));
        break;
      }

      const segLength = (bytes[offset + 2] << 8) | bytes[offset + 3];
      const segEnd = offset + 2 + segLength;
      const segDataStart = offset + 4;

      // Skip our APP15
      if (marker === 0xef) {
        const segData = bytes.slice(segDataStart, segEnd);
        if (segData.length > MAJIK_IDENTIFIER.length) {
          const ident = segData.slice(0, MAJIK_IDENTIFIER.length);
          const isOurs = MAJIK_IDENTIFIER.every((b, i) => ident[i] === b);
          if (isOurs) {
            offset = segEnd;
            continue;
          }
        }
      }

      parts.push(bytes.slice(offset, segEnd));
      offset = segEnd;
    }

    return concatBytes(...parts);
  }
}


// Freeze static methods
Object.freeze(JpegHandler);

// Freeze instance methods
Object.freeze(JpegHandler.prototype);
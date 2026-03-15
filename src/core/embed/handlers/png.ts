/**
 * handlers/png.ts — PNG handler
 *
 * Embeds the MajikSignature as a PNG iTXt (International Text) chunk.
 * iTXt is the standard way to store arbitrary UTF-8 metadata in PNG files.
 * All PNG-compatible tools ignore unknown chunks they don't need.
 *
 * Chunk layout:
 *   [4B length][4B type "iTXt"][keyword\0][compression_flag][compression_method][lang\0][translated_keyword\0][text][4B CRC]
 */

import { FormatHandler } from "../../types";
import { PNG_KEYWORD } from "../constants";
import { concatBytes, crc32, readUint32BE, textDecode, textEncode, writeUint32BE } from "../utils";



const PNG_SIGNATURE = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
]);
const ITXT_TYPE = textEncode("iTXt");
const IEND_TYPE = textEncode("IEND");

export class PngHandler implements FormatHandler {
  readonly name = "PNG";
  readonly supportedMimeTypes = ["image/png"] as const;

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (mimeType === "image/png") return true;
    if (bytes.length < 8) return false;
    return PNG_SIGNATURE.every((b, i) => bytes[i] === b);
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);
    const chunks = this._parseChunks(clean);

    // Build iTXt chunk data
    const chunkData = this._buildITxtData(PNG_KEYWORD, signatureJson);
    const sigChunk = this._buildChunk("iTXt", chunkData);

    // Insert before IEND chunk
    const iendIdx = chunks.findIndex((c) => c.type === "IEND");
    const insertAt = iendIdx >= 0 ? iendIdx : chunks.length;

    const parts: Uint8Array[] = [PNG_SIGNATURE];
    for (let i = 0; i < insertAt; i++) parts.push(chunks[i].raw);
    parts.push(sigChunk);
    for (let i = insertAt; i < chunks.length; i++) parts.push(chunks[i].raw);

    return concatBytes(...parts);
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    if (!this.canHandle(bytes)) return null;
    try {
      const chunks = this._parseChunks(bytes);
      for (const chunk of chunks) {
        if (chunk.type === "iTXt") {
          const result = this._readITxtData(chunk.data);
          if (result?.keyword === PNG_KEYWORD) return result.text;
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    if (!this.canHandle(bytes)) return bytes;
    try {
      const chunks = this._parseChunks(bytes);
      const kept = chunks.filter((c) => {
        if (c.type !== "iTXt") return true;
        const result = this._readITxtData(c.data);
        return result?.keyword !== PNG_KEYWORD;
      });
      return concatBytes(PNG_SIGNATURE, ...kept.map((c) => c.raw));
    } catch {
      return bytes;
    }
  }

  // ─── Chunk Parsing ──────────────────────────────────────────────────────────

  private _parseChunks(
    bytes: Uint8Array,
  ): Array<{ type: string; data: Uint8Array; raw: Uint8Array }> {
    const chunks: Array<{ type: string; data: Uint8Array; raw: Uint8Array }> =
      [];
    let offset = 8; // skip PNG signature

    while (offset < bytes.length) {
      if (offset + 8 > bytes.length) break;
      const length = readUint32BE(bytes, offset);
      const typeBytes = bytes.slice(offset + 4, offset + 8);
      const type = textDecode(typeBytes);
      const data = bytes.slice(offset + 8, offset + 8 + length);
      const totalLength = 4 + 4 + length + 4; // length + type + data + crc
      const raw = bytes.slice(offset, offset + totalLength);
      chunks.push({ type, data, raw });
      offset += totalLength;
    }

    return chunks;
  }

  private _buildChunk(type: string, data: Uint8Array): Uint8Array {
    const typeBytes = textEncode(type);
    const lengthBytes = writeUint32BE(data.length);
    const crcData = concatBytes(typeBytes, data);
    const crcBytes = writeUint32BE(crc32(crcData));
    return concatBytes(lengthBytes, typeBytes, data, crcBytes);
  }

  private _buildITxtData(keyword: string, text: string): Uint8Array {
    // keyword\0 + compression_flag(0) + compression_method(0) + lang\0 + translated_keyword\0 + text
    return concatBytes(
      textEncode(keyword),
      new Uint8Array([0x00, 0x00, 0x00]), // null, no_compression, method=0
      new Uint8Array([0x00]), // empty lang tag + null
      new Uint8Array([0x00]), // empty translated keyword + null
      textEncode(text),
    );
  }

  private _readITxtData(
    data: Uint8Array,
  ): { keyword: string; text: string } | null {
    try {
      // Find null terminator for keyword
      const nullIdx = data.indexOf(0x00);
      if (nullIdx < 0) return null;

      const keyword = textDecode(data.slice(0, nullIdx));
      // Skip: compression_flag(1) + compression_method(1) + lang(until null) + translated_keyword(until null)
      let cursor = nullIdx + 1 + 1 + 1; // past keyword null + 2 bytes

      // Skip lang tag
      const langEnd = data.indexOf(0x00, cursor);
      if (langEnd < 0) return null;
      cursor = langEnd + 1;

      // Skip translated keyword
      const tkEnd = data.indexOf(0x00, cursor);
      if (tkEnd < 0) return null;
      cursor = tkEnd + 1;

      const text = textDecode(data.slice(cursor));
      return { keyword, text };
    } catch {
      return null;
    }
  }
}

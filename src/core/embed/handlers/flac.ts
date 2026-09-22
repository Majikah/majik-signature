/**
 * handlers/flac.ts — FLAC handler
 *
 * FLAC files start with "fLaC" (4 bytes) followed by one or more metadata blocks.
 * Each metadata block header (4 bytes):
 *   [1B: is_last (1 bit) + block_type (7 bits)]
 *   [3B: 24-bit big-endian length]
 *
 * We embed signatures using an APPLICATION block (type = 2) with 4-byte
 * application ID "MAJK" followed by the signature JSON payload.
 */

import { FormatHandler } from "../../types";
import { concatBytes, textDecode, textEncode } from "../utils";

const FLAC_MAGIC = textEncode("fLaC");
const APPLICATION_ID = textEncode("MAJK"); // 4-byte custom Application ID

enum FlacBlockType {
  STREAMINFO = 0,
  PADDING = 1,
  APPLICATION = 2,
  SEEKTABLE = 3,
  VORBIS_COMMENT = 4,
  CUESHEET = 5,
  PICTURE = 6,
}

interface MetadataBlock {
  isLast: boolean;
  type: number;
  data: Uint8Array;
  raw: Uint8Array;
}

export class FlacHandler implements FormatHandler {
  readonly name = "FLAC";
  readonly supportedMimeTypes = ["audio/flac", "audio/x-flac"] as const;

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (mimeType === "audio/flac" || mimeType === "audio/x-flac") return true;
    if (bytes.length < 4) return false;
    return (
      bytes[0] === 0x66 && // 'f'
      bytes[1] === 0x4c && // 'L'
      bytes[2] === 0x61 && // 'a'
      bytes[3] === 0x43 // 'C'
    );
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);
    const { blocks, audioData } = this._parseMetadata(clean);

    // Build signature APPLICATION payload: [4B App ID "MAJK"][signature JSON]
    const appPayload = concatBytes(APPLICATION_ID, textEncode(signatureJson));

    // Safely clear the isLast flag bit on all existing metadata blocks
    const updatedBlocks: Uint8Array[] = blocks.map((b) => {
      const newBlock = new Uint8Array(b.raw);
      newBlock[0] &= 0x7f; // Clear bit 7 (isLast)
      return newBlock;
    });

    // Append our new APPLICATION metadata block marked as isLast = true
    const sigBlock = this._buildMetadataBlock(
      FlacBlockType.APPLICATION,
      appPayload,
      true, // isLast
    );

    return concatBytes(FLAC_MAGIC, ...updatedBlocks, sigBlock, audioData);
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    if (!this.canHandle(bytes)) return null;

    try {
      const { blocks, audioData, endOffset } = this._parseMetadata(bytes);

      // Verify overall stream integrity and ensure no trailing garbage was appended
      if (!this._validateAudioStream(audioData, bytes.length - endOffset)) {
        return null;
      }

      for (const block of blocks) {
        if (
          block.type === FlacBlockType.APPLICATION &&
          block.data.length >= 4
        ) {
          const appId = textDecode(block.data.slice(0, 4));
          // Inside FlacHandler.extract()
          if (appId === "MAJK") {
            const jsonStr = textDecode(block.data.slice(4));
            return jsonStr.replace(/\0+$/, ""); // Strip trailing null padding if present
          }
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
      const { blocks, audioData } = this._parseMetadata(bytes);

      // Filter out MAJK application metadata blocks
      const kept = blocks.filter((b) => {
        if (b.type !== FlacBlockType.APPLICATION) return true;
        if (b.data.length < 4) return true;
        const appId = textDecode(b.data.slice(0, 4));
        return appId !== "MAJK";
      });

      // Return original buffer unmodified if no signature block was found
      if (kept.length === blocks.length) {
        return bytes;
      }

      // Reconstruct metadata blocks and restore is_last bit on the final block
      const rebuiltBlocks: Uint8Array[] = kept.map((b, index) => {
        const isLast = index === kept.length - 1;
        const header = new Uint8Array(b.raw.slice(0, 4));
        if (isLast) {
          header[0] |= 0x80; // Set bit 7 to 1
        } else {
          header[0] &= 0x7f; // Clear bit 7 to 0
        }
        return concatBytes(header, b.data);
      });

      return concatBytes(FLAC_MAGIC, ...rebuiltBlocks, audioData);
    } catch {
      return bytes;
    }
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  private _parseMetadata(bytes: Uint8Array): {
    blocks: MetadataBlock[];
    audioData: Uint8Array;
    endOffset: number;
  } {
    if (bytes.length < 4 || textDecode(bytes.slice(0, 4)) !== "fLaC") {
      throw new Error("Invalid FLAC magic header");
    }

    const blocks: MetadataBlock[] = [];
    let offset = 4;

    while (offset < bytes.length) {
      if (offset + 4 > bytes.length) {
        throw new Error("Truncated metadata block header");
      }

      const headerByte = bytes[offset];
      const isLast = (headerByte & 0x80) !== 0;
      const type = headerByte & 0x7f;

      // 24-bit big-endian integer reading
      const length =
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3];

      if (offset + 4 + length > bytes.length) {
        throw new Error("Truncated metadata block payload");
      }

      const data = bytes.slice(offset + 4, offset + 4 + length);
      const raw = bytes.slice(offset, offset + 4 + length);

      blocks.push({ isLast, type, data, raw });
      offset += 4 + length;

      if (isLast) break;
    }

    const audioData = bytes.slice(offset);
    return { blocks, audioData, endOffset: offset };
  }

  private _buildMetadataBlock(
    type: number,
    data: Uint8Array,
    isLast: boolean,
  ): Uint8Array {
    const header = new Uint8Array(4);
    // Byte 0: [is_last (1 bit)][block_type (7 bits)]
    header[0] = (isLast ? 0x80 : 0x00) | (type & 0x7f);

    // Bytes 1–3: 24-bit big-endian payload size
    header[1] = (data.length >> 16) & 0xff;
    header[2] = (data.length >> 8) & 0xff;
    header[3] = data.length & 0xff;

    return concatBytes(header, data);
  }

  private _validateAudioStream(
    audioData: Uint8Array,
    expectedAudioBytes: number,
  ): boolean {
    if (audioData.length !== expectedAudioBytes) return false;
    if (audioData.length === 0) return true;

    // Validate initial audio frame sync code (14 bits: 11111111 111110xx)
    if (audioData.length >= 2) {
      if (audioData[0] !== 0xff || (audioData[1] & 0xfc) !== 0xf8) {
        return false;
      }
    }

    return true;
  }
}

// Freeze static methods
Object.freeze(FlacHandler);

// Freeze instance methods
Object.freeze(FlacHandler.prototype);

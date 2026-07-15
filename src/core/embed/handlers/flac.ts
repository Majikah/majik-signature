/**
 * handlers/flac.ts — FLAC handler
 *
 * FLAC files start with "fLaC" and a series of metadata blocks before audio frames.
 * We embed in a VORBIS_COMMENT block (block type 4) using a standard key=value pair:
 *   MAJIK-SIGNATURE=<json>
 *
 * FLAC metadata block header:
 *   [1B: last-block flag (7) | block_type (7)][3B: block_length]
 *
 * VORBIS_COMMENT format (all LE):
 *   [4B vendor_length][vendor_string]
 *   [4B comment_count]
 *   [4B comment_length][comment_utf8] × comment_count
 */

import { FormatHandler } from "../../types";
import {
  concatBytes,
  readUint32LE,
  textDecode,
  textEncode,
  writeUint32LE,
} from "../utils";

const FLAC_MAGIC = textEncode("fLaC");
const BLOCK_TYPE_STREAMINFO = 0;
const BLOCK_TYPE_VORBIS_COMMENT = 4;
const VENDOR_STRING = "MajikSignatureEmbed/1.0";

const COMMENT_KEY = "MAJIK-SIGNATURE";

export class FlacHandler implements FormatHandler {
  readonly name = "FLAC";
  readonly supportedMimeTypes = ["audio/flac", "audio/x-flac"] as const;

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (mimeType === "audio/flac" || mimeType === "audio/x-flac") return true;
    if (bytes.length < 4) return false;
    return textDecode(bytes.slice(0, 4)) === "fLaC";
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);
    const blocks = this._parseBlocks(clean);

    // Build a new VORBIS_COMMENT block with our signature
    const commentBlockData = this._buildVorbisComment(signatureJson);

    // Find existing VORBIS_COMMENT block index, or insert after STREAMINFO
    const vcIdx = blocks.findIndex((b) => b.type === BLOCK_TYPE_VORBIS_COMMENT);
    const insertAt = vcIdx >= 0 ? vcIdx : 1; // after STREAMINFO

    const newBlocks = [...blocks];
    const newBlock = {
      type: BLOCK_TYPE_VORBIS_COMMENT,
      data: commentBlockData,
    };

    if (vcIdx >= 0) {
      newBlocks[vcIdx] = newBlock;
    } else {
      newBlocks.splice(insertAt, 0, newBlock);
    }

    return this._serializeBlocks(newBlocks, clean);
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    if (!this.canHandle(bytes)) return null;
    try {
      const blocks = this._parseBlocks(bytes);
      for (const block of blocks) {
        if (block.type === BLOCK_TYPE_VORBIS_COMMENT) {
          const comments = this._readVorbisComment(block.data);
          for (const comment of comments) {
            if (comment.key === COMMENT_KEY) return comment.value;
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
      const blocks = this._parseBlocks(bytes);
      const filtered = blocks.map((b) => {
        if (b.type !== BLOCK_TYPE_VORBIS_COMMENT) return b;
        // Rebuild without our comment
        const comments = this._readVorbisComment(b.data);
        const kept = comments.filter((c) => c.key !== COMMENT_KEY);
        return {
          type: BLOCK_TYPE_VORBIS_COMMENT,
          data: this._serializeVorbisComment(kept),
        };
      });
      return this._serializeBlocks(filtered, bytes);
    } catch {
      return bytes;
    }
  }

  // ─── Block Parser ────────────────────────────────────────────────────────────

  private _parseBlocks(
    bytes: Uint8Array,
  ): Array<{ type: number; data: Uint8Array }> {
    const blocks: Array<{ type: number; data: Uint8Array }> = [];
    let offset = 4; // skip "fLaC"

    while (offset + 4 <= bytes.length) {
      const header = bytes[offset];
      const isLast = (header & 0x80) !== 0;
      const blockType = header & 0x7f;
      const length =
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3];

      const data = bytes.slice(offset + 4, offset + 4 + length);
      blocks.push({ type: blockType, data });
      offset += 4 + length;

      if (isLast) break;
    }

    return blocks;
  }

  private _serializeBlocks(
    blocks: Array<{ type: number; data: Uint8Array }>,
    originalBytes: Uint8Array,
  ): Uint8Array {
    // Find where audio data starts in original
    let audioOffset = 4;
    let offset = 4;
    while (offset + 4 <= originalBytes.length) {
      const header = originalBytes[offset];
      const isLast = (header & 0x80) !== 0;
      const length =
        (originalBytes[offset + 1] << 16) |
        (originalBytes[offset + 2] << 8) |
        originalBytes[offset + 3];
      audioOffset = offset + 4 + length;
      offset = audioOffset;
      if (isLast) break;
    }
    const audioData = originalBytes.slice(audioOffset);

    const serialized: Uint8Array[] = [FLAC_MAGIC];
    for (let i = 0; i < blocks.length; i++) {
      const isLast = i === blocks.length - 1;
      const { type, data } = blocks[i];
      const header = (isLast ? 0x80 : 0x00) | (type & 0x7f);
      const length = data.length;
      const headerBytes = new Uint8Array([
        header,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
      serialized.push(concatBytes(headerBytes, data));
    }
    serialized.push(audioData);

    return concatBytes(...serialized);
  }

  // ─── Vorbis Comment Helpers ──────────────────────────────────────────────────

  private _buildVorbisComment(signatureJson: string): Uint8Array {
    const comments = [{ key: COMMENT_KEY, value: signatureJson }];
    return this._serializeVorbisComment(comments);
  }

  private _serializeVorbisComment(
    comments: Array<{ key: string; value: string }>,
  ): Uint8Array {
    const vendor = textEncode(VENDOR_STRING);
    const vendorLength = writeUint32LE(vendor.length);
    const commentCount = writeUint32LE(comments.length);

    const commentEntries = comments.map(({ key, value }) => {
      const entry = textEncode(`${key}=${value}`);
      return concatBytes(writeUint32LE(entry.length), entry);
    });

    return concatBytes(vendorLength, vendor, commentCount, ...commentEntries);
  }

  private _readVorbisComment(
    data: Uint8Array,
  ): Array<{ key: string; value: string }> {
    const comments: Array<{ key: string; value: string }> = [];
    let offset = 0;

    const vendorLength = readUint32LE(data, offset);
    offset += 4 + vendorLength;

    const count = readUint32LE(data, offset);
    offset += 4;

    for (let i = 0; i < count; i++) {
      if (offset + 4 > data.length) break;
      const length = readUint32LE(data, offset);
      offset += 4;
      const comment = textDecode(data.slice(offset, offset + length));
      offset += length;
      const eqIdx = comment.indexOf("=");
      if (eqIdx >= 0) {
        comments.push({
          key: comment.slice(0, eqIdx).toUpperCase(),
          value: comment.slice(eqIdx + 1),
        });
      }
    }

    return comments;
  }
}

// Freeze static methods
Object.freeze(FlacHandler);

// Freeze instance methods
Object.freeze(FlacHandler.prototype);

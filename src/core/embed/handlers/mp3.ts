/**
 * handlers/mp3.ts — MP3/ID3v2 handler
 *
 * MP3 files typically begin with an ID3v2 tag.
 * We embed the signature as a TXXX (user-defined text) frame with
 * description "MAJIK-SIGNATURE" and value = signature JSON.
 *
 * If no ID3v2 header exists, we create one.
 *
 * ID3v2.3 frame layout:
 *   [4B frame_id][4B size (not syncsafe in v2.3)][2B flags][encoding(0x03=UTF-8)][description\0][value]
 *
 * ID3v2 header:
 *   "ID3" [1B major_ver=3][1B revision=0][1B flags=0][4B syncsafe_size]
 */

import { FormatHandler } from "../../types";
import { ID3_TXXX_DESCRIPTION } from "../constants";
import { concatBytes, textDecode, textEncode } from "../utils";

export class Mp3Handler implements FormatHandler {
  readonly name = "MP3";
  readonly supportedMimeTypes = ["audio/mpeg", "audio/mp3"] as const;

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (mimeType === "audio/mpeg" || mimeType === "audio/mp3") return true;
    // ID3 header
    if (
      bytes.length >= 3 &&
      bytes[0] === 0x49 &&
      bytes[1] === 0x44 &&
      bytes[2] === 0x33
    )
      return true;
    // MP3 sync bytes (0xFFEx or 0xFFFx)
    if (bytes.length >= 2 && bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0)
      return true;
    return false;
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);

    // Build TXXX frame
    const txxxFrame = this._buildTXXXFrame(ID3_TXXX_DESCRIPTION, signatureJson);

    // If existing ID3v2 header, inject frame into it; else create new header
    if (
      clean.length >= 10 &&
      clean[0] === 0x49 &&
      clean[1] === 0x44 &&
      clean[2] === 0x33
    ) {
      return this._injectFrame(clean, txxxFrame);
    } else {
      const header = this._buildID3v2Header(txxxFrame);
      return concatBytes(header, clean);
    }
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    if (!this.canHandle(bytes)) return null;
    if (bytes.length < 10) return null;
    if (bytes[0] !== 0x49 || bytes[1] !== 0x44 || bytes[2] !== 0x33)
      return null;

    try {
      const frames = this._parseID3v2Frames(bytes);
      for (const frame of frames) {
        if (frame.id === "TXXX") {
          const result = this._readTXXXFrame(frame.data);
          if (result?.description === ID3_TXXX_DESCRIPTION) {
            return result.value;
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
    if (bytes.length < 10) return bytes;
    if (bytes[0] !== 0x49 || bytes[1] !== 0x44 || bytes[2] !== 0x33)
      return bytes;

    try {
      const tagSize = this._readSyncsafeInt(bytes, 6);
      const tagEnd = 10 + tagSize;
      const audioData = bytes.slice(tagEnd);

      const frames = this._parseID3v2Frames(bytes);
      const kept = frames.filter((f) => {
        if (f.id !== "TXXX") return true;
        const result = this._readTXXXFrame(f.data);
        return result?.description !== ID3_TXXX_DESCRIPTION;
      });

      if (kept.length === 0) {
        // No frames left — drop the whole ID3 tag
        return audioData;
      }

      // Rebuild ID3 header with remaining frames
      const framesData = concatBytes(...kept.map((f) => f.raw));
      const newHeader = this._buildID3v2HeaderFromFrames(framesData);
      return concatBytes(newHeader, audioData);
    } catch {
      return bytes;
    }
  }

  // ─── ID3v2 Helpers ──────────────────────────────────────────────────────────

  private _readSyncsafeInt(bytes: Uint8Array, offset: number): number {
    return (
      ((bytes[offset] & 0x7f) << 21) |
      ((bytes[offset + 1] & 0x7f) << 14) |
      ((bytes[offset + 2] & 0x7f) << 7) |
      (bytes[offset + 3] & 0x7f)
    );
  }

  private _writeSyncsafeInt(value: number): Uint8Array {
    return new Uint8Array([
      (value >> 21) & 0x7f,
      (value >> 14) & 0x7f,
      (value >> 7) & 0x7f,
      value & 0x7f,
    ]);
  }

  private _parseID3v2Frames(
    bytes: Uint8Array,
  ): Array<{ id: string; data: Uint8Array; raw: Uint8Array }> {
    const majorVersion = bytes[3];
    const tagSize = this._readSyncsafeInt(bytes, 6);
    let offset = 10;
    const frames: Array<{ id: string; data: Uint8Array; raw: Uint8Array }> = [];

    while (offset < 10 + tagSize - 10) {
      if (offset + 10 > bytes.length) break;
      const id = textDecode(bytes.slice(offset, offset + 4));
      if (id.charCodeAt(0) === 0) break; // padding

      let frameSize: number;
      if (majorVersion === 4) {
        frameSize = this._readSyncsafeInt(bytes, offset + 4);
      } else {
        // v2.3: regular 32-bit big-endian
        frameSize =
          (bytes[offset + 4] << 24) |
          (bytes[offset + 5] << 16) |
          (bytes[offset + 6] << 8) |
          bytes[offset + 7];
      }

      const data = bytes.slice(offset + 10, offset + 10 + frameSize);
      const raw = bytes.slice(offset, offset + 10 + frameSize);
      frames.push({ id, data, raw });
      offset += 10 + frameSize;
    }

    return frames;
  }

  private _buildTXXXFrame(description: string, value: string): Uint8Array {
    const encoding = new Uint8Array([0x03]); // UTF-8
    const desc = textEncode(description);
    const nullByte = new Uint8Array([0x00]);
    const val = textEncode(value);
    const frameData = concatBytes(encoding, desc, nullByte, val);

    const frameId = textEncode("TXXX");
    const frameSize = new Uint8Array([
      (frameData.length >> 24) & 0xff,
      (frameData.length >> 16) & 0xff,
      (frameData.length >> 8) & 0xff,
      frameData.length & 0xff,
    ]);
    const frameFlags = new Uint8Array([0x00, 0x00]);

    return concatBytes(frameId, frameSize, frameFlags, frameData);
  }

  private _readTXXXFrame(
    data: Uint8Array,
  ): { description: string; value: string } | null {
    try {
      // encoding byte + description (null-terminated) + value
      let offset = 1; // skip encoding byte
      const nullIdx = data.indexOf(0x00, offset);
      if (nullIdx < 0) return null;
      const description = textDecode(data.slice(offset, nullIdx));
      const value = textDecode(data.slice(nullIdx + 1));
      return { description, value };
    } catch {
      return null;
    }
  }

  private _buildID3v2Header(framesData: Uint8Array): Uint8Array {
    return this._buildID3v2HeaderFromFrames(framesData);
  }

  private _buildID3v2HeaderFromFrames(framesData: Uint8Array): Uint8Array {
    const id3 = textEncode("ID3");
    const version = new Uint8Array([0x03, 0x00]); // ID3v2.3
    const flags = new Uint8Array([0x00]);
    const size = this._writeSyncsafeInt(framesData.length);
    return concatBytes(id3, version, flags, size, framesData);
  }

  private _injectFrame(bytes: Uint8Array, frame: Uint8Array): Uint8Array {
    const tagSize = this._readSyncsafeInt(bytes, 6);
    const tagEnd = 10 + tagSize;
    const audioData = bytes.slice(tagEnd);

    const existingFrames = this._parseID3v2Frames(bytes);
    const framesData = concatBytes(...existingFrames.map((f) => f.raw), frame);
    const newHeader = this._buildID3v2HeaderFromFrames(framesData);

    return concatBytes(newHeader, audioData);
  }
}

// Freeze static methods
Object.freeze(Mp3Handler);

// Freeze instance methods
Object.freeze(Mp3Handler.prototype);

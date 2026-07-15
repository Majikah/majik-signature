/**
 * handlers/wav.ts — WAV/RIFF handler
 *
 * WAV files are RIFF containers. We embed the signature in a LIST INFO chunk
 * using a custom IKEY entry "ISIG" (signature), which is part of the standard
 * RIFF INFO list. Audio players and DAWs ignore INFO fields they don't know.
 *
 * RIFF layout (all sizes LE):
 *   "RIFF" [4B total_size] "WAVE"
 *     "fmt " [4B size] [fmt data]
 *     "data" [4B size] [audio data]
 *     "LIST" [4B size] "INFO"
 *       "ISIG" [4B size] [signature JSON, null-padded to even length]
 */

import { FormatHandler } from "../../types";
import {
  concatBytes,
  readUint32LE,
  textDecode,
  textEncode,
  writeUint32LE,
} from "../utils";

const RIFF_MAGIC = textEncode("RIFF");
const WAVE_MAGIC = textEncode("WAVE");
const LIST_TYPE = textEncode("LIST");
const INFO_TYPE = textEncode("INFO");
const ISIG_TYPE = textEncode("ISIG");

export class WavHandler implements FormatHandler {
  readonly name = "WAV";
  readonly supportedMimeTypes = [
    "audio/wav",
    "audio/wave",
    "audio/x-wav",
  ] as const;

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (
      mimeType?.startsWith("audio/wav") ||
      mimeType === "audio/wave" ||
      mimeType === "audio/x-wav"
    )
      return true;
    if (bytes.length < 12) return false;
    const riff = textDecode(bytes.slice(0, 4));
    const wave = textDecode(bytes.slice(8, 12));
    return riff === "RIFF" && wave === "WAVE";
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);

    // Build ISIG chunk
    const payload = textEncode(signatureJson);
    // RIFF chunk data must be even-length; pad with null if odd
    const paddedPayload =
      payload.length % 2 === 1
        ? concatBytes(payload, new Uint8Array([0x00]))
        : payload;

    const isigChunk = concatBytes(
      ISIG_TYPE,
      writeUint32LE(payload.length), // actual length (not padded)
      paddedPayload,
    );

    // Build LIST INFO chunk
    const listData = concatBytes(INFO_TYPE, isigChunk);
    const listChunk = concatBytes(
      LIST_TYPE,
      writeUint32LE(listData.length),
      listData,
    );

    // Append LIST INFO after existing chunks, then fix RIFF size
    const newBody = concatBytes(clean.slice(12), listChunk);
    const riffSize = writeUint32LE(4 + newBody.length); // 4 = "WAVE"

    return concatBytes(RIFF_MAGIC, riffSize, WAVE_MAGIC, newBody);
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    if (!this.canHandle(bytes)) return null;
    try {
      const chunks = this._parseRiffChunks(bytes, 12);
      for (const chunk of chunks) {
        if (chunk.type === "LIST") {
          const listType = textDecode(chunk.data.slice(0, 4));
          if (listType === "INFO") {
            const infoChunks = this._parseRiffChunks(chunk.data, 4);
            for (const ic of infoChunks) {
              if (ic.type === "ISIG") {
                return textDecode(ic.data).replace(/\0+$/, ""); // strip null padding
              }
            }
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
      const chunks = this._parseRiffChunks(bytes, 12);
      const kept: Uint8Array[] = [];

      for (const chunk of chunks) {
        if (chunk.type === "LIST") {
          const listType = textDecode(chunk.data.slice(0, 4));
          if (listType === "INFO") {
            // Rebuild LIST INFO without ISIG
            const infoChunks = this._parseRiffChunks(chunk.data, 4);
            const filteredInfo = infoChunks.filter((ic) => ic.type !== "ISIG");

            if (filteredInfo.length === 0) {
              // Entire LIST INFO was only ISIG — drop it
              continue;
            }

            const infoBody = concatBytes(
              INFO_TYPE,
              ...filteredInfo.map((ic) => ic.raw),
            );
            const newList = concatBytes(
              LIST_TYPE,
              writeUint32LE(infoBody.length),
              infoBody,
            );
            kept.push(newList);
            continue;
          }
        }
        kept.push(chunk.raw);
      }

      const newBody = concatBytes(...kept);
      const riffSize = writeUint32LE(4 + newBody.length);
      return concatBytes(RIFF_MAGIC, riffSize, WAVE_MAGIC, newBody);
    } catch {
      return bytes;
    }
  }

  // ─── RIFF Parser ─────────────────────────────────────────────────────────────

  private _parseRiffChunks(
    bytes: Uint8Array,
    startOffset: number,
  ): Array<{ type: string; data: Uint8Array; raw: Uint8Array }> {
    const chunks: Array<{ type: string; data: Uint8Array; raw: Uint8Array }> =
      [];
    let offset = startOffset;

    while (offset + 8 <= bytes.length) {
      const type = textDecode(bytes.slice(offset, offset + 4));
      const size = readUint32LE(bytes, offset + 4);
      const paddedSize = size + (size % 2); // RIFF pads odd-sized chunks
      const data = bytes.slice(offset + 8, offset + 8 + size);
      const raw = bytes.slice(offset, offset + 8 + paddedSize);
      chunks.push({ type, data, raw });
      offset += 8 + paddedSize;
    }

    return chunks;
  }
}

// Freeze static methods
Object.freeze(WavHandler);

// Freeze instance methods
Object.freeze(WavHandler.prototype);

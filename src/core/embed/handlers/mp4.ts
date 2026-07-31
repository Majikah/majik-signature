/**
 * handlers/mp4.ts — MP4 / MOV / M4A / M4V handler
 *
 * ISO Base Media File Format (ISOBMFF) — the container used by MP4, MOV, M4A, M4V.
 * Structure is a tree of "boxes" (also called "atoms"), each with:
 *   [4B size][4B type][...data/children]
 *
 * We embed in the `udta` (user data) box inside `moov`, which is the standard
 * location for custom metadata in MP4/MOV files. QuickTime and ffmpeg preserve it.
 *
 * Strategy:
 *   moov → udta → majk (our custom 4-char type)
 *
 * If udta doesn't exist in moov, we create it.
 * If moov doesn't exist (fragmented MP4), fall through to FallbackHandler.
 */

import { FormatHandler } from "../../types";
import { MP4_BOX_TYPE } from "../constants";
import {
  concatBytes,
  readUint32BE,
  textDecode,
  textEncode,
  writeUint32BE,
} from "../utils";

const MAJK_TYPE = textEncode(MP4_BOX_TYPE); // "majk"

export class Mp4Handler implements FormatHandler {
  readonly name = "MP4/MOV";
  readonly supportedMimeTypes = [
    "video/mp4",
    "video/quicktime",
    "audio/mp4",
    "audio/m4a",
    "video/x-m4v",
    "video/m4v",
  ] as const;

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (this.supportedMimeTypes.includes(mimeType as any)) return true;
    if (bytes.length < 12) return false;
    const boxType = textDecode(bytes.slice(4, 8));
    if (boxType === "ftyp") return true;
    if (boxType === "moov" || boxType === "mdat") return true;
    return false;
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);
    const majkBox = this._buildBox(MP4_BOX_TYPE, textEncode(signatureJson));

    const { boxes, trailing: topTrailing } = this._parseBoxes(
      clean,
      0,
      clean.length,
    );
    const moovIdx = boxes.findIndex((b) => b.type === "moov");

    if (moovIdx < 0) {
      const { appendTrailer } = await import("../utils");
      return appendTrailer(clean, signatureJson);
    }

    const moovBox = boxes[moovIdx];
    const { boxes: moovChildren, trailing: moovTrailing } = this._parseBoxes(
      moovBox.data,
      0,
      moovBox.data.length,
    );
    const udtaIdx = moovChildren.findIndex((b) => b.type === "udta");

    const { boxes: existingUdtaChildren, trailing: udtaTrailing } =
      udtaIdx >= 0
        ? this._parseBoxes(
            moovChildren[udtaIdx].data,
            0,
            moovChildren[udtaIdx].data.length,
          )
        : { boxes: [], trailing: new Uint8Array(0) };

    const newUdta = this._buildBox(
      "udta",
      concatBytes(
        ...existingUdtaChildren.map((b) => b.raw),
        majkBox, // ← box-aligned, right after real children
        udtaTrailing, // ← unparseable leftovers pushed to the very end
      ),
    );

    const newMoovChildren: Uint8Array[] = [];
    if (udtaIdx >= 0) {
      // Retain the exact original index of the udta box to avoid byte shifting
      for (let i = 0; i < moovChildren.length; i++) {
        newMoovChildren.push(i === udtaIdx ? newUdta : moovChildren[i].raw);
      }
    } else {
      // If it didn't exist previously, it's safe to append it to the end
      for (let i = 0; i < moovChildren.length; i++) {
        newMoovChildren.push(moovChildren[i].raw);
      }
      newMoovChildren.push(newUdta);
    }

    const newMoov = this._buildBox(
      "moov",
      concatBytes(...newMoovChildren, moovTrailing),
    );

    const parts: Uint8Array[] = [];
    for (let i = 0; i < boxes.length; i++) {
      parts.push(i === moovIdx ? newMoov : boxes[i].raw);
    }
    return concatBytes(...parts, topTrailing);
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    if (!this.canHandle(bytes)) return null;
    try {
      const { boxes } = this._parseBoxes(bytes, 0, bytes.length);
      const moov = boxes.find((b) => b.type === "moov");

      // Fallback: If no moov box exists, check for a Tier-2 trailer
      if (!moov) {
        const { extractTrailer } = await import("../utils");
        const trailer = extractTrailer(bytes);
        return trailer ? trailer.signatureJson : null;
      }

      const { boxes: moovChildren } = this._parseBoxes(
        moov.data,
        0,
        moov.data.length,
      );
      const udta = moovChildren.find((b) => b.type === "udta");
      if (!udta) return null;

      const { boxes: udtaChildren } = this._parseBoxes(
        udta.data,
        0,
        udta.data.length,
      );
      const majk = udtaChildren.find((b) => b.type === MP4_BOX_TYPE);
      if (!majk) return null;

      return textDecode(majk.data);
    } catch {
      return null;
    }
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    if (!this.canHandle(bytes)) return bytes;
    try {
      const { boxes, trailing: topTrailing } = this._parseBoxes(
        bytes,
        0,
        bytes.length,
      );
      const moovIdx = boxes.findIndex((b) => b.type === "moov");

      // Fallback: If no moov box exists, strip the Tier-2 trailer if present
      if (moovIdx < 0) {
        const { extractTrailer } = await import("../utils");
        const trailer = extractTrailer(bytes);
        return trailer ? trailer.original : bytes;
      }

      const moovBox = boxes[moovIdx];
      const { boxes: moovChildren, trailing: moovTrailing } = this._parseBoxes(
        moovBox.data,
        0,
        moovBox.data.length,
      );
      const udtaIdx = moovChildren.findIndex((b) => b.type === "udta");
      if (udtaIdx < 0) return bytes;

      const udtaBox = moovChildren[udtaIdx];
      const { boxes: udtaChildren, trailing: udtaTrailing } = this._parseBoxes(
        udtaBox.data,
        0,
        udtaBox.data.length,
      );
      const filteredUdta = udtaChildren.filter((b) => b.type !== MP4_BOX_TYPE);

      let newMoovChildren: Uint8Array[];

      // Only remove the udta box entirely if it is completely barren of data and trailing bytes
      if (filteredUdta.length === 0 && udtaTrailing.length === 0) {
        newMoovChildren = moovChildren
          .filter((_, i) => i !== udtaIdx)
          .map((b) => b.raw);
      } else {
        const newUdta = this._buildBox(
          "udta",
          concatBytes(...filteredUdta.map((b) => b.raw), udtaTrailing),
        );
        newMoovChildren = moovChildren.map((b, i) =>
          i === udtaIdx ? newUdta : b.raw,
        );
      }

      const newMoov = this._buildBox(
        "moov",
        concatBytes(...newMoovChildren, moovTrailing),
      );
      const parts = boxes.map((b, i) => (i === moovIdx ? newMoov : b.raw));
      return concatBytes(...parts, topTrailing);
    } catch {
      return bytes;
    }
  }

  // ─── Box Parser ─────────────────────────────────────────────────────────────

  private _parseBoxes(
    bytes: Uint8Array,
    start: number,
    end: number,
  ): {
    boxes: Array<{ type: string; data: Uint8Array; raw: Uint8Array }>;
    trailing: Uint8Array;
  } {
    const boxes: Array<{ type: string; data: Uint8Array; raw: Uint8Array }> =
      [];
    let offset = start;

    while (offset + 8 <= end) {
      let size = readUint32BE(bytes, offset);
      const type = textDecode(bytes.slice(offset + 4, offset + 8));

      if (size === 1) {
        const hi = readUint32BE(bytes, offset + 8);
        const lo = readUint32BE(bytes, offset + 12);
        size = hi * 0x100000000 + lo;
      } else if (size === 0) {
        size = end - offset;
      }

      if (size < 8 || offset + size > end) break;

      const headerSize = readUint32BE(bytes, offset) === 1 ? 16 : 8;
      const data = bytes.slice(offset + headerSize, offset + size);
      const raw = bytes.slice(offset, offset + size);
      boxes.push({ type, data, raw });
      offset += size;
    }

    // Anything left over (padding, malformed box, unparseable trailing bytes)
    // — preserve it verbatim instead of silently dropping it.
    const trailing = bytes.slice(offset, end);
    return { boxes, trailing };
  }

  private _buildBox(type: string, data: Uint8Array): Uint8Array {
    const size = 8 + data.length;
    return concatBytes(writeUint32BE(size), textEncode(type), data);
  }
}

// Freeze static methods
Object.freeze(Mp4Handler);

// Freeze instance methods
Object.freeze(Mp4Handler.prototype);

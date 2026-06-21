/**
 * utils.ts — Byte manipulation, MIME sniffing, and encoding helpers
 */

import {
  CANONICAL_MTIME,
  TRAILER_MAGIC,
  TRAILER_SUFFIX_LENGTH,
} from "./constants";

// ─── Encoding ─────────────────────────────────────────────────────────────────

export function textEncode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function textDecode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** Write a 64-bit unsigned integer as 8 bytes little-endian */
export function writeUint64LE(value: number): Uint8Array {
  const buf = new Uint8Array(8);
  // JavaScript numbers are safe up to 2^53; signature JSON won't exceed that
  let v = value;
  for (let i = 0; i < 8; i++) {
    buf[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  return buf;
}

/** Read a 64-bit unsigned integer from 8 bytes little-endian */
export function readUint64LE(bytes: Uint8Array, offset: number): number {
  let value = 0;
  let multiplier = 1;
  for (let i = 0; i < 8; i++) {
    value += bytes[offset + i] * multiplier;
    multiplier *= 256;
  }
  return value;
}

/** Write a 32-bit unsigned integer as 4 bytes big-endian */
export function writeUint32BE(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

/** Read a 32-bit unsigned integer from 4 bytes big-endian */
export function readUint32BE(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0
  );
}

/** Write a 32-bit unsigned integer as 4 bytes little-endian */
export function writeUint32LE(value: number): Uint8Array {
  return new Uint8Array([
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  ]);
}

/** Read a 32-bit unsigned integer from 4 bytes little-endian */
export function readUint32LE(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

// ─── Blob / Uint8Array Conversion ─────────────────────────────────────────────

export async function blobToBytes(blob: Blob): Promise<Uint8Array> {
  const buf = await blob.arrayBuffer();
  return new Uint8Array(buf);
}

export function bytesToBlob(bytes: Uint8Array, mimeType: string): Blob {
  return new Blob([bytes as BlobPart], { type: mimeType });
}

// ─── MIME Type Detection ──────────────────────────────────────────────────────

/**
 * Detect MIME type from magic bytes.
 * Falls back to the blob's declared type, then "application/octet-stream".
 */
export function detectMimeType(bytes: Uint8Array, blobType?: string): string {
  // PDF
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46])) return "application/pdf"; // %PDF

  // PNG
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
    return "image/png";

  // JPEG
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return "image/jpeg";

  // GIF
  if (startsWith(bytes, [0x47, 0x49, 0x46, 0x38])) return "image/gif";

  // WebP (RIFF....WEBP)
  if (
    startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) &&
    bytes.length >= 12 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return "image/webp";
  }

  // RIFF-based: WAV, AVI
  if (startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) && bytes.length >= 12) {
    const fmt = textDecode(bytes.slice(8, 12));
    if (fmt === "WAVE") return "audio/wav";
    if (fmt === "AVI ") return "video/avi";
  }

  // MP3 (ID3 header or sync bytes)
  if (startsWith(bytes, [0x49, 0x44, 0x33])) return "audio/mpeg"; // ID3
  if (bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0) return "audio/mpeg"; // sync

  // FLAC
  if (startsWith(bytes, [0x66, 0x4c, 0x61, 0x43])) return "audio/flac"; // fLaC

  // OGG (Ogg/Vorbis/Opus/FLAC-in-Ogg)
  if (startsWith(bytes, [0x4f, 0x67, 0x67, 0x53])) return "audio/ogg";

  // MP4 / MOV — check ftyp box
  if (bytes.length >= 12) {
    const boxType = textDecode(bytes.slice(4, 8));
    if (boxType === "ftyp") {
      const brand = textDecode(bytes.slice(8, 12));
      if (brand.startsWith("qt") || brand === "mooV") return "video/quicktime";
      return "video/mp4";
    }
    // Some MP4s put ftyp at offset 0 with size 0
    if (boxType === "moov" || boxType === "mdat") return "video/mp4";
  }

  // MKV / WebM — EBML header
  if (startsWith(bytes, [0x1a, 0x45, 0xdf, 0xa3])) {
    // Peek into DocType
    // WebM DocType is "webm", MKV is "matroska"
    const header = textDecode(bytes.slice(0, Math.min(64, bytes.length)));
    if (header.includes("webm")) return "video/webm";
    return "video/x-matroska";
  }

  // ZIP-based (DOCX/XLSX/PPTX)
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04])) {
    // Try to detect Office format from content types
    if (blobType) {
      if (blobType.includes("wordprocessingml") || blobType.includes("docx")) {
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
      }
      if (blobType.includes("spreadsheetml") || blobType.includes("xlsx")) {
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
      }
      if (blobType.includes("presentationml") || blobType.includes("pptx")) {
        return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
      }
    }
    return "application/zip";
  }

  // Plain text
  if (isLikelyText(bytes)) return "text/plain";

  // Fall back to blob's declared type
  if (blobType && blobType !== "") return blobType;

  return "application/octet-stream";
}

function startsWith(bytes: Uint8Array, magic: number[]): boolean {
  if (bytes.length < magic.length) return false;
  return magic.every((b, i) => bytes[i] === b);
}

function isLikelyText(bytes: Uint8Array): boolean {
  const sample = bytes.slice(0, Math.min(512, bytes.length));
  let nonPrintable = 0;
  for (const b of sample) {
    if (b === 0) return false; // null byte = binary
    if (b < 0x09 || (b > 0x0d && b < 0x20 && b !== 0x1b)) nonPrintable++;
  }
  return nonPrintable / sample.length < 0.05;
}

// ─── Tier-2 Trailer ───────────────────────────────────────────────────────────

/**
 * Append a Tier-2 trailer to arbitrary bytes.
 * Layout: [original][payload_utf8][payload_length: 8 bytes LE][magic: 8 bytes]
 */
export function appendTrailer(
  original: Uint8Array,
  signatureJson: string,
): Uint8Array {
  const payload = textEncode(signatureJson);
  const lengthBytes = writeUint64LE(payload.length);
  return concatBytes(original, payload, lengthBytes, TRAILER_MAGIC);
}

/**
 * Detect and extract a Tier-2 trailer.
 * Returns the signature JSON and the original bytes (without trailer), or null.
 */
export function extractTrailer(
  bytes: Uint8Array,
): { signatureJson: string; original: Uint8Array } | null {
  if (bytes.length < TRAILER_SUFFIX_LENGTH) return null;

  // Check magic bytes at the very end
  const magic = bytes.slice(bytes.length - 8);
  if (!bufferEqual(magic, TRAILER_MAGIC)) return null;

  // Read payload length
  const payloadLength = readUint64LE(bytes, bytes.length - 16);

  const payloadStart = bytes.length - 16 - payloadLength;
  if (payloadStart < 0) return null;

  const payload = bytes.slice(payloadStart, payloadStart + payloadLength);
  const signatureJson = textDecode(payload);
  const original = bytes.slice(0, payloadStart);

  return { signatureJson, original };
}

export function bufferEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ─── CRC32 (for PNG chunks) ───────────────────────────────────────────────────

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c;
  }
  return table;
})();

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function toZippable(files: Record<string, Uint8Array>) {
  const out: Record<string, [Uint8Array, { mtime: Date }]> = {};
  for (const name of Object.keys(files)) {
    out[name] = [files[name], { mtime: CANONICAL_MTIME }];
  }
  return out;
}

/**
 * pixel-row.ts — Full MajikSignature envelope embedded as appended pixel rows
 *
 * Encodes the complete MajikSignatureJSON (Ed25519 + ML-DSA-87, ~10KB) as
 * raw RGB pixel values appended to the bottom of the image.
 *
 * ── Binary layout (per pixel row block) ──────────────────────────────────────
 *
 *   Byte 0-3:   Magic: 0x4D 0x52 0x4F 0x57  ('M','R','O','W')
 *   Byte 4-7:   Version: uint32 BE = 1
 *   Byte 8-11:  Payload length: uint32 BE (number of JSON UTF-8 bytes)
 *   Byte 12-15: Row count: uint32 BE (how many rows were appended)
 *   Byte 16+:   JSON payload (UTF-8), zero-padded to fill remaining pixels
 *
 * Each pixel carries 3 bytes (R, G, B). Alpha is always 255.
 * Bytes per row = width * 3.
 * Rows needed = ceil((16 + payloadLength) / (width * 3))
 *
 * ── Edge color blending ───────────────────────────────────────────────────────
 *
 * To minimize visual suspicion when the file is shared directly, the appended
 * rows are NOT random noise — they match the average color of the bottom edge
 * of the original image. The payload bytes are XOR'd with a repeating key
 * derived from that edge color, then stored as pixels.
 *
 * On extraction, the same XOR key is reconstructed from the row count stored
 * in the header, the original image height is computed, and the edge average
 * is re-derived from those rows.
 *
 * Wait — circular dependency: to derive the edge color we need to know which
 * rows are the original image, which requires knowing the row count, which is
 * stored in the payload rows themselves.
 *
 * Resolution: store the edge color EXPLICITLY in the header (4 bytes: R,G,B,pad).
 * The header bytes themselves are not XOR'd — only the JSON payload is.
 * This breaks the circularity cleanly.
 *
 * ── Revised layout ────────────────────────────────────────────────────────────
 *
 *   Byte 0-3:   Magic: 'MROW'
 *   Byte 4-7:   Version: 1 (uint32 BE)
 *   Byte 8-11:  Payload length (uint32 BE)
 *   Byte 12-15: Row count (uint32 BE)
 *   Byte 16:    Edge R (average R of bottom row of original image)
 *   Byte 17:    Edge G
 *   Byte 18:    Edge B
 *   Byte 19:    Reserved (0x00)
 *   Byte 20+:   JSON payload XOR'd with repeating [edgeR, edgeG, edgeB] key
 *   ...         Zero padding to fill remaining pixel capacity
 *
 * Header is 20 bytes = ceil(20/3) = 7 pixels (21 bytes, 1 byte wasted/padding).
 * Payload starts at byte 20 (pixel 7 of row 0).
 *
 * ── Strip detection ───────────────────────────────────────────────────────────
 *
 * To strip the pixel rows: read rowCount from header, remove last rowCount
 * rows. Returns original image pixels at original dimensions.
 *
 * To detect presence: check if last N rows begin with the magic bytes. We
 * try row counts from 1 to MAX_ROWS and check the magic.
 */

const MAGIC = new Uint8Array([0x4d, 0x52, 0x4f, 0x57]); // 'MROW'
const VERSION = 1;
const HEADER_SIZE = 20; // bytes
const MAX_ROWS = 32; // sanity limit — 10KB / (600px * 3B) = ~6 rows max

// ─── Public API ───────────────────────────────────────────────────────────────

export interface PixelRowEmbedResult {
  /** Modified pixel data with appended rows */
  pixels: Uint8ClampedArray;
  /** New height (original height + rowsAdded) */
  width: number;
  height: number;
  /** Number of rows appended */
  rowsAdded: number;
}

export interface PixelRowExtractResult {
  /** The full MajikSignatureJSON as a string */
  signatureJson: string;
  /** Number of appended rows that were removed */
  rowsFound: number;
  /** Original image pixels with appended rows stripped */
  originalPixels: Uint8ClampedArray;
  originalWidth: number;
  originalHeight: number;
}

/**
 * Append the full MajikSignature JSON as pixel rows at the bottom of the image.
 * The appended rows are visually blended to match the bottom edge color.
 *
 * @param pixels        RGBA pixel data of the original image
 * @param width         Image width
 * @param height        Image height
 * @param signatureJson Full MajikSignatureJSON serialized to string
 * @returns             New pixel data with appended rows, new height
 */
export function pixelRowEmbed(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
  signatureJson: string,
): PixelRowEmbedResult {
  const payload = new TextEncoder().encode(signatureJson);
  const bytesPerRow = width * 3; // RGB only, no alpha in storage

  // How many rows do we need?
  const totalBytes = HEADER_SIZE + payload.length;
  const rowsNeeded = Math.ceil(totalBytes / bytesPerRow);

  if (rowsNeeded > MAX_ROWS) {
    throw new Error(
      `Signature too large for pixel row embedding: needs ${rowsNeeded} rows, max is ${MAX_ROWS}. ` +
        `Payload is ${payload.length} bytes, image width is ${width}px.`,
    );
  }

  // Sample edge color from bottom row of original image
  const {
    r: edgeR,
    g: edgeG,
    b: edgeB,
  } = sampleBottomEdge(pixels, width, height);

  // Build the raw byte block (header + payload + padding)
  const totalCapacity = rowsNeeded * bytesPerRow;
  const block = new Uint8Array(totalCapacity); // zero-initialized = padding

  let offset = 0;

  // Magic (4 bytes)
  block.set(MAGIC, offset);
  offset += 4;

  // Version (4 bytes BE)
  writeUint32BE(block, offset, VERSION);
  offset += 4;

  // Payload length (4 bytes BE)
  writeUint32BE(block, offset, payload.length);
  offset += 4;

  // Row count (4 bytes BE)
  writeUint32BE(block, offset, rowsNeeded);
  offset += 4;

  // Edge color (3 bytes + 1 reserved)
  block[offset] = edgeR;
  block[offset + 1] = edgeG;
  block[offset + 2] = edgeB;
  block[offset + 3] = 0x00;
  offset += 4;

  // Payload XOR'd with repeating edge color key
  const key = [edgeR, edgeG, edgeB];
  for (let i = 0; i < payload.length; i++) {
    block[offset + i] = payload[i] ^ key[i % 3];
  }

  // Build new pixel array: original + appended rows
  const newHeight = height + rowsNeeded;
  const newPixels = new Uint8ClampedArray(width * newHeight * 4);

  // Copy original image
  newPixels.set(pixels, 0);

  // Write appended rows (convert RGB block to RGBA)
  const appendStart = width * height * 4;
  let blockOffset = 0;
  for (let row = 0; row < rowsNeeded; row++) {
    for (let x = 0; x < width; x++) {
      const pixelOffset = appendStart + (row * width + x) * 4;
      newPixels[pixelOffset] = block[blockOffset]; // R
      newPixels[pixelOffset + 1] = block[blockOffset + 1]; // G
      newPixels[pixelOffset + 2] = block[blockOffset + 2]; // B
      newPixels[pixelOffset + 3] = 255; // A (fully opaque)
      blockOffset += 3;
    }
  }

  return {
    pixels: newPixels,
    width,
    height: newHeight,
    rowsAdded: rowsNeeded,
  };
}

/**
 * Extract the MajikSignature JSON from pixel rows appended to the bottom.
 * Returns null if no valid pixel row signature is found.
 *
 * @param pixels  RGBA pixel data (may or may not have appended rows)
 * @param width   Image width
 * @param height  Image height
 */
export function pixelRowExtract(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
): PixelRowExtractResult | null {
  const bytesPerRow = width * 3;

  // Try to find the magic header — scan from the bottom up
  // We don't know how many rows were appended, so we probe
  for (
    let candidateRows = 1;
    candidateRows <= Math.min(MAX_ROWS, height - 1);
    candidateRows++
  ) {
    const appendedStart = height - candidateRows;
    const firstAppendedRowOffset = appendedStart * width * 4;

    // Read the first 20 bytes from the candidate appended region
    const header = new Uint8Array(HEADER_SIZE);
    for (let i = 0; i < HEADER_SIZE; i++) {
      const pixelIndex = Math.floor(i / 3);
      const channel = i % 3;
      header[i] = pixels[firstAppendedRowOffset + pixelIndex * 4 + channel];
    }

    // Check magic
    if (
      header[0] !== MAGIC[0] ||
      header[1] !== MAGIC[1] ||
      header[2] !== MAGIC[2] ||
      header[3] !== MAGIC[3]
    ) {
      continue;
    }

    // Check version
    const version = readUint32BE(header, 4);
    if (version !== VERSION) continue;

    // Read fields
    const payloadLength = readUint32BE(header, 8);
    const rowCount = readUint32BE(header, 12);
    const edgeR = header[16];
    const edgeG = header[17];
    const edgeB = header[18];

    // Sanity checks
    if (rowCount !== candidateRows) continue;
    if (payloadLength > rowCount * bytesPerRow - HEADER_SIZE) continue;
    if (payloadLength === 0) continue;

    // Read payload bytes from the appended rows
    const rawPayload = new Uint8Array(payloadLength);
    const key = [edgeR, edgeG, edgeB];

    for (let i = 0; i < payloadLength; i++) {
      const byteIndex = HEADER_SIZE + i;
      const pixelIndex = Math.floor(byteIndex / 3);
      const channel = byteIndex % 3;
      const rowIndex = Math.floor(pixelIndex / width);
      const colIndex = pixelIndex % width;
      const pixelOffset =
        (appendedStart + rowIndex) * width * 4 + colIndex * 4 + channel;

      rawPayload[i] = pixels[pixelOffset] ^ key[i % 3];
    }

    // Decode JSON
    let signatureJson: string;
    try {
      signatureJson = new TextDecoder().decode(rawPayload);
      // Quick sanity check — must be valid JSON with expected fields
      const parsed = JSON.parse(signatureJson);
      if (!parsed.version || !parsed.edSignature || !parsed.mlDsaSignature) {
        continue;
      }
    } catch {
      continue;
    }

    // Strip appended rows to recover original image
    const originalHeight = appendedStart;
    const originalPixels = pixels.slice(0, width * originalHeight * 4);

    return {
      signatureJson,
      rowsFound: candidateRows,
      originalPixels: new Uint8ClampedArray(originalPixels),
      originalWidth: width,
      originalHeight,
    };
  }

  return null;
}

/**
 * Check if an image has pixel row signature data, without extracting.
 */
export function pixelRowHasSignature(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
): boolean {
  return pixelRowExtract(pixels, width, height) !== null;
}

/**
 * Remove appended signature rows and return original image pixels.
 * If no pixel row signature is found, returns the original pixels unchanged.
 */
export function pixelRowStrip(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
): { pixels: Uint8ClampedArray; width: number; height: number } {
  const result = pixelRowExtract(pixels, width, height);
  if (!result) return { pixels, width, height };
  return {
    pixels: result.originalPixels,
    width: result.originalWidth,
    height: result.originalHeight,
  };
}

// ─── Edge color sampling ──────────────────────────────────────────────────────

/**
 * Sample the average RGB color of the bottom row of the original image.
 * Used as the XOR blending key so appended rows blend visually.
 */
function sampleBottomEdge(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
): { r: number; g: number; b: number } {
  if (height === 0 || width === 0) return { r: 255, g: 255, b: 255 };

  const rowStart = (height - 1) * width * 4;
  let sumR = 0,
    sumG = 0,
    sumB = 0;

  for (let x = 0; x < width; x++) {
    const idx = rowStart + x * 4;
    sumR += pixels[idx];
    sumG += pixels[idx + 1];
    sumB += pixels[idx + 2];
  }

  return {
    r: Math.round(sumR / width),
    g: Math.round(sumG / width),
    b: Math.round(sumB / width),
  };
}

// ─── Byte helpers ─────────────────────────────────────────────────────────────

function writeUint32BE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

function readUint32BE(buf: Uint8Array, offset: number): number {
  return (
    buf[offset] * 0x1000000 + // avoid sign bit issue with <<
    (buf[offset + 1] << 16) +
    (buf[offset + 2] << 8) +
    buf[offset + 3]
  );
}

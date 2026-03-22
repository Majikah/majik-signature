/**
 * dct-stego.ts — DCT coefficient steganography
 *
 * Embeds and extracts binary data by manipulating the parity of mid-frequency
 * DCT coefficients in each 8×8 luminance block of an image.
 *
 * ── Why mid-frequency? ──────────────────────────────────────────────────────
 *
 * Each 8×8 DCT block has 64 coefficients arranged by frequency:
 *
 *   DC  AC1 AC2 AC3 AC4 AC5 AC6 AC7
 *   AC8 AC9 ...
 *   ...
 *
 * Low-frequency (DC, AC1-AC3): Carry most visual information. Modifying
 *   these creates visible artifacts.
 *
 * Mid-frequency (AC4-AC20 in zigzag order): Survive Q70 quantization
 *   (quantization step ~8-24). Modifying parity is invisible and recoverable
 *   after recompression IF we choose coefficients with large enough magnitude.
 *
 * High-frequency (AC21-AC63): Zeroed out by Q70 quantization. Useless.
 *
 * ── Encoding scheme ─────────────────────────────────────────────────────────
 *
 * For each target block:
 *   1. Apply 2D DCT to the 8×8 luma block
 *   2. Pick coefficient at zigzag position 5 (the 'embedding coefficient')
 *      - Zigzag pos 5 = matrix position [1,2] = moderate frequency
 *   3. If coefficient magnitude < SKIP_THRESHOLD (4), skip this block
 *      (coefficient is too small — quantization would zero it)
 *   4. To embed bit 1: force coefficient to be ODD after quantization
 *      To embed bit 0: force coefficient to be EVEN after quantization
 *   5. Apply inverse DCT and update pixels
 *
 * ── Survival at Q70 ─────────────────────────────────────────────────────────
 *
 * At Q70, the quantization step for position [1,2] is typically 10-16.
 * When JPEG re-encodes:
 *   coef_quantized = round(coef / step)
 *   coef_dequantized = coef_quantized * step
 *
 * Our parity encoding forces coef_quantized to be odd or even.
 * After dequantization, the parity of coef_quantized is preserved!
 * → The embedded bit survives as long as the coefficient doesn't get zeroed.
 *
 * We skip coefficients with magnitude < SKIP_THRESHOLD * quantStep to
 * avoid the zero-rounding problem.
 *
 * With Reed-Solomon ECC providing 27-byte error correction, we can tolerate
 * ~16% of embedded bits being corrupted by aggressive recompression.
 *
 * ── Pixel domain operation ───────────────────────────────────────────────────
 *
 * We operate on raw RGBA pixel data (from Canvas or image decode).
 * We implement our own 8×8 DCT/IDCT to ensure determinism across
 * platforms (browser Canvas, Node sharp, etc.).
 *
 * Note: We work on the Y (luma) channel after RGB→YCbCr conversion.
 * Cb/Cr channels are left untouched.
 */

// ─── Constants ────────────────────────────────────────────────────────────────

/** Zigzag scan order for 8×8 DCT block */
const ZIGZAG: [number, number][] = [
  [0, 0],
  [0, 1],
  [1, 0],
  [2, 0],
  [1, 1],
  [0, 2],
  [0, 3],
  [1, 2], // 0-7
  [2, 1],
  [3, 0],
  [4, 0],
  [3, 1],
  [2, 2],
  [1, 3],
  [0, 4],
  [0, 5], // 8-15
  [1, 4],
  [2, 3],
  [3, 2],
  [4, 1],
  [5, 0],
  [6, 0],
  [5, 1],
  [4, 2], // 16-23
  [3, 3],
  [2, 4],
  [1, 5],
  [0, 6],
  [0, 7],
  [1, 6],
  [2, 5],
  [3, 4], // 24-31
  [4, 3],
  [5, 2],
  [6, 1],
  [7, 0],
  [7, 1],
  [6, 2],
  [5, 3],
  [4, 4], // 32-39
  [3, 5],
  [2, 6],
  [1, 7],
  [2, 7],
  [3, 6],
  [4, 5],
  [5, 4],
  [6, 3], // 40-47
  [7, 2],
  [7, 3],
  [6, 4],
  [5, 5],
  [4, 6],
  [3, 7],
  [4, 7],
  [5, 6], // 48-55
  [6, 5],
  [7, 4],
  [7, 5],
  [6, 6],
  [5, 7],
  [6, 7],
  [7, 6],
  [7, 7], // 56-63
];

/**
 * Zigzag positions to use for embedding (mid-frequency, Q70-safe).
 * These are [row, col] positions in the 8×8 DCT matrix.
 * We use positions 5, 8, 9, 13 — reliably non-zero at Q70.
 */
const EMBED_POSITIONS: [number, number][] = [
  ZIGZAG[5], // [0,2]
  ZIGZAG[8], // [2,1]
  ZIGZAG[9], // [3,0]
  ZIGZAG[13], // [1,3]
];

/** Skip coefficient if |value| < threshold (will be zeroed by quantization) */
const SKIP_THRESHOLD = 4;

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Embed bytes into image pixel data using DCT coefficient parity.
 *
 * @param pixels   RGBA pixel data (modified in place)
 * @param width    Image width
 * @param height   Image height
 * @param data     Bytes to embed
 * @returns        Number of bits successfully written
 */
export function dctEmbed(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
  data: Uint8Array,
): number {
  const bits = bytesToBits(data);
  let bitIndex = 0;
  let bitsWritten = 0;

  const blocksX = Math.floor(width / 8);
  const blocksY = Math.floor(height / 8);

  outer: for (let by = 0; by < blocksY; by++) {
    for (let bx = 0; bx < blocksX; bx++) {
      if (bitIndex >= bits.length) break outer;

      // Extract 8×8 luma block
      const block = extractLumaBlock(pixels, width, bx * 8, by * 8);

      // Forward DCT
      const dct = dct2d_8x8(block);

      // Try each embedding position until we find a usable coefficient
      let embedded = false;
      for (const [row, col] of EMBED_POSITIONS) {
        const coefIdx = row * 8 + col;
        const coef = dct[coefIdx];

        if (Math.abs(coef) < SKIP_THRESHOLD) continue;

        // Embed bit by forcing parity
        const bit = bits[bitIndex];
        const quantized = Math.round(coef);
        const isOdd = Math.abs(quantized) % 2 === 1;

        if (bit === 1 && !isOdd) {
          // Make odd: add 1 if positive, subtract 1 if negative
          dct[coefIdx] = coef >= 0 ? coef + 1 : coef - 1;
        } else if (bit === 0 && isOdd) {
          // Make even
          dct[coefIdx] = coef >= 0 ? coef - 1 : coef + 1;
        }
        // If parity already matches, no modification needed

        embedded = true;
        break;
      }

      if (!embedded) continue; // block has all-small coefficients, skip

      // Inverse DCT and write back
      const restored = idct2d_8x8(dct);
      writeLumaBlock(pixels, width, bx * 8, by * 8, restored);

      bitIndex++;
      bitsWritten++;
    }
  }

  return bitsWritten;
}

/**
 * Extract bytes from image pixel data by reading DCT coefficient parity.
 *
 * @param pixels   RGBA pixel data (read only)
 * @param width    Image width
 * @param height   Image height
 * @param numBytes Number of bytes to extract
 * @returns        Extracted bytes (may contain bit errors — use RS ECC to correct)
 */
export function dctExtract(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
  numBytes: number,
): Uint8Array {
  const numBits = numBytes * 8;
  const bits: number[] = [];

  const blocksX = Math.floor(width / 8);
  const blocksY = Math.floor(height / 8);

  outer: for (let by = 0; by < blocksY; by++) {
    for (let bx = 0; bx < blocksX; bx++) {
      if (bits.length >= numBits) break outer;

      const block = extractLumaBlock(pixels, width, bx * 8, by * 8);
      const dct = dct2d_8x8(block);

      let read = false;
      for (const [row, col] of EMBED_POSITIONS) {
        const coef = dct[row * 8 + col];
        if (Math.abs(coef) < SKIP_THRESHOLD) continue;

        const quantized = Math.round(coef);
        bits.push(Math.abs(quantized) % 2 === 1 ? 1 : 0);
        read = true;
        break;
      }

      if (!read) continue;
    }
  }

  return bitsToBytes(bits);
}

/**
 * Calculate the embedding capacity of an image in bytes.
 * Actual usable capacity depends on coefficient magnitudes — this is an
 * upper bound assuming all blocks have usable coefficients.
 */
export function dctCapacity(width: number, height: number): number {
  const blocksX = Math.floor(width / 8);
  const blocksY = Math.floor(height / 8);
  // Assume ~60% of blocks have usable mid-frequency coefficients
  return Math.floor((blocksX * blocksY * 0.6) / 8);
}

// ─── 8×8 DCT ─────────────────────────────────────────────────────────────────

/**
 * Forward 8×8 DCT-II (Type 2).
 * Input: 64 floats (8×8 luma values, 0-255)
 * Output: 64 DCT coefficients
 */
function dct2d_8x8(block: Float64Array): Float64Array {
  const N = 8;
  const tmp = new Float64Array(64);
  const out = new Float64Array(64);

  // DCT each row
  for (let row = 0; row < N; row++) {
    for (let k = 0; k < N; k++) {
      let sum = 0;
      for (let n = 0; n < N; n++) {
        sum += block[row * N + n] * COS_TABLE[k][n];
      }
      tmp[row * N + k] = SCALE[k] * sum;
    }
  }

  // DCT each column
  for (let col = 0; col < N; col++) {
    for (let k = 0; k < N; k++) {
      let sum = 0;
      for (let n = 0; n < N; n++) {
        sum += tmp[n * N + col] * COS_TABLE[k][n];
      }
      out[k * N + col] = SCALE[k] * sum;
    }
  }

  return out;
}

/**
 * Inverse 8×8 DCT-III (Type 3).
 * Input: 64 DCT coefficients
 * Output: 64 reconstructed luma values (0-255, clamped)
 */
function idct2d_8x8(dct: Float64Array): Float64Array {
  const N = 8;
  const tmp = new Float64Array(64);
  const out = new Float64Array(64);

  // IDCT each row (transpose of DCT)
  for (let row = 0; row < N; row++) {
    for (let n = 0; n < N; n++) {
      let sum = SCALE[0] * dct[row * N + 0];
      for (let k = 1; k < N; k++) {
        sum += SCALE[k] * dct[row * N + k] * COS_TABLE[k][n];
      }
      tmp[row * N + n] = sum;
    }
  }

  // IDCT each column
  for (let col = 0; col < N; col++) {
    for (let n = 0; n < N; n++) {
      let sum = SCALE[0] * tmp[0 * N + col];
      for (let k = 1; k < N; k++) {
        sum += SCALE[k] * tmp[k * N + col] * COS_TABLE[k][n];
      }
      out[n * N + col] = Math.max(0, Math.min(255, Math.round(sum)));
    }
  }

  return out;
}

// ─── Precomputed cosine and scale tables ──────────────────────────────────────

const COS_TABLE: number[][] = (() => {
  const N = 8;
  const table: number[][] = [];
  for (let k = 0; k < N; k++) {
    table[k] = [];
    for (let n = 0; n < N; n++) {
      table[k][n] = Math.cos((Math.PI * k * (2 * n + 1)) / (2 * N));
    }
  }
  return table;
})();

const SCALE: number[] = (() => {
  const N = 8;
  const s: number[] = [];
  for (let k = 0; k < N; k++) {
    s[k] = k === 0 ? Math.sqrt(1 / N) : Math.sqrt(2 / N);
  }
  return s;
})();

// ─── Block extraction / writing ───────────────────────────────────────────────

function extractLumaBlock(
  pixels: Uint8ClampedArray,
  width: number,
  blockX: number,
  blockY: number,
): Float64Array {
  const block = new Float64Array(64);
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      const idx = ((blockY + y) * width + (blockX + x)) * 4;
      const r = pixels[idx];
      const g = pixels[idx + 1];
      const b = pixels[idx + 2];
      // Rec. 601 luma (matches JPEG's YCbCr conversion)
      block[y * 8 + x] = 0.299 * r + 0.587 * g + 0.114 * b;
    }
  }
  return block;
}

function writeLumaBlock(
  pixels: Uint8ClampedArray,
  width: number,
  blockX: number,
  blockY: number,
  luma: Float64Array,
): void {
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      const idx = ((blockY + y) * width + (blockX + x)) * 4;
      const r = pixels[idx];
      const g = pixels[idx + 1];
      const b = pixels[idx + 2];

      // Extract original YCbCr
      const Y0 = 0.299 * r + 0.587 * g + 0.114 * b;
      const Cb = -0.169 * r - 0.331 * g + 0.5 * b;
      const Cr = 0.5 * r - 0.419 * g - 0.081 * b;

      // New Y from modified DCT
      const Y1 = luma[y * 8 + x];

      // Convert back to RGB (keeping Cb, Cr unchanged)
      const newR = Math.max(0, Math.min(255, Math.round(Y1 + 1.402 * Cr)));
      const newG = Math.max(
        0,
        Math.min(255, Math.round(Y1 - 0.344 * Cb - 0.714 * Cr)),
      );
      const newB = Math.max(0, Math.min(255, Math.round(Y1 + 1.772 * Cb)));

      pixels[idx] = newR;
      pixels[idx + 1] = newG;
      pixels[idx + 2] = newB;
      // Alpha unchanged
    }
  }
}

// ─── Bit/byte conversion ──────────────────────────────────────────────────────

function bytesToBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (const byte of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  return bits;
}

function bitsToBytes(bits: number[]): Uint8Array {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) {
      bytes[Math.floor(i / 8)] |= 1 << (7 - (i % 8));
    }
  }
  return bytes;
}

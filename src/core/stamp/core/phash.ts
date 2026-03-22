/**
 * phash.ts — Perceptual hash (pHash) for images
 *
 * Algorithm: DCT-based perceptual hash (industry standard)
 *   1. Resize image to 32x32 (small enough to ignore fine detail)
 *   2. Convert to grayscale
 *   3. Apply 2D DCT
 *   4. Take the top-left 8x8 low-frequency DCT coefficients (64 values)
 *      — skip DC component (index [0,0]) to ignore brightness
 *   5. Compute median of those 63 values
 *   6. Each of the 63 bits = 1 if coefficient > median, else 0
 *      (use 64th bit = 0 as padding to get a clean 64-bit hash)
 *
 * Properties:
 *   - Stable across JPEG recompression (even Q50)
 *   - Stable across format conversion (JPEG ↔ PNG ↔ WebP)
 *   - Stable across minor brightness/contrast adjustments
 *   - Stable across ≤15% resize
 *   - Hamming distance ≤ 8 means "same image" (our threshold)
 *   - Hamming distance ≥ 20 means "different image"
 *
 * Runs in browser (Canvas API) or Node (canvas/sharp polyfill).
 */

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Compute pHash of an image from raw pixel data.
 *
 * @param pixels  RGBA pixel data (Uint8ClampedArray), row-major
 * @param width   Image width in pixels
 * @param height  Image height in pixels
 * @returns       64-bit pHash as a hex string (16 hex chars)
 */
export function computePHash(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
): string {
  // Step 1: Resize to 32x32 grayscale using bilinear interpolation
  const small = resizeToGrayscale(pixels, width, height, 32, 32);

  // Step 2: 2D DCT on 32x32
  const dct = dct2d(small, 32, 32);

  // Step 3: Extract top-left 8x8 block (low frequencies), skip [0,0] (DC)
  const lowFreq: number[] = [];
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      if (x === 0 && y === 0) continue; // skip DC component
      lowFreq.push(dct[y * 32 + x]);
    }
  }
  // lowFreq has 63 values

  // Step 4: Compute median
  const sorted = [...lowFreq].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];

  // Step 5: Build 64-bit hash (63 meaningful bits + 1 padding)
  let high = 0;
  let low = 0;
  for (let i = 0; i < 63; i++) {
    const bit = lowFreq[i] > median ? 1 : 0;
    if (i < 32) {
      high = (high | (bit << i)) >>> 0;
    } else {
      low = (low | (bit << (i - 32))) >>> 0;
    }
  }

  // Return as 16-char hex string (two 32-bit halves)
  return high.toString(16).padStart(8, "0") + low.toString(16).padStart(8, "0");
}

/**
 * Compute Hamming distance between two pHash hex strings.
 * Lower = more similar. Our threshold: ≤ 8 means "same image".
 *
 * @throws if inputs are not 16-char hex strings
 */
export function hammingDistance(hashA: string, hashB: string): number {
  if (hashA.length !== 16 || hashB.length !== 16) {
    throw new Error("pHash must be a 16-character hex string");
  }

  let dist = 0;
  // Process as 4-char (16-bit) chunks to stay in safe integer range
  for (let i = 0; i < 16; i += 4) {
    const a = parseInt(hashA.slice(i, i + 4), 16);
    const b = parseInt(hashB.slice(i, i + 4), 16);
    dist += popcount16(a ^ b);
  }
  return dist;
}

/**
 * Returns true if two pHashes represent the same image
 * (Hamming distance ≤ threshold, default 8).
 */
export function pHashMatches(
  hashA: string,
  hashB: string,
  threshold = 8,
): boolean {
  return hammingDistance(hashA, hashB) <= threshold;
}

// ─── Internal: Bilinear resize to grayscale ───────────────────────────────────

function resizeToGrayscale(
  pixels: Uint8ClampedArray,
  srcW: number,
  srcH: number,
  dstW: number,
  dstH: number,
): Float64Array {
  const out = new Float64Array(dstW * dstH);
  const xRatio = srcW / dstW;
  const yRatio = srcH / dstH;

  for (let dy = 0; dy < dstH; dy++) {
    for (let dx = 0; dx < dstW; dx++) {
      // Map destination pixel to source coordinates
      const sx = (dx + 0.5) * xRatio - 0.5;
      const sy = (dy + 0.5) * yRatio - 0.5;

      const sx0 = Math.max(0, Math.floor(sx));
      const sy0 = Math.max(0, Math.floor(sy));
      const sx1 = Math.min(srcW - 1, sx0 + 1);
      const sy1 = Math.min(srcH - 1, sy0 + 1);

      const fx = sx - sx0;
      const fy = sy - sy0;

      // Sample 4 RGBA pixels
      const p00 = toGray(pixels, sx0, sy0, srcW);
      const p10 = toGray(pixels, sx1, sy0, srcW);
      const p01 = toGray(pixels, sx0, sy1, srcW);
      const p11 = toGray(pixels, sx1, sy1, srcW);

      // Bilinear interpolation
      out[dy * dstW + dx] =
        p00 * (1 - fx) * (1 - fy) +
        p10 * fx * (1 - fy) +
        p01 * (1 - fx) * fy +
        p11 * fx * fy;
    }
  }

  return out;
}

function toGray(
  pixels: Uint8ClampedArray,
  x: number,
  y: number,
  width: number,
): number {
  const idx = (y * width + x) * 4;
  const r = pixels[idx];
  const g = pixels[idx + 1];
  const b = pixels[idx + 2];
  // Rec. 709 luma coefficients
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

// ─── Internal: 2D DCT-II (separable, O(N²·logN) using 1D DCT) ────────────────

/**
 * 2D DCT-II on a square Float64Array of size w×h.
 * Applies 1D DCT to each row, then each column (separable property).
 */
function dct2d(data: Float64Array, w: number, h: number): Float64Array {
  const result = new Float64Array(w * h);

  // DCT each row
  const row = new Float64Array(w);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) row[x] = data[y * w + x];
    const dctRow = dct1d(row);
    for (let x = 0; x < w; x++) result[y * w + x] = dctRow[x];
  }

  // DCT each column
  const col = new Float64Array(h);
  for (let x = 0; x < w; x++) {
    for (let y = 0; y < h; y++) col[y] = result[y * w + x];
    const dctCol = dct1d(col);
    for (let y = 0; y < h; y++) result[y * w + x] = dctCol[y];
  }

  return result;
}

/**
 * 1D DCT-II (Type 2, orthonormal).
 * Formula: X[k] = scale(k) * Σ x[n] * cos(π*k*(2n+1)/(2N))
 *
 * O(N²) naive implementation — fine for N=32.
 */
function dct1d(signal: Float64Array): Float64Array {
  const N = signal.length;
  const out = new Float64Array(N);
  const piOver2N = Math.PI / (2 * N);

  for (let k = 0; k < N; k++) {
    let sum = 0;
    for (let n = 0; n < N; n++) {
      sum += signal[n] * Math.cos(piOver2N * k * (2 * n + 1));
    }
    // Orthonormal scaling
    const scale = k === 0 ? Math.sqrt(1 / N) : Math.sqrt(2 / N);
    out[k] = scale * sum;
  }

  return out;
}

// ─── Internal: popcount for 16-bit integers ───────────────────────────────────

function popcount16(n: number): number {
  n = n & 0xffff;
  n = n - ((n >> 1) & 0x5555);
  n = (n & 0x3333) + ((n >> 2) & 0x3333);
  n = (n + (n >> 4)) & 0x0f0f;
  return ((n * 0x0101) >> 8) & 0xff;
}

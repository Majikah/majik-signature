/**
 * reed-solomon.ts — Simple Reed-Solomon ECC for image signature stubs
 *
 * We use a GF(2^8) Reed-Solomon code with primitive polynomial 0x11d
 * (the standard one used by QR codes and many ECC systems).
 *
 * This is a SYSTEMATIC code:
 *   encoded = [data bytes | parity bytes]
 *
 * Configuration:
 *   - Up to MAX_DATA_BYTES data bytes
 *   - EC_SYMBOLS parity bytes → can correct up to EC_SYMBOLS/2 byte errors
 *   - With 55 parity bytes → corrects up to 27 byte errors
 *   - ~50% error rate on the ECC block → survives moderate DCT corruption
 *
 * At Q70 JPEG with our mid-frequency encoding, empirically ~10-20% of
 * bits get flipped. RS with 33% parity overhead handles this comfortably.
 *
 * Note: This is a simplified implementation suitable for fixed block sizes.
 * For production use, consider the `@nuintun/reed-solomon` package.
 *
 * ── TypeScript compatibility note ─────────────────────────────────────────────
 * Newer TS DOM types distinguish Uint8Array<ArrayBuffer> from
 * Uint8Array<ArrayBufferLike>. The array-literal constructor overload
 * `new Uint8Array([1, 2, 3])` infers ArrayBufferLike, which causes
 * assignment errors when the target variable is typed as plain Uint8Array.
 *
 * Fix: use the u8() helper for all array-literal constructions.
 * Uint8Array.from(iterable) always returns Uint8Array<ArrayBuffer>
 * across all TypeScript and lib versions.
 */

// ─── Compatibility helper ─────────────────────────────────────────────────────

/**
 * Create a Uint8Array from a number array.
 * Uint8Array.from() always returns Uint8Array<ArrayBuffer>, unlike
 * `new Uint8Array([...])` which infers Uint8Array<ArrayBufferLike>
 * in newer TS DOM lib types, causing assignment errors.
 */
function u8(values: number[]): Uint8Array {
  return Uint8Array.from(values);
}

// ─── GF(2^8) arithmetic ───────────────────────────────────────────────────────

const PRIMITIVE_POLY = 0x11d; // x^8 + x^4 + x^3 + x^2 + 1

// Precompute log/antilog tables for fast GF(2^8) multiply
const gfExp = new Uint8Array(512);
const gfLog = new Uint8Array(256);

(function buildTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    gfExp[i] = x;
    gfLog[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= PRIMITIVE_POLY;
  }
  for (let i = 255; i < 512; i++) {
    gfExp[i] = gfExp[i - 255];
  }
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return gfExp[gfLog[a] + gfLog[b]];
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error("GF division by zero");
  if (a === 0) return 0;
  return gfExp[(gfLog[a] - gfLog[b] + 255) % 255];
}

function gfPow(x: number, power: number): number {
  return gfExp[(gfLog[x] * power) % 255];
}

function gfInverse(x: number): number {
  return gfExp[255 - gfLog[x]];
}

// ─── Polynomial operations ────────────────────────────────────────────────────
// Polynomials are Uint8Array, index 0 = highest degree term.

function polyMul(p: Uint8Array, q: Uint8Array): Uint8Array {
  const result = new Uint8Array(p.length + q.length - 1);
  for (let i = 0; i < p.length; i++) {
    for (let j = 0; j < q.length; j++) {
      result[i + j] ^= gfMul(p[i], q[j]);
    }
  }
  return result;
}

function polyEval(poly: Uint8Array, x: number): number {
  let y = poly[0];
  for (let i = 1; i < poly.length; i++) {
    y = gfMul(y, x) ^ poly[i];
  }
  return y;
}

// ─── Generator polynomial ─────────────────────────────────────────────────────

function makeGenerator(nEccSymbols: number): Uint8Array {
  let g: Uint8Array = u8([1]);
  for (let i = 0; i < nEccSymbols; i++) {
    g = polyMul(g, u8([1, gfPow(2, i)]));
  }
  return g;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export const RS_DATA_BYTES = 150; // must match STUB_SIZE in stub.ts (150 bytes)
export const RS_ECC_BYTES = 75; // ~50% overhead → corrects up to 37 byte errors
export const RS_TOTAL_BYTES = RS_DATA_BYTES + RS_ECC_BYTES; // 225 bytes total

/**
 * Encode data bytes with Reed-Solomon ECC.
 *
 * @param data  Up to RS_DATA_BYTES bytes
 * @returns     RS_TOTAL_BYTES bytes (data + parity), systematic
 */
export function rsEncode(data: Uint8Array): Uint8Array {
  if (data.length > RS_DATA_BYTES) {
    throw new Error(
      `RS encode: data too long (${data.length} > ${RS_DATA_BYTES})`,
    );
  }

  // Pad data to RS_DATA_BYTES
  const padded = new Uint8Array(RS_DATA_BYTES);
  padded.set(data);

  const generator = makeGenerator(RS_ECC_BYTES);

  // Polynomial division: data * x^RS_ECC_BYTES mod generator
  const msg = new Uint8Array(RS_DATA_BYTES + RS_ECC_BYTES);
  msg.set(padded);

  for (let i = 0; i < RS_DATA_BYTES; i++) {
    const coef = msg[i];
    if (coef !== 0) {
      for (let j = 1; j < generator.length; j++) {
        msg[i + j] ^= gfMul(generator[j], coef);
      }
    }
  }

  // Result: original data + parity (last RS_ECC_BYTES bytes)
  const result = new Uint8Array(RS_TOTAL_BYTES);
  result.set(padded, 0);
  result.set(msg.slice(RS_DATA_BYTES), RS_DATA_BYTES);
  return result;
}

/**
 * Decode and error-correct a received codeword.
 *
 * @param received  RS_TOTAL_BYTES bytes (potentially with bit errors)
 * @returns         RS_DATA_BYTES bytes of corrected data, or null if uncorrectable
 */
export function rsDecode(received: Uint8Array): Uint8Array | null {
  if (received.length !== RS_TOTAL_BYTES) return null;

  try {
    // Step 1: Compute syndromes
    const syndromes = new Uint8Array(RS_ECC_BYTES);
    let hasErrors = false;
    for (let i = 0; i < RS_ECC_BYTES; i++) {
      syndromes[i] = polyEval(received, gfPow(2, i));
      if (syndromes[i] !== 0) hasErrors = true;
    }

    if (!hasErrors) {
      // No errors — return data portion
      return received.slice(0, RS_DATA_BYTES);
    }

    // Step 2: Berlekamp-Massey algorithm to find error locator polynomial
    const errLoc = berlekampMassey(syndromes);
    if (!errLoc) return null;

    const nErrors = errLoc.length - 1;
    if (nErrors > Math.floor(RS_ECC_BYTES / 2)) return null; // too many errors

    // Step 3: Chien search — find error positions
    const errPos: number[] = [];
    for (let i = 0; i < RS_TOTAL_BYTES; i++) {
      if (polyEval(errLoc, gfPow(2, i)) === 0) {
        errPos.push(RS_TOTAL_BYTES - 1 - i);
      }
    }

    if (errPos.length !== nErrors) return null;

    // Step 4: Forney algorithm — compute error magnitudes
    const corrected = new Uint8Array(received);
    const errMagnitudes = forney(syndromes, errLoc, errPos);
    for (let i = 0; i < errPos.length; i++) {
      corrected[errPos[i]] ^= errMagnitudes[i];
    }

    return corrected.slice(0, RS_DATA_BYTES);
  } catch {
    return null;
  }
}

// ─── Berlekamp-Massey ─────────────────────────────────────────────────────────

function berlekampMassey(syndromes: Uint8Array): Uint8Array | null {
  let errLoc: Uint8Array = u8([1]);
  let oldLoc: Uint8Array = u8([1]);

  for (let i = 0; i < syndromes.length; i++) {
    // Shift oldLoc by appending a zero — allocate a new Uint8Array (no spread)
    const shifted = new Uint8Array(oldLoc.length + 1);
    shifted.set(oldLoc);
    oldLoc = shifted;

    let delta = syndromes[i];
    for (let j = 1; j < errLoc.length; j++) {
      delta ^= gfMul(errLoc[errLoc.length - 1 - j], syndromes[i - j]);
    }

    if (delta === 0) continue;

    if (oldLoc.length > errLoc.length) {
      const newLoc = new Uint8Array(oldLoc.length);
      for (let j = 0; j < oldLoc.length; j++) {
        newLoc[j] = gfMul(oldLoc[j], delta);
      }
      const scaledOld = new Uint8Array(errLoc.length);
      for (let j = 0; j < errLoc.length; j++) {
        scaledOld[j] = gfMul(errLoc[j], gfInverse(delta));
      }
      oldLoc = scaledOld;
      errLoc = newLoc;
    }

    const scaled = new Uint8Array(oldLoc.length);
    for (let j = 0; j < oldLoc.length; j++) {
      scaled[j] = gfMul(oldLoc[j], delta);
    }

    if (scaled.length < errLoc.length) {
      const padded = new Uint8Array(errLoc.length);
      padded.set(scaled, errLoc.length - scaled.length);
      for (let j = 0; j < errLoc.length; j++) errLoc[j] ^= padded[j];
    } else {
      const padded = new Uint8Array(scaled.length);
      padded.set(errLoc, scaled.length - errLoc.length);
      for (let j = 0; j < scaled.length; j++) scaled[j] ^= padded[j];
      errLoc = scaled;
    }
  }

  const nErrors = errLoc.length - 1;
  if (nErrors * 2 > syndromes.length) return null;

  return errLoc;
}

// ─── Forney algorithm ─────────────────────────────────────────────────────────

function forney(
  syndromes: Uint8Array,
  errLoc: Uint8Array,
  errPos: number[],
): Uint8Array {
  // Error evaluator polynomial: Ω = S * σ mod x^(2t)
  // Reverse syndromes without spread — avoids ArrayBufferLike inference
  const synd = new Uint8Array(syndromes.length);
  for (let i = 0; i < syndromes.length; i++) {
    synd[i] = syndromes[syndromes.length - 1 - i];
  }

  let errEval = polyMul(synd, errLoc);
  errEval = errEval.slice(errEval.length - syndromes.length);

  const magnitudes = new Uint8Array(errPos.length);

  for (let i = 0; i < errPos.length; i++) {
    const Xi = gfPow(2, errPos[i]);
    const XiInv = gfInverse(Xi);

    // Forney numerator: Ω(Xi^-1)
    const num = polyEval(errEval, XiInv);

    // Forney denominator: σ'(Xi^-1) — formal derivative of error locator
    let denom = 1;
    for (let j = 0; j < errPos.length; j++) {
      if (j !== i) {
        denom = gfMul(denom, gfMul(Xi, gfPow(2, errPos[j])) ^ 1);
      }
    }

    magnitudes[i] = gfMul(Xi, gfDiv(num, denom));
  }

  return magnitudes;
}

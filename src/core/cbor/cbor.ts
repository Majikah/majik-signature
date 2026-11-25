/**
 * core/cbor.ts
 *
 * Standard CBOR encoding/decoding utilities.
 *
 * Uses ordinary CBOR maps and byte strings, without cbor-x record extensions.
 */

import { decode, encode } from "cbor-x";
import { MAX_CBOR_INPUT_BYTES } from "../constants.js";

/**
 * Encode a value as CBOR bytes.
 *
 * @returns A fresh Uint8Array containing the encoded CBOR document.
 */
export function encodeCBOR(value: unknown): Uint8Array {
  const encoded = encode(value);
  if (encoded.byteLength > MAX_CBOR_INPUT_BYTES) {
    throw new TypeError(
      `CBOR output exceeds the maximum supported size of ${MAX_CBOR_INPUT_BYTES} bytes`,
    );
  }
  return Uint8Array.from(encoded);
}

/**
 * Decode one CBOR document.
 *
 * Structural and application-specific validation belongs to the caller.
 */

export function decodeCBOR(input: Uint8Array | ArrayBuffer): unknown {
  const inputBytes =
    input instanceof Uint8Array ? input : new Uint8Array(input);

  if (inputBytes.byteLength > MAX_CBOR_INPUT_BYTES) {
    throw new TypeError(
      `CBOR input exceeds the maximum supported size of ${MAX_CBOR_INPUT_BYTES} bytes`,
    );
  }

  // Copy the exact view so bytes outside a caller-provided subarray are never decoded.
  const bytes = Uint8Array.from(inputBytes);

  if (bytes.length === 0) {
    throw new TypeError("CBOR input must not be empty");
  }

  // CBOR break (0xff) cannot appear as a standalone top-level item.
  // Reject it before passing the input to a potentially permissive decoder.
  if (bytes[0] === 0xff) {
    throw new TypeError(
      "Malformed CBOR: break code cannot appear at the top level",
    );
  }

  return decode(bytes);
}

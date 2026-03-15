/**
 * hash.ts
 *
 * Content hashing utilities for MajikSignature.
 * Thin wrappers around @stablelib/sha256 so the rest of the library
 * never imports crypto primitives directly.
 */

import { hash } from "@stablelib/sha256";

/**
 * SHA-256 hash of arbitrary bytes.
 * Returns raw 32-byte Uint8Array.
 */
export function sha256Bytes(input: Uint8Array): Uint8Array {
  return hash(input);
}

/**
 * Normalize content to Uint8Array then hash it.
 * Strings are UTF-8 encoded before hashing.
 */
export function hashContent(content: Uint8Array | string): Uint8Array {
  if (typeof content === "string") {
    return sha256Bytes(new TextEncoder().encode(content));
  }
  return sha256Bytes(content);
}

/**
 * Encode raw bytes to base64.
 * Kept here so hash.ts is self-contained for its callers.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Decode base64 to raw bytes.
 */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

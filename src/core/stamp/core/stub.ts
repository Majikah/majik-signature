/**
 * stub.ts — Compact binary serialization of ImageSignatureStub
 *
 * Binary layout (110 bytes total):
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *   0       4     Magic: 'M','S','I','G' (0x4D 0x53 0x49 0x47)
 *   4       2     Version: uint16 big-endian (currently 0x0001)
 *   6       8     pHash: raw 8 bytes (64-bit perceptual hash, big-endian)
 *   14      32    signerEdPublicKey: raw 32 bytes
 *   46      64    edSignature: raw 64 bytes
 *   110     ---   (end)
 *
 * signerId and timestamp are NOT included in the binary stub to save space.
 * They are included in the signed payload (via buildImageSigningPayload) so
 * they can't be forged, but the verifier recovers them from the Ed25519
 * payload search — or they can be omitted from the UI display.
 *
 * Wait — we DO need signerId and timestamp for the verifier to reconstruct
 * the canonical payload for verification. Without them, we can't re-sign.
 *
 * Revised layout (including signerId as 32 bytes SHA-256 of the fingerprint
 * string, and timestamp as 8-byte Unix ms):
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *   0       4     Magic: 'MSIG'
 *   4       2     Version: uint16 BE = 1
 *   6       8     pHash: 64-bit
 *   14      32    signerEdPublicKey: 32 bytes
 *   46      8     timestamp: Unix milliseconds, uint64 BE (as two uint32)
 *   54      2     signerIdLen: uint16 BE, length of signerId UTF-8 string
 *   56      N     signerId: UTF-8 string (variable, max 48 bytes)
 *   56+N    64    edSignature: 64 bytes
 *
 * Max total: 56 + 48 + 64 = 168 bytes → still under our 110-byte target?
 * No — 168 > 110. We need to trim.
 *
 * FINAL decision: cap signerId at 32 bytes (fingerprints are hex strings,
 * 32 bytes = 64 hex chars which covers any reasonable fingerprint).
 * Use fixed 32-byte zero-padded field.
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *   0       4     Magic: 'MSIG'
 *   4       2     Version: 1
 *   6       8     pHash
 *   14      32    signerEdPublicKey
 *   46      8     timestamp (Unix ms, as two uint32 BE)
 *   54      32    signerId (UTF-8, zero-padded)
 *   86      64    edSignature
 *   ------  ---
 *   Total: 150 bytes
 *
 *   150 bytes + 75 RS parity = 225 bytes → 1800 bits
 * At 0.5 bits/block at Q70: needs ~3600 blocks → ~480x480px minimum
 * Our minimum is 640x640 → comfortable (480 bytes capacity, 113% headroom).
 */

import type { ImageSignatureStub } from "./types";

const MAGIC = new Uint8Array([0x4d, 0x53, 0x49, 0x47]); // 'MSIG'
const VERSION = 1;
const STUB_SIZE = 150;

/**
 * Serialize an ImageSignatureStub to compact binary (150 bytes).
 */
export function serializeStub(stub: ImageSignatureStub): Uint8Array {
  const buf = new Uint8Array(STUB_SIZE);
  let offset = 0;

  // Magic (4 bytes)
  buf.set(MAGIC, offset);
  offset += 4;

  // Version (2 bytes BE)
  buf[offset] = 0;
  buf[offset + 1] = VERSION;
  offset += 2;

  // pHash (8 bytes) — parse hex string to bytes
  const pHashBytes = hexToBytes(stub.pHash, 8);
  buf.set(pHashBytes, offset);
  offset += 8;

  // signerEdPublicKey (32 bytes)
  const edPubBytes = hexToBytes(stub.signerEdPublicKey, 32);
  buf.set(edPubBytes, offset);
  offset += 32;

  // timestamp as Unix ms (8 bytes, stored as two uint32 BE)
  const ts = new Date(stub.timestamp).getTime();
  const tsHigh = Math.floor(ts / 0x100000000);
  const tsLow = ts >>> 0;
  buf[offset] = (tsHigh >>> 24) & 0xff;
  buf[offset + 1] = (tsHigh >>> 16) & 0xff;
  buf[offset + 2] = (tsHigh >>> 8) & 0xff;
  buf[offset + 3] = tsHigh & 0xff;
  buf[offset + 4] = (tsLow >>> 24) & 0xff;
  buf[offset + 5] = (tsLow >>> 16) & 0xff;
  buf[offset + 6] = (tsLow >>> 8) & 0xff;
  buf[offset + 7] = tsLow & 0xff;
  offset += 8;

  // signerId (32 bytes, zero-padded UTF-8)
  const signerIdBytes = new TextEncoder().encode(stub.signerId);
  const signerIdField = new Uint8Array(32);
  signerIdField.set(signerIdBytes.slice(0, 32));
  buf.set(signerIdField, offset);
  offset += 32;

  // edSignature (64 bytes)
  const edSigBytes = hexToBytes(stub.edSignature, 64);
  buf.set(edSigBytes, offset);
  offset += 64;

  // Sanity check
  if (offset !== STUB_SIZE) {
    throw new Error(
      `Stub serialization bug: wrote ${offset}, expected ${STUB_SIZE}`,
    );
  }

  return buf;
}

/**
 * Deserialize an ImageSignatureStub from binary (150 bytes).
 * Returns null if magic/version don't match.
 */
export function deserializeStub(buf: Uint8Array): ImageSignatureStub | null {
  if (buf.length < STUB_SIZE) return null;

  let offset = 0;

  // Magic check
  for (let i = 0; i < 4; i++) {
    if (buf[offset + i] !== MAGIC[i]) return null;
  }
  offset += 4;

  // Version check
  const version = (buf[offset] << 8) | buf[offset + 1];
  if (version !== VERSION) return null;
  offset += 2;

  // pHash (8 bytes → hex string)
  const pHash = bytesToHex(buf.slice(offset, offset + 8));
  offset += 8;

  // signerEdPublicKey (32 bytes → hex string)
  const signerEdPublicKey = bytesToHex(buf.slice(offset, offset + 32));
  offset += 32;

  // timestamp (8 bytes → ISO string)
  const tsHigh =
    (buf[offset] * 0x1000000 +
      (buf[offset + 1] << 16) +
      (buf[offset + 2] << 8) +
      buf[offset + 3]) >>>
    0;
  const tsLow =
    (buf[offset + 4] * 0x1000000 +
      (buf[offset + 5] << 16) +
      (buf[offset + 6] << 8) +
      buf[offset + 7]) >>>
    0;
  const ts = tsHigh * 0x100000000 + tsLow;
  const timestamp = new Date(ts).toISOString();
  offset += 8;

  // signerId (32 bytes → trim nulls)
  const signerIdRaw = buf.slice(offset, offset + 32);
  const nullIdx = signerIdRaw.indexOf(0);
  const signerIdBytes =
    nullIdx >= 0 ? signerIdRaw.slice(0, nullIdx) : signerIdRaw;
  const signerId = new TextDecoder().decode(signerIdBytes);
  offset += 32;

  // edSignature (64 bytes → hex string)
  const edSignature = bytesToHex(buf.slice(offset, offset + 64));
  offset += 64;

  return {
    pHash,
    signerEdPublicKey,
    edSignature,
    signerId,
    timestamp,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hexToBytes(hex: string, expectedLen: number): Uint8Array {
  // Strip '0x' prefix if present
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length !== expectedLen * 2) {
    throw new Error(
      `hexToBytes: expected ${expectedLen * 2} hex chars, got ${clean.length}`,
    );
  }
  const bytes = new Uint8Array(expectedLen);
  for (let i = 0; i < expectedLen; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export { STUB_SIZE };

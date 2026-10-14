/**
 * core/cbor-wire.ts
 *
 * Conversion between Majik Signature's JSON-compatible types and
 * its CBOR-native wire types.
 *
 * This module does not sign or verify anything.
 */

import { base64ToBytes, bytesToBase64 } from "../hash.js";

import type {
  ExpectedSignerCBOR,
  FileVersionCBOR,
  MajikSignatureCBOR,
  MajikSignatureEnvelopeCBOR,
  MajikTimestampCBOR,
  MajikChainAnchorCBOR,
} from "./types.js";

import type { MajikChainAnchor } from "../../anchor/types.js";
import {
  ExpectedSigner,
  FileVersion,
  MajikSignatureEnvelopeJSON,
  MajikSignatureJSON,
  MajikTimestamp,
} from "../types.js";

// Prevent pathological recursion through nested TSA signature records.
const MAX_NESTING = 8;

function assertDepth(depth: number): void {
  if (depth > MAX_NESTING) {
    throw new TypeError("CBOR signature nesting exceeds the maximum depth");
  }
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value instanceof Uint8Array ||
    value instanceof ArrayBuffer
  ) {
    throw new TypeError(`${path} must be a CBOR map/object`);
  }

  return value as Record<string, unknown>;
}

function requiredString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${path} must be a non-empty string`);
  }
  return value;
}

function optionalString(value: unknown, path: string): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value, path);
}

function assertVersionOne(value: unknown, path: string): void {
  if (value !== 1) {
    throw new TypeError(`${path} must be version 1`);
  }
}

function assertBytesLength(
  bytes: Uint8Array,
  expectedLength: number | undefined,
  path: string,
): Uint8Array {
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new TypeError(
      `${path} must be ${expectedLength} bytes; received ${bytes.length}`,
    );
  }

  return Uint8Array.from(bytes);
}

function bytesFromCBOR(
  value: unknown,
  path: string,
  expectedLength?: number,
): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${path} must be a CBOR byte string`);
  }

  return assertBytesLength(value, expectedLength, path);
}

function bytesFromBase64(
  value: string,
  path: string,
  expectedLength?: number,
): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${path} must be a non-empty Base64 string`);
  }

  return assertBytesLength(base64ToBytes(value), expectedLength, path);
}

function base64FromBytes(
  value: unknown,
  path: string,
  expectedLength?: number,
): string {
  return bytesToBase64(bytesFromCBOR(value, path, expectedLength));
}

function hexFromBytes(
  value: unknown,
  path: string,
  expectedLength: number,
): string {
  return Array.from(bytesFromCBOR(value, path, expectedLength), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

function bytesFromHex(
  value: string,
  path: string,
  expectedLength: number,
): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length !== expectedLength * 2 ||
    !/^[0-9a-fA-F]+$/.test(value)
  ) {
    throw new TypeError(
      `${path} must be a ${expectedLength * 2}-character hexadecimal string`,
    );
  }

  const bytes = new Uint8Array(expectedLength);

  for (let i = 0; i < expectedLength; i++) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

function requiredNumber(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new TypeError(`${path} must be a finite number`);
  }
  return value;
}

function nullableNumber(value: unknown, path: string): number | null {
  if (value === null) return null;
  return requiredNumber(value, path);
}

function nullableString(value: unknown, path: string): string | null {
  if (value === null) return null;
  return requiredString(value, path);
}

// ─── Expected signers ──────────────────────────────────────────────────────

function expectedSignerToCBOR(signer: ExpectedSigner): ExpectedSignerCBOR {
  return {
    signerId: bytesFromBase64(signer.signerId, "allowlist.signerId", 32),
    edPublicKey: bytesFromBase64(
      signer.edPublicKey,
      "allowlist.edPublicKey",
      32,
    ),
    mlDsaPublicKey: bytesFromBase64(
      signer.mlDsaPublicKey,
      "allowlist.mlDsaPublicKey",
      2592,
    ),
  };
}

function expectedSignerFromCBOR(input: unknown): ExpectedSigner {
  const obj = record(input, "allowlist entry");

  return {
    signerId: base64FromBytes(obj.signerId, "allowlist.signerId", 32),
    edPublicKey: base64FromBytes(obj.edPublicKey, "allowlist.edPublicKey", 32),
    mlDsaPublicKey: base64FromBytes(
      obj.mlDsaPublicKey,
      "allowlist.mlDsaPublicKey",
      2592,
    ),
  };
}

// ─── TSA records ───────────────────────────────────────────────────────────

function timestampToCBOR(
  tsa: MajikTimestamp,
  depth: number,
): MajikTimestampCBOR {
  assertDepth(depth);
  assertVersionOne(tsa.version, "tsa.version");

  return {
    version: 1,
    id: tsa.id,
    payload: {
      digest: {
        algorithm: tsa.payload.digest.algorithm,
        value: bytesFromBase64(
          tsa.payload.digest.value,
          "tsa.payload.digest.value",
          32,
        ),
      },
      nonce: bytesFromBase64(tsa.payload.nonce, "tsa.payload.nonce", 32),
      timestamp: tsa.payload.timestamp,
      tsa: {
        id: tsa.payload.tsa.id,
        signerFingerprint: bytesFromBase64(
          tsa.payload.tsa.signerFingerprint,
          "tsa.payload.tsa.signerFingerprint",
          32,
        ),
      },
    },
    signature: signatureToCBOR(tsa.signature, depth + 1),
  };
}

function timestampFromCBOR(input: unknown, depth: number): MajikTimestamp {
  assertDepth(depth);

  const obj = record(input, "tsa");
  assertVersionOne(obj.version, "tsa.version");

  const payload = record(obj.payload, "tsa.payload");
  const digest = record(payload.digest, "tsa.payload.digest");
  const tsaIdentity = record(payload.tsa, "tsa.payload.tsa");

  if (digest.algorithm !== "SHA-256") {
    throw new TypeError("tsa.payload.digest.algorithm must be SHA-256");
  }

  return {
    version: 1,
    id: requiredString(obj.id, "tsa.id"),
    payload: {
      digest: {
        algorithm: "SHA-256",
        value: base64FromBytes(digest.value, "tsa.payload.digest.value", 32),
      },
      nonce: base64FromBytes(payload.nonce, "tsa.payload.nonce", 32),
      timestamp: requiredString(payload.timestamp, "tsa.payload.timestamp"),
      tsa: {
        id: requiredString(tsaIdentity.id, "tsa.payload.tsa.id"),
        signerFingerprint: base64FromBytes(
          tsaIdentity.signerFingerprint,
          "tsa.payload.tsa.signerFingerprint",
          32,
        ),
      },
    },
    signature: signatureFromCBOR(obj.signature, depth + 1),
  };
}

// ─── Individual signature ──────────────────────────────────────────────────

export function signatureToCBOR(
  signature: MajikSignatureJSON,
  depth = 0,
): MajikSignatureCBOR {
  assertDepth(depth);
  assertVersionOne(signature.version, "signature.version");

  return {
    version: 1,
    signerId: bytesFromBase64(signature.signerId, "signerId", 32),
    signerEdPublicKey: bytesFromBase64(
      signature.signerEdPublicKey,
      "signerEdPublicKey",
      32,
    ),
    signerMlDsaPublicKey: bytesFromBase64(
      signature.signerMlDsaPublicKey,
      "signerMlDsaPublicKey",
      2592,
    ),
    contentHash: bytesFromBase64(signature.contentHash, "contentHash", 32),
    ...(signature.contentType !== undefined
      ? { contentType: signature.contentType }
      : {}),
    timestamp: signature.timestamp,
    edSignature: bytesFromBase64(signature.edSignature, "edSignature", 64),
    mlDsaSignature: bytesFromBase64(
      signature.mlDsaSignature,
      "mlDsaSignature",
      4627,
    ),
    ...(signature.allowlistHash !== undefined
      ? {
          allowlistHash: bytesFromBase64(
            signature.allowlistHash,
            "allowlistHash",
            32,
          ),
        }
      : {}),
    ...(signature.validUntil !== undefined
      ? { validUntil: signature.validUntil }
      : {}),
    ...(signature.versionChainHash !== undefined
      ? {
          versionChainHash: bytesFromBase64(
            signature.versionChainHash,
            "versionChainHash",
            32,
          ),
        }
      : {}),
    ...(signature.tsa !== undefined
      ? { tsa: timestampToCBOR(signature.tsa, depth + 1) }
      : {}),
  };
}

export function signatureFromCBOR(
  input: unknown,
  depth = 0,
): MajikSignatureJSON {
  assertDepth(depth);

  const obj = record(input, "signature");
  assertVersionOne(obj.version, "signature.version");

  const contentType = optionalString(obj.contentType, "contentType");
  const validUntil = optionalString(obj.validUntil, "validUntil");

  const allowlistHash =
    obj.allowlistHash === undefined
      ? undefined
      : base64FromBytes(obj.allowlistHash, "allowlistHash", 32);

  const versionChainHash =
    obj.versionChainHash === undefined
      ? undefined
      : base64FromBytes(obj.versionChainHash, "versionChainHash", 32);

  return {
    version: 1,
    signerId: base64FromBytes(obj.signerId, "signerId", 32),
    signerEdPublicKey: base64FromBytes(
      obj.signerEdPublicKey,
      "signerEdPublicKey",
      32,
    ),
    signerMlDsaPublicKey: base64FromBytes(
      obj.signerMlDsaPublicKey,
      "signerMlDsaPublicKey",
      2592,
    ),
    contentHash: base64FromBytes(obj.contentHash, "contentHash", 32),
    ...(contentType !== undefined ? { contentType } : {}),
    timestamp: requiredString(obj.timestamp, "timestamp"),
    edSignature: base64FromBytes(obj.edSignature, "edSignature", 64),
    mlDsaSignature: base64FromBytes(obj.mlDsaSignature, "mlDsaSignature", 4627),
    ...(allowlistHash !== undefined ? { allowlistHash } : {}),
    ...(validUntil !== undefined ? { validUntil } : {}),
    ...(versionChainHash !== undefined ? { versionChainHash } : {}),
    ...(obj.tsa !== undefined
      ? { tsa: timestampFromCBOR(obj.tsa, depth + 1) }
      : {}),
  };
}

// ─── Chain anchors ─────────────────────────────────────────────────────────

function anchorToCBOR(anchor: MajikChainAnchor): MajikChainAnchorCBOR {
  if (anchor.payload.digest.algorithm !== "SHA3-512") {
    throw new TypeError("Unsupported chain-anchor digest algorithm");
  }

  return {
    version: 1,
    id: anchor.id,
    payload: {
      chain: anchor.payload.chain,
      network: anchor.payload.network,
      digest: {
        algorithm: "SHA3-512",
        value: bytesFromHex(
          anchor.payload.digest.value,
          "chainAnchor.payload.digest.value",
          64,
        ),
      },
    },
    memo: anchor.memo,
    txSignature: anchor.txSignature,
    slot: anchor.slot,
    blockTime: anchor.blockTime,
    confirmedAt: anchor.confirmedAt,
    status: anchor.status,
  };
}

function anchorFromCBOR(input: unknown): MajikChainAnchor {
  const obj = record(input, "chainAnchor");
  assertVersionOne(obj.version, "chainAnchor.version");

  const payload = record(obj.payload, "chainAnchor.payload");
  const digest = record(payload.digest, "chainAnchor.payload.digest");

  if (digest.algorithm !== "SHA3-512") {
    throw new TypeError(
      "chainAnchor.payload.digest.algorithm must be SHA3-512",
    );
  }

  const status = requiredString(obj.status, "chainAnchor.status");
  if (
    status !== "pending" &&
    status !== "confirmed" &&
    status !== "finalized" &&
    status !== "failed"
  ) {
    throw new TypeError("Invalid chainAnchor.status");
  }

  return {
    version: 1,
    id: requiredString(obj.id, "chainAnchor.id"),
    payload: {
      chain: requiredString(payload.chain, "chainAnchor.payload.chain"),
      network: requiredString(payload.network, "chainAnchor.payload.network"),
      digest: {
        algorithm: "SHA3-512",
        value: hexFromBytes(
          digest.value,
          "chainAnchor.payload.digest.value",
          64,
        ),
      },
    },
    memo: requiredString(obj.memo, "chainAnchor.memo"),
    txSignature: requiredString(obj.txSignature, "chainAnchor.txSignature"),
    slot: nullableNumber(obj.slot, "chainAnchor.slot"),
    blockTime: nullableNumber(obj.blockTime, "chainAnchor.blockTime"),
    confirmedAt: nullableString(obj.confirmedAt, "chainAnchor.confirmedAt"),
    status,
  };
}

// ─── File versions ─────────────────────────────────────────────────────────

function fileVersionToCBOR(entry: FileVersion): FileVersionCBOR {
  return {
    version: entry.version,
    timestamp: entry.timestamp,
    contentHash: bytesFromBase64(
      entry.contentHash,
      "fileVersion.contentHash",
      32,
    ),
    ...(entry.previousVersionHash !== undefined
      ? {
          previousVersionHash: bytesFromBase64(
            entry.previousVersionHash,
            "fileVersion.previousVersionHash",
            32,
          ),
        }
      : {}),
    ...(entry.createdBy !== undefined
      ? {
          createdBy: bytesFromBase64(
            entry.createdBy,
            "fileVersion.createdBy",
            32,
          ),
        }
      : {}),
    ...(entry.message !== undefined ? { message: entry.message } : {}),
  };
}

function fileVersionFromCBOR(input: unknown): FileVersion {
  const obj = record(input, "fileVersion");

  const previousVersionHash =
    obj.previousVersionHash === undefined
      ? undefined
      : base64FromBytes(
          obj.previousVersionHash,
          "fileVersion.previousVersionHash",
          32,
        );

  const createdBy =
    obj.createdBy === undefined
      ? undefined
      : base64FromBytes(obj.createdBy, "fileVersion.createdBy", 32);

  const message = optionalString(obj.message, "fileVersion.message");

  return {
    version: requiredNumber(obj.version, "fileVersion.version"),
    timestamp: requiredString(obj.timestamp, "fileVersion.timestamp"),
    contentHash: base64FromBytes(
      obj.contentHash,
      "fileVersion.contentHash",
      32,
    ),
    ...(previousVersionHash !== undefined ? { previousVersionHash } : {}),
    ...(createdBy !== undefined ? { createdBy } : {}),
    ...(message !== undefined ? { message } : {}),
  };
}

// ─── Complete envelope ─────────────────────────────────────────────────────

export function envelopeToCBOR(
  envelope: MajikSignatureEnvelopeJSON,
): MajikSignatureEnvelopeCBOR {
  assertVersionOne(envelope.version, "envelope.version");

  return {
    version: 1,
    signatures: envelope.signatures.map((signature) =>
      signatureToCBOR(signature),
    ),
    ...(envelope.allowlist !== undefined
      ? { allowlist: envelope.allowlist.map(expectedSignerToCBOR) }
      : {}),
    ...(envelope.allowlistSignerId !== undefined
      ? {
          allowlistSignerId: bytesFromBase64(
            envelope.allowlistSignerId,
            "allowlistSignerId",
            32,
          ),
        }
      : {}),
    ...(envelope.sealHash !== undefined
      ? {
          sealHash: bytesFromHex(envelope.sealHash, "sealHash", 64),
        }
      : {}),
    ...(envelope.sealTimestamp !== undefined
      ? { sealTimestamp: envelope.sealTimestamp }
      : {}),
    ...(envelope.sealedBy !== undefined
      ? {
          sealedBy: bytesFromBase64(envelope.sealedBy, "sealedBy", 32),
        }
      : {}),
    ...(envelope.chainAnchors !== undefined
      ? { chainAnchors: envelope.chainAnchors.map(anchorToCBOR) }
      : {}),
    ...(envelope.fileVersions !== undefined
      ? { fileVersions: envelope.fileVersions.map(fileVersionToCBOR) }
      : {}),
  };
}

export function envelopeFromCBOR(input: unknown): MajikSignatureEnvelopeJSON {
  const obj = record(input, "envelope");
  assertVersionOne(obj.version, "envelope.version");

  if (!Array.isArray(obj.signatures)) {
    throw new TypeError("envelope.signatures must be an array");
  }

  if (obj.allowlist !== undefined && !Array.isArray(obj.allowlist)) {
    throw new TypeError("envelope.allowlist must be an array");
  }

  if (obj.chainAnchors !== undefined && !Array.isArray(obj.chainAnchors)) {
    throw new TypeError("envelope.chainAnchors must be an array");
  }

  if (obj.fileVersions !== undefined && !Array.isArray(obj.fileVersions)) {
    throw new TypeError("envelope.fileVersions must be an array");
  }

  const allowlistSignerId =
    obj.allowlistSignerId === undefined
      ? undefined
      : base64FromBytes(obj.allowlistSignerId, "allowlistSignerId", 32);

  const sealHash =
    obj.sealHash === undefined
      ? undefined
      : hexFromBytes(obj.sealHash, "sealHash", 64);

  const sealTimestamp = optionalString(obj.sealTimestamp, "sealTimestamp");

  const sealedBy =
    obj.sealedBy === undefined
      ? undefined
      : base64FromBytes(obj.sealedBy, "sealedBy", 32);

  return {
    version: 1,
    signatures: obj.signatures.map((signature) => signatureFromCBOR(signature)),
    ...(obj.allowlist !== undefined
      ? { allowlist: obj.allowlist.map(expectedSignerFromCBOR) }
      : {}),
    ...(allowlistSignerId !== undefined ? { allowlistSignerId } : {}),
    ...(sealHash !== undefined ? { sealHash } : {}),
    ...(sealTimestamp !== undefined ? { sealTimestamp } : {}),
    ...(sealedBy !== undefined ? { sealedBy } : {}),
    ...(obj.chainAnchors !== undefined
      ? { chainAnchors: obj.chainAnchors.map(anchorFromCBOR) }
      : {}),
    ...(obj.fileVersions !== undefined
      ? { fileVersions: obj.fileVersions.map(fileVersionFromCBOR) }
      : {}),
  };
}

import { ISODateString } from "@majikah/majik-key";




/**
 * CBOR wire representation of one Majik Signature signature record.
 *
 * Binary fields that are Base64 strings in MajikSignatureJSON are represented
 * as native CBOR byte strings (Uint8Array) here.
 *
 * These fields must be converted back to the existing JSON representation
 * before calling MajikSignature.fromJSON() or the existing verification APIs.
 *
 * IMPORTANT: This is a serialization format, not a change to the signed
 * canonical payload or cryptographic verification protocol.
 */
export interface MajikSignatureCBOR {
  /** Signature-envelope version. */
  version: 1;

  /** Raw 32-byte MajikKey fingerprint. */
  signerId: Uint8Array;

  /** Raw Ed25519 public key (32 bytes). */
  signerEdPublicKey: Uint8Array;

  /** Raw ML-DSA-87 public key (2,592 bytes). */
  signerMlDsaPublicKey: Uint8Array;

  /** Raw SHA-256 digest of the signed content (32 bytes). */
  contentHash: Uint8Array;

  /** Advisory content type. */
  contentType?: string;

  /** ISO 8601 signing timestamp. */
  timestamp: ISODateString;

  /** Raw Ed25519 signature (64 bytes). */
  edSignature: Uint8Array;

  /** Raw ML-DSA-87 signature (4,595 bytes). */
  mlDsaSignature: Uint8Array;

  /** Raw SHA-256 allowlist commitment (32 bytes). */
  allowlistHash?: Uint8Array;

  /** Optional ISO 8601 expiration time. */
  validUntil?: ISODateString;

  /** Raw SHA-256 revision-chain commitment (32 bytes). */
  versionChainHash?: Uint8Array;

  /** Optional TSA record using the CBOR-native representation. */
  tsa?: MajikTimestampCBOR;
}

/**
 * Compact CBOR signature representation without embedded public keys.
 *
 * Public keys must be resolved through a trusted source during verification.
 */
export interface MajikSignatureCompactCBOR {
  /** Compact signature version. */
  v: 1;

  /** Raw 32-byte signer fingerprint. */
  signerId: Uint8Array;

  /** Raw SHA-256 content digest (32 bytes). */
  contentHash: Uint8Array;

  /** Advisory content type. */
  contentType?: string;

  /** ISO 8601 signing timestamp. */
  timestamp: ISODateString;

  /** Raw Ed25519 signature (64 bytes). */
  edSignature: Uint8Array;

  /** Raw ML-DSA-87 signature (4,595 bytes). */
  mlDsaSignature: Uint8Array;

  /** Raw SHA-256 allowlist commitment (32 bytes). */
  allowlistHash?: Uint8Array;

  /** Optional ISO 8601 expiration time. */
  validUntil?: ISODateString;

  /** Raw SHA-256 revision-chain commitment (32 bytes). */
  versionChainHash?: Uint8Array;
}



/**
 * CBOR wire representation of an expected signer.
 */
export interface ExpectedSignerCBOR {
  /** Raw 32-byte signer fingerprint. */
  signerId: Uint8Array;

  /** Raw Ed25519 public key (32 bytes). */
  edPublicKey: Uint8Array;

  /** Raw ML-DSA-87 public key (2,592 bytes). */
  mlDsaPublicKey: Uint8Array;
}

/**
 * CBOR-native digest descriptor used by TSA records.
 */
export interface TSADigestCBOR {
  /** Digest algorithm. */
  algorithm: "SHA-256";

  /** Raw SHA-256 digest (32 bytes). */
  value: Uint8Array;
}

/**
 * CBOR wire representation of a TSA-signed payload.
 */
export interface MajikTSAPayloadCBOR {
  digest: TSADigestCBOR;

  /** Raw server-generated nonce (32 bytes in the current implementation). */
  nonce: Uint8Array;

  /** ISO 8601 server-authoritative timestamp. */
  timestamp: string;

  tsa: {
    /** Stable TSA service identifier. */
    id: string;

    /** Raw 32-byte fingerprint of the TSA signing key. */
    signerFingerprint: Uint8Array;
  };
}

/**
 * CBOR wire representation of a complete trusted-timestamp record.
 */
export interface MajikTimestampCBOR {
  version: 1;

  /** Unique issuance identifier (UUID). */
  id: string;

  payload: MajikTSAPayloadCBOR;

  /** CBOR-native representation of the TSA's signature. */
  signature: MajikSignatureCBOR;
}

/**
 * CBOR wire representation of one revision-chain entry.
 */
export interface FileVersionCBOR {
  /** Sequential, 1-indexed revision number. */
  version: number;

  /** ISO 8601 revision timestamp. */
  timestamp: ISODateString;

  /** Raw SHA-256 digest of the revision's content (32 bytes). */
  contentHash: Uint8Array;

  /** Raw SHA-256 digest of the previous entry (32 bytes), when present. */
  previousVersionHash?: Uint8Array;

  /** Raw 32-byte fingerprint of the creator, when present. */
  createdBy?: Uint8Array;

  /** Optional human-readable revision note. */
  message?: string;
}



/**
 * CBOR-native multi-signature envelope wire representation.
 *
 * Binary values are represented as byte strings rather than Base64 or hex
 * text. The original JSON interfaces remain unchanged.
 */
export interface MultiSigEnvelopeCBOR {
  /** Top-level envelope schema version. */
  version: 1;

  /** Optional allowlist of permitted signers. */
  allowlist?: ExpectedSignerCBOR[];

  /** Raw 32-byte fingerprint of the allowlist issuer. */
  allowlistSignerId?: Uint8Array;

  /** Per-signer CBOR signature records. */
  signatures: MajikSignatureCBOR[];

  /**
   * Raw SHA3-512 seal digest (64 bytes).
   *
   * The existing JSON representation encodes this digest as 128 hex
   * characters; the CBOR adapter converts between these representations.
   */
  sealHash?: Uint8Array;

  /** ISO 8601 timestamp recorded when the envelope was sealed. */
  sealTimestamp?: ISODateString;

  /** Recorded sealer fingerprint as raw bytes (32 bytes). */
  sealedBy?: Uint8Array;

  /**
   * Existing chain-anchor schema.
   *
   * Keep the current type until a dedicated CBOR representation for
   * MajikChainAnchorCBOR has been defined and its fields mapped explicitly.
   */
  chainAnchors?: MajikChainAnchorCBOR[];

  /** CBOR-native revision history. */
  fileVersions?: FileVersionCBOR[];
}

/**
 * CBOR representation of the serialized envelope type.
 */
export type MajikSignatureEnvelopeCBOR = MultiSigEnvelopeCBOR;

/**
 * One file entry in a CBOR-native batch manifest.
 */
export interface MjksMapEntryCBOR {
  /** Relative POSIX-normalized file path. */
  path: string;

  /** Raw SHA-256 content digest (32 bytes). */
  contentHash: Uint8Array;

  /** Optional content size in bytes. */
  size?: number;

  /** Optional descriptive MIME type. */
  mimeType?: string;

  /** CBOR-native detached signature envelope. */
  envelope: MajikSignatureEnvelopeCBOR;
}

/**
 * CBOR-native representation of a .mjksmap batch manifest.
 */
export interface MjksMapCBOR {
  /** Manifest schema version. */
  version: 1;

  /** ISO 8601 manifest creation timestamp. */
  createdAt: ISODateString;

  /** Detached signature entries. */
  entries: MjksMapEntryCBOR[];
}



export interface MajikChainAnchorPayloadCBOR {
  chain: string;
  network: string;
  digest: {
    algorithm: "SHA3-512";
    /** Raw 64-byte SHA3-512 digest. */
    value: Uint8Array;
  };
}

export interface MajikChainAnchorCBOR {
  version: 1;
  id: string;
  payload: MajikChainAnchorPayloadCBOR;
  /** Exact memo string written on-chain. */
  memo: string;
  /** Base58 transaction signature, kept as text. */
  txSignature: string;
  slot: number | null;
  blockTime: number | null;
  confirmedAt: string | null;
  status: "pending" | "confirmed" | "finalized" | "failed";
}

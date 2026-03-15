# Majik Signature

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

**Majik Signature** is a hybrid post-quantum content signing and verification library for the Majikah ecosystem. Built on top of **Majik Key**, it provides tamper-proof, forgery-resistant digital signatures for any content format — plaintext, JSON, PDF, audio, video, binary — using a dual-algorithm architecture that combines classical Ed25519 with post-quantum ML-DSA-87 (FIPS-204).

![npm](https://img.shields.io/npm/v/@majikah/majik-signature) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-signature) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-signature) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)

---

- [Majik Signature](#majik-signature)
  - [Security Architecture](#security-architecture)
    - [1. Hybrid Dual-Algorithm Signing](#1-hybrid-dual-algorithm-signing)
    - [2. Canonical Payload Binding](#2-canonical-payload-binding)
    - [3. Content-Agnostic Hashing](#3-content-agnostic-hashing)
  - [Overview](#overview)
    - [What is a Majik Signature?](#what-is-a-majik-signature)
    - [Use Cases](#use-cases)
  - [Features](#features)
    - [Security \& Post-Quantum Readiness](#security--post-quantum-readiness)
    - [Content Format Support](#content-format-support)
    - [Developer Experience](#developer-experience)
    - [Serialization \& Portability](#serialization--portability)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [API Reference](#api-reference)
    - [Static Methods](#static-methods)
      - [`MajikSignature.sign(content, key, options?)`](#majiksignaturesigncontent-key-options)
      - [`MajikSignature.verify(content, signature, publicKeys)`](#majiksignatureverifycontent-signature-publickeys)
      - [`MajikSignature.verifyWithKey(content, signature, key)`](#majiksignatureverifywithkeycontent-signature-key)
      - [`MajikSignature.publicKeysFromMajikKey(key)`](#majiksignaturepublickeysfrommajikkeykey)
      - [`MajikSignature.fromJSON(json)`](#majiksignaturefromjsonjson)
      - [`MajikSignature.deserialize(base64)`](#majiksignaturedeserializebase64)
    - [Instance Methods](#instance-methods)
      - [`validate()`](#validate)
      - [`isValid()`](#isvalid)
      - [`extractPublicKeys()`](#extractpublickeys)
      - [`toJSON()`](#tojson)
      - [`serialize()`](#serialize)
      - [`toString()`](#tostring)
    - [Getters](#getters)
  - [Usage Examples](#usage-examples)
    - [Example 1: Sign and Verify a Text Document](#example-1-sign-and-verify-a-text-document)
    - [Example 2: Sign and Verify a Binary File](#example-2-sign-and-verify-a-binary-file)
    - [Example 3: Sign a JSON Payload](#example-3-sign-a-json-payload)
    - [Example 4: Serialize and Store a Signature](#example-4-serialize-and-store-a-signature)
    - [Example 5: Verify from Stored Signature](#example-5-verify-from-stored-signature)
    - [Example 6: Verify Using Only Public Keys](#example-6-verify-using-only-public-keys)
    - [Example 7: Sign Audio or Video Content](#example-7-sign-audio-or-video-content)
  - [Signature Envelope](#signature-envelope)
  - [Security Considerations](#security-considerations)
    - [What is Guaranteed](#what-is-guaranteed)
    - [What is Your Responsibility](#what-is-your-responsibility)
    - [What NOT to Do](#what-not-to-do)
    - [What TO Do](#what-to-do)
  - [Related Projects](#related-projects)
    - [Majik Key](#majik-key)
    - [Majik Message](#majik-message)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [Contact](#contact)

---

## Security Architecture

### 1. Hybrid Dual-Algorithm Signing

Every Majik Signature is produced by **two independent signing algorithms** over the same canonical payload:

- **Ed25519** — Classical elliptic curve signature (128-bit security, 64-byte signature)
- **ML-DSA-87 (FIPS-204)** — Post-quantum lattice-based signature (Category 5, ~AES-256 PQ security, 4595-byte signature)

Verification requires **both** to pass. This means:
- A classical attacker breaking Ed25519 still cannot forge the ML-DSA-87 signature
- A quantum attacker breaking ML-DSA-87 still cannot forge the Ed25519 signature
- No single algorithmic break is sufficient to forge a valid signature

### 2. Canonical Payload Binding

Both signatures cover a **domain-separated canonical payload** that binds together:
```
"majik-signature-v1:" + JSON({ v, id, ts, ct, hash })
```

| Field  | Description                             |
| ------ | --------------------------------------- |
| `v`    | Envelope version                        |
| `id`   | Signer fingerprint (MajikKey identity)  |
| `ts`   | ISO 8601 timestamp                      |
| `ct`   | Content type (advisory)                 |
| `hash` | SHA-256 of the original content, base64 |

This binding means a valid signature cannot be:
- Reused on different content (hash binding)
- Transferred to a different signer identity (id binding)
- Replayed with a modified timestamp (ts binding)
- Forged without both private keys

### 3. Content-Agnostic Hashing

Content is never embedded in the envelope. Only its SHA-256 hash is signed. This means:
- A 500 MB video signs at the same speed as a 10-byte string
- Any format — binary, text, JSON, PDF, audio, video — is supported identically
- The original content travels separately; the signature is a portable proof

---

## Overview

### What is a Majik Signature?

A Majik Signature is a cryptographic proof that:
- A specific piece of content (file, document, message, media) was produced or approved by the holder of a specific **Majik Key** account
- The content has not been modified since it was signed
- The signature cannot be forged without access to the signer's private keys
- The signature remains valid against future quantum computing threats

Verification is fully **public** — anyone with the signer's public keys can verify. No private key is ever needed for verification.

### Use Cases

- **Content Provenance**: Prove that a piece of music, art, document, or dataset was produced by a specific identity
- **File Integrity**: Detect any tampering or modification to distributed files
- **API Payload Signing**: Sign JSON responses or requests for non-repudiation
- **Document Authentication**: Certify legal documents, contracts, or records
- **Media Certification**: Stamp audio, video, or image files as authentic originals
- **Software Distribution**: Sign release artifacts to prove they come from the original author
- **Majikah Ecosystem**: Integrate with Majik Message and other Majikah products for identity-bound content

---

## Features

### Security & Post-Quantum Readiness

- **Hybrid Signatures**: Ed25519 (classical) + ML-DSA-87 (post-quantum, FIPS-204, Category 5) — both must verify
- **Tamper Detection**: SHA-256 content hash is bound inside the signed payload — any byte change invalidates both signatures
- **Domain Separation**: `"majik-signature-v1:"` prefix prevents cross-protocol signature reuse
- **Signer Binding**: Signer fingerprint is part of the signed payload — signatures cannot be transferred between identities
- **Timestamp Binding**: Timestamp is part of the signed payload — cannot be altered after signing
- **No Private Key for Verification**: Pure public-key verification — safe to verify in any context

### Content Format Support

- **Plain text** — UTF-8 strings
- **JSON** — Any JSON-serializable payload
- **Binary** — `Uint8Array` of any format
- **PDF** — Read as raw bytes
- **Audio** — WAV, MP3, FLAC, and any other audio format
- **Video** — MP4, MOV, and any other video format
- **Images** — PNG, JPEG, WEBP, and others
- **Any file** — If you can read it into a `Uint8Array`, it can be signed

### Developer Experience

- **First-Class TypeScript Support**: Full type definitions for all interfaces and classes
- **Simple Two-Method Core API**: `sign()` and `verify()` cover the primary use case
- **Convenience Helpers**: `verifyWithKey()` and `publicKeysFromMajikKey()` for common patterns
- **Structured Errors**: Typed error hierarchy for precise error handling
- **Self-Validation**: `isValid()` and `validate()` for envelope integrity checks
- **Isomorphic**: Works in Node.js and modern browser environments

### Serialization & Portability

- **JSON Envelope**: Full `toJSON()` / `fromJSON()` round-trip
- **Base64 Serialization**: `serialize()` / `deserialize()` for compact transport
- **Embeddable**: Base64 signature fits in database fields, HTTP headers, file metadata, or sidecar files
- **Self-Contained**: Envelope includes signer's public keys — verifiable without a key registry

---

## Installation
```bash
# Using npm
npm install @majikah/majik-signature

# Peer dependency — must also be installed
npm install @majikah/majik-key
```

---

## Quick Start
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature, CONTENT_TYPES } from '@majikah/majik-signature';

// ── Step 1: Create and unlock a MajikKey ──────────────────────────────────────
const mnemonic = MajikKey.generateMnemonic();
const key = await MajikKey.create(mnemonic, 'my-passphrase', 'My Signing Key');
// key is unlocked after create() — signing keys are ready

// ── Step 2: Sign content ──────────────────────────────────────────────────────
const document = 'This is the original content of my document.';

const signature = await MajikSignature.sign(document, key, {
  contentType: CONTENT_TYPES.TEXT,
});

console.log('Signed!');
console.log('Signer ID:', signature.signerId);
console.log('Content Hash:', signature.contentHash);
console.log('Timestamp:', signature.timestamp);

// ── Step 3: Serialize for storage or transport ────────────────────────────────
const serialized = signature.serialize(); // base64 string
// Store in a database, embed in a file, send via HTTP header, etc.

// ── Step 4: Verify (no private key needed) ────────────────────────────────────
const publicKeys = MajikSignature.publicKeysFromMajikKey(key);
const result = MajikSignature.verify(document, signature, publicKeys);

console.log('Valid:', result.valid);         // true
console.log('Signer:', result.signerId);
console.log('Hash:', result.contentHash);

// ── Shorthand: verify directly against a MajikKey ────────────────────────────
const result2 = MajikSignature.verifyWithKey(document, signature, key);
console.log('Valid:', result2.valid);        // true
```

---

## API Reference

### Static Methods

#### `MajikSignature.sign(content, key, options?)`

Sign content with an unlocked MajikKey. Produces a hybrid Ed25519 + ML-DSA-87 signature.

The key must be unlocked and must have signing keys (`key.hasSigningKeys === true`). Keys created with the current version of Majik Key always include signing keys. Legacy keys can be upgraded by re-importing via `importFromMnemonicBackup()`.

**Parameters:**
- `content: Uint8Array | string` — Content to sign. Strings are UTF-8 encoded before hashing.
- `key: MajikKey` — An unlocked MajikKey with signing keys present.
- `options?: SignOptions` — Optional configuration.
  - `contentType?: string` — Advisory label (e.g. `"audio/wav"`, `"application/pdf"`). See `CONTENT_TYPES`.
  - `timestamp?: string` — ISO 8601 timestamp override. Defaults to `new Date().toISOString()`. Useful for deterministic tests.

**Returns:** `Promise<MajikSignature>` — A new MajikSignature instance ready to serialize or verify.

**Throws:** `MajikSignatureKeyError` if the key is locked or has no signing keys. `MajikSignatureError` on any other failure.

**Example:**
```typescript
const signature = await MajikSignature.sign(content, key, {
  contentType: 'application/pdf',
});
```

---

#### `MajikSignature.verify(content, signature, publicKeys)`

Verify a signature against content and the signer's public keys.

No private key is needed. Both Ed25519 and ML-DSA-87 must pass. Returns a structured result rather than throwing on invalid signatures — only throws on unexpected internal errors.

**Parameters:**
- `content: Uint8Array | string` — The original content that was signed. Must be byte-for-byte identical to what was passed to `sign()`.
- `signature: MajikSignature | MajikSignatureJSON` — The signature to verify.
- `publicKeys: MajikSignerPublicKeys` — Signer's Ed25519 (32 bytes) and ML-DSA-87 (2592 bytes) public keys.

**Returns:** `VerificationResult`
```typescript
{
  valid: boolean;       // true only if both Ed25519 and ML-DSA-87 pass
  signerId: string;     // signer fingerprint from the envelope
  contentHash: string;  // SHA-256 of content, base64
  timestamp: string;    // ISO 8601 from the envelope
  contentType?: string; // advisory content type if present
}
```

**Throws:** `MajikSignatureVerificationError` on unexpected internal failure.

**Example:**
```typescript
const result = MajikSignature.verify(content, signature, publicKeys);
if (result.valid) {
  console.log('Verified — signed by:', result.signerId);
} else {
  console.log('Invalid signature');
}
```

---

#### `MajikSignature.verifyWithKey(content, signature, key)`

Convenience method — verify content directly against a MajikKey instance. Extracts public keys automatically. Works on both locked and unlocked keys.

**Parameters:**
- `content: Uint8Array | string` — The original content.
- `signature: MajikSignature | MajikSignatureJSON` — The signature to verify.
- `key: MajikKey` — The MajikKey to verify against. Does not need to be unlocked.

**Returns:** `VerificationResult` — same as `verify()`.

**Example:**
```typescript
const result = MajikSignature.verifyWithKey(content, signature, key);
console.log('Valid:', result.valid);
```

---

#### `MajikSignature.publicKeysFromMajikKey(key)`

Extract the public keys needed for `verify()` from a MajikKey. Works on locked keys — only reads public fields.

**Parameters:**
- `key: MajikKey` — Any MajikKey with signing keys (locked or unlocked).

**Returns:** `MajikSignerPublicKeys`
```typescript
{
  signerId: string;           // MajikKey fingerprint
  edPublicKey: Uint8Array;    // Ed25519 public key (32 bytes)
  mlDsaPublicKey: Uint8Array; // ML-DSA-87 public key (2592 bytes)
}
```

**Throws:** `MajikSignatureKeyError` if the key has no signing public keys.

**Example:**
```typescript
const publicKeys = MajikSignature.publicKeysFromMajikKey(key);
// Store publicKeys or pass to verify()
```

---

#### `MajikSignature.fromJSON(json)`

Reconstruct a MajikSignature from its JSON representation. Validates envelope structure on parse.

**Parameters:**
- `json: MajikSignatureJSON | string` — JSON object or JSON string.

**Returns:** `MajikSignature`

**Throws:** `MajikSignatureSerializationError` on invalid or malformed JSON.

**Example:**
```typescript
const signature = MajikSignature.fromJSON(storedJson);
```

---

#### `MajikSignature.deserialize(base64)`

Reconstruct a MajikSignature from a base64 serialized string produced by `serialize()`.

**Parameters:**
- `base64: string` — Base64 string from a previous `serialize()` call.

**Returns:** `MajikSignature`

**Throws:** `MajikSignatureSerializationError` on invalid input.

**Example:**
```typescript
const signature = MajikSignature.deserialize(storedBase64);
```

---

### Instance Methods

#### `validate()`

Validate the envelope's internal structure without performing cryptographic verification. Checks all required fields, base64 lengths, and timestamp format. Useful before storing or transmitting.

**Returns:** `void`

**Throws:** `MajikSignatureValidationError` on any structural problem.

**Example:**
```typescript
signature.validate(); // throws if structurally invalid
```

---

#### `isValid()`

Returns `true` if the envelope is structurally valid, `false` otherwise. Never throws — safe to use as a boolean guard anywhere.

**Returns:** `boolean`

**Example:**
```typescript
if (!signature.isValid()) {
  console.error('Envelope is malformed');
}
```

---

#### `extractPublicKeys()`

Extract the signer's public keys from the envelope itself.

> ⚠️ **Important:** Public keys embedded in the envelope are self-reported by the signer. Always cross-check `signerId` against a trusted source (e.g. a known `MajikKey.fingerprint`) before trusting extracted keys for verification. Use `verifyWithKey()` or keep your own key store when possible.

**Returns:** `MajikSignerPublicKeys`

**Throws:** `MajikSignatureKeyError` if keys cannot be decoded.

**Example:**
```typescript
const keys = signature.extractPublicKeys();
// Cross-check keys.signerId against a known trusted fingerprint
```

---

#### `toJSON()`

Export the full signature envelope as a plain JSON object.

**Returns:** `MajikSignatureJSON`

**Example:**
```typescript
const json = signature.toJSON();
await db.signatures.insert({ id: docId, sig: json });
```

---

#### `serialize()`

Serialize the envelope to a compact base64 string. Suitable for embedding in database fields, HTTP headers, file metadata, or sidecar `.sig` files.

**Returns:** `string` — Base64 encoded envelope.

**Throws:** `MajikSignatureSerializationError` on failure.

**Example:**
```typescript
const b64 = signature.serialize();
res.setHeader('X-Majik-Signature', b64);
```

---

#### `toString()`

Alias for `serialize()`. Returns the base64 serialized envelope.

**Returns:** `string`

---

### Getters

| Getter                 | Type                  | Description                               |
| ---------------------- | --------------------- | ----------------------------------------- |
| `version`              | `1`                   | Envelope version                          |
| `signerId`             | `string`              | MajikKey fingerprint of the signer        |
| `signerEdPublicKey`    | `string`              | Ed25519 public key, base64 (32 bytes)     |
| `signerMlDsaPublicKey` | `string`              | ML-DSA-87 public key, base64 (2592 bytes) |
| `contentHash`          | `string`              | SHA-256 of the signed content, base64     |
| `contentType`          | `string \| undefined` | Advisory content type label               |
| `timestamp`            | `string`              | ISO 8601 signing timestamp                |
| `edSignature`          | `string`              | Ed25519 signature, base64 (64 bytes)      |
| `mlDsaSignature`       | `string`              | ML-DSA-87 signature, base64 (4595 bytes)  |

---

## Usage Examples

### Example 1: Sign and Verify a Text Document
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature, CONTENT_TYPES } from '@majikah/majik-signature';

async function signDocument() {
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'passphrase', 'Author Key');

  const document = `
    AGREEMENT

    This agreement is entered into on January 1, 2026.
    Party A agrees to deliver the software by March 31, 2026.
  `;

  // Sign
  const signature = await MajikSignature.sign(document, key, {
    contentType: CONTENT_TYPES.TEXT,
  });

  console.log('✅ Document signed');
  console.log('Signer:', signature.signerId);
  console.log('At:', signature.timestamp);

  // Verify
  const result = MajikSignature.verifyWithKey(document, signature, key);
  console.log('✅ Verified:', result.valid); // true

  // Tamper detection
  const tampered = document + ' (modified)';
  const tamperResult = MajikSignature.verifyWithKey(tampered, signature, key);
  console.log('❌ Tampered rejected:', tamperResult.valid); // false
}

signDocument();
```

---

### Example 2: Sign and Verify a Binary File
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature, CONTENT_TYPES } from '@majikah/majik-signature';
import { readFileSync } from 'fs';

async function signFile() {
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'passphrase', 'Publisher Key');

  // Read any binary file — PDF, WAV, MP4, etc.
  const fileBytes = new Uint8Array(readFileSync('./release.zip'));

  const signature = await MajikSignature.sign(fileBytes, key, {
    contentType: 'application/zip',
  });

  console.log('✅ File signed');
  console.log('Content Hash:', signature.contentHash);

  // Verification
  const result = MajikSignature.verifyWithKey(fileBytes, signature, key);
  console.log('✅ File verified:', result.valid); // true
}

signFile();
```

---

### Example 3: Sign a JSON Payload
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature, CONTENT_TYPES } from '@majikah/majik-signature';

async function signJson() {
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'passphrase', 'API Key');

  const payload = {
    userId: 'usr_abc123',
    action: 'transfer',
    amount: 1000,
    currency: 'USD',
    nonce: crypto.randomUUID(),
  };

  // Always sign the canonical string — agree on stringify format
  const content = JSON.stringify(payload);

  const signature = await MajikSignature.sign(content, key, {
    contentType: CONTENT_TYPES.JSON,
  });

  // Attach to the API response
  const response = {
    data: payload,
    signature: signature.toJSON(),
  };

  // On the receiving end — verify before processing
  const result = MajikSignature.verifyWithKey(
    JSON.stringify(response.data),
    response.signature,
    key,
  );

  console.log('✅ Payload verified:', result.valid); // true
}

signJson();
```

---

### Example 4: Serialize and Store a Signature
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature } from '@majikah/majik-signature';

async function storeSignature() {
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'passphrase', 'Storage Key');

  const content = 'Original content of the certified document.';
  const signature = await MajikSignature.sign(content, key);

  // Option A: Store as JSON (in a database column, sidecar file, etc.)
  const json = signature.toJSON();
  localStorage.setItem('doc_sig_001', JSON.stringify(json));

  // Option B: Store as base64 (in an HTTP header, metadata field, etc.)
  const b64 = signature.serialize();
  localStorage.setItem('doc_sig_001_b64', b64);

  console.log('✅ Signature stored in both formats');
  console.log('JSON size (approx):', JSON.stringify(json).length, 'bytes');
  console.log('Base64 size (approx):', b64.length, 'bytes');
}

storeSignature();
```

---

### Example 5: Verify from Stored Signature
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature } from '@majikah/majik-signature';

async function verifyStored() {
  // Reload a stored key (locked) and a stored signature
  const keyJson = JSON.parse(localStorage.getItem('myKey')!);
  const key = MajikKey.fromJSON(keyJson);
  // key does NOT need to be unlocked for verification

  const content = 'Original content of the certified document.';

  // Option A: From stored JSON
  const storedJson = JSON.parse(localStorage.getItem('doc_sig_001')!);
  const signatureA = MajikSignature.fromJSON(storedJson);
  const resultA = MajikSignature.verifyWithKey(content, signatureA, key);
  console.log('✅ JSON verify:', resultA.valid); // true

  // Option B: From stored base64
  const storedB64 = localStorage.getItem('doc_sig_001_b64')!;
  const signatureB = MajikSignature.deserialize(storedB64);
  const resultB = MajikSignature.verifyWithKey(content, signatureB, key);
  console.log('✅ Base64 verify:', resultB.valid); // true
}

verifyStored();
```

---

### Example 6: Verify Using Only Public Keys
```typescript
import { MajikSignature } from '@majikah/majik-signature';
import type { MajikSignerPublicKeys } from '@majikah/majik-signature';

// Scenario: You only have the signer's public keys (from a registry or
// shared contact card) — no MajikKey instance needed.

async function verifyPublicOnly() {
  // Public keys received from a trusted source (e.g. a user profile API)
  const publicKeys: MajikSignerPublicKeys = {
    signerId: 'base64-fingerprint-of-the-signer',
    edPublicKey: new Uint8Array(/* 32 bytes */),
    mlDsaPublicKey: new Uint8Array(/* 2592 bytes */),
  };

  const content = 'Content to verify.';
  const storedSig = MajikSignature.fromJSON(/* stored JSON */);

  // Cross-check signerId against the known signer before trusting
  if (storedSig.signerId !== publicKeys.signerId) {
    console.error('❌ Signer mismatch — signature is not from expected identity');
    return;
  }

  const result = MajikSignature.verify(content, storedSig, publicKeys);
  console.log('✅ Verified:', result.valid);
  console.log('Signed at:', result.timestamp);
}

verifyPublicOnly();
```

---

### Example 7: Sign Audio or Video Content
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature, CONTENT_TYPES } from '@majikah/majik-signature';

async function signMediaFile(file: File) {
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'passphrase', 'Artist Key');

  // Read file bytes — works for WAV, MP3, MP4, MOV, PNG, etc.
  const arrayBuffer = await file.arrayBuffer();
  const fileBytes = new Uint8Array(arrayBuffer);

  const contentType =
    file.type || CONTENT_TYPES.BINARY;

  const signature = await MajikSignature.sign(fileBytes, key, { contentType });

  console.log('✅ Media file signed');
  console.log('File:', file.name);
  console.log('Content Hash:', signature.contentHash);
  console.log('Content Type:', signature.contentType);
  console.log('Signer:', signature.signerId);

  // Attach signature as a sidecar JSON alongside the media file
  const sigJson = JSON.stringify(signature.toJSON(), null, 2);
  const sigBlob = new Blob([sigJson], { type: 'application/json' });

  // e.g. download as "track.wav.sig.json"
  return { signature, sigBlob };
}
```

---

## Signature Envelope

Every `MajikSignature` serializes to the following JSON structure:
```json
{
  "version": 1,
  "signerId": "base64-sha256-fingerprint-of-signer",
  "signerEdPublicKey": "base64-ed25519-public-key-32-bytes",
  "signerMlDsaPublicKey": "base64-ml-dsa-87-public-key-2592-bytes",
  "contentHash": "base64-sha256-of-content-44-chars",
  "contentType": "audio/wav",
  "timestamp": "2026-01-01T00:00:00.000Z",
  "edSignature": "base64-ed25519-signature-64-bytes",
  "mlDsaSignature": "base64-ml-dsa-87-signature-4595-bytes"
}
```

**Approximate serialized sizes:**

| Format            | Size   |
| ----------------- | ------ |
| JSON (minified)   | ~10 KB |
| Base64 serialized | ~14 KB |

The dominant contributor is `mlDsaSignature` (~6 KB base64) and `signerMlDsaPublicKey` (~3.5 KB base64). This is the inherent cost of post-quantum signatures and is negligible relative to any content being signed.

---

## Security Considerations

### What is Guaranteed

- **Content integrity**: Any byte change to the content invalidates the signature
- **Signer binding**: The signature is cryptographically bound to a specific MajikKey fingerprint
- **Timestamp binding**: The signing timestamp cannot be altered after signing
- **Forgery resistance (classical)**: Ed25519 provides 128-bit classical security
- **Forgery resistance (post-quantum)**: ML-DSA-87 provides NIST Category 5 post-quantum security
- **Hybrid downgrade resistance**: Both algorithms must be broken simultaneously to forge — a break in one is not sufficient

### What is Your Responsibility

- **Signer identity verification**: The library proves content was signed by a specific key. It does not prove who owns that key in the real world. You must maintain the mapping between `signerId` (fingerprint) and a real-world identity through your own means — a user registry, a `MajikContact`, or a `MajikMessageIdentity`.
- **Byte-for-byte content consistency**: The same bytes must be passed to both `sign()` and `verify()`. For strings, both sides must use the same encoding (UTF-8 is always used internally). For JSON, both sides must use the same `JSON.stringify()` output.
- **Key upgrade**: Legacy MajikKey accounts without signing keys must be re-imported via `importFromMnemonicBackup()` before signing. Load with `key.hasSigningKeys` to check.

### What NOT to Do

❌ **DON'T** trust `extractPublicKeys()` without cross-checking `signerId` against a known trusted source  
❌ **DON'T** sign JSON by passing the object directly — always `JSON.stringify()` first and agree on format  
❌ **DON'T** transform file bytes (compress, transcode, re-encode) between signing and verification  
❌ **DON'T** pass a locked key to `sign()` — call `unlock()` first  
❌ **DON'T** use `contentType` as a security mechanism — it is advisory only and not enforced  

### What TO Do

✅ **DO** verify `result.signerId` matches a known trusted fingerprint after calling `verify()`  
✅ **DO** use `verifyWithKey()` when you have the signer's `MajikKey` — it handles key extraction safely  
✅ **DO** lock the key immediately after signing to purge secret keys from memory  
✅ **DO** store signatures as sidecar files (`.sig.json`) alongside content for easy retrieval  
✅ **DO** use `CONTENT_TYPES` constants for standard content type labels  
✅ **DO** call `key.lock()` after `sign()` completes — do not keep keys unlocked longer than needed  

---

## Related Projects

### [Majik Key](https://www.npmjs.com/package/@majikah/majik-key)
Seed phrase account library — required peer dependency for signing.

### [Majik Message](https://message.majikah.solutions)
Secure messaging platform using Majik Keys and Majik Signatures for identity-bound communication.

[Read Docs](https://majikah.solutions/products/majik-message/docs)

Also available on [Microsoft Store](https://apps.microsoft.com/detail/9pmjgvzzjspn) for free.

---

## Contributing

If you want to contribute or help extend support to more platforms, reach out via email. All contributions are welcome!

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---

## Author

Made with 💙 by [@thezelijah](https://github.com/jedlsf)

**Developer**: Josef Elijah Fabian  
**GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)  
**Project Repository**: [https://github.com/Majikah/majik-signature](https://github.com/Majikah/majik-signature)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
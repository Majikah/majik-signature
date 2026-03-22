# Majik Signature

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

**Majik Signature** is a hybrid post-quantum content signing and verification library for the Majikah ecosystem. Built on top of **Majik Key**, it provides tamper-proof, forgery-resistant digital signatures for any content format — plaintext, JSON, PDF, audio, video, binary — using a dual-algorithm architecture that combines classical Ed25519 with post-quantum ML-DSA-87 (FIPS-204).

**Majik Signature now includes built-in file embedding** — sign any file and embed the signature directly into it. No sidecar files needed. PDFs stay PDFs, WAVs stay WAVs, MP4s stay MP4s.

![npm](https://img.shields.io/npm/v/@majikah/majik-signature) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-signature) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-signature) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)

---

- [Majik Signature](#majik-signature)
  - [Security Architecture](#security-architecture)
  - [Overview](#overview)
  - [Features](#features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [File Embedding — Quick Start](#file-embedding--quick-start)
  - [API Reference](#api-reference)
    - [Content Signing (bytes/strings)](#content-signing-bytesstrings)
    - [File Embedding](#file-embedding)
    - [Lower-Level Embed API](#lower-level-embed-api)
    - [Instance Methods](#instance-methods)
    - [Getters](#getters)
  - [Supported File Formats](#supported-file-formats)
  - [Usage Examples](#usage-examples)
  - [Signature Envelope](#signature-envelope)
  - [Security Considerations](#security-considerations)
  - [Related Projects](#related-projects)
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

This binding means a valid signature cannot be reused on different content, transferred to a different signer, replayed with a modified timestamp, or forged without both private keys.

### 3. Content-Agnostic Hashing

Content is never embedded in the envelope — only its SHA-256 hash is signed. This means a 500 MB video signs at the same speed as a 10-byte string, and any format is supported identically.

### 4. File Embedding Integrity

When a signature is embedded into a file, it always covers the **original file bytes before embedding**. Verification automatically strips the embedded signature before re-hashing, so the round-trip is always:

```
sign(originalBytes) → embed into file → extract → strip → verify(originalBytes)
```

Re-signing the same file is always safe and idempotent — the existing signature is stripped before the new one is created.

---

## Overview

### What is a Majik Signature?

A Majik Signature is a cryptographic proof that a specific piece of content was produced or approved by the holder of a specific **Majik Key** account, that the content has not been modified since it was signed, and that the signature remains valid against future quantum computing threats.

Verification is fully **public** — anyone with the signer's public keys can verify. No private key is ever needed for verification.

### Use Cases

- **Content Provenance**: Prove that a piece of music, art, document, or dataset was produced by a specific identity
- **File Integrity**: Detect any tampering or modification to distributed files
- **API Payload Signing**: Sign JSON responses or requests for non-repudiation
- **Document Authentication**: Certify legal documents, contracts, or records
- **Media Certification**: Stamp audio, video, or image files as authentic originals — with the signature embedded directly in the file
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

- **Plain text**, **JSON**, **Binary** — `Uint8Array` or `string`
- **PDF** — Signature appended as a clean trailer after the PDF's `%%EOF` marker; file remains valid and openable
- **PNG, JPEG** — Embedded in native chunk/marker metadata
- **WAV, MP3, FLAC** — Embedded in RIFF/ID3/Vorbis metadata
- **MP4, MOV, M4A, M4V** — Embedded in `moov/udta` box
- **DOCX, XLSX, PPTX, ODF** — Embedded as a file entry inside the ZIP container
- **MKV, WebM** — Embedded via append-safe trailer
- **HTML, Markdown, JSON, plain text, source code** — Appended comment block
- **Any other format** — Universal binary trailer (self-describing, cleanly strippable)

### Developer Experience

- **First-Class TypeScript Support**: Full type definitions for all interfaces and classes
- **Simple Core API**: `sign()` and `verify()` for bytes/strings; `signFile()` and `verifyFile()` for files
- **One-liner file signing**: `MajikSignature.signFile(blob, key)` — sign and embed in a single call
- **Format auto-detection**: MIME type and magic-byte sniffing — no manual format hints required
- **Idempotent re-signing**: Safely re-sign any file without accumulating stacked signatures
- **Structured Errors**: Typed error hierarchy for precise error handling
- **Isomorphic**: Works in Node.js and modern browser environments (no native deps)

### Serialization & Portability

- **JSON Envelope**: Full `toJSON()` / `fromJSON()` round-trip
- **Base64 Serialization**: `serialize()` / `deserialize()` for compact transport
- **File-embedded**: Signature lives inside the file itself — no sidecar files needed
- **Self-Contained**: Envelope includes signer's public keys — verifiable without a key registry

---

## Installation

```bash
# Using npm
npm install @majikah/majik-signature

# Peer dependency — must also be installed
npm install @majikah/majik-key
```

No native bindings. Works in Node.js 18+, all modern browsers, Deno, and Bun.

---

## Quick Start

```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature, CONTENT_TYPES } from '@majikah/majik-signature';

// ── Step 1: Create and unlock a MajikKey ─────────────────────────────────────
const mnemonic = MajikKey.generateMnemonic();
const key = await MajikKey.create(mnemonic, 'my-passphrase', 'My Signing Key');

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

// ── Step 4: Verify (no private key needed) ────────────────────────────────────
const publicKeys = MajikSignature.publicKeysFromMajikKey(key);
const result = MajikSignature.verify(document, signature, publicKeys);

console.log('Valid:', result.valid);      // true
console.log('Signer:', result.signerId);

// Shorthand — verify directly against a MajikKey
const result2 = MajikSignature.verifyWithKey(document, signature, key);
console.log('Valid:', result2.valid);     // true
```

---

## File Embedding — Quick Start

```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature } from '@majikah/majik-signature';

// ── Sign a file and embed the signature into it ───────────────────────────────
const { blob: signedBlob } = await MajikSignature.signFile(file, key);
// signedBlob is the same format as file — PDF stays PDF, WAV stays WAV, etc.

// ── Verify the embedded signature later ──────────────────────────────────────
const result = await MajikSignature.verifyFile(signedBlob, key);
if (result.valid) {
  console.log('Verified — signed by:', result.signerId);
  console.log('At:', result.timestamp);
  console.log('Handler used:', result.handler); // e.g. "PDF", "WAV", "MP4/MOV"
}

// ── Check if a file is signed (without verifying) ────────────────────────────
const signed = await MajikSignature.isSigned(file);

// ── Extract the embedded signature as a typed instance ───────────────────────
const sig = await MajikSignature.extractFrom(signedBlob);
if (sig) {
  console.log(sig.signerId, sig.timestamp, sig.contentHash);
}

// ── Get the original clean file (signature removed) ──────────────────────────
const originalBlob = await MajikSignature.stripFrom(signedBlob);

// ── Embed an already-computed signature into a file ──────────────────────────
const sig2 = await MajikSignature.sign(await file.arrayBuffer(), key);
const signedBlob2 = await sig2.embedIn(file);
```

---

## API Reference

### Content Signing (bytes/strings)

#### `MajikSignature.sign(content, key, options?)`

Sign raw bytes or a string with an unlocked MajikKey.

**Parameters:**
- `content: Uint8Array | string` — Content to sign. Strings are UTF-8 encoded before hashing.
- `key: MajikKey` — An unlocked MajikKey with signing keys present.
- `options?: SignOptions`
  - `contentType?: string` — Advisory label (e.g. `"audio/wav"`, `"application/pdf"`). See `CONTENT_TYPES`.
  - `timestamp?: string` — ISO 8601 timestamp override. Defaults to `new Date().toISOString()`.

**Returns:** `Promise<MajikSignature>`

**Throws:** `MajikSignatureKeyError` if the key is locked or has no signing keys.

---

#### `MajikSignature.verify(content, signature, publicKeys)`

Verify a signature against content and the signer's public keys. Both Ed25519 and ML-DSA-87 must pass.

**Parameters:**
- `content: Uint8Array | string` — The original content that was signed.
- `signature: MajikSignature | MajikSignatureJSON` — The signature to verify.
- `publicKeys: MajikSignerPublicKeys` — Signer's Ed25519 and ML-DSA-87 public keys.

**Returns:** `VerificationResult`
```typescript
{
  valid: boolean;
  signerId: string;
  contentHash: string;
  timestamp: string;
  contentType?: string;
  reason?: string;      // present when valid is false
}
```

---

#### `MajikSignature.verifyWithKey(content, signature, key)`

Convenience — verify directly against a MajikKey instance. Works on locked keys.

---

#### `MajikSignature.publicKeysFromMajikKey(key)`

Extract public keys from a MajikKey for use with `verify()`. Works on locked keys.

**Returns:** `MajikSignerPublicKeys`
```typescript
{
  signerId: string;
  edPublicKey: Uint8Array;    // 32 bytes
  mlDsaPublicKey: Uint8Array; // 2592 bytes
}
```

---

#### `MajikSignature.fromJSON(json)` / `MajikSignature.deserialize(base64)`

Reconstruct a `MajikSignature` from stored JSON or base64.

---

### File Embedding

These methods sign or verify files with the signature embedded directly in the file. The file format is auto-detected from magic bytes — no manual hints needed in most cases.

---

#### `MajikSignature.signFile(file, key, options?)`

Sign a file and embed the signature into it in one call. Strips any existing signature before signing so re-signing is always safe.

**Parameters:**
- `file: Blob` — The file to sign.
- `key: MajikKey` — An unlocked MajikKey with signing keys.
- `options?`
  - `contentType?: string` — Advisory label stored in the envelope.
  - `timestamp?: string` — ISO 8601 override.
  - `mimeType?: string` — Override auto-detected MIME type.

**Returns:** `Promise<{ blob: Blob; signature: MajikSignature; handler: string; mimeType: string }>`

- `blob` — The signed file. Same format as the input.
- `signature` — The `MajikSignature` instance, if you need it separately.
- `handler` — Which format handler was used (e.g. `"PDF"`, `"WAV"`, `"MP4/MOV"`).
- `mimeType` — The detected MIME type.

**Example:**
```typescript
const { blob: signedPdf } = await MajikSignature.signFile(pdfBlob, key);
// signedPdf is a valid PDF with the signature appended after its %%EOF marker
```

---

#### `MajikSignature.verifyFile(file, keyOrPublicKeys, options?)`

Verify a file's embedded signature. Accepts either a `MajikKey` instance or raw `MajikSignerPublicKeys`.

**Parameters:**
- `file: Blob` — The signed file.
- `keyOrPublicKeys: MajikKey | MajikSignerPublicKeys` — The key or public keys to verify against.
- `options?`
  - `expectedSignerId?: string` — If provided, checks `signerId` before running crypto.
  - `mimeType?: string` — Override auto-detected MIME type.

**Returns:** `Promise<VerificationResult & { handler?: string }>`

**Example:**
```typescript
const result = await MajikSignature.verifyFile(signedWav, key);
if (result.valid) {
  console.log('Signed by:', result.signerId);
  console.log('At:', result.timestamp);
}
```

---

#### `MajikSignature.extractFrom(file, options?)`

Extract the embedded signature as a fully typed `MajikSignature` instance. Returns `null` if no signature is found.

**Returns:** `Promise<MajikSignature | null>`

**Example:**
```typescript
const sig = await MajikSignature.extractFrom(file);
if (sig) {
  console.log(sig.signerId, sig.timestamp, sig.contentHash);
}
```

---

#### `MajikSignature.stripFrom(file, options?)`

Return a clean copy of the file with any embedded signature removed. The returned bytes are exactly what was originally signed.

**Returns:** `Promise<Blob>`

**Example:**
```typescript
const original = await MajikSignature.stripFrom(signedMp4);
// original bytes are what was hashed when the signature was created
```

---

#### `MajikSignature.isSigned(file, options?)`

Check whether a file contains an embedded signature. Does not verify — purely a structural presence check. Useful as a fast guard before verification.

**Returns:** `Promise<boolean>`

**Example:**
```typescript
if (await MajikSignature.isSigned(file)) {
  const result = await MajikSignature.verifyFile(file, key);
}
```

---

#### `signature.embedIn(file, options?)` *(instance method)*

Embed this `MajikSignature` instance into a file. Call on an existing instance when you have already signed the content separately.

> **Note:** The signature must have been created from the original file bytes **before** embedding. Use `signFile()` if you want signing and embedding together.

**Returns:** `Promise<Blob>`

**Example:**
```typescript
const originalBytes = new Uint8Array(await file.arrayBuffer());
const sig = await MajikSignature.sign(originalBytes, key);
const signedBlob = await sig.embedIn(file);
```

---

### Lower-Level Embed API

For advanced use cases — custom handler registration, explicit format control, or accessing handler metadata — the underlying `MajikSignatureEmbed` class is also exported.

```typescript
import { MajikSignatureEmbed } from '@majikah/majik-signature';

// Register a custom handler for an unsupported format
MajikSignatureEmbed.registry.register(new MyCustomHandler());

// List all registered handlers
console.log(MajikSignatureEmbed.listHandlers());
// → ['PDF', 'PNG', 'JPEG', 'WAV', 'MP3', 'MP4/MOV', 'FLAC', 'MKV/WebM',
//    'Office (DOCX/XLSX/PPTX/ODF)', 'Text/Markup/Source',
//    'Fallback (Universal Trailer)']

// Force the Tier-2 trailer even for natively supported formats
const { blob } = await MajikSignatureEmbed.embed(file, sig, { forceFallback: true });
```

---

### Instance Methods

#### `validate()`
Validate the envelope's internal structure without performing cryptographic verification. Throws `MajikSignatureValidationError` on any structural problem.

#### `isValid()`
Returns `true` if the envelope is structurally valid. Never throws — safe to use as a boolean guard.

#### `extractPublicKeys()`
Extract the signer's public keys from the envelope.

> ⚠️ Public keys embedded in the envelope are self-reported by the signer. Always cross-check `signerId` against a trusted source before trusting extracted keys for verification.

#### `toJSON()`
Export the full signature envelope as a plain JSON object.

#### `serialize()`
Serialize the envelope to a compact base64 string. Suitable for embedding in database fields, HTTP headers, file metadata, or sidecar files.

#### `toString()`
Alias for `serialize()`.

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

## Supported File Formats

### Tier 1 — Native or format-aware embedding

The signature is stored using each format's established extension point or a spec-compliant append location. The file remains structurally valid and openable with standard tools.

| Format                                    | Embedding mechanism                                                                                                                                                                                                                                                           |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **PDF**                                   | Binary trailer appended after the final `%%EOF` marker (`\n%%MajikSig%%\n` sentinel). PDF spec §7.5.6 permits trailing data; the file opens normally in all viewers. Human-readable display metadata can be added separately via `MajikSignatureClient.addDisplayMetadata()`. |
| **PNG**                                   | `iTXt` chunk with keyword `majik-signature`                                                                                                                                                                                                                                   |
| **JPEG / JPG**                            | Custom `APP15` marker segment                                                                                                                                                                                                                                                 |
| **WAV / WAVE**                            | RIFF `LIST INFO` chunk — `ISIG` entry                                                                                                                                                                                                                                         |
| **MP3**                                   | ID3v2 `TXXX` frame with description `MAJIK-SIGNATURE`                                                                                                                                                                                                                         |
| **MP4 / MOV / M4A / M4V**                 | `moov → udta → majk` box                                                                                                                                                                                                                                                      |
| **FLAC**                                  | `VORBIS_COMMENT` block — `MAJIK-SIGNATURE=` field                                                                                                                                                                                                                             |
| **MKV / WebM**                            | Append-safe binary trailer                                                                                                                                                                                                                                                    |
| **DOCX / XLSX / PPTX / ODF**              | `majik-signature.json` entry inside the ZIP container                                                                                                                                                                                                                         |
| **HTML / XML / SVG / Markdown**           | `<!-- MAJIK-SIGNATURE-BEGIN -->` block appended at end                                                                                                                                                                                                                        |
| **Plain text / JSON / CSV / source code** | Same comment block                                                                                                                                                                                                                                                            |

### Tier 2 — Universal trailer

For any format not covered above, a self-describing binary trailer is appended:

```
[original file bytes][signature JSON UTF-8][8-byte payload length LE][8-byte magic: MAJIKSIG]
```

The magic bytes at the end allow detection and clean stripping from any file without knowing its format. Most parsers and players ignore trailing bytes.

> **Re-mux warning:** For MKV/WebM and the Tier-2 fallback, the embedded signature will be stripped if the file is re-encoded or re-muxed through a tool that rewrites the container. For MP4, DOCX, and all other Tier-1 native-metadata formats, the signature survives standard open → save round-trips.

---

## Usage Examples

### Example 1: Sign and Verify a Text Document
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature, CONTENT_TYPES } from '@majikah/majik-signature';

const mnemonic = MajikKey.generateMnemonic();
const key = await MajikKey.create(mnemonic, 'passphrase', 'Author Key');

const document = `
  AGREEMENT
  This agreement is entered into on January 1, 2026.
  Party A agrees to deliver the software by March 31, 2026.
`;

const signature = await MajikSignature.sign(document, key, {
  contentType: CONTENT_TYPES.TEXT,
});

const result = MajikSignature.verifyWithKey(document, signature, key);
console.log('Valid:', result.valid); // true

// Tamper detection
const tampered = document + ' (modified)';
const tamperResult = MajikSignature.verifyWithKey(tampered, signature, key);
console.log('Tampered rejected:', tamperResult.valid); // false
```

---

### Example 2: Sign a File and Embed the Signature
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature } from '@majikah/majik-signature';

const mnemonic = MajikKey.generateMnemonic();
const key = await MajikKey.create(mnemonic, 'passphrase', 'Artist Key');

// Works for any file — PDF, WAV, MP3, MP4, PNG, DOCX, etc.
const { blob: signedFile, handler } = await MajikSignature.signFile(file, key);

console.log('Signed using handler:', handler);
// e.g. "PDF", "WAV", "MP4/MOV", "Office (DOCX/XLSX/PPTX/ODF)"

// The signed file is the same format — upload or save it directly
await uploadFile(signedFile);
```

---

### Example 3: Verify an Embedded Signature
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature } from '@majikah/majik-signature';

// key does NOT need to be unlocked for verification
const key = MajikKey.fromJSON(storedKeyJson);

const result = await MajikSignature.verifyFile(downloadedFile, key);

if (result.valid) {
  console.log('Authentic. Signed by:', result.signerId);
  console.log('Signed at:', result.timestamp);
} else {
  console.log('Invalid or tampered:', result.reason);
}
```

---

### Example 4: Sign a Binary File (Node.js)
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature, CONTENT_TYPES } from '@majikah/majik-signature';
import { readFileSync } from 'fs';

const key = await MajikKey.create(mnemonic, 'passphrase', 'Publisher Key');
const fileBytes = new Uint8Array(readFileSync('./release.zip'));

// Option A: Sign bytes, store signature separately
const signature = await MajikSignature.sign(fileBytes, key, {
  contentType: 'application/zip',
});
const result = MajikSignature.verifyWithKey(fileBytes, signature, key);
console.log('Verified:', result.valid); // true

// Option B: Sign and embed into the file itself
const fileBlob = new Blob([fileBytes], { type: 'application/zip' });
const { blob: signedBlob } = await MajikSignature.signFile(fileBlob, key);
```

---

### Example 5: Sign a JSON Payload
```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikSignature, CONTENT_TYPES } from '@majikah/majik-signature';

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

const response = { data: payload, signature: signature.toJSON() };

// On the receiving end
const result = MajikSignature.verifyWithKey(
  JSON.stringify(response.data),
  response.signature,
  key,
);
console.log('Payload verified:', result.valid); // true
```

---

### Example 6: Extract and Inspect an Embedded Signature
```typescript
import { MajikSignature } from '@majikah/majik-signature';

// Extract without verifying — useful for inspecting provenance metadata
const sig = await MajikSignature.extractFrom(file);

if (sig) {
  console.log('Signer ID:', sig.signerId);
  console.log('Signed at:', sig.timestamp);
  console.log('Content hash:', sig.contentHash);
  console.log('Content type:', sig.contentType);
} else {
  console.log('No signature found');
}
```

---

### Example 7: Re-sign a File
```typescript
import { MajikSignature } from '@majikah/majik-signature';

// signFile() strips any existing signature before signing — always safe to call
const { blob: resignedFile } = await MajikSignature.signFile(previouslySignedFile, key);
// The new signature covers the original content bytes, not the previously signed file
```

---

### Example 8: Verify Using Only Public Keys
```typescript
import { MajikSignature } from '@majikah/majik-signature';
import type { MajikSignerPublicKeys } from '@majikah/majik-signature';

// Public keys received from a trusted source (e.g. a user profile API)
const publicKeys: MajikSignerPublicKeys = {
  signerId: 'base64-fingerprint-of-the-signer',
  edPublicKey: new Uint8Array(/* 32 bytes */),
  mlDsaPublicKey: new Uint8Array(/* 2592 bytes */),
};

// Verify embedded signature without a MajikKey instance
const result = await MajikSignature.verifyFile(signedFile, publicKeys, {
  expectedSignerId: publicKeys.signerId,
});
console.log('Verified:', result.valid);
```

---

### Example 9: Serialize and Store a Signature
```typescript
const signature = await MajikSignature.sign(content, key);

// Store as JSON
const json = signature.toJSON();
await db.signatures.insert({ id: docId, sig: json });

// Store as base64 (HTTP header, metadata field, etc.)
const b64 = signature.serialize();
res.setHeader('X-Majik-Signature', b64);

// Restore later
const sigFromJson = MajikSignature.fromJSON(json);
const sigFromB64 = MajikSignature.deserialize(b64);
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
- **Embed integrity**: File embedding always signs original bytes — the embedding container is never part of what's signed

### What is Your Responsibility

- **Signer identity verification**: The library proves content was signed by a specific key. It does not prove who owns that key in the real world. Maintain the mapping between `signerId` (fingerprint) and a real-world identity through your own means.
- **Byte-for-byte content consistency**: The same bytes must be passed to both `sign()` and `verify()`. For strings, both sides must use UTF-8. For JSON, both sides must use the same `JSON.stringify()` output.
- **Key upgrade**: Legacy MajikKey accounts without signing keys must be re-imported via `importFromMnemonicBackup()` before signing. Check with `key.hasSigningKeys`.

### What NOT to Do

❌ **DON'T** trust `extractPublicKeys()` without cross-checking `signerId` against a known trusted source  
❌ **DON'T** sign JSON by passing the object directly — always `JSON.stringify()` first  
❌ **DON'T** transform file bytes (compress, transcode, re-encode) between signing and verification  
❌ **DON'T** pass a locked key to `sign()` or `signFile()` — call `unlock()` first  
❌ **DON'T** use `contentType` as a security mechanism — it is advisory only and not enforced  
❌ **DON'T** assume a Tier-2 trailer signature survives re-muxing — use native-metadata formats where durability matters  

### What TO Do

✅ **DO** verify `result.signerId` matches a known trusted fingerprint after calling `verify()` or `verifyFile()`  
✅ **DO** use `verifyWithKey()` / `verifyFile(key)` when you have the signer's `MajikKey` — it handles key extraction safely  
✅ **DO** lock the key immediately after signing — `key.lock()` purges secret keys from memory  
✅ **DO** use `signFile()` for media and documents to keep signature and content together  
✅ **DO** use `isSigned()` as a fast guard before calling `verifyFile()` in hot paths  
✅ **DO** use `CONTENT_TYPES` constants for standard content type labels  

---

## Related Projects

### [Majik Key](https://www.npmjs.com/package/@majikah/majik-key)
Seed phrase account library — required peer dependency for signing.

### [Majik Message](https://message.majikah.solutions)
Secure messaging platform using Majik Keys and Majik Signatures for identity-bound communication.

[Read Docs](https://majikah.solutions/products/majik-message/docs) · [Microsoft Store](https://apps.microsoft.com/detail/9pmjgvzzjspn)

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
# Changelog

## 1.6.0 - 2026-11-28

- Make MJKSMAP container version 2 with CBOR the default binary output; continue reading legacy version 1 JSON containers.
- Encode MJKSMAP entry content hashes and nested envelope binary fields (keys, signatures, signer IDs, digests, hashes, and anchors) as raw CBOR byte strings instead of Base64/hex text.
- Preserve the public version-1 `MjksMapJSON` schema and `toJSON()` / `fromJSON()` compatibility APIs.
- Keep the 16 MiB limit on binary payloads; allow a 24 MiB JSON model input budget for Base64 expansion while preserving the legacy v1 container's 16 MiB limit.
- Align the TypeScript core release with `majik-signature-rs` 1.6.0.
- Cap the supported streaming hash chunk override at 64 MiB while retaining the 1 MiB default and 8 MiB automatic threshold.
- Add `StreamingHashOptions.totalBytes` to validate exact stream length and detect truncated or overlong sources.
- Add `MajikSignature.signBatchDetachedStream()` for sequential, bounded-memory detached batch signing into `.mjksmap` or separate `.mjksig` outputs.
- Add per-file progress reporting and per-file failure collection for streaming batch signing.
- Add `MajikSignature.verifyFilesFromMjksMapStream()` with single-pass hashing, path-first tamper detection, and content-hash relocation.
- Cover both `.mjksmap` and separate `.mjksig` output modes in streaming batch signing tests.
- Add regression tests for declared stream lengths, chunk boundaries, cross-path verification, and streaming batch results.
- Bound MJKSMAP payloads to 16 MiB, entries to 10,000, and normalized paths to 4,096 UTF-16 code units; reject traversal, spoofing controls, duplicate normalized paths, malformed UTF-8, trailing bytes, and invalid header fields.
- Apply the 16 MiB envelope ceiling to object inputs and immutable builders; reject oversized Base64 before decoding and validate builder-supplied signatures, allowlists, seals, anchors, and revision metadata.
- Deep-freeze envelope and MJKSMAP instances plus nested JSON snapshots; `toJSON()` returns detached mutable copies so post-validation mutation cannot alter stored state.
- Add virtual 32 MiB multi-chunk stress tests and an opt-in 10 GiB streaming stress test; exercise timer cancellation, stream errors, malformed chunks, and option validation.


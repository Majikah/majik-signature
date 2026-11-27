# Changelog

## 1.6.0 - 2026-11-28

- Align the TypeScript core release with `majik-signature-rs` 1.6.0.
- Align the supported streaming hash chunk override ceiling at 256 MiB while retaining the 1 MiB default and 8 MiB automatic threshold.
- Add `StreamingHashOptions.totalBytes` to validate exact stream length and detect truncated or overlong sources.
- Add `MajikSignature.signBatchDetachedStream()` for sequential, bounded-memory detached batch signing into `.mjksmap` or separate `.mjksig` outputs.
- Add per-file progress reporting and per-file failure collection for streaming batch signing.
- Add `MajikSignature.verifyFilesFromMjksMapStream()` with single-pass hashing, path-first tamper detection, and content-hash relocation.
- Add regression tests for declared stream lengths, maximum chunk configuration, cross-path verification, and streaming batch results.


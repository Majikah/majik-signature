/**
 * index.ts
 * Public API surface for majik-signature.
 */

// ── Main class ────────────────────────────────────────────────────────────────
export { MajikSignature } from "./majik-signature";

// ── Types ─────────────────────────────────────────────────────────────────────
export type * from "./core/types";

// ── Errors ────────────────────────────────────────────────────────────────────
export * from "./core/errors";

// ── Constants ─────────────────────────────────────────────────────────────────
export * from "./core/constants";

export * from "./core/embed/majik-embed";

// ── Chain Anchor ─────────────────────────────────────────────────────────────────
export type * from "./anchor/types";

// ── Low-level utilities (opt-in) ──────────────────────────────────────────────
// These are exported for consumers who want to build on top of the primitives
// without going through MajikSignature (e.g. streaming hash pipelines,
// custom envelope formats). Not needed for normal sign/verify usage.
export { buildSigningPayload } from "./core/payload";
export { hashContent, bytesToBase64, base64ToBytes } from "./core/hash";
export { MajikSignatureValidator } from "./core/validator";

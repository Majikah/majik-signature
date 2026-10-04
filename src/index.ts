/**
 * index.ts
 * Public API surface for majik-signature.
 */

// ── Main class ────────────────────────────────────────────────────────────────
export { MajikSignature } from "./majik-signature.js";

// ── Types ─────────────────────────────────────────────────────────────────────
export type * from "./core/types.js";

// ── Errors ────────────────────────────────────────────────────────────────────
export * from "./core/errors.js";

// ── Constants ─────────────────────────────────────────────────────────────────
export * from "./core/constants.js";

export * from "./core/embed/handlers/index.js";

export * from "./core/embed/majik-embed.js";

export * from "./core/envelope.js";

export * from "./core/mjksmap.js";
export * from "./cli.js";
export * from "./cli-core/index.js";

// ── Chain Anchor ─────────────────────────────────────────────────────────────────
export type * from "./anchor/types.js";

// ── Low-level utilities (opt-in) ──────────────────────────────────────────────
// These are exported for consumers who want to build on top of the primitives
// without going through MajikSignature (e.g. streaming hash pipelines,
// custom envelope formats). Not needed for normal sign/verify usage.
export { buildSigningPayload } from "./core/payload.js";
export { hashContent, bytesToBase64, base64ToBytes } from "./core/hash.js";
export { MajikSignatureValidator } from "./core/validator.js";

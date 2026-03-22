/**
 * image-signature.ts — MajikImageSignature (dual-layer)
 *
 * Two independent proofs embedded in every signed image:
 *
 *   Layer 1 — Pixel row  (bottom of image, +~6px height)
 *     · Full MajikSignature envelope: Ed25519 + ML-DSA-87
 *     · Survives direct file sharing, email attachments, Slack, internal tools
 *     · Visually blended to bottom edge color
 *     · Stripped by platforms that crop/resize (expected — Layer 2 covers this)
 *
 *   Layer 2 — DCT steganography (invisible, within existing pixels)
 *     · Compact stub: Ed25519 only (150 bytes + Reed-Solomon ECC = 225 bytes total)
 *     · Survives Q70 JPEG recompression, WebP conversion, platform uploads
 *     · Invisible — no dimension change, no visible artifact
 *     · Cannot carry ML-DSA-87 at Q70 (mathematically impossible at typical sizes)
 *
 * ── Verification logic ────────────────────────────────────────────────────────
 *
 *   Both layers present → BOTH must pass (maximum integrity)
 *   Pixel row only      → pixel row must pass (full post-quantum)
 *   DCT stub only       → DCT stub must pass (Ed25519 fallback)
 *   Neither             → invalid
 *
 * ── Signing flow ──────────────────────────────────────────────────────────────
 *
 *   1. Decode input image → RGBA pixels
 *   2. Pad to 640×640 minimum
 *   3. Strip any existing layers (idempotent re-signing)
 *   4. Compute pHash of clean pixels
 *   5. Sign with Ed25519 → build DCT stub
 *   6. Embed DCT stub into pixels (Layer 2)
 *   7. Sign DCT-modified pixels with full MajikSignature (Ed25519 + ML-DSA-87)
 *   8. Append pixel rows with full envelope (Layer 1)
 *   9. Encode output (PNG default)
 */

import * as ed25519 from "@stablelib/ed25519";
import type { MajikKey } from "@majikah/majik-key";

// ─── MajikSignature adapter ───────────────────────────────────────────────────
//
// MajikImageSignature cannot import MajikSignature directly — it lives inside
// the same package and that would be a circular import:
//
//   majik-signature → core/stamp/image-signature → majik-signature  ✗
//
// Instead, callers (MajikSignature.stampImage / verifyStamp) pass the class
// itself as `MajikSig` at call time. These interfaces define the exact surface
// MajikImageSignature needs — nothing more.
//
// MajikSignatureJSON is also defined here locally (mirroring the canonical type)
// rather than imported, for the same reason.

/** Mirrors MajikSignatureJSON from the parent package — kept in sync manually. */
export interface MajikSignatureJSON {
  version: 1;
  signerId: string;
  signerEdPublicKey: string;
  signerMlDsaPublicKey: string;
  contentHash: string;
  contentType?: string;
  timestamp: string;
  edSignature: string;
  mlDsaSignature: string;
}

export interface MajikSignerPublicKeys {
  signerId: string;
  edPublicKey: Uint8Array;
  mlDsaPublicKey: Uint8Array;
}

/** Minimal static surface of MajikSignature that MajikImageSignature needs. */
export interface MajikSignatureStaticAdapter {
  signFile(
    file: Blob,
    key: MajikKey,
    options?: { contentType?: string; timestamp?: string; mimeType?: string },
  ): Promise<{
    blob: Blob;
    signature: { toJSON(): MajikSignatureJSON };
    handler: string;
    mimeType: string;
  }>;

  verifyFile(
    file: Blob,
    keyOrPublicKeys: MajikSignerPublicKeys,
    options?: { expectedSignerId?: string; mimeType?: string },
    debug?: boolean,
  ): Promise<{ valid: boolean; reason?: string }>;
}

import { computePHash, pHashMatches, hammingDistance } from "./core/phash";
import { dctEmbed, dctExtract, dctCapacity } from "./core/dct-stego";
import { rsEncode, rsDecode, RS_TOTAL_BYTES } from "./core/reed-solomon";
import { serializeStub, deserializeStub } from "./core/stub";
import { buildImageSigningPayload } from "./core/payload";
import {
  pixelRowEmbed,
  pixelRowExtract,
  pixelRowStrip,
} from "./core/pixel-row";
import {
  decodeImage,
  encodeImage,
  padToMinimum,
  MIN_DIMENSION,
} from "./core/image-utils";
import type { ImageSignatureStub, ImageSignOptions } from "./core/types";

// ─── Result types ─────────────────────────────────────────────────────────────

export type VerificationLayer = "both" | "pixel-row" | "dct-only";

export interface ImageVerificationResult {
  valid: boolean;
  reason?: string;
  /** Which layer(s) were found and used for verification */
  layer?: VerificationLayer;
  signerId?: string;
  timestamp?: string;
  storedPHash?: string;
  computedPHash?: string;
  hammingDistance?: number;
  signerEdPublicKey?: string;
  /** Full MajikSignatureJSON from pixel row, when present */
  fullEnvelope?: MajikSignatureJSON;
}

// ─── Errors ───────────────────────────────────────────────────────────────────

export class MajikImageSignatureError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "MajikImageSignatureError";
    if (cause) this.cause = cause;
  }
}

export class MajikImageCapacityError extends MajikImageSignatureError {
  constructor(
    width: number,
    height: number,
    needed: number,
    available: number,
  ) {
    super(
      `Image too small for DCT embedding. ` +
        `At ${width}×${height}px, DCT capacity is ~${available} bytes ` +
        `but ${needed} bytes needed. Minimum: ${MIN_DIMENSION}×${MIN_DIMENSION}px.`,
    );
    this.name = "MajikImageCapacityError";
  }
}

// ─── MajikImageSignature ──────────────────────────────────────────────────────

export class MajikImageSignature {
  /**
   * Sign an image with dual-layer embedding.
   *
   * Layer 1 (pixel rows): full MajikSignature — Ed25519 + ML-DSA-87.
   * Layer 2 (DCT stego):  Ed25519-only stub, survives Q70 recompression.
   *
   * @param imageBlob   Any browser-supported image format
   * @param key         Unlocked MajikKey with signing keys
   * @param MajikSig    MajikSignature class reference (avoids circular import)
   * @param options     Output format and timestamp overrides
   */
  static async sign(
    imageBlob: Blob,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options: ImageSignOptions = {},
  ): Promise<{
    blob: Blob;
    stub: ImageSignatureStub;
    fullEnvelope: MajikSignatureJSON;
  }> {
    if (key.isLocked) {
      throw new MajikImageSignatureError(
        "MajikKey is locked. Call unlock() before signing.",
      );
    }
    if (!key.hasSigningKeys) {
      throw new MajikImageSignatureError(
        "MajikKey has no signing keys. Re-import via importFromMnemonicBackup().",
      );
    }

    // ── Decode and strip any existing signature ──
    let { pixels, width, height } = await decodeImage(imageBlob);
    const stripped = pixelRowStrip(pixels, width, height);
    pixels = stripped.pixels;
    width = stripped.width;
    height = stripped.height;

    // ── Pad to minimum dimensions ──
    if (width < MIN_DIMENSION || height < MIN_DIMENSION) {
      const padded = padToMinimum({ pixels, width, height });
      pixels = padded.pixels;
      width = padded.width;
      height = padded.height;
    }

    // ── Check DCT capacity ──
    const capacity = dctCapacity(width, height);
    if (capacity < RS_TOTAL_BYTES) {
      throw new MajikImageCapacityError(
        width,
        height,
        RS_TOTAL_BYTES,
        capacity,
      );
    }

    // ── pHash and timestamp ──
    const pHash = computePHash(pixels, width, height);
    const timestamp = options.timestamp ?? new Date().toISOString();
    const signerId = key.fingerprint;

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 2: DCT stub — Ed25519 signs the pHash directly
    // ─────────────────────────────────────────────────────────────────────────

    const imagePayload = buildImageSigningPayload({
      signerId,
      timestamp,
      pHash,
    });
    const edSecretKey = key.getEdSecretKey();
    const edPublicKey = key.edPublicKey!;
    const edSigBytes = ed25519.sign(edSecretKey, imagePayload);

    const stub: ImageSignatureStub = {
      pHash,
      signerEdPublicKey: bytesToHex(edPublicKey),
      edSignature: bytesToHex(edSigBytes),
      signerId,
      timestamp,
    };

    // Embed DCT stub
    const pixelsWithDct = new Uint8ClampedArray(pixels);
    const bitsWritten = dctEmbed(
      pixelsWithDct,
      width,
      height,
      rsEncode(serializeStub(stub)),
    );

    if (bitsWritten < RS_TOTAL_BYTES * 8) {
      throw new MajikImageSignatureError(
        `DCT embedding incomplete: ${bitsWritten} bits written, ${RS_TOTAL_BYTES * 8} needed. ` +
          `Image may lack sufficient high-magnitude DCT coefficients.`,
      );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 1: Pixel row — full MajikSignature signs the DCT-modified image
    //
    // We sign the DCT-modified PNG bytes. This means the full signature covers
    // the image *including* the invisible DCT stub. When the pixel rows are
    // stripped by a platform, what remains is exactly what was signed — the
    // DCT-modified image — which the stub then verifies perceptually.
    // ─────────────────────────────────────────────────────────────────────────

    const dctBlob = await encodeImage(pixelsWithDct, width, height, {
      mimeType: "image/png",
    });

    const { signature: fullSig } = await MajikSig.signFile(dctBlob, key, {
      contentType: "image/majik-signed",
      timestamp,
    });
    const fullEnvelope = fullSig.toJSON();

    // Append pixel rows
    const pixelRowResult = pixelRowEmbed(
      pixelsWithDct,
      width,
      height,
      JSON.stringify(fullEnvelope),
    );

    // ── Encode output ──
    const blob = await encodeImage(
      pixelRowResult.pixels,
      pixelRowResult.width,
      pixelRowResult.height,
      {
        mimeType: options.outputMimeType ?? "image/png",
        quality: options.jpegQuality ? options.jpegQuality / 100 : 0.92,
      },
    );

    return { blob, stub, fullEnvelope };
  }

  /**
   * Verify an image's dual-layer MajikImageSignature.
   *
   * Both layers present → both must pass.
   * Only DCT present   → DCT must pass (platform-compressed fallback).
   * Only pixel row     → pixel row must pass.
   * Neither            → invalid.
   *
   * @param imageBlob   The (possibly compressed) signed image
   * @param MajikSig    MajikSignature class reference
   * @param options     hammingThreshold override (default 8)
   */
  static async verify(
    imageBlob: Blob,
    MajikSig: MajikSignatureStaticAdapter,
    options: { hammingThreshold?: number } = {},
  ): Promise<ImageVerificationResult> {
    const threshold = options.hammingThreshold ?? 8;

    const { pixels, width, height } = await decodeImage(imageBlob);

    // ── Try pixel row layer ──
    const pixelRowResult = pixelRowExtract(pixels, width, height);
    const hasPixelRow = pixelRowResult !== null;

    // Work with clean pixels (rows stripped) for DCT and pHash
    let cleanPixels = hasPixelRow ? pixelRowResult!.originalPixels : pixels;
    let cleanWidth = hasPixelRow ? pixelRowResult!.originalWidth : width;
    let cleanHeight = hasPixelRow ? pixelRowResult!.originalHeight : height;

    if (cleanWidth < MIN_DIMENSION || cleanHeight < MIN_DIMENSION) {
      const padded = padToMinimum({
        pixels: cleanPixels,
        width: cleanWidth,
        height: cleanHeight,
      });
      cleanPixels = padded.pixels;
      cleanWidth = padded.width;
      cleanHeight = padded.height;
    }

    // ── Try DCT layer ──
    const rawDctBytes = dctExtract(
      cleanPixels,
      cleanWidth,
      cleanHeight,
      RS_TOTAL_BYTES,
    );
    const correctedDct = rsDecode(rawDctBytes);
    const dctStub = correctedDct ? deserializeStub(correctedDct) : null;
    const hasDct = dctStub !== null;

    if (!hasPixelRow && !hasDct) {
      return {
        valid: false,
        reason:
          "No MajikImageSignature found. Image was not signed, or both layers were " +
          "destroyed (screenshot, heavy crop, or below-Q70 recompression).",
      };
    }

    // ── Recompute pHash ──
    const computedPHash = computePHash(cleanPixels, cleanWidth, cleanHeight);

    // ── Verify DCT stub ──
    let dctValid = false;
    let dctFailReason: string | undefined;

    if (hasDct) {
      const dist = hammingDistance(dctStub!.pHash, computedPHash);
      if (!pHashMatches(dctStub!.pHash, computedPHash, threshold)) {
        dctFailReason = `DCT layer: pHash mismatch (Hamming ${dist} > threshold ${threshold}).`;
      } else {
        try {
          const payload = buildImageSigningPayload({
            signerId: dctStub!.signerId,
            timestamp: dctStub!.timestamp,
            pHash: dctStub!.pHash,
          });
          dctValid = ed25519.verify(
            hexToBytes(dctStub!.signerEdPublicKey),
            payload,
            hexToBytes(dctStub!.edSignature),
          );
          if (!dctValid)
            dctFailReason = "DCT layer: Ed25519 signature invalid.";
        } catch {
          dctFailReason = "DCT layer: Ed25519 verification error.";
        }
      }
    }

    // ── Verify pixel row ──
    let pixelRowValid = false;
    let pixelRowFailReason: string | undefined;
    let fullEnvelope: MajikSignatureJSON | undefined;
    let pixelRowSignerId: string | undefined;
    let pixelRowTimestamp: string | undefined;
    let pixelRowEdPubKey: string | undefined;

    if (hasPixelRow) {
      try {
        const parsedEnvelope = JSON.parse(
          pixelRowResult!.signatureJson,
        ) as MajikSignatureJSON;
        fullEnvelope = parsedEnvelope;

        // Re-encode clean (DCT-modified) pixels as PNG — this is what was signed
        const dctBlob = await encodeImage(
          cleanPixels,
          cleanWidth,
          cleanHeight,
          {
            mimeType: "image/png",
          },
        );

        const verifyResult = await MajikSig.verifyFile(dctBlob, {
          signerId: parsedEnvelope.signerId,
          edPublicKey: base64ToBytes(parsedEnvelope.signerEdPublicKey),
          mlDsaPublicKey: base64ToBytes(parsedEnvelope.signerMlDsaPublicKey),
        });

        if (verifyResult.valid) {
          pixelRowValid = true;
          pixelRowSignerId = parsedEnvelope.signerId;
          pixelRowTimestamp = parsedEnvelope.timestamp;
          pixelRowEdPubKey = bytesToHex(
            base64ToBytes(parsedEnvelope.signerEdPublicKey),
          );

          // Cross-check: if both layers present, signerIds must match
          if (
            hasDct &&
            dctStub!.signerId &&
            pixelRowSignerId !== dctStub!.signerId
          ) {
            pixelRowValid = false;
            pixelRowFailReason =
              `Layer mismatch: pixel row signerId "${pixelRowSignerId}" ≠ ` +
              `DCT signerId "${dctStub!.signerId}". Image may be tampered.`;
          }
        } else {
          pixelRowFailReason = `Pixel row layer: ${verifyResult.reason ?? "verification failed."}`;
        }
      } catch (err) {
        pixelRowFailReason = `Pixel row layer: failed to verify (${err}).`;
      }
    }

    // ── Decision ──
    const dist = dctStub
      ? hammingDistance(dctStub.pHash, computedPHash)
      : undefined;
    const commonMeta = {
      storedPHash: dctStub?.pHash,
      computedPHash,
      hammingDistance: dist,
      fullEnvelope,
    };

    if (hasPixelRow && hasDct) {
      if (pixelRowValid && dctValid) {
        return {
          valid: true,
          layer: "both",
          signerId: pixelRowSignerId ?? dctStub!.signerId,
          timestamp: pixelRowTimestamp ?? dctStub!.timestamp,
          signerEdPublicKey: pixelRowEdPubKey ?? dctStub!.signerEdPublicKey,
          ...commonMeta,
        };
      }
      const reasons = [
        !pixelRowValid ? pixelRowFailReason : null,
        !dctValid ? dctFailReason : null,
      ]
        .filter(Boolean)
        .join(" | ");
      return {
        valid: false,
        layer: "both",
        reason: `Both layers present but one or more failed: ${reasons}`,
        signerId: pixelRowSignerId ?? dctStub?.signerId,
        timestamp: pixelRowTimestamp ?? dctStub?.timestamp,
        ...commonMeta,
      };
    }

    if (hasPixelRow && !hasDct) {
      return pixelRowValid
        ? {
            valid: true,
            layer: "pixel-row",
            signerId: pixelRowSignerId,
            timestamp: pixelRowTimestamp,
            signerEdPublicKey: pixelRowEdPubKey,
            ...commonMeta,
          }
        : {
            valid: false,
            layer: "pixel-row",
            reason: pixelRowFailReason ?? "Pixel row failed.",
            ...commonMeta,
          };
    }

    // DCT only
    return dctValid
      ? {
          valid: true,
          layer: "dct-only",
          signerId: dctStub!.signerId,
          timestamp: dctStub!.timestamp,
          signerEdPublicKey: dctStub!.signerEdPublicKey,
          ...commonMeta,
        }
      : {
          valid: false,
          layer: "dct-only",
          reason: dctFailReason ?? "DCT verification failed.",
          signerId: dctStub?.signerId,
          timestamp: dctStub?.timestamp,
          ...commonMeta,
        };
  }

  /**
   * Fast inspection of which layers are present, without full verification.
   */
  static async inspect(imageBlob: Blob): Promise<{
    hasPixelRow: boolean;
    hasDct: boolean;
    pixelRowMeta?: { signerId: string; timestamp: string };
    dctMeta?: { signerId: string; timestamp: string; pHash: string };
  }> {
    try {
      const { pixels, width, height } = await decodeImage(imageBlob);
      const pixelRowResult = pixelRowExtract(pixels, width, height);
      const hasPixelRow = pixelRowResult !== null;

      const cleanPixels = hasPixelRow ? pixelRowResult!.originalPixels : pixels;
      const cleanWidth = hasPixelRow ? pixelRowResult!.originalWidth : width;
      const cleanHeight = hasPixelRow ? pixelRowResult!.originalHeight : height;

      const paddedImg =
        cleanWidth < MIN_DIMENSION || cleanHeight < MIN_DIMENSION
          ? padToMinimum({
              pixels: cleanPixels,
              width: cleanWidth,
              height: cleanHeight,
            })
          : { pixels: cleanPixels, width: cleanWidth, height: cleanHeight };

      const rawDct = dctExtract(
        paddedImg.pixels,
        paddedImg.width,
        paddedImg.height,
        RS_TOTAL_BYTES,
      );
      const dctStub = rsDecode(rawDct)
        ? deserializeStub(rsDecode(rawDct)!)
        : null;

      let pixelRowMeta: { signerId: string; timestamp: string } | undefined;
      if (hasPixelRow) {
        try {
          const env = JSON.parse(
            pixelRowResult!.signatureJson,
          ) as MajikSignatureJSON;
          pixelRowMeta = { signerId: env.signerId, timestamp: env.timestamp };
        } catch {
          /* ignore */
        }
      }

      return {
        hasPixelRow,
        hasDct: dctStub !== null,
        pixelRowMeta,
        dctMeta: dctStub
          ? {
              signerId: dctStub.signerId,
              timestamp: dctStub.timestamp,
              pHash: dctStub.pHash,
            }
          : undefined,
      };
    } catch {
      return { hasPixelRow: false, hasDct: false };
    }
  }

  /** Returns true if either layer is present in the image. */
  static async isSigned(imageBlob: Blob): Promise<boolean> {
    const info = await MajikImageSignature.inspect(imageBlob);
    return info.hasPixelRow || info.hasDct;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

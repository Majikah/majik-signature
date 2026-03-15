/**
 * majik-embed.ts — MajikSignatureEmbed
 *
 * Universal MajikSignature embedding and extraction for any file format.
 *
 * Circular dependency note:
 * ─────────────────────────
 * majik-embed lives inside the majik-signature package and cannot import
 * MajikSignature directly — that would create a circular dependency:
 *
 *   majik-signature → majik-embed → majik-signature  ✗
 *
 * Instead, the two operations that genuinely need MajikSignature
 * (signAndEmbed + verifyWithKey) receive it via the MajikSignatureAdapter
 * interface. MajikSignature satisfies this interface and passes itself in
 * via the static wrappers in majik-signature.ts — no circular import needed.
 */

import type { MajikKey } from "@majikah/majik-key";

import type {
  EmbedOptions,
  EmbedResult,
  EmbedVerifyResult,
  ExtractOptions,
  ExtractResult,
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  SignOptions,
  VerificationResult,
} from "../../core/types";
import { FormatHandlerRegistry } from "./registry";
import { blobToBytes, bytesToBlob, detectMimeType } from "./utils";

import { PdfHandler } from "./handlers/pdf";
import { PngHandler } from "./handlers/png";
import { JpegHandler } from "./handlers/jpeg";
import { WavHandler } from "./handlers/wav";
import { Mp3Handler } from "./handlers/mp3";
import { Mp4Handler } from "./handlers/mp4";
import { FlacHandler } from "./handlers/flac";
import { MkvHandler } from "./handlers/mkv";
import { OfficeHandler } from "./handlers/office";
import { TextHandler } from "./handlers/text";
import { FallbackHandler } from "./fallback";

// ─── Adapter interface ────────────────────────────────────────────────────────
//
// The minimal surface of MajikSignature that MajikSignatureEmbed needs.
// Passed in by the callers in majik-signature.ts — never imported directly.

export interface MajikSignatureAdapter {
  toJSON(): MajikSignatureJSON;
}

export interface MajikSignatureStaticAdapter {
  sign(
    content: Uint8Array | string,
    key: MajikKey,
    options?: SignOptions,
  ): Promise<MajikSignatureAdapter>;

  verify(
    content: Uint8Array | string,
    signature: MajikSignatureAdapter | MajikSignatureJSON,
    publicKeys: MajikSignerPublicKeys,
  ): VerificationResult;

  publicKeysFromMajikKey(key: MajikKey): MajikSignerPublicKeys;

  fromJSON(json: MajikSignatureJSON | string): MajikSignatureAdapter;
}

// ─── Registry ─────────────────────────────────────────────────────────────────

const DEFAULT_REGISTRY = new FormatHandlerRegistry()
  .register(new PdfHandler())
  .register(new PngHandler())
  .register(new JpegHandler())
  .register(new WavHandler())
  .register(new Mp3Handler())
  .register(new Mp4Handler())
  .register(new FlacHandler())
  .register(new MkvHandler())
  .register(new OfficeHandler())
  .register(new TextHandler());

// ─── MajikSignatureEmbed ──────────────────────────────────────────────────────

export class MajikSignatureEmbed {
  /**
   * Embed a pre-computed signature into a file Blob.
   * Does NOT sign — call signAndEmbed() for sign + embed together.
   */
  static async embed(
    file: Blob,
    signature: MajikSignatureAdapter | MajikSignatureJSON,
    options?: EmbedOptions,
  ): Promise<EmbedResult> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);

    const handler = options?.forceFallback
      ? new FallbackHandler()
      : DEFAULT_REGISTRY.resolve(bytes, mimeType);

    const sigJson =
      typeof (signature as MajikSignatureAdapter).toJSON === "function"
        ? JSON.stringify((signature as MajikSignatureAdapter).toJSON())
        : JSON.stringify(signature);

    const resultBytes = await handler.embed(bytes, sigJson);
    const blob = bytesToBlob(resultBytes, mimeType);

    return { blob, handler: handler.name, mimeType };
  }

  /**
   * Sign a file and embed the signature in one call.
   *
   * Requires the MajikSignature static class passed in as `MajikSig` to
   * avoid a circular import. Called from MajikSignature.signFile().
   *
   * Internally:
   *   1. Strips any existing signature (idempotent re-signing)
   *   2. Signs the stripped bytes
   *   3. Embeds the new signature
   */
  static async signAndEmbed<T extends MajikSignatureAdapter>(
    file: Blob,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: EmbedOptions & { contentType?: string; timestamp?: string },
  ): Promise<EmbedResult & { signature: T }> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);

    const handler = options?.forceFallback
      ? new FallbackHandler()
      : DEFAULT_REGISTRY.resolve(bytes, mimeType);

    const originalBytes = await handler.strip(bytes);

    const signature = await MajikSig.sign(originalBytes, key, {
      contentType: options?.contentType,
      timestamp: options?.timestamp,
    });

    const sigJson = JSON.stringify(signature.toJSON());
    const resultBytes = await handler.embed(originalBytes, sigJson);
    const blob = bytesToBlob(resultBytes, mimeType);

    return { blob, handler: handler.name, mimeType, signature: signature as T };
  }

  /**
   * Extract the embedded MajikSignatureJSON from a file.
   * Returns null if no signature is found.
   */
  static async extract(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<ExtractResult | null> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);
    const handler = DEFAULT_REGISTRY.resolve(bytes, mimeType);

    const signatureJson = await handler.extract(bytes);
    if (!signatureJson) return null;

    return { signatureJson, handler: handler.name };
  }

  /**
   * Verify a file's embedded signature against public keys.
   *
   * Requires the MajikSignature static class passed in as `MajikSig` to
   * avoid a circular import. Called from MajikSignature.verifyFile().
   */
  static async verify(
    file: Blob,
    publicKeys: MajikSignerPublicKeys,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { expectedSignerId?: string },
  ): Promise<EmbedVerifyResult> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);
    const handler = DEFAULT_REGISTRY.resolve(bytes, mimeType);

    const signatureJson = await handler.extract(bytes);
    if (!signatureJson) {
      return {
        valid: false,
        reason: "No embedded signature found",
        timestamp: new Date().toISOString(),
      };
    }

    let parsedSig: MajikSignatureJSON;
    try {
      parsedSig = JSON.parse(signatureJson) as MajikSignatureJSON;
    } catch {
      return {
        valid: false,
        reason: "Embedded signature JSON is malformed",
        timestamp: new Date().toISOString(),
      };
    }

    const originalBytes = await handler.strip(bytes);

    if (
      options?.expectedSignerId &&
      parsedSig.signerId !== options.expectedSignerId
    ) {
      return {
        valid: false,
        signerId: parsedSig.signerId,
        reason: `signerId mismatch: expected ${options.expectedSignerId}, got ${parsedSig.signerId}`,
        timestamp: parsedSig.timestamp,
      };
    }

    const result = MajikSig.verify(originalBytes, parsedSig, publicKeys);

    return { ...result, handler: handler.name };
  }

  /**
   * Verify using a MajikKey instance instead of raw public keys.
   * Called from MajikSignature.verifyFile() — MajikSig passed to avoid
   * circular import.
   */
  static async verifyWithKey(
    file: Blob,
    key: MajikKey,
    MajikSig: MajikSignatureStaticAdapter,
    options?: ExtractOptions & { expectedSignerId?: string },
  ): Promise<EmbedVerifyResult> {
    const publicKeys = MajikSig.publicKeysFromMajikKey(key);
    return MajikSignatureEmbed.verify(file, publicKeys, MajikSig, options);
  }

  /**
   * Return a clean copy of the file with any embedded signature removed.
   */
  static async strip(file: Blob, options?: ExtractOptions): Promise<Blob> {
    const bytes = await blobToBytes(file);
    const mimeType = options?.mimeType ?? detectMimeType(bytes, file.type);
    const handler = DEFAULT_REGISTRY.resolve(bytes, mimeType);
    const stripped = await handler.strip(bytes);
    return bytesToBlob(stripped, mimeType);
  }

  /**
   * Check whether a file has an embedded MajikSignature (without verifying).
   */
  static async hasSignature(
    file: Blob,
    options?: ExtractOptions,
  ): Promise<boolean> {
    const result = await MajikSignatureEmbed.extract(file, options);
    return result !== null;
  }

  static readonly registry = DEFAULT_REGISTRY;

  static listHandlers(): string[] {
    return DEFAULT_REGISTRY.listHandlers();
  }
}

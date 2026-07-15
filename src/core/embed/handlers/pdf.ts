/**
 * handlers/pdf.ts — PDF handler
 *
 * Embeds the MajikSignature as a binary trailer appended after the PDF's
 * last %%EOF marker. This approach is:
 *   - Deterministic: strip() is a pure byte slice, no parsing
 *   - Non-destructive: the PDF remains valid and openable
 *   - Spec-compliant: appending after %%EOF is allowed by PDF 1.7 §7.5.6
 *
 * If you want human-readable metadata visible in Adobe/Preview, call
 * MajikSignatureClient.addDisplayMetadata() after signing — that is a
 * separate display-only step and does not affect verification.
 */

import { FormatHandler } from "../../types";

const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46]; // %PDF
const MAGIC = new TextEncoder().encode("\n%%MajikSig%%\n");

export class PdfHandler implements FormatHandler {
  readonly name = "PDF";
  readonly supportedMimeTypes = ["application/pdf"] as const;

  private _findMagic(bytes: Uint8Array): number {
    outer: for (let i = bytes.length - MAGIC.length; i >= 0; i--) {
      if (bytes[i] !== MAGIC[0]) continue;
      for (let j = 1; j < MAGIC.length; j++) {
        if (bytes[i + j] !== MAGIC[j]) continue outer;
      }
      return i;
    }
    return -1;
  }

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (mimeType === "application/pdf") return true;
    return (
      bytes.length >= 4 &&
      bytes[0] === PDF_MAGIC[0] &&
      bytes[1] === PDF_MAGIC[1] &&
      bytes[2] === PDF_MAGIC[2] &&
      bytes[3] === PDF_MAGIC[3]
    );
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);
    const sigBytes = new TextEncoder().encode(signatureJson);
    const lenBytes = new Uint8Array(4);
    new DataView(lenBytes.buffer).setUint32(0, sigBytes.length, false);

    const out = new Uint8Array(
      clean.length + MAGIC.length + sigBytes.length + lenBytes.length,
    );
    out.set(clean, 0);
    out.set(MAGIC, clean.length);
    out.set(sigBytes, clean.length + MAGIC.length);
    out.set(lenBytes, clean.length + MAGIC.length + sigBytes.length);
    return out;
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    const i = this._findMagic(bytes);
    return i === -1 ? bytes : bytes.slice(0, i);
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    const i = this._findMagic(bytes);
    if (i === -1) return null;
    const sigStart = i + MAGIC.length;
    const sigEnd = bytes.length - 4;
    return new TextDecoder().decode(bytes.slice(sigStart, sigEnd));
  }
}

// Freeze static methods
Object.freeze(PdfHandler);

// Freeze instance methods
Object.freeze(PdfHandler.prototype);

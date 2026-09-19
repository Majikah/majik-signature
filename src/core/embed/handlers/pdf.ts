/**
 * handlers/pdf.ts — PDF handler
 *
 * Layout (unchanged, existing signed PDFs stay valid):
 *   [PDF bytes]["\n%%MajikSig%%\n"][signature JSON utf8][4-byte big-endian length]
 *
 * Security invariant (see advisory for 0.4.1):
 *   The block is parsed FROM THE TAIL using the length field, and must end the
 *   file exactly. Anything that is not a well-formed tail block is CONTENT and
 *   stays inside the hashed bytes. Previously strip() cut at the last
 *   occurrence of the magic anywhere and discarded the rest, so a PDF
 *   incremental update placed after a "\n%%MajikSig%%\n" comment line was
 *   never hashed on the detached-verification path.
 */

import { FormatHandler } from "../../types";
import { concatBytes, includesBytes, matchesAt } from "../utils";

const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46]; // %PDF
const MAGIC = new TextEncoder().encode("\n%%MajikSig%%\n");

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export class PdfHandler implements FormatHandler {
  readonly name = "PDF";
  readonly supportedMimeTypes = ["application/pdf"] as const;

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

  /** Pure append (callers strip first) — same reasoning as TextHandler.embed. */
  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const sigBytes = new TextEncoder().encode(signatureJson);
    const lenBytes = new Uint8Array(4);
    new DataView(lenBytes.buffer).setUint32(0, sigBytes.length, false);
    return concatBytes(bytes, MAGIC, sigBytes, lenBytes);
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    return this.split(bytes)?.payload ?? null;
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    return this.split(bytes)?.original ?? bytes;
  }

  /** Single tail-anchored parser shared by extract() and strip(). */
  split(bytes: Uint8Array): { payload: string; original: Uint8Array } | null {
    if (bytes.length < MAGIC.length + 1 + 4) return null;

    const lenPos = bytes.length - 4;
    const sigLen = new DataView(
      bytes.buffer,
      bytes.byteOffset + lenPos,
      4,
    ).getUint32(0, false);

    const sigStart = lenPos - sigLen;
    if (sigLen === 0 || sigStart < MAGIC.length) return null;

    const magicStart = sigStart - MAGIC.length;
    if (!matchesAt(bytes, MAGIC, magicStart)) return null;

    let payload: string;
    try {
      payload = STRICT_UTF8.decode(bytes.subarray(sigStart, lenPos));
    } catch {
      return null;
    }
    return { payload, original: bytes.slice(0, magicStart) };
  }

  diagnose(bytes: Uint8Array): string | null {
    if (this.split(bytes)) return null;
    if (!includesBytes(bytes, MAGIC)) return null;
    return (
      "A Majik signature marker was found, but no well-formed signature block " +
      "ends the file. The file may have been modified after signing."
    );
  }
}

// Freeze static methods
Object.freeze(PdfHandler);

// Freeze instance methods
Object.freeze(PdfHandler.prototype);

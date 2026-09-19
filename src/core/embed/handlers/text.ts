/**
 * handlers/text.ts — Plain text / source code / markup handler
 *
 * The signature is appended as a comment block that MUST be the very end of
 * the file:
 *
 *   \n\n<!-- MAJIK-SIGNATURE-BEGIN -->\n<base64(signature JSON)>\n<!-- MAJIK-SIGNATURE-END -->\n
 *
 * Security invariant (see advisory for 0.4.1):
 *   Bytes that are not part of a well-formed, tail-anchored block are CONTENT.
 *   They are never discarded by strip(), so they are always covered by the
 *   content hash. In particular:
 *     - anything after the END marker  -> no block is recognised; the file no
 *       longer verifies (zero tolerance, not even whitespace);
 *     - a marker inside ordinary text  -> just text, never truncates anything.
 *
 * Everything operates on BYTES. The previous implementation decoded to a
 * string and re-encoded, which silently dropped a BOM and replaced invalid
 * UTF-8 with U+FFFD, so the hashed bytes were not the file's bytes.
 *
 * extract() and strip() share one parser (split()) so they cannot disagree.
 */

import { FormatHandler } from "../../types";
import {
  concatBytes,
  includesBytes,
  matchesAt,
  textDecode,
  textEncode,
} from "../utils";

const BEGIN_MARKER = "<!-- MAJIK-SIGNATURE-BEGIN -->";
const END_MARKER = "<!-- MAJIK-SIGNATURE-END -->";

const BEGIN_BYTES = textEncode(BEGIN_MARKER);
const END_BYTES = textEncode(END_MARKER);
/** Exactly what embed() writes before / after the base64 payload. */
const HEAD_BYTES = textEncode(`\n\n${BEGIN_MARKER}\n`);
const TAIL_BYTES = textEncode(`\n${END_MARKER}\n`);

const TEXT_MIME_TYPES = [
  "text/plain",
  "text/html",
  "text/xml",
  "application/xml",
  "text/markdown",
  "text/csv",
  "application/json",
  "application/javascript",
  "text/javascript",
  "application/typescript",
  "text/typescript",
  "text/css",
  "text/x-python",
  "text/x-java-source",
  "text/x-c",
  "text/x-c++",
  "application/x-sh",
  "text/x-shellscript",
  "application/x-yaml",
  "text/yaml",
  "text/x-toml",
  "application/toml",
];

function isBase64Byte(b: number): boolean {
  return (
    (b >= 0x41 && b <= 0x5a) || // A-Z
    (b >= 0x61 && b <= 0x7a) || // a-z
    (b >= 0x30 && b <= 0x39) || // 0-9
    b === 0x2b || // +
    b === 0x2f || // /
    b === 0x3d // =
  );
}

export class TextHandler implements FormatHandler {
  readonly name = "Text/Markup/Source";
  readonly supportedMimeTypes = TEXT_MIME_TYPES as unknown as readonly string[];

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (mimeType && TEXT_MIME_TYPES.includes(mimeType)) return true;
    if (!mimeType || mimeType === "application/octet-stream") return false;
    if (mimeType?.startsWith("text/")) return true;
    return false;
  }

  /**
   * Append the signature block. Pure append: does NOT strip first.
   * Callers (MajikSignatureEmbed) always strip() before embed(); stripping
   * again here would silently drop a second well-formed block that is part of
   * the content the signature was computed over.
   */
  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const encoded = btoa(signatureJson);
    const block = `\n\n${BEGIN_MARKER}\n${encoded}\n${END_MARKER}\n`;
    return concatBytes(bytes, textEncode(block));
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    return this.split(bytes)?.payload ?? null;
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    return this.split(bytes)?.original ?? bytes;
  }

  /**
   * The single parser. Returns the signature payload and the bytes before the
   * block, or null when the file does not END with a well-formed block.
   */
  split(bytes: Uint8Array): { payload: string; original: Uint8Array } | null {
    // 1. The file must end with "\n<END marker>\n" — nothing may follow.
    const tailStart = bytes.length - TAIL_BYTES.length;
    if (!matchesAt(bytes, TAIL_BYTES, tailStart)) return null;

    // 2. Walk back over the base64 payload.
    let payloadStart = tailStart;
    while (payloadStart > 0 && isBase64Byte(bytes[payloadStart - 1])) {
      payloadStart--;
    }
    const payloadLen = tailStart - payloadStart;
    if (payloadLen === 0 || payloadLen % 4 !== 0) return null;

    // 3. The payload must be preceded by "\n\n<BEGIN marker>\n".
    const headStart = payloadStart - HEAD_BYTES.length;
    if (!matchesAt(bytes, HEAD_BYTES, headStart)) return null;

    // 4. Decode, and require canonical base64 (re-encoding must reproduce the
    //    exact bytes on disk — atob() alone ignores non-zero trailing bits).
    let payload: string;
    try {
      const encoded = textDecode(bytes.subarray(payloadStart, tailStart));
      payload = atob(encoded);
      if (btoa(payload) !== encoded) return null;
    } catch {
      return null;
    }

    return { payload, original: bytes.slice(0, headStart) };
  }

  /**
   * Human-readable reason when a marker is present but no well-formed
   * tail-anchored block exists (e.g. content appended after the signature).
   */
  diagnose(bytes: Uint8Array): string | null {
    if (this.split(bytes)) return null;
    if (
      !includesBytes(bytes, BEGIN_BYTES) &&
      !includesBytes(bytes, END_BYTES)
    ) {
      return null;
    }
    return (
      "A Majik signature marker was found, but no well-formed signature block " +
      "ends the file. The file may have been modified after signing " +
      "(for example, content appended after the signature block)."
    );
  }
}

// Freeze static methods
Object.freeze(TextHandler);

// Freeze instance methods
Object.freeze(TextHandler.prototype);

/**
 * handlers/text.ts — Plain text / source code / markup handler
 *
 * For text-based formats (TXT, MD, HTML, JSON, XML, CSV, JS, TS, etc.),
 * we append the signature as a structured comment block at the very end.
 *
 * Format:
 *   \n\n<!-- MAJIK-SIGNATURE-BEGIN -->\n
 *   <base64-encoded signature JSON>
 *   \n<!-- MAJIK-SIGNATURE-END -->\n
 *
 * The HTML comment markers are chosen because they are:
 *   - Valid in HTML, XML, and SVG
 *   - Visually clear in plain text
 *   - Easily searchable/strippable
 *   - Not affecting rendering in most formats
 *
 * For JSON files specifically, the block is still appended (making it technically
 * invalid JSON), which means you should strip before parsing JSON.
 */

import { FormatHandler } from "../../types";
import { concatBytes, textDecode, textEncode } from "../utils";

const BEGIN_MARKER = "<!-- MAJIK-SIGNATURE-BEGIN -->";
const END_MARKER = "<!-- MAJIK-SIGNATURE-END -->";

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

export class TextHandler implements FormatHandler {
  readonly name = "Text/Markup/Source";
  readonly supportedMimeTypes = TEXT_MIME_TYPES as unknown as readonly string[];

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (mimeType && TEXT_MIME_TYPES.includes(mimeType)) return true;
    // Check if content looks like UTF-8 text
    if (!mimeType || mimeType === "application/octet-stream") return false;
    if (mimeType?.startsWith("text/")) return true;
    return false;
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    const clean = await this.strip(bytes);
    const encoded = btoa(signatureJson);
    const block = `\n\n${BEGIN_MARKER}\n${encoded}\n${END_MARKER}\n`;
    return concatBytes(clean, textEncode(block));
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    try {
      const text = textDecode(bytes);
      const beginIdx = text.lastIndexOf(BEGIN_MARKER);
      if (beginIdx < 0) return null;

      const endIdx = text.lastIndexOf(END_MARKER);
      if (endIdx < 0 || endIdx <= beginIdx) return null;

      const encoded = text.slice(beginIdx + BEGIN_MARKER.length, endIdx).trim();
      return atob(encoded);
    } catch {
      return null;
    }
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    try {
      const text = textDecode(bytes);
      const beginIdx = text.lastIndexOf(BEGIN_MARKER);
      if (beginIdx < 0) return bytes;

      // Strip back to the \n\n before the marker
      let stripFrom = beginIdx;
      if (
        stripFrom >= 2 &&
        text[stripFrom - 1] === "\n" &&
        text[stripFrom - 2] === "\n"
      ) {
        stripFrom -= 2;
      }

      return textEncode(text.slice(0, stripFrom));
    } catch {
      return bytes;
    }
  }
}

// Freeze static methods
Object.freeze(TextHandler);

// Freeze instance methods
Object.freeze(TextHandler.prototype);

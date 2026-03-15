/**
 * handlers/office.ts — OOXML Office format handler (DOCX / XLSX / PPTX)
 *
 * Office Open XML formats are ZIP archives. We add a file named
 * "majik-signature.json" to the root of the ZIP.
 *
 * This approach:
 *   - Is completely non-destructive — Office apps ignore unknown ZIP entries
 *   - Survives round-trips through Word, Excel, PowerPoint
 *   - Is visible to any ZIP inspector
 *   - Does not require modifying any existing XML
 *
 * Uses fflate for pure-JS ZIP manipulation (works in browser + Node).
 */

import { unzipSync, zipSync, strToU8, strFromU8 } from "fflate";
import { OFFICE_ZIP_ENTRY } from "../constants";
import { FormatHandler } from "../../types";

const OFFICE_MIME_TYPES = [
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.ms-word.document.macroEnabled.12",
  "application/vnd.ms-excel.sheet.macroEnabled.12",
  "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
  // Also handle ODT/ODS/ODP (LibreOffice) — also ZIP-based
  "application/vnd.oasis.opendocument.text",
  "application/vnd.oasis.opendocument.spreadsheet",
  "application/vnd.oasis.opendocument.presentation",
];

const ZIP_MAGIC = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);

export class OfficeHandler implements FormatHandler {
  readonly name = "Office (DOCX/XLSX/PPTX/ODF)";
  readonly supportedMimeTypes =
    OFFICE_MIME_TYPES as unknown as readonly string[];

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    if (mimeType && OFFICE_MIME_TYPES.includes(mimeType)) return true;

    // Must be a ZIP file
    if (!this._isZip(bytes)) return false;

    // Distinguish from plain ZIP by checking for Office content types file
    try {
      const files = unzipSync(bytes);
      return (
        "[Content_Types].xml" in files || "mimetype" in files // ODF
      );
    } catch {
      return false;
    }
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    try {
      const files = unzipSync(bytes);

      // Remove any existing signature entry
      delete files[OFFICE_ZIP_ENTRY];

      // Add new signature entry
      files[OFFICE_ZIP_ENTRY] = strToU8(signatureJson);

      return zipSync(files, { level: 0 }); // store without compression for fast access
    } catch (err) {
      throw new Error(`OfficeHandler.embed failed: ${err}`);
    }
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    if (!this.canHandle(bytes)) return null;
    try {
      const files = unzipSync(bytes);
      if (!(OFFICE_ZIP_ENTRY in files)) return null;
      return strFromU8(files[OFFICE_ZIP_ENTRY]);
    } catch {
      return null;
    }
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    if (!this.canHandle(bytes)) return bytes;
    try {
      const files = unzipSync(bytes);
      if (!(OFFICE_ZIP_ENTRY in files)) return bytes;
      delete files[OFFICE_ZIP_ENTRY];
      return zipSync(files, { level: 0 });
    } catch {
      return bytes;
    }
  }

  private _isZip(bytes: Uint8Array): boolean {
    return (
      bytes.length >= 4 &&
      bytes[0] === ZIP_MAGIC[0] &&
      bytes[1] === ZIP_MAGIC[1] &&
      bytes[2] === ZIP_MAGIC[2] &&
      bytes[3] === ZIP_MAGIC[3]
    );
  }
}

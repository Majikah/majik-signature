/**
 * handlers/office.ts — OOXML Office format handler (DOCX / XLSX / PPTX)
 *
 * Office Open XML formats are ZIP archives. We add a file named
 * "majik-signature.json" to the root of the ZIP.
 *
 * ODF formats (ODT / ODS / ODP) are also supported.
 *
 * Important:
 *   `[Content_Types].xml` alone is NOT sufficient to identify Office.
 *   MSIX/AppX packages are also OPC/ZIP-based and may contain that file.
 *
 * Uses fflate for pure-JS ZIP manipulation (works in browser + Node).
 */

import { unzipSync, zipSync, strToU8, strFromU8 } from "fflate";
import { OFFICE_ZIP_ENTRY } from "../constants.js";
import { FormatHandler } from "../../types.js";
import { toZippable } from "../utils.js";

const OFFICE_MIME_TYPES = [
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.ms-word.document.macroEnabled.12",
  "application/vnd.ms-excel.sheet.macroEnabled.12",
  "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
  "application/vnd.oasis.opendocument.text",
  "application/vnd.oasis.opendocument.spreadsheet",
  "application/vnd.oasis.opendocument.presentation",
] as const;

const ODF_MIME_TYPES = new Set([
  "application/vnd.oasis.opendocument.text",
  "application/vnd.oasis.opendocument.spreadsheet",
  "application/vnd.oasis.opendocument.presentation",
]);

const ZIP_MAGIC = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);

/**
 * Generic OPC metadata must NOT be treated as an Office identifier.
 *
 * MSIX/AppX packages can also contain [Content_Types].xml.
 */
const MSIX_PACKAGE_ENTRIES = new Set([
  "AppxManifest.xml",
  "AppxBlockMap.xml",
  "AppxSignature.p7x",
]);

const OOXML_ENTRIES = new Set([
  "word/document.xml",
  "xl/workbook.xml",
  "ppt/presentation.xml",
]);

const SNIFF_ENTRIES = new Set([
  "[Content_Types].xml",
  "mimetype",
  ...MSIX_PACKAGE_ENTRIES,
  ...OOXML_ENTRIES,
]);

const MAX_SIGNATURE_ENTRY_BYTES = 8 * 1024 * 1024;

export const MAX_UNZIPPED_BYTES = 512 * 1024 * 1024;

function unzipBounded(bytes: Uint8Array): Record<string, Uint8Array> {
  let total = 0;

  return unzipSync(bytes, {
    filter: (f) => {
      total += f.originalSize;

      if (total > MAX_UNZIPPED_BYTES) {
        throw new Error("Archive too large to process");
      }

      return true;
    },
  });
}

export class OfficeHandler implements FormatHandler {
  readonly name = "Office (DOCX/XLSX/PPTX/ODF)";

  readonly supportedMimeTypes =
    OFFICE_MIME_TYPES as unknown as readonly string[];

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    /*
     * MIME type is authoritative only for known Office/ODF MIME types.
     */
    if (mimeType && OFFICE_MIME_TYPES.includes(mimeType as never)) {
      return true;
    }

    if (!this._isZip(bytes)) {
      return false;
    }

    try {
      const files = unzipSync(bytes, {
        filter: (f) =>
          SNIFF_ENTRIES.has(f.name) &&
          f.originalSize <= MAX_SIGNATURE_ENTRY_BYTES,
      });

      /*
       * Explicitly reject MSIX/AppX packages.
       *
       * This is important because MSIX is also an OPC/ZIP container.
       */
      if (
        "AppxManifest.xml" in files ||
        "AppxBlockMap.xml" in files ||
        "AppxSignature.p7x" in files
      ) {
        return false;
      }

      /*
       * OOXML:
       *
       * Do not use [Content_Types].xml by itself.
       *
       * Require an actual Office document payload.
       */
      if (
        "word/document.xml" in files ||
        "xl/workbook.xml" in files ||
        "ppt/presentation.xml" in files
      ) {
        return true;
      }

      /*
       * ODF:
       *
       * The "mimetype" entry must actually contain one of the expected
       * OpenDocument MIME types.
       */
      if ("mimetype" in files) {
        const detectedMime = strFromU8(files.mimetype).trim();

        return ODF_MIME_TYPES.has(detectedMime);
      }

      return false;
    } catch {
      return false;
    }
  }

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    try {
      const files = unzipBounded(bytes);

      delete files[OFFICE_ZIP_ENTRY];

      files[OFFICE_ZIP_ENTRY] = strToU8(signatureJson);

      return zipSync(toZippable(files), { level: 0 });
    } catch (err) {
      throw new Error(`OfficeHandler.embed failed: ${err}`);
    }
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    if (!this.canHandle(bytes)) {
      return null;
    }

    try {
      const files = unzipSync(bytes, {
        filter: (f) =>
          f.name === OFFICE_ZIP_ENTRY &&
          f.originalSize <= MAX_SIGNATURE_ENTRY_BYTES,
      });

      if (!(OFFICE_ZIP_ENTRY in files)) {
        return null;
      }

      return strFromU8(files[OFFICE_ZIP_ENTRY]);
    } catch {
      return null;
    }
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    if (!this.canHandle(bytes)) {
      return bytes;
    }

    try {
      const files = unzipBounded(bytes);

      /*
       * Canonicalize Office/ODF ZIP contents.
       *
       * The signing and verification paths must both reproduce this
       * exact representation.
       */
      delete files[OFFICE_ZIP_ENTRY];

      return zipSync(toZippable(files), { level: 0 });
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

Object.freeze(OfficeHandler);
Object.freeze(OfficeHandler.prototype);

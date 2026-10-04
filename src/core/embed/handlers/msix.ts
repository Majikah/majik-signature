/**
 * handlers/msix.ts — MSIX / AppX package handler
 *
 * MSIX/AppX packages are ZIP/OPC-based Windows application packages.
 *
 * IMPORTANT:
 *   MSIX packages contain their own package integrity structures such as
 *   AppxBlockMap.xml and AppxSignature.p7x. Repacking or injecting an
 *   arbitrary ZIP entry changes the package and can invalidate those
 *   structures.
 *
 * Therefore this handler treats MSIX/AppX as an opaque byte stream for
 * detached Majik Signature operations.
 *
 * Detached signing:
 *
 *   exact MSIX bytes
 *       ↓
 *   SHA-256
 *       ↓
 *   Majik Signature
 *
 * No canonical ZIP reconstruction is performed.
 */

import { unzipSync } from "fflate";
import { FormatHandler } from "../../types";

const MSIX_MIME_TYPES = ["application/msix", "application/appx"] as const;

const ZIP_MAGIC = 0x04034b50;

const MSIX_REQUIRED_ENTRIES = new Set([
  "AppxManifest.xml",
  "AppxBlockMap.xml",
]);

export class MsixHandler implements FormatHandler {
  readonly name = "MSIX / AppX";

  readonly supportedMimeTypes = MSIX_MIME_TYPES as unknown as readonly string[];

  canHandle(bytes: Uint8Array, mimeType?: string): boolean {
    /*
     * First make sure this is actually a ZIP-based container.
     */
    if (!this._isZip(bytes)) {
      return false;
    }

    /*
     * A declared MSIX/AppX MIME type is enough after ZIP validation.
     *
     * This avoids unnecessary ZIP parsing for callers that already know
     * the package type.
     */
    if (mimeType && MSIX_MIME_TYPES.includes(mimeType as never)) {
      return true;
    }

    /*
     * For MIME-less detection, inspect ZIP metadata only.
     *
     * IMPORTANT:
     *   The filter ALWAYS returns false.
     *
     * This means fflate parses ZIP directory metadata but does NOT
     * decompress any file contents.
     */
    const foundEntries = new Set<string>();

    try {
      unzipSync(bytes, {
        filter: (file) => {
          if (MSIX_REQUIRED_ENTRIES.has(file.name)) {
            foundEntries.add(file.name);
          }

          /*
           * Never extract anything.
           */
          return false;
        },
      });

      return (
        foundEntries.has("AppxManifest.xml") &&
        foundEntries.has("AppxBlockMap.xml")
      );
    } catch {
      return false;
    }
  }

  /**
   * MSIX is intentionally NOT modified by Majik Signature embedding.
   *
   * Use detached signatures / MJKS Maps instead.
   */
  async embed(
    _bytes: Uint8Array,
    _signatureJson: string,
  ): Promise<Uint8Array> {
    throw new Error(
      "MsixHandler does not support embedded signatures. " +
        "MSIX packages must be signed using detached Majik Signature " +
        "artifacts to preserve package integrity.",
    );
  }

  /**
   * No embedded Majik Signature is extracted from MSIX packages because
   * this handler does not write one.
   */
  async extract(_bytes: Uint8Array): Promise<string | null> {
    return null;
  }

  /**
   * MSIX is an opaque release artifact.
   *
   * Do NOT unzip, normalize, strip, or reconstruct it.
   *
   * The exact bytes on disk are the bytes that get hashed/signed.
   */
  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    return bytes;
  }

  private _isZip(bytes: Uint8Array): boolean {
    return (
      bytes.length >= 4 &&
      bytes[0] === 0x50 &&
      bytes[1] === 0x4b &&
      bytes[2] === 0x03 &&
      bytes[3] === 0x04
    );
  }
}

Object.freeze(MsixHandler);
Object.freeze(MsixHandler.prototype);
/**
 * handlers/pdf.ts — PDF handler using pdf-lib
 *
 * Embeds the MajikSignature in two places:
 *   1. PDF /Info dictionary custom key "majik-signature" (visible in File → Properties)
 *   2. XMP metadata stream (MajikSignature element in custom namespace)
 *
 * Strip reads the original bytes from the /Info key, reconstructs a clean PDF.
 * If neither is present, the file is returned as-is (no signature found).
 */

import { PDFDocument, PDFName, PDFString, PDFHexString } from "pdf-lib";
import { FormatHandler } from "../../types";
import { MAJIK_NAMESPACE, SIGNATURE_KEY } from "../constants";

const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46]; // %PDF

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

  async embed(bytes: Uint8Array, signatureJson: string): Promise<Uint8Array> {
    // Strip any existing signature first
    const clean = await this.strip(bytes);

    const pdf = await PDFDocument.load(clean, { ignoreEncryption: true });

    // ── 1. /Info dictionary ──────────────────────────────────────────────────
    // pdf-lib exposes the info dict via getInfoDict()
    // We set a custom key so it appears in File > Properties > Custom
    const infoDict = pdf.context.lookup(pdf.context.trailerInfo.Info);
    if (infoDict && "set" in infoDict) {
      (infoDict as any).set(
        PDFName.of(SIGNATURE_KEY),
        PDFString.of(signatureJson),
      );
    }

    // Also set via built-in keywords field as a fallback visibility trick
    // (some PDF viewers show keywords in properties)
    try {
      pdf.setKeywords([`${SIGNATURE_KEY}:${signatureJson}`]);
    } catch {
      // Non-critical — ignore if keywords already set in a way we can't override
    }

    // ── 2. XMP metadata stream ───────────────────────────────────────────────
    const xmp = this._buildXMP(signatureJson);
    try {
      pdf.setProducer("MajikSignatureEmbed/1.0");
      // Set raw XMP via the underlying context
      const metadataStream = pdf.context.stream(xmp, {
        Type: "Metadata",
        Subtype: "XML",
      });
      const metadataRef = pdf.context.register(metadataStream);
      pdf.catalog.set(PDFName.of("Metadata"), metadataRef);
    } catch {
      // XMP embed is best-effort; /Info key is the primary store
    }

    return pdf.save();
  }

  async extract(bytes: Uint8Array): Promise<string | null> {
    try {
      const pdf = await PDFDocument.load(bytes, {
        ignoreEncryption: true,
        updateMetadata: false,
      });

      // ── Try /Info dictionary ──
      const infoDict = pdf.context.lookup(pdf.context.trailerInfo.Info) as any;
      if (infoDict) {
        const sigValue = infoDict.get(PDFName.of(SIGNATURE_KEY));
        if (sigValue) {
          const raw =
            sigValue instanceof PDFHexString
              ? sigValue.decodeText()
              : (sigValue as PDFString).asString();
          if (raw) return raw;
        }
      }

      // ── Try Keywords field ──
      try {
        const keywords = pdf.getKeywords();
        if (keywords) {
          const prefix = `${SIGNATURE_KEY}:`;
          if (keywords.startsWith(prefix)) {
            return keywords.slice(prefix.length);
          }
        }
      } catch {
        /* ignore */
      }

      // ── Try XMP metadata stream ──
      try {
        const metadataRef = pdf.catalog.get(PDFName.of("Metadata")) as any;
        if (metadataRef) {
          const metadataStream = pdf.context.lookup(metadataRef) as any;
          if (metadataStream) {
            const xmpBytes = metadataStream.getContents();
            const xmpStr = new TextDecoder().decode(xmpBytes);
            const extracted = this._extractFromXMP(xmpStr);
            if (extracted) return extracted;
          }
        }
      } catch {
        /* ignore */
      }

      return null;
    } catch {
      return null;
    }
  }

  async strip(bytes: Uint8Array): Promise<Uint8Array> {
    try {
      const pdf = await PDFDocument.load(bytes, {
        ignoreEncryption: true,
        updateMetadata: false,
      });

      const infoDict = pdf.context.lookup(pdf.context.trailerInfo.Info) as any;
      if (infoDict) {
        infoDict.delete(PDFName.of(SIGNATURE_KEY));
      }

      // Remove signature from keywords
      try {
        const keywords = pdf.getKeywords();
        if (keywords) {
          const prefix = `${SIGNATURE_KEY}:`;
          if (keywords.startsWith(prefix)) {
            pdf.setKeywords([]);
          }
        }
      } catch {
        /* ignore */
      }

      // Remove XMP metadata (regenerate clean)
      try {
        pdf.catalog.delete(PDFName.of("Metadata"));
      } catch {
        /* ignore */
      }

      return pdf.save();
    } catch {
      // If PDF is unreadable, return as-is
      return bytes;
    }
  }

  // ─── XMP Helpers ────────────────────────────────────────────────────────────

  private _buildXMP(signatureJson: string): string {
    // Escape XML entities in the JSON (rare but safe)
    const escaped = signatureJson
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

    return `<?xpacket begin="\uFEFF" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:majik="${MAJIK_NAMESPACE}">
      <majik:signature>${escaped}</majik:signature>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>`;
  }

  private _extractFromXMP(xmp: string): string | null {
    // Try <majik:signature>...</majik:signature>
    const tagMatch = xmp.match(
      /<majik:signature>([\s\S]*?)<\/majik:signature>/,
    );
    if (tagMatch) {
      return tagMatch[1]
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .trim();
    }
    return null;
  }
}

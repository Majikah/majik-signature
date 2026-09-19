/**
 * Mutation matrix: every handler x every "modify the signed file" attack.
 *
 * "accepted" = the verifier would report valid:true over the ORIGINAL content
 * although the bytes on disk differ from the honestly signed file.
 *   legacy predicate : extract() != null && strip(mutated) == strip(original)
 *   fixed predicate  : extract() != null && assertCanonical() ok && original == strip(F)
 * The fixed predicate must be false for every mutation. The legacy column is
 * printed for the record (it is what 0.4.1 does today).
 */
import { describe, it, expect } from "vitest";
import { zipSync, strToU8 } from "fflate";
import type { FormatHandler } from "../src/core/types";
import {
  assertCanonical,
  prepareDetachedBytes,
} from "../src/core/embed/canonical";
import {
  bufferEqual,
  concatBytes,
  textEncode,
  toZippable,
} from "../src/core/embed/utils";
import { TextHandler } from "../src/core/embed/handlers/text";
import { PdfHandler } from "../src/core/embed/handlers/pdf";
import { JpegHandler } from "../src/core/embed/handlers/jpeg";
import { WavHandler } from "../src/core/embed/handlers/wav";
import { Mp3Handler } from "../src/core/embed/handlers/mp3";
import { OfficeHandler } from "../src/core/embed/handlers/office";
import { LegacyTextHandler } from "./legacy/legacy-text-handler";
import { LegacyPdfHandler } from "./legacy/legacy-pdf-handler";

const J = '{"v":1,"note":"hello"}';
type Mut = { name: string; fn: (s: Uint8Array) => Uint8Array };
const junk = (n: number, b = 0x41) => new Uint8Array(n).fill(b);
const append = (n: number): Mut => ({
  name: `append ${n} byte(s)`,
  fn: (s) => concatBytes(s, junk(n)),
});

// ── fixtures ────────────────────────────────────────────────────────────────
const textF = textEncode(
  "# Invoice 4471\n\nAmount due: USD 100.00\nPay to: Acme Ltd\n",
);
const pdfF = textEncode(
  "%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\nstartxref\n0\n%%EOF\n",
);
const jpegF = new Uint8Array([
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01,
  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01,
  0x00, 0x00, 0x3f, 0x00, 0x12, 0x34, 0x56, 0x78, 0xff, 0xd9,
]);
const wavF = (() => {
  const fmt = concatBytes(
    textEncode("fmt "),
    new Uint8Array([16, 0, 0, 0]),
    new Uint8Array([
      1, 0, 1, 0, 0x44, 0xac, 0, 0, 0x88, 0x58, 1, 0, 2, 0, 16, 0,
    ]),
  );
  const data = concatBytes(
    textEncode("data"),
    new Uint8Array([8, 0, 0, 0]),
    new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
  );
  const body = concatBytes(textEncode("WAVE"), fmt, data);
  return concatBytes(
    textEncode("RIFF"),
    new Uint8Array([body.length & 0xff, 0, 0, 0]),
    body,
  );
})();
const mp3F = (() => {
  const frame = concatBytes(
    textEncode("TIT2"),
    new Uint8Array([0, 0, 0, 3]),
    new Uint8Array([0, 0]),
    new Uint8Array([0, 0x48, 0x69]),
  );
  const padding = new Uint8Array(20);
  const size = frame.length + padding.length;
  const hdr = concatBytes(
    textEncode("ID3"),
    new Uint8Array([
      3,
      0,
      0,
      (size >> 21) & 0x7f,
      (size >> 14) & 0x7f,
      (size >> 7) & 0x7f,
      size & 0x7f,
    ]),
  );
  return concatBytes(
    hdr,
    frame,
    padding,
    new Uint8Array([0xff, 0xfb, 0x90, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]),
  );
})();
const officeF = zipSync(
  toZippable({
    "[Content_Types].xml": strToU8("<Types/>"),
    "word/document.xml": strToU8("<w:document>Amount due: 100</w:document>"),
  }),
  { level: 0 },
);

// ── mutations ───────────────────────────────────────────────────────────────
const BEGIN = "<!-- MAJIK-SIGNATURE-BEGIN -->";
const END = "<!-- MAJIK-SIGNATURE-END -->";
const PDF_MAGIC = "\n%%MajikSig%%\n";
const common: Mut[] = [
  append(1),
  append(100),
  { name: "prepend 1 byte", fn: (s) => concatBytes(junk(1), s) },
];
const cases: {
  name: string;
  fixed: FormatHandler;
  legacy: FormatHandler;
  file: Uint8Array;
  embedded: Mut[];
  detached: Mut[];
}[] = [
  {
    name: "text",
    fixed: new TextHandler(),
    legacy: new LegacyTextHandler(),
    file: textF,
    embedded: [
      ...common,
      {
        name: "append '\\n' (whitespace)",
        fn: (s) => concatBytes(s, textEncode("\n")),
      },
      {
        name: "append lone BEGIN marker + junk",
        fn: (s) => concatBytes(s, textEncode(`\n\n${BEGIN}\nhidden`)),
      },
      {
        name: "append 2nd well-formed block (junk b64)",
        fn: (s) => concatBytes(s, textEncode(`\n\n${BEGIN}\nQUJD\n${END}\n`)),
      },
      {
        name: "prepend UTF-8 BOM",
        fn: (s) => concatBytes(new Uint8Array([0xef, 0xbb, 0xbf]), s),
      },
    ],
    detached: [
      {
        name: "append lone BEGIN marker + junk",
        fn: (f) =>
          concatBytes(f, textEncode(`\n\n${BEGIN}\nAmount due: USD 900`)),
      },
      {
        name: "append well-formed block (junk b64)",
        fn: (f) => concatBytes(f, textEncode(`\n\n${BEGIN}\nQUJD\n${END}\n`)),
      },
      {
        name: "prepend UTF-8 BOM",
        fn: (f) => concatBytes(new Uint8Array([0xef, 0xbb, 0xbf]), f),
      },
    ],
  },
  {
    name: "pdf",
    fixed: new PdfHandler(),
    legacy: new LegacyPdfHandler(),
    file: pdfF,
    embedded: [...common],
    detached: [
      {
        name: "append magic line + incremental update",
        fn: (f) =>
          concatBytes(
            f,
            textEncode(
              PDF_MAGIC +
                "2 0 obj<</Evil true>>endobj\nxref\ntrailer<<>>\nstartxref\n99\n%%EOF\n",
            ),
          ),
      },
    ],
  },
  {
    name: "jpeg",
    fixed: new JpegHandler(),
    legacy: new JpegHandler(),
    file: jpegF,
    embedded: [
      ...common,
      {
        name: "insert 2nd MAJIK APP15 after SOI",
        fn: (s) => {
          const data = concatBytes(
            textEncode("MAJIK\0"),
            textEncode('{"x":1}'),
          );
          const seg = concatBytes(
            new Uint8Array([
              0xff,
              0xef,
              (data.length + 2) >> 8,
              (data.length + 2) & 0xff,
            ]),
            data,
          );
          return concatBytes(s.slice(0, 2), seg, s.slice(2));
        },
      },
    ],
    detached: [],
  },
  {
    name: "wav",
    fixed: new WavHandler(),
    legacy: new WavHandler(),
    file: wavF,
    embedded: [
      ...common,
      append(5),
      {
        name: "change RIFF size field",
        fn: (s) => {
          const c = s.slice();
          c[4] = (c[4] + 8) & 0xff;
          return c;
        },
      },
      {
        name: "append LIST/INFO holding only an ISIG",
        fn: (s) => {
          const isig = concatBytes(
            textEncode("ISIG"),
            new Uint8Array([4, 0, 0, 0]),
            textEncode("evil"),
          );
          const info = concatBytes(textEncode("INFO"), isig);
          return concatBytes(
            s,
            textEncode("LIST"),
            new Uint8Array([info.length, 0, 0, 0]),
            info,
          );
        },
      },
    ],
    detached: [],
  },
  {
    name: "mp3",
    fixed: new Mp3Handler(),
    legacy: new Mp3Handler(),
    file: mp3F,
    embedded: [
      ...common,
      {
        name: "set ID3 header flag 0x40 (ext. header)",
        fn: (s) => {
          const c = s.slice();
          c[5] |= 0x40;
          return c;
        },
      },
      {
        name: "grow tag by 4 zero bytes (padding)",
        fn: (s) => {
          const size =
            ((s[6] & 0x7f) << 21) |
            ((s[7] & 0x7f) << 14) |
            ((s[8] & 0x7f) << 7) |
            (s[9] & 0x7f);
          const n = size + 4;
          const c = concatBytes(
            s.slice(0, 10 + size),
            new Uint8Array(4),
            s.slice(10 + size),
          );
          c[6] = (n >> 21) & 0x7f;
          c[7] = (n >> 14) & 0x7f;
          c[8] = (n >> 7) & 0x7f;
          c[9] = n & 0x7f;
          return c;
        },
      },
    ],
    detached: [],
  },
  {
    name: "office",
    fixed: new OfficeHandler(),
    legacy: new OfficeHandler(),
    file: officeF,
    embedded: [...common.slice(0, 2)],
    detached: [],
  },
];

async function legacyAccepted(h: FormatHandler, F: Uint8Array, m: Uint8Array) {
  const raw = await h.extract(m);
  return raw !== null && bufferEqual(await h.strip(m), await h.strip(F));
}
async function fixedAccepted(h: FormatHandler, F: Uint8Array, m: Uint8Array) {
  const raw = await h.extract(m);
  if (raw === null) return false;
  const c = await assertCanonical(h, m, raw);
  return c.ok && bufferEqual(c.original, await h.strip(F));
}
async function legacyDetached(h: FormatHandler, F: Uint8Array, m: Uint8Array) {
  return bufferEqual(await h.strip(m), await h.strip(F));
}
async function fixedDetached(h: FormatHandler, F: Uint8Array, m: Uint8Array) {
  const r = await prepareDetachedBytes(h, m, {
    validateEnvelope: (raw) => void JSON.parse(raw),
  });
  return r.ok && bufferEqual(r.original, await h.strip(F));
}

const rows: string[] = [];
describe("mutation matrix", () => {
  for (const c of cases) {
    describe(c.name, () => {
      it("honest signed file is accepted (both predicates)", async () => {
        const signedLegacy = await c.legacy.embed(
          await c.legacy.strip(c.file),
          J,
        );
        const signedFixed = await c.fixed.embed(await c.fixed.strip(c.file), J);
        expect(await legacyAccepted(c.legacy, c.file, signedLegacy)).toBe(true);
        expect(await fixedAccepted(c.fixed, c.file, signedFixed)).toBe(true);
        // wire format unchanged: new handler emits the same bytes as 0.4.1
        expect(bufferEqual(signedLegacy, signedFixed)).toBe(true);
      });
      for (const m of c.embedded) {
        it(`embedded: ${m.name}`, async () => {
          const s = await c.fixed.embed(await c.fixed.strip(c.file), J);
          const mutated = m.fn(s);
          const before = await legacyAccepted(c.legacy, c.file, mutated);
          const after = await fixedAccepted(c.fixed, c.file, mutated);
          rows.push(
            `${c.name.padEnd(7)} embedded  ${m.name.padEnd(42)} 0.4.1:${before ? "ACCEPTED" : "rejected"}  fixed:${after ? "ACCEPTED" : "rejected"}`,
          );
          expect(after).toBe(false);
        });
      }
      for (const m of c.detached) {
        it(`detached: ${m.name}`, async () => {
          const mutated = m.fn(c.file);
          const before = await legacyDetached(c.legacy, c.file, mutated);
          const after = await fixedDetached(c.fixed, c.file, mutated);
          rows.push(
            `${c.name.padEnd(7)} detached  ${m.name.padEnd(42)} 0.4.1:${before ? "ACCEPTED" : "rejected"}  fixed:${after ? "ACCEPTED" : "rejected"}`,
          );
          expect(after).toBe(false);
        });
      }
    });
  }
  it("prints the before/after table", () => {
    console.log("\n" + rows.join("\n"));
  });
});

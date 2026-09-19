import { describe, it, expect } from "vitest";
import { TextHandler } from "../../src/core/embed/handlers/text";

import { PdfHandler } from "../../src/core/embed/handlers/pdf";
import { assertCanonical } from "../../src/core/embed/canonical";
import {
  bufferEqual,
  concatBytes,
  textEncode,
} from "../../src/core/embed/utils";
import { LegacyTextHandler } from "../legacy/legacy-text-handler";

const J = '{"v":1,"note":"hello"}';
const h = new TextHandler();
const legacy = new LegacyTextHandler();
const BEGIN = "<!-- MAJIK-SIGNATURE-BEGIN -->";
const END = "<!-- MAJIK-SIGNATURE-END -->";

async function signRoundTrip(
  handler: TextHandler | LegacyTextHandler,
  file: Uint8Array,
) {
  const original = await handler.strip(file);
  const signed = await handler.embed(original, J);
  const back = await handler.strip(signed);
  return { original, signed, back };
}

describe("TextHandler (fixed)", () => {
  it("planted marker in body is content, not truncation (marker-planting repro)", async () => {
    const doc = textEncode(
      `# Agreement\n\nClause 1.\n\n${BEGIN}\n\nClause 2: forfeits deposit.\n`,
    );
    const { signed, back } = await signRoundTrip(h, doc);
    expect(bufferEqual(back, doc)).toBe(true); // nothing lost
    expect(new TextDecoder().decode(signed)).toContain("forfeits"); // Clause 2 survives signing
    expect(await h.extract(signed)).toBe(J);
  });

  it("BOM files round-trip byte-exactly (0.4.1 dropped the BOM)", async () => {
    const doc = concatBytes(
      new Uint8Array([0xef, 0xbb, 0xbf]),
      textEncode("héllo\n"),
    );
    const fixed = await signRoundTrip(h, doc);
    expect(bufferEqual(fixed.back, doc)).toBe(true);
    const old = await signRoundTrip(legacy, doc);
    expect(bufferEqual(old.back, doc)).toBe(false); // documents the old bug
  });

  it("invalid UTF-8 (e.g. Latin-1) round-trips byte-exactly", async () => {
    const doc = new Uint8Array([0x63, 0x61, 0x66, 0xe9, 0x0a]); // "caf\xe9\n"
    const fixed = await signRoundTrip(h, doc);
    expect(bufferEqual(fixed.back, doc)).toBe(true);
    const old = await signRoundTrip(legacy, doc);
    expect(bufferEqual(old.back, doc)).toBe(false);
  });

  it("swapping U+FFFD for a lone invalid byte is detected", async () => {
    const doc = textEncode("a\u{FFFD}b\n");
    const { signed, original } = await signRoundTrip(h, doc);
    const evil = signed.slice();
    const i = evil.indexOf(0xef); // EF BF BD -> FF + 2 bytes removed
    const swapped = concatBytes(
      evil.slice(0, i),
      new Uint8Array([0xff]),
      evil.slice(i + 3),
    );
    const raw = await h.extract(swapped);
    const c = raw === null ? null : await assertCanonical(h, swapped, raw);
    expect(c === null || !c.ok || !bufferEqual(c.original, original)).toBe(
      true,
    );
  });

  it("zero tolerance: not even a trailing newline / CRLF is accepted", async () => {
    const { signed } = await signRoundTrip(h, textEncode("x\n"));
    for (const tail of ["\n", " ", "\r\n", "\t"]) {
      const m = concatBytes(signed, textEncode(tail));
      expect(await h.extract(m)).toBeNull();
      expect(h.diagnose(m)).toMatch(/modified after signing/);
    }
  });

  it("diagnose(): null for unsigned text and for a well-formed block", async () => {
    expect(h.diagnose(textEncode("plain\n"))).toBeNull();
    const { signed } = await signRoundTrip(h, textEncode("x\n"));
    expect(h.diagnose(signed)).toBeNull();
  });

  it("non-canonical base64 (same decoded bytes, different encoding) is rejected", async () => {
    const enc = btoa("ab"); // "YWI="
    const alt = "YWJ="; // atob() accepts it too
    expect(atob(alt)).toBe(atob(enc));
    const m = textEncode(`doc\n\n${BEGIN}\n${alt}\n${END}\n`);
    expect(await h.extract(m)).toBeNull();
  });

  it("old 0.4.1-signed files still verify (wire format is unchanged)", async () => {
    const doc = textEncode("Invoice\n\nAmount: 100\n");
    const s = await legacy.embed(doc, J);
    expect(await h.extract(s)).toBe(J);
    const raw = (await h.extract(s))!;
    const c = await assertCanonical(h, s, raw);
    expect(c.ok && bufferEqual(c.original, doc)).toBe(true);
  });

  it("FUZZ: strip(embed(x)) === x and extract(embed(x)) === J for arbitrary x (incl. markers, BOM, junk)", async () => {
    let seed = 1234567;
    const rnd = () =>
      (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const pieces = [
      textEncode(BEGIN),
      textEncode(END),
      textEncode("\n\n"),
      textEncode("\n"),
      textEncode("QUJD"),
      textEncode("hello world"),
      new Uint8Array([0xef, 0xbb, 0xbf]),
      new Uint8Array([0xff, 0xfe, 0x00, 0xe9]),
      textEncode(`\n\n${BEGIN}\nQUJD\n${END}\n`),
    ];
    for (let n = 0; n < 3000; n++) {
      const parts: Uint8Array[] = [];
      for (let k = Math.floor(rnd() * 6); k > 0; k--)
        parts.push(pieces[Math.floor(rnd() * pieces.length)]);
      const x = concatBytes(...parts);
      const s = await h.embed(x, J);
      expect(bufferEqual(await h.strip(s), x)).toBe(true);
      expect(await h.extract(s)).toBe(J);
      // and anything split() accepts is canonical: embed(original, payload) === input
      const sp = h.split(x);
      if (sp)
        expect(bufferEqual(await h.embed(sp.original, sp.payload), x)).toBe(
          true,
        );
    }
  });
});

describe("PdfHandler (fixed)", () => {
  const p = new PdfHandler();
  const pdf = textEncode("%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n");
  it("round-trips, and a length field that lies is rejected", async () => {
    const s = await p.embed(pdf, J);
    expect(await p.extract(s)).toBe(J);
    expect(bufferEqual(await p.strip(s), pdf)).toBe(true);
    const bad = s.slice();
    bad[bad.length - 1] ^= 1;
    expect(await p.extract(bad)).toBeNull();
  });
  it("marker planted mid-PDF is content (no truncation)", async () => {
    const planted = concatBytes(
      pdf,
      textEncode("\n%%MajikSig%%\n"),
      textEncode("3 0 obj<<>>endobj\n%%EOF\n"),
    );
    expect(bufferEqual(await p.strip(planted), planted)).toBe(true);
    const s = await p.embed(planted, J);
    expect(bufferEqual(await p.strip(s), planted)).toBe(true);
  });
  it("FUZZ: strip(embed(x)) === x", async () => {
    for (let n = 0; n < 500; n++) {
      const x = new Uint8Array(Math.floor(Math.random() * 200)).map(() =>
        Math.floor(Math.random() * 256),
      );
      const s = await p.embed(x, J);
      expect(bufferEqual(await p.strip(s), x)).toBe(true);
      expect(await p.extract(s)).toBe(J);
    }
  });
});

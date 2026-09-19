import { describe, it, expect } from "vitest";
import { zipSync, strToU8 } from "fflate";

import { toZippable, concatBytes } from "../src/core/embed/utils";
import { OfficeHandler } from "../src/core/embed/handlers/office";
import { assertCanonical } from "../src/core/embed/canonical";

const h = new OfficeHandler();
const J = '{"v":1}';
const docx = zipSync(
  toZippable({
    "[Content_Types].xml": strToU8("<Types/>"),
    "word/document.xml": strToU8("<d>hi</d>"),
  }),
  { level: 0 },
);

describe("OfficeHandler hardening", () => {
  it("still detects, signs, verifies canonically", async () => {
    expect(h.canHandle(docx)).toBe(true);
    const s = await h.embed(await h.strip(docx), J);
    expect(await h.extract(s)).toBe(J);
    const c = await assertCanonical(h, s, J);
    expect(c.ok).toBe(true);
  });
  it("plain zip is not claimed", () => {
    const z = zipSync({ "a.txt": strToU8("x") });
    expect(h.canHandle(z)).toBe(false);
  });
  it("sniffing does not inflate large entries", () => {
    const big = new Uint8Array(200 * 1024 * 1024); // compresses to ~200 KB, would inflate 200 MB
    const z = zipSync({
      "[Content_Types].xml": strToU8("<Types/>"),
      "big.bin": [big, { level: 6 }],
    });
    const t0 = performance.now();
    expect(h.canHandle(z)).toBe(true);
    expect(performance.now() - t0).toBeLessThan(500);
  });
  it("embed/strip refuse an archive declaring > MAX_UNZIPPED_BYTES", async () => {
    const big = new Uint8Array(600 * 1024 * 1024);
    const z = zipSync({
      "[Content_Types].xml": strToU8("<Types/>"),
      "big.bin": [big, { level: 1 }],
    });
    await expect(h.embed(z, J)).rejects.toThrow();
  }, 60000);
  it("trailing junk after the ZIP is now rejected by the canonical check", async () => {
    const s = await h.embed(await h.strip(docx), J);
    const m = concatBytes(s, new Uint8Array(50).fill(0x41));
    const raw = await h.extract(m);
    if (raw === null) return; // also acceptable: not recognised
    const c = await assertCanonical(h, m, raw);
    expect(c.ok).toBe(false);
  });
});

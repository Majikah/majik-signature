// Public-API regression tests for the 0.4.1 advisory (flips the reporter's repro expectations).
// NOTE: not run in my sandbox (needs your getTestKey helper + full package) - run with `npx vitest run test/issue`.
import { describe, it, expect } from "vitest";
import { MajikSignature } from "../../src/index";
import { getTestKey } from "../helpers/crypto";

const BEGIN = "<!-- MAJIK-SIGNATURE-BEGIN -->";
const blob = (s: string | Uint8Array) =>
  new Blob([s as BlobPart], { type: "text/plain" });
const bytesOf = async (b: Blob) => new Uint8Array(await b.arrayBuffer());
const allInvalid = (r: { valid: boolean }[]) =>
  r.length > 0 && r.every((x) => !x.valid);

describe("advisory: append-after-signature (0.4.1)", () => {
  it("embedded: content appended after the signature block is REJECTED with a clear reason", async () => {
    const key = await getTestKey();
    const signed = await MajikSignature.signFile(
      blob("# Invoice\n\nAmount due: USD 100.00\n"),
      key,
    );
    const good = await MajikSignature.verifyFile(signed.blob, key);
    expect(good[0].valid).toBe(true);

    const attacked =
      new TextDecoder().decode(await bytesOf(signed.blob)) +
      "\n\nAmount due: USD 900.00\nPay to: Mallory\n";
    const res = await MajikSignature.verifyFile(blob(attacked), key);
    expect(allInvalid(res)).toBe(true);
    expect(res[0].reason).toMatch(/modified after signing/);
  });

  it("zero tolerance: a single trailing newline is rejected", async () => {
    const key = await getTestKey();
    const signed = await MajikSignature.signFile(blob("x\n"), key);
    const text = new TextDecoder().decode(await bytesOf(signed.blob));
    expect(
      allInvalid(await MajikSignature.verifyFile(blob(text + "\n"), key)),
    ).toBe(true);
  });

  it("planted marker no longer truncates the document at signing time", async () => {
    const key = await getTestKey();
    const doc = `# Agreement\n\nClause 1.\n\n${BEGIN}\n\nClause 2: forfeits deposit.\n`;
    const signed = await MajikSignature.signFile(blob(doc), key);
    const out = new TextDecoder().decode(await bytesOf(signed.blob));
    expect(out).toContain("forfeits");
    expect((await MajikSignature.verifyFile(signed.blob, key))[0].valid).toBe(
      true,
    );
    // and the stripped original is byte-identical to the input
    expect(
      new TextDecoder().decode(
        await bytesOf(await MajikSignature.stripFrom(signed.blob)),
      ),
    ).toBe(doc);
  });

  it("BOM + invalid UTF-8 documents sign, verify and strip byte-exactly", async () => {
    const key = await getTestKey();
    for (const doc of [
      new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69, 0x0a]),
      new Uint8Array([0x63, 0x61, 0x66, 0xe9, 0x0a]),
    ]) {
      const signed = await MajikSignature.signFile(blob(doc), key);
      expect((await MajikSignature.verifyFile(signed.blob, key))[0].valid).toBe(
        true,
      );
      expect(
        await bytesOf(await MajikSignature.stripFrom(signed.blob)),
      ).toEqual(doc);
    }
  });

  it("detached: a lone BEGIN marker + junk appended to the file is REJECTED", async () => {
    const key = await getTestKey();
    const orig = "# Invoice\n\nAmount due: USD 100.00\n";
    const { envelope } = await MajikSignature.signFileDetached(blob(orig), key);
    expect(
      (await MajikSignature.verifyFileDetached(blob(orig), envelope, key))[0]
        .valid,
    ).toBe(true);
    const attacked = orig + `\n\n${BEGIN}\nAmount due: USD 900.00`;
    expect(
      allInvalid(
        await MajikSignature.verifyFileDetached(blob(attacked), envelope, key),
      ),
    ).toBe(true);
  });
});

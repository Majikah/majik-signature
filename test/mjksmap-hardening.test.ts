import { describe, expect, it } from "vitest";

import {
  MAX_MJKSMAP_BYTES,
  MAX_MJKSMAP_ENTRIES,
  MAX_MJKSMAP_PATH_CHARS,
  MJKSMAP_HEADER_LEN,
  MJKSMAP_MAGIC,
  MJKSMAP_VERSION,
} from "../src/core/constants.js";
import { bytesToBase64 } from "../src/core/hash.js";
import { MajikSignatureMap } from "../src/core/mjksmap.js";

const validHash = bytesToBase64(new Uint8Array(32).fill(0x2a));
const validEnvelope = { version: 1 as const, signatures: [] };

function entry(path = "docs/report.txt") {
  return {
    path,
    contentHash: validHash,
    size: 0,
    mimeType: "text/plain",
    envelope: validEnvelope,
  };
}

function mapJson(entries: ReturnType<typeof entry>[]) {
  return {
    version: MJKSMAP_VERSION,
    createdAt: "2026-11-28T00:00:00.000Z",
    entries,
  };
}

function container(
  payload: Uint8Array,
  options: { reserved?: number; declaredLength?: number; suffix?: Uint8Array } = {},
): Uint8Array {
  const out = new Uint8Array(
    MJKSMAP_HEADER_LEN + payload.byteLength + (options.suffix?.byteLength ?? 0),
  );
  out.set(MJKSMAP_MAGIC, 0);
  out[MJKSMAP_MAGIC.length] = MJKSMAP_VERSION;
  out[MJKSMAP_MAGIC.length + 1] = options.reserved ?? 0;
  new DataView(out.buffer).setUint32(
    MJKSMAP_MAGIC.length + 2,
    options.declaredLength ?? payload.byteLength,
    false,
  );
  out.set(payload, MJKSMAP_HEADER_LEN);
  if (options.suffix) out.set(options.suffix, MJKSMAP_HEADER_LEN + payload.byteLength);
  return out;
}

describe("MJKSMAP parser and input hardening", () => {
  it("rejects a path that escapes the logical root or contains control/spoofing characters", () => {
    for (const path of [
      "../secret.txt",
      "docs/../../secret.txt",
      "docs\\u0000/report.txt",
      "docs\\u202e/report.txt",
    ]) {
      expect(() => MajikSignatureMap.empty().withEntry(entry(path))).toThrow();
    }
  });

  it("enforces bounded path length", () => {
    expect(() =>
      MajikSignatureMap.empty().withEntry(entry("a".repeat(MAX_MJKSMAP_PATH_CHARS + 1))),
    ).toThrow(/path length/i);
  });

  it("rejects duplicate paths after Windows separator and drive normalization", () => {
    const input = mapJson([
      entry("C:\\docs\\report.txt"),
      entry("docs/report.txt"),
    ]);
    expect(() => MajikSignatureMap.fromJSON(input)).toThrow(/duplicate normalized path/i);
  });

  it("rejects malformed digest, negative/unsafe size and injected MIME metadata", () => {
    for (const bad of [
      { ...entry(), contentHash: "A".repeat(44) },
      { ...entry(), size: -1 },
      { ...entry(), size: Number.MAX_SAFE_INTEGER + 1 },
      { ...entry(), size: 1.5 },
      { ...entry(), mimeType: "text/plain\\r\\nInjected: yes" },
    ]) {
      expect(() => MajikSignatureMap.fromJSON(mapJson([bad]))).toThrow();
    }
  });

  it("limits manifest entry count before building lookup indices", () => {
    const entries = Array.from({ length: MAX_MJKSMAP_ENTRIES + 1 }, (_, i) =>
      entry(`docs/${i}.txt`),
    );
    expect(() => MajikSignatureMap.fromJSON(mapJson(entries))).toThrow(/entries exceeds/i);
  });

  it("rejects oversized JSON and binary payloads before parsing", async () => {
    expect(() => MajikSignatureMap.fromJSON(" ".repeat(MAX_MJKSMAP_BYTES + 1))).toThrow(
      /maximum supported size/i,
    );
    const oversizedBlob = new Blob([new Uint8Array(MAX_MJKSMAP_BYTES + MJKSMAP_HEADER_LEN + 1)]);
    await expect(MajikSignatureMap.fromMJKSMAP(oversizedBlob)).rejects.toThrow(
      /maximum supported size/i,
    );
  });

  it("requires a zero reserved byte and exact payload length", async () => {
    const payload = new TextEncoder().encode(JSON.stringify(mapJson([entry()])));
    await expect(
      MajikSignatureMap.fromMJKSMAP(container(payload, { reserved: 1 })),
    ).rejects.toThrow(/reserved byte/i);
    await expect(
      MajikSignatureMap.fromMJKSMAP(container(payload, { suffix: new Uint8Array([0]) })),
    ).rejects.toThrow(/trailing bytes/i);
    await expect(
      MajikSignatureMap.fromMJKSMAP(container(payload, { declaredLength: payload.byteLength + 1 })),
    ).rejects.toThrow(/exceeds buffer/i);
  });

  it("rejects invalid UTF-8 and malformed JSON payloads", async () => {
    await expect(
      MajikSignatureMap.fromMJKSMAP(container(new Uint8Array([0xff]))),
    ).rejects.toThrow(/UTF-8/i);
    await expect(
      MajikSignatureMap.fromMJKSMAP(container(new TextEncoder().encode("{"))),
    ).rejects.toThrow(/JSON/i);
  });

  it("preserves valid maps and path normalization", async () => {
    const map = MajikSignatureMap.empty().withEntry(entry("C:\\docs\\report.txt"));
    const bytes = map.toMJKSMAPBytes();
    const restored = await MajikSignatureMap.fromMJKSMAP(bytes);
    expect(restored.size).toBe(1);
    expect(restored.getEntry("docs/report.txt")).toBeDefined();
    expect(restored.getEntry("C:\\docs\\report.txt")).toBeDefined();
  });
});

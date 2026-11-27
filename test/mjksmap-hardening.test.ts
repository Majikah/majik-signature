import { describe, expect, it } from "vitest";

import {
  MAX_MJKSMAP_BYTES,
  MAX_MJKSMAP_JSON_BYTES,
  MAX_MJKSMAP_ENTRIES,
  MAX_MJKSMAP_PATH_CHARS,
  MJKSMAP_HEADER_LEN,
  MJKSMAP_MAGIC,
  MJKSMAP_VERSION,
  MJKSMAP_JSON_VERSION,
  MJKSMAP_CBOR_VERSION,
  MJKSMAP_SCHEMA_VERSION,
} from "../src/core/constants.js";
import { bytesToBase64 } from "../src/core/hash.js";
import { MajikSignatureMap } from "../src/core/mjksmap.js";
import { decodeCBOR } from "../src/core/cbor/cbor.js";

const validHash = bytesToBase64(new Uint8Array(32).fill(0x2a));
function entry(path = "docs/report.txt") {
  return {
    path,
    contentHash: validHash,
    size: 0,
    mimeType: "text/plain",
    // Each fixture owns its envelope so mutation tests cannot contaminate
    // later cases through a shared object reference.
    envelope: { version: 1 as const, signatures: [] },
  };
}

function mapJson(entries: ReturnType<typeof entry>[]) {
  return {
    version: MJKSMAP_SCHEMA_VERSION,
    createdAt: "2026-11-28T00:00:00.000Z",
    entries,
  };
}

function container(
  payload: Uint8Array,
  options: { reserved?: number; declaredLength?: number; suffix?: Uint8Array } = {},
  version = MJKSMAP_VERSION,
): Uint8Array {
  const out = new Uint8Array(
    MJKSMAP_HEADER_LEN + payload.byteLength + (options.suffix?.byteLength ?? 0),
  );
  out.set(MJKSMAP_MAGIC, 0);
  out[MJKSMAP_MAGIC.length] = version;
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
      "docs\u0000/report.txt",
      "docs\u202e/report.txt",
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
      { ...entry(), mimeType: "text/plain\r\nInjected: yes" },
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
    expect(() => MajikSignatureMap.fromJSON(" ".repeat(MAX_MJKSMAP_JSON_BYTES + 1))).toThrow(
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
      MajikSignatureMap.fromMJKSMAP(container(new Uint8Array([0xff]), {}, MJKSMAP_JSON_VERSION)),
    ).rejects.toThrow(/UTF-8/i);
    await expect(
      MajikSignatureMap.fromMJKSMAP(container(new TextEncoder().encode("{"), {}, MJKSMAP_JSON_VERSION)),
    ).rejects.toThrow(/JSON/i);
  });

  it("writes CBOR v2 with raw byte strings and reads legacy JSON v1", async () => {
    const map = MajikSignatureMap.empty().withEntry(entry());
    const current = map.toMJKSMAPBytes();

    expect(current[MJKSMAP_MAGIC.length]).toBe(MJKSMAP_CBOR_VERSION);
    const payload = current.subarray(MJKSMAP_HEADER_LEN);
    const decoded = decodeCBOR(payload) as {
      version: number;
      entries: Array<{ contentHash: unknown; envelope: Record<string, unknown> }>;
    };
    expect(decoded.version).toBe(MJKSMAP_SCHEMA_VERSION);
    expect(decoded.entries[0]?.contentHash).toBeInstanceOf(Uint8Array);
    expect((decoded.entries[0]?.contentHash as Uint8Array).byteLength).toBe(32);

    const legacyJson = new TextEncoder().encode(JSON.stringify(map.toJSON()));
    const legacy = container(legacyJson, {}, MJKSMAP_JSON_VERSION);
    const restored = await MajikSignatureMap.fromMJKSMAP(legacy);
    expect(restored.toJSON()).toEqual(map.toJSON());
  });

  it("rejects trailing CBOR items instead of accepting a valid prefix", async () => {
    const map = MajikSignatureMap.empty().withEntry(entry());
    const valid = map.toMJKSMAPBytes();
    const payload = valid.subarray(MJKSMAP_HEADER_LEN);
    const appended = new Uint8Array(payload.length + 1);
    appended.set(payload);
    appended[appended.length - 1] = 0x00; // CBOR null as a second top-level item
    await expect(
      MajikSignatureMap.fromMJKSMAP(container(appended)),
    ).rejects.toThrow(/CBOR/i);
  });

  it("freezes stored entries and returns detached mutable JSON snapshots", () => {
    const source = entry("docs/immutable.txt");
    const map = MajikSignatureMap.empty().withEntry(source);

    source.path = "docs/changed-after-build.txt";
    source.envelope.signatures.push({} as any);

    expect(Object.isFrozen(map)).toBe(true);
    const stored = map.getEntry("docs/immutable.txt");
    expect(stored).toBeDefined();
    expect(Object.isFrozen(stored)).toBe(true);
    expect(Object.isFrozen(stored?.envelope)).toBe(true);
    expect(stored?.envelope.signatures).toHaveLength(0);

    const jsonCopy = map.toJSON();
    jsonCopy.entries[0]!.path = "docs/changed-json-copy.txt";
    expect(map.getEntry("docs/immutable.txt")).toBeDefined();
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

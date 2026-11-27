import { describe, expect, it } from "vitest";

import { MajikSignatureMap } from "../src/core/mjksmap";
import { buildSessionContextHash } from "../src/core/session-context";

const EMPTY_ENVELOPE = {
  version: 1,
  signatures: [],
} as any;

const ZERO_SHA256_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

describe("ECMAScript whitespace compatibility", () => {
  it("trims U+FEFF from MJKSMAP paths", () => {
    const map = MajikSignatureMap.empty().withEntry({
      path: "\uFEFFdocs/report.txt\uFEFF",
      contentHash: ZERO_SHA256_BASE64,
      envelope: EMPTY_ENVELOPE,
    });

    expect(map.getEntry("docs/report.txt")).toBeDefined();
  });

  it("does not trim U+0085 from MJKSMAP paths", () => {
    const path = "\u0085docs/report.txt\u0085";
    const map = MajikSignatureMap.empty().withEntry({
      path,
      contentHash: ZERO_SHA256_BASE64,
      envelope: EMPTY_ENVELOPE,
    });

    expect(map.getEntry(path)).toBeDefined();
    expect(map.getEntry("docs/report.txt")).toBeUndefined();
  });

  it("uses ECMAScript trim semantics for SignRoom session identifiers", () => {
    const base = {
      challengeId: "challenge-1",
      policyHash: ZERO_SHA256_BASE64,
    };

    expect(() =>
      buildSessionContextHash({ ...base, sessionId: "\u0085session-1\u0085" }),
    ).not.toThrow();

    expect(() =>
      buildSessionContextHash({ ...base, sessionId: "\uFEFFsession-1" }),
    ).toThrow(/sessionId/);

    expect(() =>
      buildSessionContextHash({
        ...base,
        sessionId: "session-1",
        challengeId: "\uFEFFchallenge-1",
      }),
    ).toThrow(/challengeId/);
  });
});

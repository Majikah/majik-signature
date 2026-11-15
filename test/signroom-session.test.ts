import { beforeAll, describe, expect, it } from "vitest";
import type { MajikKey } from "@majikah/majik-key";

import { MajikSignature } from "../src/majik-signature.js";
import { buildSessionContextHash } from "../src/core/session-context.js";
import { bytesToBase64, hashContent } from "../src/core/hash.js";
import { getTestKey } from "./helpers/crypto.js";

const CONTENT = new TextEncoder().encode(
  "SignRoom immutable source document for session-bound signing.",
);

function hashText(value: string): string {
  return bytesToBase64(hashContent(value));
}

describe("SignRoom session-bound signature foundation", () => {
  let issuerKey: MajikKey;
  let signerKey: MajikKey;
  let tsaKey: MajikKey;

  beforeAll(async () => {
    [issuerKey, signerKey, tsaKey] = await Promise.all([
      getTestKey(),
      getTestKey(),
      getTestKey(),
    ]);
  }, 120000);

  it("creates a deterministic context hash bound to session, challenge, and policy", () => {
    const context = {
      sessionId: "session-001",
      challengeId: "challenge-001",
      policyHash: hashText("immutable-session-policy"),
    };
    const first = buildSessionContextHash(context);

    expect(buildSessionContextHash(context)).toBe(first);
    expect(first).toHaveLength(44);
    expect(
      buildSessionContextHash({ ...context, challengeId: "challenge-002" }),
    ).not.toBe(first);
    expect(
      buildSessionContextHash({
        ...context,
        policyHash: hashText("modified-policy"),
      }),
    ).not.toBe(first);
    expect(() =>
      buildSessionContextHash({ ...context, policyHash: "not-a-digest" }),
    ).toThrow(/policyHash/i);
    expect(() =>
      buildSessionContextHash({ ...context, sessionId: " session-001" }),
    ).toThrow(/sessionId/i);
  });

  it("signs the context into both hybrid signatures and verifies a trusted digest without plaintext", async () => {
    const sessionContextHash = buildSessionContextHash({
      sessionId: "session-verify",
      challengeId: "challenge-verify",
      policyHash: hashText("policy-v1"),
    });
    const signature = await MajikSignature.sign(CONTENT, issuerKey, {
      contentType: "application/octet-stream",
      sessionContextHash,
    });

    const verified = MajikSignature.verify(
      CONTENT,
      signature,
      signature.extractPublicKeys(),
    );
    expect(signature.sessionContextHash).toBe(sessionContextHash);
    expect(verified.valid).toBe(true);
    expect(verified.sessionContextHash).toBe(sessionContextHash);

    const digestResult = MajikSignature.verifyDigest(
      signature.contentHash,
      signature,
      signature.extractPublicKeys(),
      { expectedSessionContextHash: sessionContextHash },
    );
    expect(digestResult.valid).toBe(true);
    expect(digestResult.commitmentOnly).toBe(true);
  });

  it("rejects a signature presented with a different context or document digest", async () => {
    const signedContext = buildSessionContextHash({
      sessionId: "session-original",
      challengeId: "challenge-original",
      policyHash: hashText("policy-original"),
    });
    const otherContext = buildSessionContextHash({
      sessionId: "session-other",
      challengeId: "challenge-other",
      policyHash: hashText("policy-other"),
    });
    const signature = await MajikSignature.sign(CONTENT, issuerKey, {
      sessionContextHash: signedContext,
    });

    expect(
      MajikSignature.verifyDigest(
        signature.contentHash,
        signature,
        signature.extractPublicKeys(),
        { expectedSessionContextHash: otherContext },
      ).valid,
    ).toBe(false);
    expect(
      MajikSignature.verifyDigest(
        hashText("different-document"),
        signature,
        signature.extractPublicKeys(),
        { expectedSessionContextHash: signedContext },
      ).valid,
    ).toBe(false);
    expect(
      MajikSignature.verifyDigest(
        signature.contentHash,
        signature,
        signature.extractPublicKeys(),
      ).valid,
    ).toBe(false);

    const tampered = MajikSignature.fromJSON({
      ...signature.toJSON(),
      sessionContextHash: otherContext,
    });
    expect(
      MajikSignature.verify(
        CONTENT,
        tampered,
        tampered.extractPublicKeys(),
      ).valid,
    ).toBe(false);
  });

  it("rejects public keys that do not match the signature's embedded key record", async () => {
    const signature = await MajikSignature.sign(CONTENT, issuerKey);
    const otherKeys = signerKey
      ? MajikSignature.publicKeysFromMajikKey(signerKey)
      : signature.extractPublicKeys();

    expect(
      MajikSignature.verify(CONTENT, signature, otherKeys).valid,
    ).toBe(false);
    expect(
      MajikSignature.verifyDigest(
        signature.contentHash,
        signature,
        otherKeys,
      ).valid,
    ).toBe(false);
  });

  it("round-trips the session commitment through JSON, compact form, and CBOR", async () => {
    const sessionContextHash = buildSessionContextHash({
      sessionId: "session-serialization",
      challengeId: "challenge-serialization",
      policyHash: hashText("policy-serialization"),
    });
    const signature = await MajikSignature.sign(CONTENT, signerKey, {
      sessionContextHash,
    });

    expect(
      MajikSignature.fromJSON(signature.toJSON()).sessionContextHash,
    ).toBe(sessionContextHash);

    const compact = signature.toCompact();
    expect(compact.sessionContextHash).toBe(sessionContextHash);
    const keys = signature.extractPublicKeys();
    const fromCompact = MajikSignature.fromCompact(compact, {
      edPublicKey: keys.edPublicKey,
      mlDsaPublicKey: keys.mlDsaPublicKey,
    });
    expect(fromCompact.sessionContextHash).toBe(sessionContextHash);
    expect(
      MajikSignature.verifyDigest(
        signature.contentHash,
        fromCompact,
        fromCompact.extractPublicKeys(),
        { expectedSessionContextHash: sessionContextHash },
      ).valid,
    ).toBe(true);

    const fromCbor = MajikSignature.fromCBOR(signature.toCBOR());
    expect(fromCbor.sessionContextHash).toBe(sessionContextHash);
    expect(
      MajikSignature.verify(
        CONTENT,
        fromCbor,
        fromCbor.extractPublicKeys(),
      ).valid,
    ).toBe(true);
  });

  it("keeps legacy standalone signatures compatible by omitting the session field", async () => {
    const signature = await MajikSignature.sign(CONTENT, issuerKey);

    expect(signature.sessionContextHash).toBeUndefined();
    expect(
      Object.prototype.hasOwnProperty.call(
        signature.toJSON(),
        "sessionContextHash",
      ),
    ).toBe(false);
    expect(
      MajikSignature.verify(
        CONTENT,
        signature,
        signature.extractPublicKeys(),
      ).valid,
    ).toBe(true);
    expect(
      MajikSignature.verifyDigest(
        signature.contentHash,
        signature,
        signature.extractPublicKeys(),
      ).valid,
    ).toBe(true);
  });

  it("creates and verifies a TSA attestation over the unsigned signature record", async () => {
    const sessionContextHash = buildSessionContextHash({
      sessionId: "session-tsa",
      challengeId: "challenge-tsa",
      policyHash: hashText("policy-tsa"),
    });
    const signature = await MajikSignature.sign(CONTENT, issuerKey, {
      sessionContextHash,
    });

    const request = signature.buildTSARequestPayload("signature");
    expect(request.digest.scope).toBe("signature");
    expect(request.digest.value).not.toBe(signature.contentHash);

    const timestamp = await MajikSignature.signTSA(request, tsaKey, {
      id: "tsa.majikah.solutions",
      signerFingerprint: tsaKey.fingerprint,
    });
    signature.addTSA(timestamp, MajikSignature.publicKeysFromMajikKey(tsaKey));

    expect(signature.hasTSA).toBe(true);
    expect(signature.verifyTSA(MajikSignature.publicKeysFromMajikKey(tsaKey)).valid).toBe(true);
    expect(signature.toJSON().tsa?.payload.digest.scope).toBe("signature");

    const restored = MajikSignature.fromCBOR(signature.toCBOR());
    expect(restored.sessionContextHash).toBe(sessionContextHash);
    expect(restored.toJSON().tsa?.payload.digest.scope).toBe("signature");
    expect(restored.verifyTSA(MajikSignature.publicKeysFromMajikKey(tsaKey)).valid).toBe(true);
    expect(() => restored.verifyTSA(MajikSignature.publicKeysFromMajikKey(signerKey))).toThrow(
      /trusted TSA identity/i,
    );
  });

  it("does not reuse a signature-scoped TSA token for a different signer record", async () => {
    const policyHash = hashText("shared-policy");
    const signatureA = await MajikSignature.sign(CONTENT, issuerKey, {
      sessionContextHash: buildSessionContextHash({
        sessionId: "session-shared",
        challengeId: "challenge-a",
        policyHash,
      }),
    });
    const signatureB = await MajikSignature.sign(CONTENT, signerKey, {
      sessionContextHash: buildSessionContextHash({
        sessionId: "session-shared",
        challengeId: "challenge-b",
        policyHash,
      }),
    });

    const tokenA = await MajikSignature.signTSA(
      signatureA.buildTSARequestPayload("signature"),
      tsaKey,
      {
        id: "tsa.majikah.solutions",
        signerFingerprint: tsaKey.fingerprint,
      },
    );
    signatureA.addTSA(tokenA, MajikSignature.publicKeysFromMajikKey(tsaKey));

    expect(() => signatureB.addTSA(tokenA, MajikSignature.publicKeysFromMajikKey(tsaKey))).toThrow(
      /TSA digest does not match the canonical signature record/i,
    );
  });

  it("rejects an untrusted TSA fingerprint when attaching an otherwise valid token", async () => {
    const signature = await MajikSignature.sign(CONTENT, issuerKey);
    const token = await MajikSignature.signTSA(
      signature.buildTSARequestPayload("signature"),
      tsaKey,
      {
        id: "tsa.majikah.solutions",
        signerFingerprint: tsaKey.fingerprint,
      },
    );

    expect(() => signature.addTSA(token, MajikSignature.publicKeysFromMajikKey(signerKey))).toThrow(
      /trusted TSA identity/i,
    );
    expect(signature.hasTSA).toBe(false);
  });
});

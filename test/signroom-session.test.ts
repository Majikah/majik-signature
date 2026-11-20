import { beforeAll, describe, expect, it } from "vitest";
import type { MajikKey } from "@majikah/majik-key";

import { MajikSignature } from "../src/majik-signature.js";
import { MajikSignatureEnvelope } from "../src/core/envelope.js";
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
      /TSA identity does not match the trusted TSA public-key fingerprint/i,
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

  it("rejects an untrusted TSA key when attaching an otherwise valid token", async () => {
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
      /TSA identity does not match the trusted TSA public-key fingerprint/i,
    );
    expect(signature.hasTSA).toBe(false);
  });

  describe("session-aware detached file APIs", () => {
    const makeContext = (sessionId: string, challengeId: string, policy: string) => ({
      sessionId,
      challengeId,
      policyHash: hashText(policy),
    });

    it("signs a session-bound document and round-trips its .mjksig sidecar", async () => {
      const file = new Blob(["session-bound document"], {
        type: "text/plain",
      });
      const sessionContext = makeContext(
        "session-single",
        "challenge-single-1",
        "session-policy-v1",
      );

      const signed = await MajikSignature.signSessionFile(file, issuerKey, {
        sessionContext,
        contentType: "text/plain",
      });

      expect(signed.signature.sessionContextHash).toBe(
        buildSessionContextHash(sessionContext),
      );
      expect(await MajikSignatureEnvelope.isMJKSIG(signed.mjksig)).toBe(true);

      const restored = await MajikSignatureEnvelope.fromMJKSIG(signed.mjksig);
      expect(restored.signatures).toHaveLength(1);

      const verified = await MajikSignature.verifySessionFile(
        signed.blob,
        signed.mjksig,
        {
          expectedSessionContexts: {
            [issuerKey.fingerprint]: sessionContext,
          },
          expectedSignerPublicKeys: {
            [issuerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(issuerKey),
          },
        },
      );

      expect(verified.valid).toBe(true);
      expect(verified.results).toHaveLength(1);
      expect(verified.results[0].valid).toBe(true);
      expect(verified.results[0].sessionContextHash).toBe(
        buildSessionContextHash(sessionContext),
      );
    });

    it("verifies multiple participants against their individual challenge contexts", async () => {
      const file = new Blob(["multi-signer session document"], {
        type: "text/plain",
      });
      const issuerContext = makeContext(
        "session-multi",
        "challenge-issuer",
        "shared-policy",
      );
      const signerContext = makeContext(
        "session-multi",
        "challenge-participant",
        "shared-policy",
      );

      const issuer = await MajikSignature.signSessionFile(file, issuerKey, {
        sessionContext: issuerContext,
        contentType: "text/plain",
        expectedSigners: [
          MajikSignature.expectedSignerFromKey(issuerKey),
          MajikSignature.expectedSignerFromKey(signerKey),
        ],
      });
      const participant = await MajikSignature.signSessionFile(
        issuer.blob,
        signerKey,
        {
          sessionContext: signerContext,
          contentType: "text/plain",
          existingEnvelope: issuer.envelope,
        },
      );

      expect(participant.envelope.signatures).toHaveLength(2);
      expect(
        participant.envelope.signatures[0].sessionContextHash,
      ).not.toBe(participant.envelope.signatures[1].sessionContextHash);

      const verified = await MajikSignature.verifySessionFile(
        participant.blob,
        participant.mjksig,
        {
          expectedSessionContexts: {
            [issuerKey.fingerprint]: issuerContext,
            [signerKey.fingerprint]: signerContext,
          },
          expectedSignerPublicKeys: {
            [issuerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(issuerKey),
            [signerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(signerKey),
          },
        },
      );

      expect(verified.valid).toBe(true);
      expect(verified.results).toHaveLength(2);
      expect(verified.results.every((result) => result.valid)).toBe(true);
    });

    it("rejects missing or mismatched authoritative signer contexts", async () => {
      const file = new Blob(["strict session verification"], {
        type: "text/plain",
      });
      const signedContext = makeContext(
        "session-strict",
        "challenge-real",
        "policy-real",
      );
      const signed = await MajikSignature.signSessionFile(file, issuerKey, {
        sessionContext: signedContext,
        contentType: "text/plain",
      });

      const missing = await MajikSignature.verifySessionFile(
        signed.blob,
        signed.mjksig,
        {
          expectedSessionContexts: {},
          expectedSignerPublicKeys: {
            [issuerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(issuerKey),
          },
        },
      );
      expect(missing.valid).toBe(false);
      expect(missing.results[0].reason).toMatch(/No authoritative session context/i);

      const mismatched = await MajikSignature.verifySessionFile(
        signed.blob,
        signed.mjksig,
        {
          expectedSessionContexts: {
            [issuerKey.fingerprint]: makeContext(
              "session-strict",
              "challenge-replayed",
              "policy-real",
            ),
          },
          expectedSignerPublicKeys: {
            [issuerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(issuerKey),
          },
        },
      );
      expect(mismatched.valid).toBe(false);
      expect(mismatched.results[0].reason).toMatch(/session context does not match/i);
    });

    it("extends and verifies a session-bound visual-stamp revision chain", async () => {
      const original = new Blob(["original session document revision"], {
        type: "text/plain",
      });
      const issuerContext = makeContext(
        "session-revisions",
        "challenge-revision-issuer",
        "revision-policy",
      );
      const participantContext = makeContext(
        "session-revisions",
        "challenge-revision-participant",
        "revision-policy",
      );
      const issuer = await MajikSignature.signSessionFile(
        original,
        issuerKey,
        {
          sessionContext: issuerContext,
          contentType: "text/plain",
          expectedSigners: [
            MajikSignature.expectedSignerFromKey(issuerKey),
            MajikSignature.expectedSignerFromKey(signerKey),
          ],
        },
      );

      const stamped = new Blob(["original session document revision\nvisual stamp"], {
        type: "text/plain",
      });
      const participant = await MajikSignature.signSessionFile(
        stamped,
        signerKey,
        {
          sessionContext: participantContext,
          contentType: "text/plain",
          existingEnvelope: issuer.envelope,
          priorFile: issuer.blob,
          message: "Participant added a visual stamp",
        },
      );

      expect(participant.envelope.fileVersions).toHaveLength(2);
      expect(participant.signature.versionChainHash).toBeTruthy();

      const verified = await MajikSignature.verifySessionFile(
        participant.blob,
        participant.mjksig,
        {
          expectedSessionContexts: {
            [issuerKey.fingerprint]: issuerContext,
            [signerKey.fingerprint]: participantContext,
          },
          expectedSignerPublicKeys: {
            [issuerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(issuerKey),
            [signerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(signerKey),
          },
        },
      );

      expect(verified.valid).toBe(true);
      expect(verified.chain?.chainValid).toBe(true);
      expect(verified.results).toHaveLength(2);
      expect(verified.results.every((result) => result.valid)).toBe(true);
    });

    it("checks a signature-scoped TSA and can require a pinned TSA identity", async () => {
      const file = new Blob(["session document with official timestamp"], {
        type: "text/plain",
      });
      const sessionContext = makeContext(
        "session-tsa-api",
        "challenge-tsa-api",
        "tsa-policy",
      );
      const signed = await MajikSignature.signSessionFile(file, issuerKey, {
        sessionContext,
        contentType: "text/plain",
      });
      const timestamp = await MajikSignature.signTSA(
        signed.signature.buildTSARequestPayload("signature"),
        tsaKey,
        {
          id: "tsa.majikah.solutions",
          signerFingerprint: tsaKey.fingerprint,
        },
      );
      signed.signature.addTSA(
        timestamp,
        MajikSignature.publicKeysFromMajikKey(tsaKey),
      );
      const timestampedEnvelope = signed.envelope.withSignature(
        signed.signature.toJSON(),
      );
      const verified = await MajikSignature.verifySessionFile(
        signed.blob,
        timestampedEnvelope.toMJKSIG(),
        {
          expectedSessionContexts: {
            [issuerKey.fingerprint]: sessionContext,
          },
          expectedSignerPublicKeys: {
            [issuerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(issuerKey),
          },
          trustedTsaPublicKeys: MajikSignature.publicKeysFromMajikKey(tsaKey),
          requireTSA: true,
          requireTrustedTSA: true,
        },
      );

      expect(verified.valid).toBe(true);
      expect(verified.tsaResults).toEqual([
        {
          signerId: issuerKey.fingerprint,
          present: true,
          valid: true,
          trusted: true,
        },
      ]);
    });

    it("rejects mixed session policies and reused one-time challenges", async () => {
      const file = new Blob(["challenge isolation"], { type: "text/plain" });
      const issuerContext = makeContext(
        "session-isolation",
        "challenge-shared",
        "policy-isolation",
      );
      const participantContext = makeContext(
        "session-isolation",
        "challenge-shared",
        "policy-isolation",
      );
      const issuer = await MajikSignature.signSessionFile(file, issuerKey, {
        sessionContext: issuerContext,
        contentType: "text/plain",
        expectedSigners: [
          MajikSignature.expectedSignerFromKey(issuerKey),
          MajikSignature.expectedSignerFromKey(signerKey),
        ],
      });
      const participant = await MajikSignature.signSessionFile(
        issuer.blob,
        signerKey,
        {
          sessionContext: participantContext,
          contentType: "text/plain",
          existingEnvelope: issuer.envelope,
        },
      );

      const reusedChallenge = await MajikSignature.verifySessionFile(
        participant.blob,
        participant.mjksig,
        {
          expectedSessionContexts: {
            [issuerKey.fingerprint]: issuerContext,
            [signerKey.fingerprint]: participantContext,
          },
          expectedSignerPublicKeys: {
            [issuerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(issuerKey),
            [signerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(signerKey),
          },
        },
      );
      expect(reusedChallenge.valid).toBe(false);
      expect(reusedChallenge.reason).toMatch(/distinct one-time challenge/i);

      const mixedSession = await MajikSignature.verifySessionFile(
        participant.blob,
        participant.mjksig,
        {
          expectedSessionContexts: {
            [issuerKey.fingerprint]: issuerContext,
            [signerKey.fingerprint]: makeContext(
              "another-session",
              "challenge-participant-unique",
              "policy-isolation",
            ),
          },
          expectedSignerPublicKeys: {
            [issuerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(issuerKey),
            [signerKey.fingerprint]: MajikSignature.publicKeysFromMajikKey(signerKey),
          },
        },
      );
      expect(mixedSession.valid).toBe(false);
      expect(mixedSession.reason).toMatch(/same SignRoom session/i);
    });
  });

});

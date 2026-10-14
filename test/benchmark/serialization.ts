/**
 * Majik Signature serialization benchmark.
 *
 * Place this file at test/benchmark/serialization.ts, then run:
 *   npx vite-node test/benchmark/serialization.ts
 *
 * Optional environment variables:
 *   SERIALIZATION_BENCH_ITERATIONS=5
 *   SERIALIZATION_BENCH_SIGNERS=5 (must be 1 through 5)
 *   SERIALIZATION_BENCH_OUT=test/results/serialization
 *
 * This benchmark uses the repository's real getTestKey() helper and on-disk
 * fixtures. It measures byte sizes and timings from the current checkout;
 * it does not rely on hard-coded payload-size estimates.
 */
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { isDeepStrictEqual } from "node:util";

import { getTestKey } from "../helpers/crypto";
import { MajikSignature } from "../../src/majik-signature";
import { MajikSignatureEnvelope } from "../../src/core/envelope";
import { MJKSIG_CBOR_VERSION, MJKSIG_HEADER_LEN } from "../../src/core/constants";
import {
  JpegHandler,
  PdfHandler,
  WavHandler,
} from "../../src/core/embed/handlers";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const TEST_DIR = dirname(SCRIPT_PATH);
const PROJECT_ROOT = resolve(TEST_DIR, "..", "..");
const FIXTURES_DIR = join(PROJECT_ROOT, "test", "fixtures");
const REPORT_DIR_SETTING = process.env.SERIALIZATION_BENCH_OUT;
const REPORT_DIR = REPORT_DIR_SETTING
  ? isAbsolute(REPORT_DIR_SETTING)
    ? REPORT_DIR_SETTING
    : resolve(PROJECT_ROOT, REPORT_DIR_SETTING)
  : join(PROJECT_ROOT, "test", "results", "serialization");

const ITERATIONS = parsePositiveInteger(
  process.env.SERIALIZATION_BENCH_ITERATIONS,
  5,
);
const MAX_SIGNERS = parsePositiveInteger(
  process.env.SERIALIZATION_BENCH_SIGNERS,
  5,
);
if (MAX_SIGNERS > 5) {
  throw new Error("SERIALIZATION_BENCH_SIGNERS must be between 1 and 5.");
}
const WARMUP_ITERATIONS = 1;
const BENCHMARK_TIMESTAMP = "2026-10-14T00:00:00.000Z";

const FIXTURE_DEFINITIONS = [
  {
    file: "sample.pdf",
    label: "PDF sample",
    mimeType: "application/pdf",
    Handler: PdfHandler,
  },
  {
    file: "sample.jpg",
    label: "JPEG sample",
    mimeType: "image/jpeg",
    Handler: JpegHandler,
  },
  {
    file: "sample.wav",
    label: "WAV sample",
    mimeType: "audio/wav",
    Handler: WavHandler,
  },
] as const;

const LEGACY_FIXTURE_DEFINITIONS = [
  {
    file: join("compat", "compat.pdf"),
    label: "Legacy JSON-embedded PDF",
    mimeType: "application/pdf",
    Handler: PdfHandler,
  },
  {
    file: join("compat", "compat.jpg"),
    label: "Legacy JSON-embedded JPEG",
    mimeType: "image/jpeg",
    Handler: JpegHandler,
  },
  {
    file: join("compat", "compat.wav"),
    label: "Legacy JSON-embedded WAV",
    mimeType: "audio/wav",
    Handler: WavHandler,
  },
] as const;

type TimingResult = {
  name: string;
  iterations: number;
  warmupIterations: number;
  totalMs: number;
  meanMs: number;
  medianMs: number;
  minMs: number;
  maxMs: number;
  operationsPerSecond: number;
};

type CheckResult = {
  name: string;
  passed: boolean;
  details?: string;
};

type SizeMeasurement = {
  fixture: string;
  mimeType: string;
  signerCount: number;
  originalFileBytes: number;
  detachedCleanFileBytes: number;
  embeddedFileBytes: number;
  embeddedFileGrowthBytes: number;
  signatureJsonBytes: number;
  signatureBase64SerializedBytes: number;
  signatureCborBytes: number;
  envelopeJsonBytes: number;
  envelopeBase64SerializedBytes: number;
  envelopeCborBytes: number;
  mjksigContainerBytes: number;
  mjksigHeaderOverheadBytes: number;
  embeddedPayloadUtf8Bytes: number;
  embeddedPayloadCharacters: number;
  embeddedPayloadLooksLikeVersionedText: boolean;
  cborReductionVsEnvelopeJsonPercent: number;
  cborReductionVsEnvelopeBase64Percent: number;
  embeddedPayloadReductionVsEnvelopeBase64Percent: number;
};

type SizeTrendMeasurement = {
  signerCount: number;
  fixtureCount: number;
  averageEnvelopeJsonBytes: number;
  averageEnvelopeBase64SerializedBytes: number;
  averageEnvelopeCborBytes: number;
  averageMjksigContainerBytes: number;
  averageEmbeddedPayloadBytes: number;
  averageEmbeddedFileGrowthBytes: number;
};

type TimingTrendMeasurement = {
  signerCount: number;
  fixtureCount: number;
  averageOperationMeanMs: number;
};

type LegacyFixtureResult = {
  fixture: string;
  mimeType: string;
  fileBytes: number;
  legacyPayloadBytes: number | null;
  extractedSignatures: number;
  strippedBytes: number | null;
  payloadLooksLikeLegacyJson: boolean;
  passed: boolean;
  error?: string;
};

type Report = {
  title: string;
  startedAt: string;
  finishedAt: string;
  benchmarkElapsedMs: number;
  reportPersistenceMs?: number;
  approximateTotalRunMs?: number;
  iterations: number;
  warmupIterations: number;
  runtime: {
    node: string;
    platform: string;
    architecture: string;
    packageName: string;
    packageVersion: string;
  };
  keySetup: {
    helper: string;
    keyCount: number;
    generationMs: number;
    perKeyGenerationMs: number[];
    keyType: string;
    secretMaterialWrittenToReport: false;
  };
  fixtureDiscovery: {
    fixtureDirectory: string;
    included: string[];
    skipped: string[];
    signerCount: number;
  };
  timings: TimingResult[];
  sizes: SizeMeasurement[];
  sizeTrend: SizeTrendMeasurement[];
  timingTrend: TimingTrendMeasurement[];
  legacyCompatibility: LegacyFixtureResult[];
  checks: CheckResult[];
  summary: {
    fixtureCount: number;
    sizeSampleCount: number;
    maxSigners: number;
    legacyFixtureCount: number;
    checksPassed: number;
    checksFailed: number;
    averageEnvelopeJsonBytes: number;
    averageEnvelopeCborBytes: number;
    averageCborReductionVsJsonPercent: number;
    averageEnvelopeBase64Bytes: number;
    averageEmbeddedPayloadBytes: number;
    averageEmbeddedFileGrowthBytes: number;
    fastestMeasuredOperation: { name: string; meanMs: number } | null;
    slowestMeasuredOperation: { name: string; meanMs: number } | null;
    analysis: string[];
  };
};

const checks: CheckResult[] = [];
const timings: TimingResult[] = [];
const sizeResults: SizeMeasurement[] = [];
const legacyResults: LegacyFixtureResult[] = [];
const includedFixtureNames: string[] = [];
const skippedFixtureNames: string[] = [];
const startWallTime = new Date();
const startMonotonic = performance.now();

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`Expected a positive integer, received: ${value}`);
  }
  return parsed;
}

function bytesToBlob(bytes: Uint8Array, mimeType: string): Blob {
  // Buffer's backing store has an ArrayBuffer type accepted by the DOM Blob API.
  return new Blob([Buffer.from(bytes)], { type: mimeType });
}

function textByteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function toKiB(bytes: number): number {
  return Number((bytes / 1024).toFixed(3));
}

function percentReduction(referenceBytes: number, comparisonBytes: number): number {
  if (referenceBytes <= 0) return 0;
  return Number((((referenceBytes - comparisonBytes) / referenceBytes) * 100).toFixed(2));
}

function containerVersionMatchesVersion2(bytes: Uint8Array): boolean {
  // MJKSIG magic is six bytes; version is the next byte in the 12-byte header.
  return bytes.length >= MJKSIG_HEADER_LEN && bytes[6] === MJKSIG_CBOR_VERSION;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[middle - 1] + sorted[middle]) / 2
    : sorted[middle];
}

async function measure<T>(
  name: string,
  operation: () => T | Promise<T>,
  iterations = ITERATIONS,
): Promise<T> {
  for (let i = 0; i < WARMUP_ITERATIONS; i++) {
    await operation();
  }

  const samples: number[] = [];
  let lastValue!: T;

  for (let i = 0; i < iterations; i++) {
    const began = performance.now();
    lastValue = await operation();
    samples.push(performance.now() - began);
  }

  const totalMs = samples.reduce((sum, value) => sum + value, 0);
  const meanMs = totalMs / samples.length;
  timings.push({
    name,
    iterations,
    warmupIterations: WARMUP_ITERATIONS,
    totalMs: roundMs(totalMs),
    meanMs: roundMs(meanMs),
    medianMs: roundMs(median(samples)),
    minMs: roundMs(Math.min(...samples)),
    maxMs: roundMs(Math.max(...samples)),
    operationsPerSecond: meanMs > 0 ? roundMs(1000 / meanMs) : 0,
  });

  return lastValue;
}

function roundMs(value: number): number {
  return Number(value.toFixed(3));
}

function check(name: string, passed: boolean, details?: string): void {
  checks.push({ name, passed, ...(details ? { details } : {}) });
  const marker = passed ? "PASS" : "FAIL";
  console.log(`[${marker}] ${name}${details ? ` — ${details}` : ""}`);
}

function loadFixture(relativePath: string): Uint8Array {
  const absolutePath = join(FIXTURES_DIR, relativePath);
  return new Uint8Array(readFileSync(absolutePath));
}

function getPackageMetadata(): { name: string; version: string } {
  const packageJsonPath = join(PROJECT_ROOT, "package.json");
  try {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {
      name?: string;
      version?: string;
    };
    return {
      name: packageJson.name ?? "@majikah/majik-signature",
      version: packageJson.version ?? "unknown",
    };
  } catch {
    return { name: "@majikah/majik-signature", version: "unknown" };
  }
}

type TestKey = Awaited<ReturnType<typeof getTestKey>>;
type DetachedSignResult = Awaited<ReturnType<typeof MajikSignature.signFileDetached>>;
type EmbeddedSignResult = Awaited<ReturnType<typeof MajikSignature.signFile>>;
type SigningSnapshot = {
  signerCount: number;
  detached: DetachedSignResult;
  embedded: EmbeddedSignResult;
};

function timestampForSigner(index: number): string {
  return new Date(Date.parse(BENCHMARK_TIMESTAMP) + index * 1_000).toISOString();
}

async function benchmarkFixture(
  definition: (typeof FIXTURE_DEFINITIONS)[number],
  keys: TestKey[],
): Promise<void> {
  const fixturePath = join(FIXTURES_DIR, definition.file);
  if (!existsSync(fixturePath)) {
    skippedFixtureNames.push(`${definition.file} (not present)`);
    console.warn(`[SKIP] Fixture not found: ${fixturePath}`);
    return;
  }

  includedFixtureNames.push(definition.file);
  const fileReadStarted = performance.now();
  const originalBytes = loadFixture(definition.file);
  const sourceBlob = bytesToBlob(originalBytes, definition.mimeType);
  const fixtureReadMs = roundMs(performance.now() - fileReadStarted);
  check(
    `${definition.file}: fixture loaded`,
    originalBytes.byteLength > 0,
    `${originalBytes.byteLength} bytes; read + Blob preparation ${fixtureReadMs} ms`,
  );

  const states: SigningSnapshot[] = [];
  const firstOptions = {
    mimeType: definition.mimeType,
    timestamp: timestampForSigner(0),
  };

  const firstDetached = await measure(
    `${definition.file}: detached signing (signer 1/${keys.length})`,
    () => MajikSignature.signFileDetached(sourceBlob, keys[0], firstOptions),
  );
  const firstEmbedded = await measure(
    `${definition.file}: embedded signing (signer 1/${keys.length})`,
    () => MajikSignature.signFile(sourceBlob, keys[0], firstOptions),
  );
  states.push({ signerCount: 1, detached: firstDetached, embedded: firstEmbedded });

  // Each step starts from the immutable previous envelope/file and adds exactly
  // one new signer. The same prior input is reused for every measured iteration.
  for (let index = 1; index < keys.length; index++) {
    const signerCount = index + 1;
    const previous = states[index - 1];
    const options = {
      mimeType: definition.mimeType,
      timestamp: timestampForSigner(index),
    };

    const detached = await measure(
      `${definition.file}: detached multi-sig add signer ${signerCount}/${keys.length}`,
      () =>
        MajikSignature.signFileDetached(sourceBlob, keys[index], {
          ...options,
          existingEnvelope: previous.detached.envelope,
        }),
    );
    const embedded = await measure(
      `${definition.file}: embedded multi-sig add signer ${signerCount}/${keys.length}`,
      () => MajikSignature.signFile(previous.embedded.blob, keys[index], options),
    );
    states.push({ signerCount, detached, embedded });
  }

  // Snapshot and benchmark every envelope size from one signer through N
  // signers. This makes the growth curve come from real SDK output, not a
  // linear extrapolation from a single signature.
  for (const state of states) {
    const signerCount = state.signerCount;
    const { detached, embedded } = state;
    const signature = detached.signature;
    const envelope = detached.envelope;
    const signatureJson = JSON.stringify(signature.toJSON());
    const envelopeJson = JSON.stringify(envelope.toJSON());
    const signatureBase64 = signature.serialize();
    const envelopeBase64 = envelope.serialize();
    const signatureCbor = signature.toCBOR();
    const envelopeCbor = envelope.toCBOR();
    const mjksigContainer = envelope.toMJKSIGBytes();

    const signatureJsonBytes = textByteLength(signatureJson);
    const signatureBase64Bytes = textByteLength(signatureBase64);
    const signatureCborBytes = signatureCbor.byteLength;
    const envelopeJsonBytes = textByteLength(envelopeJson);
    const envelopeBase64Bytes = textByteLength(envelopeBase64);
    const envelopeCborBytes = envelopeCbor.byteLength;
    const mjksigBytes = mjksigContainer.byteLength;
    const mjksigHeaderOverhead = mjksigBytes - envelopeCborBytes;

    check(
      `${definition.file}: ${signerCount}-signer envelope contains expected signer count`,
      envelope.signatures.length === signerCount,
      `expected ${signerCount}; received ${envelope.signatures.length}`,
    );
    check(
      `${definition.file}: ${signerCount}-signer .mjksig v2 payload/framing matches direct CBOR`,
      mjksigHeaderOverhead === MJKSIG_HEADER_LEN &&
        containerVersionMatchesVersion2(mjksigContainer),
      `container ${mjksigBytes} bytes; CBOR payload ${envelopeCborBytes} bytes; framing ${mjksigHeaderOverhead} bytes`,
    );

    const embeddedBytes = new Uint8Array(await embedded.blob.arrayBuffer());
    const handler = new definition.Handler();
    const embeddedPayload = await handler.extract(embeddedBytes);
    assert.ok(
      embeddedPayload,
      `${definition.file}: handler could not extract the ${signerCount}-signer payload it just embedded`,
    );
    const embeddedPayloadBytes = textByteLength(embeddedPayload);
    const embeddedVersionedText = !embeddedPayload.trimStart().startsWith("{");

    check(
      `${definition.file}: ${signerCount}-signer embedded payload uses versioned representation`,
      embeddedVersionedText,
      `${embeddedPayloadBytes} UTF-8 bytes including codec prefix/wrapper`,
    );

    const extractedEmbeddedSignatures = await measure(
      `${definition.file}: extract embedded envelope (${signerCount} signers)`,
      () => MajikSignature.extractFrom(embedded.blob, { mimeType: definition.mimeType }),
    );
    check(
      `${definition.file}: ${signerCount}-signer embedded envelope extracts all signatures`,
      extractedEmbeddedSignatures.length === signerCount,
      `${extractedEmbeddedSignatures.length}/${signerCount} signature(s) extracted`,
    );

    const strippedEmbeddedBlob = await measure(
      `${definition.file}: strip embedded envelope (${signerCount} signers)`,
      () => MajikSignature.stripFrom(embedded.blob, { mimeType: definition.mimeType }),
    );
    const strippedEmbeddedBytes = new Uint8Array(await strippedEmbeddedBlob.arrayBuffer());
    check(
      `${definition.file}: ${signerCount}-signer embedding/stripping preserves original bytes`,
      Buffer.compare(Buffer.from(strippedEmbeddedBytes), Buffer.from(originalBytes)) === 0,
      `stripped ${strippedEmbeddedBytes.byteLength} bytes; original ${originalBytes.byteLength} bytes`,
    );

    const restoredSignatureFromJson = MajikSignature.fromJSON(
      JSON.parse(signatureJson) as ReturnType<MajikSignature["toJSON"]>,
    );
    const restoredSignatureFromBase64 = MajikSignature.deserialize(signatureBase64);
    const restoredSignatureFromCbor = MajikSignature.fromCBOR(signatureCbor);
    const restoredEnvelopeFromJson = MajikSignatureEnvelope.fromJSON(JSON.parse(envelopeJson));
    const restoredEnvelopeFromBase64 = MajikSignatureEnvelope.deserialize(envelopeBase64);
    const restoredEnvelopeFromCbor = MajikSignatureEnvelope.fromCBOR(envelopeCbor);
    const restoredEnvelopeFromMjksig = await MajikSignatureEnvelope.fromMJKSIG(mjksigContainer);
    const containerVersion = await MajikSignatureEnvelope.getMJKSIGVersion(mjksigContainer);

    check(
      `${definition.file}: ${signerCount}-signer signature JSON round trip`,
      isDeepStrictEqual(restoredSignatureFromJson.toJSON(), signature.toJSON()),
    );
    check(
      `${definition.file}: ${signerCount}-signer signature Base64 round trip`,
      isDeepStrictEqual(restoredSignatureFromBase64.toJSON(), signature.toJSON()),
    );
    check(
      `${definition.file}: ${signerCount}-signer signature CBOR round trip`,
      isDeepStrictEqual(restoredSignatureFromCbor.toJSON(), signature.toJSON()),
    );
    check(
      `${definition.file}: ${signerCount}-signer envelope JSON round trip`,
      isDeepStrictEqual(restoredEnvelopeFromJson.toJSON(), envelope.toJSON()),
    );
    check(
      `${definition.file}: ${signerCount}-signer envelope Base64 round trip`,
      isDeepStrictEqual(restoredEnvelopeFromBase64.toJSON(), envelope.toJSON()),
    );
    check(
      `${definition.file}: ${signerCount}-signer envelope CBOR round trip`,
      isDeepStrictEqual(restoredEnvelopeFromCbor.toJSON(), envelope.toJSON()),
    );
    check(
      `${definition.file}: ${signerCount}-signer .mjksig round trip and v2 header`,
      isDeepStrictEqual(restoredEnvelopeFromMjksig.toJSON(), envelope.toJSON()) &&
        containerVersion === MJKSIG_CBOR_VERSION,
      `reported container version: ${String(containerVersion)}`,
    );

    const cleanBytes = new Uint8Array(await detached.blob.arrayBuffer());
    check(
      `${definition.file}: ${signerCount}-signer detached file is canonical clean content`,
      Buffer.compare(Buffer.from(cleanBytes), Buffer.from(originalBytes)) === 0,
      `${cleanBytes.byteLength} bytes`,
    );

    const allSignerVerification = await measure(
      `${definition.file}: verify detached envelope (${signerCount} signers)`,
      async () => {
        const perSignerResults = [];
        for (const signerKey of keys.slice(0, signerCount)) {
          const signerPublicKeys = MajikSignature.publicKeysFromMajikKey(signerKey);
          const results = await MajikSignature.verifyFileDetached(
            detached.blob,
            envelope,
            signerPublicKeys,
            { expectedSignerId: signerPublicKeys.signerId, mimeType: definition.mimeType },
          );
          perSignerResults.push(...results);
        }
        return perSignerResults;
      },
    );
    check(
      `${definition.file}: all ${signerCount} detached signatures verify`,
      allSignerVerification.length === signerCount && allSignerVerification.every((result) => result.valid),
      `${allSignerVerification.filter((result) => result.valid).length}/${signerCount} signer result(s) valid`,
    );

    const allEmbeddedVerification = await measure(
      `${definition.file}: verify embedded file (${signerCount} signers)`,
      async () => {
        const perSignerResults = [];
        for (const signerKey of keys.slice(0, signerCount)) {
          const signerPublicKeys = MajikSignature.publicKeysFromMajikKey(signerKey);
          const results = await MajikSignature.verifyFile(
            embedded.blob,
            signerPublicKeys,
            { expectedSignerId: signerPublicKeys.signerId, mimeType: definition.mimeType },
          );
          perSignerResults.push(...results);
        }
        return perSignerResults;
      },
    );
    check(
      `${definition.file}: all ${signerCount} embedded signatures verify`,
      allEmbeddedVerification.length === signerCount && allEmbeddedVerification.every((result) => result.valid),
      `${allEmbeddedVerification.filter((result) => result.valid).length}/${signerCount} signer result(s) valid`,
    );

    await measure(
      `${definition.file}: signature JSON encode (${signerCount}-signer snapshot)`,
      () => JSON.stringify(signature.toJSON()),
    );
    await measure(
      `${definition.file}: signature Base64 encode (${signerCount}-signer snapshot)`,
      () => signature.serialize(),
    );
    await measure(
      `${definition.file}: signature CBOR encode (${signerCount}-signer snapshot)`,
      () => signature.toCBOR(),
    );
    await measure(
      `${definition.file}: signature JSON decode (${signerCount}-signer snapshot)`,
      () => MajikSignature.fromJSON(JSON.parse(signatureJson)),
    );
    await measure(
      `${definition.file}: signature Base64 decode (${signerCount}-signer snapshot)`,
      () => MajikSignature.deserialize(signatureBase64),
    );
    await measure(
      `${definition.file}: signature CBOR decode (${signerCount}-signer snapshot)`,
      () => MajikSignature.fromCBOR(signatureCbor),
    );
    await measure(
      `${definition.file}: envelope JSON encode (${signerCount} signers)`,
      () => JSON.stringify(envelope.toJSON()),
    );
    await measure(
      `${definition.file}: envelope Base64 encode (${signerCount} signers)`,
      () => envelope.serialize(),
    );
    await measure(
      `${definition.file}: envelope CBOR encode (${signerCount} signers)`,
      () => envelope.toCBOR(),
    );
    await measure(
      `${definition.file}: MJKSIG v2 container encode (${signerCount} signers)`,
      () => envelope.toMJKSIGBytes(),
    );
    await measure(
      `${definition.file}: envelope JSON decode (${signerCount} signers)`,
      () => MajikSignatureEnvelope.fromJSON(JSON.parse(envelopeJson)),
    );
    await measure(
      `${definition.file}: envelope Base64 decode (${signerCount} signers)`,
      () => MajikSignatureEnvelope.deserialize(envelopeBase64),
    );
    await measure(
      `${definition.file}: envelope CBOR decode (${signerCount} signers)`,
      () => MajikSignatureEnvelope.fromCBOR(envelopeCbor),
    );
    await measure(
      `${definition.file}: MJKSIG v2 container decode (${signerCount} signers)`,
      () => MajikSignatureEnvelope.fromMJKSIG(mjksigContainer),
    );

    const publicKeysForLastSigner = MajikSignature.publicKeysFromMajikKey(keys[signerCount - 1]);
    const rawVerification = await measure(
      `${definition.file}: raw signature verification (signer ${signerCount})`,
      () => MajikSignature.verify(cleanBytes, restoredSignatureFromCbor, publicKeysForLastSigner),
    );
    check(
      `${definition.file}: CBOR-restored signature verifies (signer ${signerCount})`,
      rawVerification.valid,
      rawVerification.reason,
    );

    const embeddedFileGrowthBytes = embeddedBytes.byteLength - originalBytes.byteLength;
    sizeResults.push({
      fixture: definition.file,
      mimeType: definition.mimeType,
      signerCount,
      originalFileBytes: originalBytes.byteLength,
      detachedCleanFileBytes: cleanBytes.byteLength,
      embeddedFileBytes: embeddedBytes.byteLength,
      embeddedFileGrowthBytes,
      signatureJsonBytes,
      signatureBase64SerializedBytes: signatureBase64Bytes,
      signatureCborBytes,
      envelopeJsonBytes,
      envelopeBase64SerializedBytes: envelopeBase64Bytes,
      envelopeCborBytes,
      mjksigContainerBytes: mjksigBytes,
      mjksigHeaderOverheadBytes: mjksigHeaderOverhead,
      embeddedPayloadUtf8Bytes: embeddedPayloadBytes,
      embeddedPayloadCharacters: embeddedPayload.length,
      embeddedPayloadLooksLikeVersionedText: embeddedVersionedText,
      cborReductionVsEnvelopeJsonPercent: percentReduction(envelopeJsonBytes, envelopeCborBytes),
      cborReductionVsEnvelopeBase64Percent: percentReduction(envelopeBase64Bytes, envelopeCborBytes),
      embeddedPayloadReductionVsEnvelopeBase64Percent: percentReduction(envelopeBase64Bytes, embeddedPayloadBytes),
    });

    console.log(
      `[SIZE] ${definition.file} (${signerCount} signer${signerCount === 1 ? "" : "s"}): JSON ${envelopeJsonBytes} B | Base64 ${envelopeBase64Bytes} B | CBOR ${envelopeCborBytes} B | .mjksig ${mjksigBytes} B | embedded payload ${embeddedPayloadBytes} B | full-file growth ${embeddedFileGrowthBytes} B`,
    );
  }
}

async function benchmarkLegacyCompatibility(
  definition: (typeof LEGACY_FIXTURE_DEFINITIONS)[number],
): Promise<void> {
  const fixturePath = join(FIXTURES_DIR, definition.file);
  if (!existsSync(fixturePath)) {
    skippedFixtureNames.push(`${definition.file} (optional legacy fixture not present)`);
    console.log(`[SKIP] Optional legacy fixture not found: ${fixturePath}`);
    return;
  }

  const rawBytes = loadFixture(definition.file);
  const blob = bytesToBlob(rawBytes, definition.mimeType);
  const handler = new definition.Handler();
  const rawPayload = await handler.extract(rawBytes);
  let extractedSignatures = 0;
  let strippedBytes: number | null = null;
  let error: string | undefined;

  try {
    const signatures = await measure(
      `${definition.file}: legacy embedded signature extraction`,
      () => MajikSignature.extractFrom(blob, { mimeType: definition.mimeType }),
    );
    extractedSignatures = signatures.length;
    const strippedBlob = await measure(
      `${definition.file}: legacy embedded signature stripping`,
      () => MajikSignature.stripFrom(blob, { mimeType: definition.mimeType }),
    );
    strippedBytes = strippedBlob.size;
    const payloadLooksLikeLegacyJson = !!rawPayload && rawPayload.trimStart().startsWith("{");

    const passed = extractedSignatures > 0 && payloadLooksLikeLegacyJson && strippedBytes < rawBytes.byteLength;
    check(
      `${definition.file}: legacy JSON embedded envelope remains readable`,
      passed,
      `${extractedSignatures} signature(s); payload ${rawPayload ? textByteLength(rawPayload) : 0} bytes; stripped file ${strippedBytes}/${rawBytes.byteLength} bytes`,
    );
    legacyResults.push({
      fixture: definition.file,
      mimeType: definition.mimeType,
      fileBytes: rawBytes.byteLength,
      legacyPayloadBytes: rawPayload ? textByteLength(rawPayload) : null,
      extractedSignatures,
      strippedBytes,
      payloadLooksLikeLegacyJson,
      passed,
    });
  } catch (caught) {
    error = caught instanceof Error ? caught.message : String(caught);
    check(`${definition.file}: legacy compatibility`, false, error);
    legacyResults.push({
      fixture: definition.file,
      mimeType: definition.mimeType,
      fileBytes: rawBytes.byteLength,
      legacyPayloadBytes: rawPayload ? textByteLength(rawPayload) : null,
      extractedSignatures,
      strippedBytes,
      payloadLooksLikeLegacyJson: !!rawPayload && rawPayload.trimStart().startsWith("{"),
      passed: false,
      error,
    });
  }
}

function average(values: number[]): number {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}

function buildSizeTrend(): SizeTrendMeasurement[] {
  const rows: SizeTrendMeasurement[] = [];
  for (let signerCount = 1; signerCount <= MAX_SIGNERS; signerCount++) {
    const samples = sizeResults.filter((item) => item.signerCount === signerCount);
    if (samples.length === 0) continue;
    rows.push({
      signerCount,
      fixtureCount: samples.length,
      averageEnvelopeJsonBytes: Math.round(average(samples.map((item) => item.envelopeJsonBytes))),
      averageEnvelopeBase64SerializedBytes: Math.round(average(samples.map((item) => item.envelopeBase64SerializedBytes))),
      averageEnvelopeCborBytes: Math.round(average(samples.map((item) => item.envelopeCborBytes))),
      averageMjksigContainerBytes: Math.round(average(samples.map((item) => item.mjksigContainerBytes))),
      averageEmbeddedPayloadBytes: Math.round(average(samples.map((item) => item.embeddedPayloadUtf8Bytes))),
      averageEmbeddedFileGrowthBytes: Math.round(average(samples.map((item) => item.embeddedFileGrowthBytes))),
    });
  }
  return rows;
}

function buildTimingTrend(): TimingTrendMeasurement[] {
  const rows: TimingTrendMeasurement[] = [];
  for (let signerCount = 1; signerCount <= MAX_SIGNERS; signerCount++) {
    const suffix = signerCount === 1
      ? `detached signing (signer 1/${MAX_SIGNERS})`
      : `detached multi-sig add signer ${signerCount}/${MAX_SIGNERS}`;
    const samples = timings.filter((item) => item.name.endsWith(suffix));
    if (samples.length === 0) continue;
    rows.push({
      signerCount,
      fixtureCount: samples.length,
      averageOperationMeanMs: roundMs(average(samples.map((item) => item.meanMs))),
    });
  }
  return rows;
}

function buildAnalysis(): string[] {
  if (sizeResults.length === 0) {
    return ["No supported sample fixtures were found, so serialization size analysis could not be calculated."];
  }

  const avgJson = average(sizeResults.map((result) => result.envelopeJsonBytes));
  const avgCbor = average(sizeResults.map((result) => result.envelopeCborBytes));
  const avgBase64 = average(sizeResults.map((result) => result.envelopeBase64SerializedBytes));
  const avgEmbedded = average(sizeResults.map((result) => result.embeddedPayloadUtf8Bytes));
  const avgCborReduction = percentReduction(avgJson, avgCbor);
  const avgEmbedDiff = percentReduction(avgBase64, avgEmbedded);
  const avgFileGrowth = average(sizeResults.map((result) => result.embeddedFileGrowthBytes));
  const trend = buildSizeTrend();
  const oneSigner = trend.find((row) => row.signerCount === 1);
  const maxSigner = trend.find((row) => row.signerCount === MAX_SIGNERS);
  const countGrowth = (first: number | undefined, last: number | undefined) => {
    if (first === undefined || last === undefined) return "not available";
    const delta = last - first;
    const pct = first > 0 ? (delta / first) * 100 : 0;
    return `${delta >= 0 ? "+" : ""}${Math.round(delta)} bytes (${delta >= 0 ? "+" : ""}${pct.toFixed(2)}%)`;
  };

  const analysis = [
    `Across ${sizeResults.length} measured fixture-by-signer-count sample(s) spanning ${new Set(sizeResults.map((item) => item.fixture)).size} actual fixture(s), the average envelope representation is ${Math.round(avgJson)} bytes as minified JSON, ${Math.round(avgCbor)} bytes as raw CBOR, and ${Math.round(avgBase64)} bytes using the existing Base64 serializer. Across these samples, raw CBOR is ${avgCborReduction >= 0 ? `${avgCborReduction}% smaller` : `${Math.abs(avgCborReduction)}% larger`} than minified JSON on average.`,
    `From 1 signer to ${MAX_SIGNERS} signer(s), average minified JSON size changes by ${countGrowth(oneSigner?.averageEnvelopeJsonBytes, maxSigner?.averageEnvelopeJsonBytes)}; raw CBOR changes by ${countGrowth(oneSigner?.averageEnvelopeCborBytes, maxSigner?.averageEnvelopeCborBytes)}; existing Base64 serialization changes by ${countGrowth(oneSigner?.averageEnvelopeBase64SerializedBytes, maxSigner?.averageEnvelopeBase64SerializedBytes)}. The trend is measured from actual SDK envelopes at every signer count, not linearly extrapolated.`,
    `The embedded payload, including its version marker and Base64 wrapper, averages ${Math.round(avgEmbedded)} bytes across all measured samples. Compared with the existing Base64 envelope serialization, it is ${avgEmbedDiff >= 0 ? `${avgEmbedDiff}% smaller` : `${Math.abs(avgEmbedDiff)}% larger`} on average; this is a representation comparison, not a claim that the embedded payload is raw CBOR.`,
    `The complete embedded file grows by an average of ${Math.round(avgFileGrowth)} bytes. This includes the handler's metadata/trailer overhead and can differ from the payload size.`,
    "Raw CBOR is the best fit when a consumer accepts binary data directly. The versioned .mjksig container adds a small header for identification and version dispatch; embedded payloads add their text prefix and Base64 overhead because the existing format handlers accept string payloads.",
    "JSON remains useful for inspection and JSON-native integrations. The existing Base64 serializer is appropriate for text-only transport. Use .mjksig when a detached envelope needs to be self-identifying and versioned.",
  ];
  return analysis;
}

function summarize(): Report["summary"] {
  const failed = checks.filter((item) => !item.passed).length;
  const passed = checks.length - failed;
  const byMean = [...timings].sort((a, b) => a.meanMs - b.meanMs);
  return {
    fixtureCount: new Set(sizeResults.map((item) => item.fixture)).size,
    sizeSampleCount: sizeResults.length,
    maxSigners: MAX_SIGNERS,
    legacyFixtureCount: legacyResults.length,
    checksPassed: passed,
    checksFailed: failed,
    averageEnvelopeJsonBytes: Math.round(average(sizeResults.map((r) => r.envelopeJsonBytes))),
    averageEnvelopeCborBytes: Math.round(average(sizeResults.map((r) => r.envelopeCborBytes))),
    averageCborReductionVsJsonPercent: percentReduction(
      average(sizeResults.map((r) => r.envelopeJsonBytes)),
      average(sizeResults.map((r) => r.envelopeCborBytes)),
    ),
    averageEnvelopeBase64Bytes: Math.round(average(sizeResults.map((r) => r.envelopeBase64SerializedBytes))),
    averageEmbeddedPayloadBytes: Math.round(average(sizeResults.map((r) => r.embeddedPayloadUtf8Bytes))),
    averageEmbeddedFileGrowthBytes: Math.round(average(sizeResults.map((r) => r.embeddedFileGrowthBytes))),
    fastestMeasuredOperation: byMean.length ? { name: byMean[0].name, meanMs: byMean[0].meanMs } : null,
    slowestMeasuredOperation: byMean.length ? { name: byMean[byMean.length - 1].name, meanMs: byMean[byMean.length - 1].meanMs } : null,
    analysis: buildAnalysis(),
  };
}

function chartAxisMax(values: number[]): number {
  const rawMax = Math.max(1, ...values);
  if (rawMax < 100) return Number((Math.ceil(rawMax * 1.2 * 10) / 10).toFixed(1));
  return Math.ceil((rawMax * 1.15) / 1000) * 1000;
}

function buildMermaidSizeBarChart(report: Report): string[] {
  const trend = report.sizeTrend;
  if (trend.length === 0) return ["No size trend data available for charts."];
  const labels = `[${trend.map((row) => row.signerCount).join(", ")}]`;
  const json = `[${trend.map((row) => row.averageEnvelopeJsonBytes).join(", ")}]`;
  const cbor = `[${trend.map((row) => row.averageEnvelopeCborBytes).join(", ")}]`;
  const base64 = `[${trend.map((row) => row.averageEnvelopeBase64SerializedBytes).join(", ")}]`;
  const max = chartAxisMax(trend.flatMap((row) => [
    row.averageEnvelopeJsonBytes,
    row.averageEnvelopeCborBytes,
    row.averageEnvelopeBase64SerializedBytes,
  ]));
  return [
    "```mermaid",
    "xychart-beta",
    "    title \"Average Envelope Payload Size by Signer Count\"",
    `    x-axis \"Signer count\" ${labels}`,
    `    y-axis \"Payload bytes\" 0 --> ${max}`,
    `    bar \"Minified JSON\" ${json}`,
    `    bar \"Raw CBOR\" ${cbor}`,
    `    bar \"Base64 serialized\" ${base64}`,
    "```",
  ];
}

function buildMermaidTimingLineChart(report: Report): string[] {
  const trend = report.timingTrend;
  if (trend.length === 0) return ["No timing trend data available for charts."];
  const labels = `[${trend.map((row) => row.signerCount).join(", ")}]`;
  const values = `[${trend.map((row) => row.averageOperationMeanMs).join(", ")}]`;
  const max = chartAxisMax(trend.map((row) => row.averageOperationMeanMs));
  return [
    "```mermaid",
    "xychart-beta",
    "    title \"Mean Time to Sign or Add One Signer\"",
    `    x-axis \"Resulting signer count\" ${labels}`,
    `    y-axis \"Mean operation time (ms)\" 0 --> ${max}`,
    `    line \"Mean detached signing operation\" ${values}`,
    "```",
  ];
}

function buildMarkdown(report: Report): string {
  const formatBytes = (bytes: number) => `${bytes.toLocaleString("en-US")} B (${toKiB(bytes)} KiB)`;
  const lines: string[] = [
    "# Majik Signature Serialization Benchmark",
    "",
    `- **Started:** ${report.startedAt}`,
    `- **Finished (benchmark operations):** ${report.finishedAt}`,
    `- **Elapsed benchmark time:** ${report.benchmarkElapsedMs.toLocaleString("en-US")} ms`,
    ...(report.reportPersistenceMs !== undefined ? [`- **Report persistence time (initial write):** ${report.reportPersistenceMs.toLocaleString("en-US")} ms`] : []),
    ...(report.approximateTotalRunMs !== undefined ? [`- **Approximate end-to-end total:** ${report.approximateTotalRunMs.toLocaleString("en-US")} ms`] : []),
    `- **Iterations per timing:** ${report.iterations} (plus ${report.warmupIterations} warm-up iteration per operation)`,
    `- **Runtime:** Node ${report.runtime.node} / ${report.runtime.platform} ${report.runtime.architecture}`,
    `- **Package:** ${report.runtime.packageName}@${report.runtime.packageVersion}`,
    `- **Test keys:** ${report.keySetup.keyCount} fresh keys generated using \`${report.keySetup.helper}\`; key secrets are not included in this report`,
    `- **Signer-count increments:** 1 through ${report.summary.maxSigners}`,
    "",
    "## Summary",
    "",
    `- Fixtures benchmarked: **${report.summary.fixtureCount}**`,
    `- Fixture × signer-count size samples: **${report.summary.sizeSampleCount}**`,
    `- Legacy fixtures checked: **${report.summary.legacyFixtureCount}**`,
    `- Checks passed: **${report.summary.checksPassed}**`,
    `- Checks failed: **${report.summary.checksFailed}**`,
    `- Average envelope JSON size across all fixture/count samples: **${formatBytes(report.summary.averageEnvelopeJsonBytes)}**`,
    `- Average envelope raw CBOR size across all fixture/count samples: **${formatBytes(report.summary.averageEnvelopeCborBytes)}**`,
    `- Average CBOR reduction vs JSON: **${report.summary.averageCborReductionVsJsonPercent}%**`,
    `- Average existing Base64 serialization size: **${formatBytes(report.summary.averageEnvelopeBase64Bytes)}**`,
    `- Average embedded payload size, including prefix/wrapper: **${formatBytes(report.summary.averageEmbeddedPayloadBytes)}**`,
    `- Average complete embedded-file growth: **${formatBytes(report.summary.averageEmbeddedFileGrowthBytes)}**`,
    "",
    "## Multi-signature serialization charts",
    "",
    "The bar chart compares measured envelope sizes at each signer count, averaged across fixtures. The line chart shows the mean time taken to sign the initial envelope or add the next signer; it is an operation time, not cumulative workflow time.",
    "",
    "### Payload size by signer count",
    "",
    ...buildMermaidSizeBarChart(report),
    "",
    "### Detached signing operation time by signer count",
    "",
    ...buildMermaidTimingLineChart(report),
    "",
    "### Average sizes at each increment",
    "",
    "| Signers | Fixtures averaged | JSON | Base64 serialized | Raw CBOR | `.mjksig` v2 | Embedded payload | Complete file growth |",
    "|---:|---:|---:|---:|---:|---:|---:|---:|",
  ];

  for (const item of report.sizeTrend) {
    lines.push(`| ${item.signerCount} | ${item.fixtureCount} | ${item.averageEnvelopeJsonBytes} B | ${item.averageEnvelopeBase64SerializedBytes} B | ${item.averageEnvelopeCborBytes} B | ${item.averageMjksigContainerBytes} B | ${item.averageEmbeddedPayloadBytes} B | ${item.averageEmbeddedFileGrowthBytes} B |`);
  }

  lines.push(
    "",
    "### Mean detached signing time by signer count",
    "",
    "| Resulting signers | Fixture samples | Mean time to sign/add signer |",
    "|---:|---:|---:|",
  );
  for (const item of report.timingTrend) {
    lines.push(`| ${item.signerCount} | ${item.fixtureCount} | ${item.averageOperationMeanMs} ms |`);
  }

  lines.push(
    "",
    "## Payload sizes by fixture and signer count",
    "",
    "| Fixture | Signers | Original file | Envelope JSON | Base64 serialized | Raw CBOR | `.mjksig` v2 | Embedded payload | Full-file growth |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
  );
  for (const item of report.sizes) {
    lines.push(`| ${item.fixture} | ${item.signerCount} | ${item.originalFileBytes} B | ${item.envelopeJsonBytes} B | ${item.envelopeBase64SerializedBytes} B | ${item.envelopeCborBytes} B | ${item.mjksigContainerBytes} B | ${item.embeddedPayloadUtf8Bytes} B | ${item.embeddedFileGrowthBytes} B |`);
  }

  lines.push(
    "",
    "### Last-signature object sizes",
    "",
    "Signature-object sizes describe the individual signer entry added at that step; envelope columns show cumulative multi-signature growth.",
    "",
    "| Fixture | Signers in envelope | Signature JSON | Signature Base64 serialized | Signature CBOR |",
    "|---|---:|---:|---:|---:|",
  );
  for (const item of report.sizes) {
    lines.push(`| ${item.fixture} | ${item.signerCount} | ${item.signatureJsonBytes} B | ${item.signatureBase64SerializedBytes} B | ${item.signatureCborBytes} B |`);
  }

  lines.push("", "## Legacy embedded-file compatibility", "");
  if (report.legacyCompatibility.length === 0) {
    lines.push("No optional legacy compatibility fixtures were present in this checkout.");
  } else {
    lines.push(
      "| Fixture | File bytes | Legacy payload bytes | Extracted signatures | Stripped bytes | Result |",
      "|---|---:|---:|---:|---:|---|",
    );
    for (const item of report.legacyCompatibility) {
      lines.push(`| ${item.fixture} | ${item.fileBytes} B | ${item.legacyPayloadBytes ?? "n/a"} | ${item.extractedSignatures} | ${item.strippedBytes ?? "n/a"} | ${item.passed ? "PASS" : "FAIL"} |`);
    }
  }

  lines.push("", "## Timing results", "", "| Operation | Iterations | Mean ms | Median ms | Min ms | Max ms | Ops/sec |", "|---|---:|---:|---:|---:|---:|---:|");
  for (const item of report.timings) {
    lines.push(`| ${item.name.replaceAll("|", "\\|")} | ${item.iterations} | ${item.meanMs} | ${item.medianMs} | ${item.minMs} | ${item.maxMs} | ${item.operationsPerSecond} |`);
  }

  lines.push("", "## Checks", "", "| Status | Check | Details |", "|---|---|---|");
  for (const item of report.checks) {
    lines.push(`| ${item.passed ? "PASS" : "FAIL"} | ${item.name.replaceAll("|", "\\|")} | ${(item.details ?? "").replaceAll("|", "\\|").replaceAll("\n", " ")} |`);
  }

  lines.push("", "## Analysis", "");
  for (const item of report.summary.analysis) lines.push(`- ${item}`);

  lines.push(
    "",
    "## Interpretation notes",
    "",
    "- All byte counts are measured from the current SDK checkout; they are not estimates copied from the README.",
    "- Each signer-count increment uses one additional freshly generated `MajikKey`; keys are created with the existing `getTestKey()` helper.",
    "- `JSON` measures UTF-8 bytes of minified `JSON.stringify(envelope.toJSON())`.",
    "- `Base64 serialized` measures the actual string returned by `envelope.serialize()`.",
    "- `Raw CBOR` measures `envelope.toCBOR()` bytes with no `.mjksig` container header.",
    "- `.mjksig v2` measures `envelope.toMJKSIGBytes()`, including its actual header/framing.",
    "- `Embedded payload` measures the exact UTF-8 string extracted by the selected file handler, including the version prefix and Base64 wrapper.",
    "- `Full-file growth` is the final embedded Blob length minus the original fixture length; it includes native metadata/trailer overhead and can differ from the embedded-payload length.",
    "- Timing for signer count N measures the first detached signature (N=1) or the operation that adds signer N to an envelope with N-1 existing signers. The chart reports means averaged across fixtures.",
    "- Timings include one warm-up call per operation before measured iterations. Aggregate key generation/setup time is reported separately.",
    "- Benchmark times are environment-dependent. Use the same runtime, machine, iteration count, signer count, and fixture set when comparing commits.",
    "",
  );
  return lines.join("\n");
}

function buildTimingCsv(report: Report): string {
  const header = [
    "operation", "iterations", "warmupIterations", "totalMs", "meanMs", "medianMs",
    "minMs", "maxMs", "operationsPerSecond",
  ];
  const rows = report.timings.map((entry) => header.map((key) => csvCell((entry as unknown as Record<string, unknown>)[key])).join(","));
  return [header.join(","), ...rows].join("\n") + "\n";
}

function buildCsv(report: Report): string {
  const header = [
    "fixture", "mimeType", "originalFileBytes", "detachedCleanFileBytes", "embeddedFileBytes",
    "embeddedFileGrowthBytes", "signerCount", "signatureJsonBytes", "signatureBase64SerializedBytes",
    "signatureCborBytes", "envelopeJsonBytes", "envelopeBase64SerializedBytes", "envelopeCborBytes",
    "mjksigContainerBytes", "mjksigHeaderOverheadBytes", "embeddedPayloadUtf8Bytes", "embeddedPayloadCharacters",
    "cborReductionVsEnvelopeJsonPercent", "cborReductionVsEnvelopeBase64Percent",
    "embeddedPayloadReductionVsEnvelopeBase64Percent",
  ];
  const rows = report.sizes.map((entry) => header.map((key) => csvCell((entry as unknown as Record<string, unknown>)[key])).join(","));
  return [header.join(","), ...rows].join("\n") + "\n";
}

function csvCell(value: unknown): string {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

async function main(): Promise<void> {
  console.log("\nMajik Signature serialization benchmark");
  console.log(`Iterations: ${ITERATIONS}; warm-ups per operation: ${WARMUP_ITERATIONS}`);
  console.log(`Signer-count increments: 1..${MAX_SIGNERS}`);
  console.log(`Fixtures: ${FIXTURES_DIR}`);
  console.log(`Reports: ${REPORT_DIR}\n`);

  const keyStart = performance.now();
  const keys: TestKey[] = [];
  const perKeyGenerationMs: number[] = [];
  let keyGenerationMs = 0;

  try {
    for (let index = 0; index < MAX_SIGNERS; index++) {
      const singleKeyStart = performance.now();
      keys.push(await getTestKey());
      perKeyGenerationMs.push(roundMs(performance.now() - singleKeyStart));
      console.log(`[KEY] Generated test key ${index + 1}/${MAX_SIGNERS} in ${perKeyGenerationMs[index]} ms`);
    }
    keyGenerationMs = roundMs(performance.now() - keyStart);
    console.log(`[KEY] Generated ${keys.length} unlocked test keys in ${keyGenerationMs} ms total`);

    for (const definition of FIXTURE_DEFINITIONS) {
      try {
        await benchmarkFixture(definition, keys);
      } catch (caught) {
        const message = caught instanceof Error ? caught.stack ?? caught.message : String(caught);
        check(`${definition.file}: benchmark completed without uncaught error`, false, message);
        console.error(`[ERROR] ${definition.file}:`, message);
      }
    }
    for (const definition of LEGACY_FIXTURE_DEFINITIONS) {
      try {
        await benchmarkLegacyCompatibility(definition);
      } catch (caught) {
        const message = caught instanceof Error ? caught.stack ?? caught.message : String(caught);
        check(`${definition.file}: legacy compatibility completed without uncaught error`, false, message);
        console.error(`[ERROR] ${definition.file}:`, message);
      }
    }
  } finally {
    // Do not retain test secret material after benchmarking, including if key
    // creation or an individual fixture fails partway through the run.
    for (const key of keys) {
      try {
        key.lock();
      } catch {
        // Some test key versions may already be locked; that does not invalidate results.
      }
    }
  }

  const finishedAt = new Date();
  const benchmarkElapsedMs = roundMs(performance.now() - startMonotonic);
  const packageMetadata = getPackageMetadata();
  const summary = summarize();
  const sizeTrend = buildSizeTrend();
  const timingTrend = buildTimingTrend();
  const report: Report = {
    title: "Majik Signature Serialization Benchmark",
    startedAt: startWallTime.toISOString(),
    finishedAt: finishedAt.toISOString(),
    benchmarkElapsedMs,
    iterations: ITERATIONS,
    warmupIterations: WARMUP_ITERATIONS,
    runtime: {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      packageName: packageMetadata.name,
      packageVersion: packageMetadata.version,
    },
    keySetup: {
      helper: "test/helpers/crypto.ts:getTestKey()",
      keyCount: keys.length,
      generationMs: keyGenerationMs,
      perKeyGenerationMs,
      keyType: "fresh generated MajikKey instances used only for this benchmark run",
      secretMaterialWrittenToReport: false,
    },
    fixtureDiscovery: {
      fixtureDirectory: FIXTURES_DIR,
      included: includedFixtureNames,
      skipped: skippedFixtureNames,
      signerCount: MAX_SIGNERS,
    },
    timings,
    sizes: sizeResults,
    sizeTrend,
    timingTrend,
    legacyCompatibility: legacyResults,
    checks,
    summary,
  };

  mkdirSync(REPORT_DIR, { recursive: true });
  const stamp = startWallTime.toISOString().replace(/[:.]/g, "-");
  const baseName = `serialization-${stamp}`;
  const jsonPath = join(REPORT_DIR, `${baseName}.json`);
  const markdownPath = join(REPORT_DIR, `${baseName}.md`);
  const csvPath = join(REPORT_DIR, `${baseName}-sizes.csv`);
  const timingCsvPath = join(REPORT_DIR, `${baseName}-timings.csv`);

  // Persist once, measure persistence, then refresh JSON/Markdown with the
  // first measured write cost. The benchmark timing itself is frozen above.
  const persistStart = performance.now();
  writeFileSync(jsonPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  writeFileSync(markdownPath, buildMarkdown(report), "utf8");
  writeFileSync(csvPath, buildCsv(report), "utf8");
  writeFileSync(timingCsvPath, buildTimingCsv(report), "utf8");
  report.reportPersistenceMs = roundMs(performance.now() - persistStart);
  report.approximateTotalRunMs = roundMs(report.benchmarkElapsedMs + report.reportPersistenceMs);
  writeFileSync(jsonPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  writeFileSync(markdownPath, buildMarkdown(report), "utf8");

  console.log("\n=== Serialization Benchmark Summary ===");
  console.log(`Real fixtures benchmarked: ${summary.fixtureCount}`);
  console.log(`Size samples (fixture × signer-count): ${summary.sizeSampleCount}`);
  console.log(`Signer counts benchmarked: 1..${summary.maxSigners}`);
  console.log(`Legacy fixtures checked: ${summary.legacyFixtureCount}`);
  console.log(`Checks: ${summary.checksPassed} passed, ${summary.checksFailed} failed`);
  console.log(`Average envelope JSON: ${summary.averageEnvelopeJsonBytes} bytes`);
  console.log(`Average raw envelope CBOR: ${summary.averageEnvelopeCborBytes} bytes`);
  console.log(`Average CBOR reduction vs JSON: ${summary.averageCborReductionVsJsonPercent}%`);
  console.log(`Benchmark elapsed: ${report.benchmarkElapsedMs} ms`);
  console.log(`Report persistence (first write): ${report.reportPersistenceMs} ms`);
  console.log(`Approximate run total: ${report.approximateTotalRunMs} ms`);
  console.log(`\nJSON report: ${jsonPath}`);
  console.log(`Markdown report: ${markdownPath}`);
  console.log(`CSV size report: ${csvPath}`);
  console.log(`CSV timing report: ${timingCsvPath}`);

  if (summary.checksFailed > 0) {
    process.exitCode = 1;
    console.error("\nBenchmark completed with failed checks. Review the generated report.");
  }
  if (summary.fixtureCount === 0) {
    process.exitCode = 1;
    console.error("\nNo sample fixtures were available. Ensure test/fixtures/sample.pdf, sample.jpg, and/or sample.wav exist.");
  }
}

void main().catch((error: unknown) => {
  console.error("Serialization benchmark failed before report generation:", error);
  process.exitCode = 1;
});

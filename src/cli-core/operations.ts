/**
 * src/cli/operations.ts
 *
 * High-level filesystem operations for the Majik Signature CLI.
 *
 * This file intentionally does NOT reproduce the desktop application's
 * CliRequest / IPC architecture.
 *
 * CLI
 *   ↓
 * typed options
 *   ↓
 * existing MajikSignature SDK
 *   ↓
 * filesystem
 */

import {
  basename,
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";

import { zipSync } from "fflate";

import { MajikKey } from "@majikah/majik-key";

import { MajikSignature } from "../majik-signature";

import { MajikSignatureEnvelope } from "../core/envelope";

import { MajikSignatureMap } from "../core/mjksmap";

import type {
  BatchFileInput,
  ExpectedSigner,
  MajikTimestamp,
  VerificationResult,
} from "../core/types";

import {
  getPathKind,
  mimeTypeForPath,
  outputPathForDetachedFile,
  outputPathForMap,
  outputPathForMapBundle,
  readBlob,
  readFolderFiles,
  readJsonFile,
  resolveCliPath,
  summarizeFiles,
  writeBlob,
  writeBytes,
} from "./io.js";

import { loadMajikKey, loadSigningKey, lockKey } from "./key.js";

import type {
  CanSignCliOptions,
  CliResult,
  FolderFile,
  InspectCliOptions,
  SealCliOptions,
  SignCliOptions,
  VerifyCliOptions,
} from "./types.js";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function result(
  command: string,
  data: Record<string, unknown>,
  ok = true,
  message = "Operation completed.",
): CliResult {
  return {
    ok,
    command,
    message,
    ...data,
  };
}

function sha256FromSignature(
  signatures: Array<{
    contentHash?: string;
  }>,
): string | undefined {
  return signatures[0]?.contentHash;
}

/**
 * Convert a MajikSignature public-key set into an ExpectedSigner.
 *
 * ExpectedSigner is serialized using base64 public keys.
 */
function expectedSignerFromSignature(signature: {
  extractPublicKeys(): {
    signerId: string;
    edPublicKey: Uint8Array;
    mlDsaPublicKey: Uint8Array;
  };
}): ExpectedSigner {
  const publicKeys = signature.extractPublicKeys();

  return {
    signerId: publicKeys.signerId,
    edPublicKey: Buffer.from(publicKeys.edPublicKey).toString("base64"),
    mlDsaPublicKey: Buffer.from(publicKeys.mlDsaPublicKey).toString("base64"),
  };
}

function dedupeExpectedSigners(signers: ExpectedSigner[]): ExpectedSigner[] {
  const bySigner = new Map<string, ExpectedSigner>();

  for (const signer of signers) {
    bySigner.set(signer.signerId, signer);
  }

  return [...bySigner.values()];
}

/**
 * Load the primary signing key plus any --allow-key files.
 *
 * The current signing key is automatically included in the allowlist.
 */
async function buildExpectedSigners(
  signingKey: MajikKey,
  additionalKeyPaths: string[],
): Promise<ExpectedSigner[]> {
  const signers: ExpectedSigner[] = [
    MajikSignature.expectedSignerFromKey(signingKey),
  ];

  for (const path of additionalKeyPaths) {
    const key = await loadMajikKey(path);

    if (!key.hasSigningKeys) {
      throw new Error(
        `Allowlist key "${path}" does not contain signing public keys.`,
      );
    }

    signers.push(MajikSignature.expectedSignerFromKey(key));
  }

  return dedupeExpectedSigners(signers);
}

async function loadTsaToken(
  tsaTokenPath?: string,
): Promise<MajikTimestamp | undefined> {
  if (!tsaTokenPath) {
    return undefined;
  }

  const token = await readJsonFile<MajikTimestamp>(
    resolveCliPath(tsaTokenPath),
  );

  if (token === null || typeof token !== "object") {
    throw new Error(`TSA token "${tsaTokenPath}" must contain a JSON object.`);
  }

  return token;
}

function assertFolder(
  kind: "file" | "directory",
  expected: "file" | "directory",
): void {
  if (kind !== expected) {
    throw new Error(
      `This operation requires a ${expected}, but the supplied input is a ${kind}.`,
    );
  }
}

function assertNotInsideInput(
  inputDirectory: string,
  outputDirectory: string,
): void {
  const input = resolve(inputDirectory);
  const output = resolve(outputDirectory);

  const rel = relative(input, output);

  if (
    rel &&
    !rel.startsWith("..") &&
    !rel.startsWith(`..${requireSeparator()}`) &&
    !isAbsoluteLike(rel)
  ) {
    throw new Error(
      `Output directory "${output}" cannot be inside input directory "${input}".`,
    );
  }
}

function requireSeparator(): string {
  return process.platform === "win32" ? "\\" : "/";
}

function isAbsoluteLike(path: string): boolean {
  return isAbsolute(path);
}

async function readSignatureEnvelopeFromFile(
  path: string,
): Promise<MajikSignatureEnvelope> {
  const blob = await readBlob(path);

  return MajikSignatureEnvelope.fromMJKSIG(blob);
}

async function writeMapBundle(
  inputDirectory: string,
  files: FolderFile[],
  mapPath: string,
  mapBlob: Blob,
  outputPath: string,
  overwrite: boolean,
): Promise<void> {
  const entries: Record<string, Uint8Array> = {};

  for (const file of files) {
    entries[file.relativePath] = new Uint8Array(await file.blob.arrayBuffer());
  }

  entries[basename(mapPath)] = new Uint8Array(await mapBlob.arrayBuffer());

  const zip = zipSync(entries, {
    level: 6,
  });

  await writeBytes(outputPath, zip, overwrite);
}

async function signSingleEmbeddedFile(
  inputPath: string,
  options: SignCliOptions,
  signingKey: MajikKey,
  expectedSigners?: ExpectedSigner[],
): Promise<CliResult> {
  const source = await readBlob(inputPath);

  const signed = await MajikSignature.signFile(source, signingKey, {
    contentType: options.contentType,
    timestamp: options.timestamp,
    mimeType: mimeTypeForPath(inputPath),
    expectedSigners,
    validUntil: options.validUntil,
  });

  let outputBlob = signed.blob;
  let isSealed = false;

  let sealInfo:
    | {
        sealHash: string;
        sealTimestamp: string;
        sealedBy: string;
      }
    | undefined;

  if (options.seal) {
    const sealedResult = await MajikSignature.seal(outputBlob, signingKey, {
      mimeType: signed.mimeType,
      timestamp: options.timestamp,
    });

    outputBlob = sealedResult.blob;
    isSealed = true;
    sealInfo = sealedResult.sealInfo;
  }

  const outputPath = options.output
    ? resolveCliPath(options.output)
    : inputPath;

  await writeBlob(
    outputPath,
    outputBlob,
    options.overwrite || outputPath === inputPath,
  );

  const signatures = await MajikSignature.extractFrom(outputBlob, {
    mimeType: signed.mimeType,
  });

  const first = signatures[0];

  return result(
    "sign",
    {
      mode: "embedded",
      input: inputPath,
      output: outputPath,
      signerId: signingKey.fingerprint,
      algorithm: "Ed25519 + ML-DSA-87",
      sha256: first?.contentHash,
      sha3_512: undefined,
      sealed: isSealed,
      seal: sealInfo,
    },
    true,
    "Embedded signature created successfully.",
  );
}

async function signSingleDetachedFile(
  inputPath: string,
  options: SignCliOptions,
  signingKey: MajikKey,
  expectedSigners?: ExpectedSigner[],
  tsa?: MajikTimestamp,
): Promise<CliResult> {
  const source = await readBlob(inputPath);

  const signed = await MajikSignature.signFileDetached(source, signingKey, {
    contentType: options.contentType,
    timestamp: options.timestamp,
    mimeType: mimeTypeForPath(inputPath),
    expectedSigners,
    validUntil: options.validUntil,
    tsa,
  });

  let envelope = signed.envelope;
  let sealInfo:
    | {
        sealHash: string;
        sealTimestamp: string;
        sealedBy: string;
      }
    | undefined;

  if (options.seal) {
    envelope = envelope.withSeal(signingKey.fingerprint, options.timestamp);

    sealInfo = {
      sealHash: envelope.sealHash!,
      sealTimestamp: envelope.sealTimestamp!,
      sealedBy: envelope.sealedBy!,
    };
  }

  const outputPath = options.output
    ? resolveCliPath(options.output)
    : outputPathForDetachedFile(inputPath);

  const envelopeBlob = envelope.toMJKSIG();

  await writeBlob(outputPath, envelopeBlob, options.overwrite);

  const first = envelope.signatures[0];

  return result(
    "sign",
    {
      mode: "detached",
      input: inputPath,
      output: outputPath,
      signerId: signingKey.fingerprint,
      algorithm: "Ed25519 + ML-DSA-87",
      sha256: first?.contentHash,
      sealed: Boolean(sealInfo),
      seal: sealInfo,
      tsa: Boolean(tsa),
    },
    true,
    "Detached signature created successfully.",
  );
}

async function signFolderEmbedded(
  inputDirectory: string,
  options: SignCliOptions,
  signingKey: MajikKey,
  expectedSigners?: ExpectedSigner[],
): Promise<CliResult> {
  const files = await readFolderFiles(inputDirectory);

  if (files.length === 0) {
    return result(
      "sign",
      {
        mode: "embedded",
        input: inputDirectory,
        output: options.output ?? inputDirectory,
        signerId: signingKey.fingerprint,
        files: 0,
      },
      true,
      "No signable files were found in the folder.",
    );
  }

  const outputDirectory = options.output
    ? resolveCliPath(options.output)
    : inputDirectory;

  if (outputDirectory !== inputDirectory) {
    assertNotInsideInput(inputDirectory, outputDirectory);
  }

  const failures: Array<{
    path: string;
    error: string;
  }> = [];

  for (let index = 0; index < files.length; index++) {
    const file = files[index];

    console.error(
      `[${index + 1}/${files.length}] Signing ${file.relativePath}`,
    );

    try {
      const signed = await MajikSignature.signFile(file.blob, signingKey, {
        contentType: options.contentType,
        timestamp: options.timestamp,
        mimeType: file.mimeType,
        expectedSigners,
        validUntil: options.validUntil,
      });

      let outputBlob = signed.blob;

      if (options.seal) {
        outputBlob = (
          await MajikSignature.seal(outputBlob, signingKey, {
            mimeType: file.mimeType,
            timestamp: options.timestamp,
          })
        ).blob;
      }

      const outputPath = join(outputDirectory, ...file.relativePath.split("/"));

      await writeBlob(
        outputPath,
        outputBlob,
        options.overwrite || outputDirectory === inputDirectory,
      );
    } catch (error) {
      const message = errorMessage(error);

      failures.push({
        path: file.relativePath,
        error: message,
      });

      console.error(`    ✘ ${message}`);

      if (!options.continueOnError) {
        throw new Error(
          `Signing stopped at "${file.relativePath}": ${message}`,
        );
      }
    }
  }

  const summary = summarizeFiles(files);

  return result(
    "sign",
    {
      mode: "embedded",
      input: inputDirectory,
      output: outputDirectory,
      signerId: signingKey.fingerprint,
      algorithm: "Ed25519 + ML-DSA-87",
      files: summary.count,
      bytes: summary.bytes,
      failures,
      sealed: options.seal,
    },
    failures.length === 0,
    failures.length === 0
      ? "Folder signing completed successfully."
      : "Folder signing completed with failures.",
  );
}

async function signFolderDetached(
  inputDirectory: string,
  options: SignCliOptions,
  signingKey: MajikKey,
  expectedSigners?: ExpectedSigner[],
  tsa?: MajikTimestamp,
): Promise<CliResult> {
  const files = await readFolderFiles(inputDirectory);

  const outputDirectory = options.output
    ? resolveCliPath(options.output)
    : inputDirectory;

  if (outputDirectory !== inputDirectory) {
    assertNotInsideInput(inputDirectory, outputDirectory);
  }

  const failures: Array<{
    path: string;
    error: string;
  }> = [];

  for (let index = 0; index < files.length; index++) {
    const file = files[index];

    console.error(
      `[${index + 1}/${files.length}] Signing ${file.relativePath}`,
    );

    try {
      const signed = await MajikSignature.signFileDetached(
        file.blob,
        signingKey,
        {
          contentType: options.contentType,
          timestamp: options.timestamp,
          mimeType: file.mimeType,
          expectedSigners,
          validUntil: options.validUntil,
          tsa,
        },
      );

      let envelope = signed.envelope;

      if (options.seal) {
        envelope = envelope.withSeal(signingKey.fingerprint, options.timestamp);
      }

      const outputPath = join(outputDirectory, `${file.relativePath}.mjksig`);

      await writeBlob(outputPath, envelope.toMJKSIG(), options.overwrite);
    } catch (error) {
      const message = errorMessage(error);

      failures.push({
        path: file.relativePath,
        error: message,
      });

      console.error(`    ✘ ${message}`);

      if (!options.continueOnError) {
        throw new Error(
          `Signing stopped at "${file.relativePath}": ${message}`,
        );
      }
    }
  }

  return result(
    "sign",
    {
      mode: "detached",
      input: inputDirectory,
      output: outputDirectory,
      signerId: signingKey.fingerprint,
      algorithm: "Ed25519 + ML-DSA-87",
      files: files.length,
      failures,
      sealed: options.seal,
      tsa: Boolean(tsa),
    },
    failures.length === 0,
    failures.length === 0
      ? "Detached folder signing completed successfully."
      : "Detached folder signing completed with failures.",
  );
}

async function signFolderMap(
  inputDirectory: string,
  options: SignCliOptions,
  signingKey: MajikKey,
  expectedSigners?: ExpectedSigner[],
): Promise<CliResult> {
  if (options.tsaTokenPath) {
    throw new Error(
      "--tsa-token is not supported with --map yet. " +
        "The current batch signing SDK does not accept a per-signature TSA token.",
    );
  }

  const files = await readFolderFiles(inputDirectory);

  const batchInputs: BatchFileInput[] = files.map((file) => ({
    path: file.relativePath,
    blob: file.blob,
  }));

  const batchResult = await MajikSignature.signBatchDetached(
    batchInputs,
    signingKey,
    {
      contentType: options.contentType,
      timestamp: options.timestamp,
      expectedSigners,
      validUntil: options.validUntil,
      mode: "map",
      continueOnError: options.continueOnError,
    },
  );

  if (batchResult.mode !== "map") {
    throw new Error("Unexpected SDK batch result: expected map mode.");
  }

  let map = batchResult.map;

  if (options.seal) {
    for (const entry of map.entries) {
      const envelope = MajikSignatureEnvelope.fromJSON(entry.envelope);

      const sealedEnvelope = envelope.withSeal(
        signingKey.fingerprint,
        options.timestamp,
      );

      map = map.withEntry({
        ...entry,
        envelope: sealedEnvelope.toJSON(),
      });
    }
  }

  const mapBlob = map.toMJKSMAP();

  const mapPath = options.output
    ? resolveCliPath(options.output)
    : outputPathForMap(inputDirectory);

  await writeBlob(mapPath, mapBlob, options.overwrite);

  let bundlePath: string | undefined;

  if (options.bundle) {
    bundlePath = outputPathForMapBundle(inputDirectory, mapPath);

    await writeMapBundle(
      inputDirectory,
      files,
      mapPath,
      mapBlob,
      bundlePath,
      options.overwrite,
    );
  }

  const failures = batchResult.failures;

  return result(
    "sign",
    {
      mode: "map",
      input: inputDirectory,
      map: mapPath,
      bundle: bundlePath,
      signerId: signingKey.fingerprint,
      algorithm: "Ed25519 + ML-DSA-87",
      files: files.length,
      entries: map.entries.length,
      failures,
      sealed: options.seal,
    },
    failures.length === 0,
    failures.length === 0
      ? "MJKSMAP created successfully."
      : "MJKSMAP created with batch failures.",
  );
}

async function cosignFolderMap(
  inputDirectory: string,
  options: SignCliOptions,
  signingKey: MajikKey,
  tsa?: MajikTimestamp,
): Promise<CliResult> {
  if (!options.cosignMapPath) {
    throw new Error("An existing map path is required for cosign mode.");
  }

  const files = await readFolderFiles(inputDirectory);

  const mapPath = resolveCliPath(options.cosignMapPath);

  const mapBlob = await readBlob(mapPath);
  let map = await MajikSignatureMap.fromMJKSMAP(mapBlob);

  const failures: Array<{
    path: string;
    error: string;
  }> = [];

  let updatedEntries = 0;

  for (let index = 0; index < files.length; index++) {
    const file = files[index];

    console.error(
      `[${index + 1}/${files.length}] Cosigning ${file.relativePath}`,
    );

    try {
      const lookup = await map.findEntry(file.relativePath, file.blob);

      if (!lookup.found || !lookup.entry) {
        throw new Error("File is not present in the supplied .mjksmap.");
      }

      if (lookup.hashMatches === false) {
        throw new Error(
          "File content does not match the hash recorded in the .mjksmap.",
        );
      }

      const signed = await MajikSignature.signFileDetached(
        file.blob,
        signingKey,
        {
          contentType: lookup.entry.mimeType ?? file.mimeType,
          timestamp: options.timestamp,
          mimeType: lookup.entry.mimeType ?? file.mimeType,
          existingEnvelope: lookup.entry.envelope,
          validUntil: options.validUntil,
          tsa,
        },
      );

      let envelope = signed.envelope;

      if (options.seal) {
        envelope = envelope.withSeal(signingKey.fingerprint, options.timestamp);
      }

      map = map.withEntry({
        ...lookup.entry,
        envelope: envelope.toJSON(),
      });

      updatedEntries++;
    } catch (error) {
      const message = errorMessage(error);

      failures.push({
        path: file.relativePath,
        error: message,
      });

      console.error(`    ✘ ${message}`);

      if (!options.continueOnError) {
        throw new Error(
          `Cosigning stopped at "${file.relativePath}": ${message}`,
        );
      }
    }
  }

  const outputMapPath = options.output
    ? resolveCliPath(options.output)
    : mapPath;

  const outputMapBlob = map.toMJKSMAP();

  await writeBlob(
    outputMapPath,
    outputMapBlob,
    options.overwrite || outputMapPath === mapPath,
  );

  let bundlePath: string | undefined;

  if (options.bundle) {
    bundlePath = outputPathForMapBundle(inputDirectory, outputMapPath);

    await writeMapBundle(
      inputDirectory,
      files,
      outputMapPath,
      outputMapBlob,
      bundlePath,
      options.overwrite,
    );
  }

  return result(
    "sign",
    {
      mode: "cosign-map",
      input: inputDirectory,
      map: outputMapPath,
      bundle: bundlePath,
      signerId: signingKey.fingerprint,
      algorithm: "Ed25519 + ML-DSA-87",
      files: files.length,
      updatedEntries,
      failures,
      sealed: options.seal,
      tsa: Boolean(tsa),
    },
    failures.length === 0,
    failures.length === 0
      ? "MJKSMAP cosigning completed successfully."
      : "MJKSMAP cosigning completed with failures.",
  );
}

export async function runSign(options: SignCliOptions): Promise<CliResult> {
  const inputPath = resolveCliPath(options.input);
  const kind = await getPathKind(inputPath);

  if (options.mode === "map" || options.mode === "cosign-map") {
    assertFolder(kind, "directory");
  }

  const signingKey = await loadSigningKey(options.keyPath);

  try {
    let expectedSigners: ExpectedSigner[] | undefined;

    if (options.allowKeyPaths.length > 0 && options.mode !== "cosign-map") {
      expectedSigners = await buildExpectedSigners(
        signingKey,
        options.allowKeyPaths,
      );
    }

    const tsa = await loadTsaToken(options.tsaTokenPath);

    if (tsa && options.mode !== "detached" && options.mode !== "cosign-map") {
      throw new Error("--tsa-token requires --detached or --cosign-map.");
    }

    if (kind === "file" && options.mode === "embedded") {
      if (options.bundle) {
        throw new Error("--bundle only applies to --map or --cosign-map.");
      }

      return await signSingleEmbeddedFile(
        inputPath,
        options,
        signingKey,
        expectedSigners,
      );
    }

    if (kind === "file" && options.mode === "detached") {
      if (options.bundle) {
        throw new Error("--bundle only applies to --map or --cosign-map.");
      }

      return await signSingleDetachedFile(
        inputPath,
        options,
        signingKey,
        expectedSigners,
        tsa,
      );
    }

    if (kind === "directory" && options.mode === "embedded") {
      if (options.output) {
        assertNotInsideInput(inputPath, resolveCliPath(options.output));
      }

      if (options.bundle) {
        throw new Error("--bundle only applies to --map or --cosign-map.");
      }

      return await signFolderEmbedded(
        inputPath,
        options,
        signingKey,
        expectedSigners,
      );
    }

    if (kind === "directory" && options.mode === "detached") {
      if (options.output) {
        assertNotInsideInput(inputPath, resolveCliPath(options.output));
      }

      if (options.bundle) {
        throw new Error("--bundle only applies to --map or --cosign-map.");
      }

      return await signFolderDetached(
        inputPath,
        options,
        signingKey,
        expectedSigners,
        tsa,
      );
    }

    if (options.mode === "map") {
      return await signFolderMap(
        inputPath,
        options,
        signingKey,
        expectedSigners,
      );
    }

    if (options.mode === "cosign-map") {
      return await cosignFolderMap(inputPath, options, signingKey, tsa);
    }

    throw new Error("Unsupported signing mode.");
  } finally {
    lockKey(signingKey);
  }
}

async function verifyOneEmbeddedFile(
  inputPath: string,
  options: VerifyCliOptions,
  trustedKey?: MajikKey,
): Promise<CliResult> {
  const blob = await readBlob(inputPath);

  const signatures = await MajikSignature.extractFrom(blob);

  if (signatures.length === 0) {
    return result(
      "verify",
      {
        input: inputPath,
        verdict: "unsigned",
        signatures: [],
        reason: "No embedded Majik Signature envelope was found.",
      },
      false,
      "File is unsigned.",
    );
  }

  let verificationResults: VerificationResult[] = [];

  if (trustedKey) {
    verificationResults = await MajikSignature.verifyFile(blob, trustedKey, {
      mimeType: mimeTypeForPath(inputPath),
    });
  } else {
    for (const signature of signatures) {
      const publicKeys = signature.extractPublicKeys();

      const current = await MajikSignature.verifyFile(blob, publicKeys, {
        expectedSignerId: signature.signerId,
        mimeType: mimeTypeForPath(inputPath),
      });

      verificationResults.push(...current);
    }
  }

  const allValid =
    verificationResults.length > 0 &&
    verificationResults.every((verification) => verification.valid === true);

  let orderResult: unknown;

  if (options.order.length > 0) {
    const signatureById = new Map(
      signatures.map((signature) => [signature.signerId, signature]),
    );

    const expectedOrder: ExpectedSigner[] = [];

    for (const signerId of options.order) {
      const signature = signatureById.get(signerId);

      if (!signature) {
        return result(
          "verify",
          {
            input: inputPath,
            verdict: "invalid-order",
            signatures: verificationResults,
            reason: `Signer "${signerId}" does not exist in the envelope.`,
          },
          false,
          "Signing order is invalid.",
        );
      }

      expectedOrder.push(expectedSignerFromSignature(signature));
    }

    orderResult = await MajikSignature.verifyFileOrder(blob, expectedOrder, {
      mimeType: mimeTypeForPath(inputPath),
      strict: options.strict,
    });
  }

  const orderValid =
    !orderResult ||
    (typeof orderResult === "object" &&
      orderResult !== null &&
      "valid" in orderResult &&
      (orderResult as { valid: boolean }).valid);

  const valid = allValid && orderValid;

  return result(
    "verify",
    {
      input: inputPath,
      verdict: valid ? "valid" : "invalid",
      signatures: verificationResults,
      order: orderResult,
      reason: valid
        ? undefined
        : verificationResults.find((item) => !item.valid)?.reason,
    },
    valid,
    valid ? "Signature verification passed." : "Signature verification failed.",
  );
}

async function verifyOneDetachedFile(
  inputPath: string,
  detachedPath: string,
  options: VerifyCliOptions,
  trustedKey?: MajikKey,
): Promise<CliResult> {
  const inputBlob = await readBlob(inputPath);

  const envelopeBlob = await readBlob(detachedPath);

  const envelope = await MajikSignatureEnvelope.fromMJKSIG(envelopeBlob);

  if (envelope.signatures.length === 0) {
    return result(
      "verify",
      {
        input: inputPath,
        detached: detachedPath,
        verdict: "unsigned",
        signatures: [],
      },
      false,
      "Detached envelope contains no signatures.",
    );
  }

  let verificationResults: VerificationResult[] = [];

  if (trustedKey) {
    verificationResults = await MajikSignature.verifyFileDetached(
      inputBlob,
      envelope,
      trustedKey,
      {
        mimeType: mimeTypeForPath(inputPath),
      },
    );
  } else {
    for (const signature of envelope.signatures) {
      const publicKeys = {
        signerId: signature.signerId,
        edPublicKey: Buffer.from(signature.signerEdPublicKey, "base64"),
        mlDsaPublicKey: Buffer.from(signature.signerMlDsaPublicKey, "base64"),
      };

      const current = await MajikSignature.verifyFileDetached(
        inputBlob,
        envelope,
        publicKeys,
        {
          expectedSignerId: signature.signerId,
          mimeType: mimeTypeForPath(inputPath),
        },
      );

      verificationResults.push(...current);
    }
  }

  const allValid =
    verificationResults.length > 0 &&
    verificationResults.every((verification) => verification.valid === true);

  let orderResult: unknown;

  if (options.order.length > 0) {
    const expectedOrder: ExpectedSigner[] = [];

    for (const signerId of options.order) {
      const signature = envelope.signatures.find(
        (entry) => entry.signerId === signerId,
      );

      if (!signature) {
        return result(
          "verify",
          {
            input: inputPath,
            detached: detachedPath,
            verdict: "invalid-order",
            signatures: verificationResults,
            reason: `Signer "${signerId}" does not exist in the detached envelope.`,
          },
          false,
          "Signing order is invalid.",
        );
      }

      expectedOrder.push(
        expectedSignerFromSignature(
          MajikSignature.fromJSON(JSON.stringify(signature)),
        ),
      );
    }

    orderResult = await MajikSignature.verifyFileDetachedOrder(
      inputBlob,
      envelope,
      expectedOrder,
      {
        mimeType: mimeTypeForPath(inputPath),
        strict: options.strict,
      },
    );
  }

  const orderValid =
    !orderResult ||
    (typeof orderResult === "object" &&
      orderResult !== null &&
      "valid" in orderResult &&
      (orderResult as { valid: boolean }).valid);

  const valid = allValid && orderValid;

  return result(
    "verify",
    {
      input: inputPath,
      detached: detachedPath,
      verdict: valid ? "valid" : "invalid",
      signatures: verificationResults,
      order: orderResult,
      sealed: envelope.sealHash !== undefined,
      seal:
        envelope.sealHash !== undefined
          ? {
              sealHash: envelope.sealHash,
              sealTimestamp: envelope.sealTimestamp,
              sealedBy: envelope.sealedBy,
            }
          : undefined,
      reason: valid
        ? undefined
        : verificationResults.find((item) => !item.valid)?.reason,
    },
    valid,
    valid
      ? "Detached signature verification passed."
      : "Detached signature verification failed.",
  );
}

async function verifyMapFolder(
  inputDirectory: string,
  mapPath: string,
  options: VerifyCliOptions,
  trustedKey?: MajikKey,
): Promise<CliResult> {
  const files = await readFolderFiles(inputDirectory);

  const mapBlob = await readBlob(mapPath);

  const map = await MajikSignatureMap.fromMJKSMAP(mapBlob);

  const fileResults: unknown[] = [];
  const accountedFor = new Set<string>();

  for (const file of files) {
    const direct = await map.findEntry(file.relativePath, file.blob);

    let entry = direct.found && direct.entry ? direct.entry : undefined;

    let relocatedFrom: string | undefined;

    if (!entry) {
      const matches = await map.findEntriesByHash(file.blob);

      if (matches.length === 1) {
        entry = matches[0];
        relocatedFrom = entry.path;
      }
    }

    if (!entry) {
      fileResults.push({
        path: file.relativePath,
        status: "not_in_map",
        reason: "The file is not represented by the supplied .mjksmap.",
      });
      continue;
    }

    accountedFor.add(entry.path);

    if (direct.found && direct.hashMatches === false) {
      fileResults.push({
        path: file.relativePath,
        status: "tampered",
        reason:
          "The file content does not match the content hash recorded in the map.",
      });
      continue;
    }

    const envelope = MajikSignatureEnvelope.fromJSON(entry.envelope);

    const signatures = envelope.signatures;

    let verificationResults: VerificationResult[] = [];

    if (trustedKey) {
      verificationResults = await MajikSignature.verifyFileDetached(
        file.blob,
        envelope,
        trustedKey,
        {
          mimeType: entry.mimeType ?? file.mimeType,
        },
      );
    } else {
      for (const signature of signatures) {
        const publicKeys = {
          signerId: signature.signerId,
          edPublicKey: Buffer.from(signature.signerEdPublicKey, "base64"),
          mlDsaPublicKey: Buffer.from(signature.signerMlDsaPublicKey, "base64"),
        };

        const current = await MajikSignature.verifyFileDetached(
          file.blob,
          envelope,
          publicKeys,
          {
            expectedSignerId: signature.signerId,
            mimeType: entry.mimeType ?? file.mimeType,
          },
        );

        verificationResults.push(...current);
      }
    }

    const cryptoValid =
      verificationResults.length > 0 &&
      verificationResults.every((verification) => verification.valid);

    let orderResult: unknown | undefined;

    if (options.order.length > 0) {
      const expectedOrder: ExpectedSigner[] = [];

      for (const signerId of options.order) {
        const signature = signatures.find((item) => item.signerId === signerId);

        if (!signature) {
          orderResult = {
            valid: false,
            reason: `Signer "${signerId}" does not exist in the envelope.`,
          };

          break;
        }

        expectedOrder.push(
          expectedSignerFromSignature(
            MajikSignature.fromJSON(JSON.stringify(signature)),
          ),
        );
      }

      if (
        !orderResult ||
        (typeof orderResult === "object" &&
          orderResult !== null &&
          !("valid" in orderResult))
      ) {
        orderResult = await MajikSignature.verifyFileDetachedOrder(
          file.blob,
          envelope,
          expectedOrder,
          {
            mimeType: entry.mimeType ?? file.mimeType,
            strict: options.strict,
          },
        );
      }
    }

    const orderValid =
      !orderResult ||
      (typeof orderResult === "object" &&
        orderResult !== null &&
        "valid" in orderResult &&
        (
          orderResult as {
            valid: boolean;
          }
        ).valid);

    fileResults.push({
      path: file.relativePath,
      status: cryptoValid && orderValid ? "verified" : "invalid",
      relocatedFrom,
      signatures: verificationResults,
      order: orderResult,
      reason:
        cryptoValid && orderValid
          ? undefined
          : (verificationResults.find((item) => !item.valid)?.reason ??
            "Signature or signing-order verification failed."),
    });
  }

  const missing = map.entries
    .map((entry) => entry.path)
    .filter((path) => !accountedFor.has(path));

  if (missing.length > 0) {
    for (const path of missing) {
      fileResults.push({
        path,
        status: "not_in_map",
        reason:
          "The map contains this path, but the file was not supplied for verification.",
      });
    }
  }

  const invalidCount = fileResults.filter((item) => {
    if (typeof item !== "object" || item === null) {
      return true;
    }

    const status = (
      item as {
        status?: string;
      }
    ).status;

    return status !== "verified";
  }).length;

  const allValid = fileResults.length === 0 || invalidCount === 0;

  return result(
    "verify",
    {
      input: inputDirectory,
      map: mapPath,
      verdict: allValid ? "valid" : "invalid",
      files: fileResults,
      missing,
    },
    allValid,
    allValid ? "MJKSMAP verification passed." : "MJKSMAP verification failed.",
  );
}

export async function runVerify(options: VerifyCliOptions): Promise<CliResult> {
  const inputPath = resolveCliPath(options.input);

  const kind = await getPathKind(inputPath);

  let trustedKey: MajikKey | undefined;

  if (options.keyPath) {
    trustedKey = await loadMajikKey(options.keyPath);
  }

  try {
    if (options.mapPath) {
      assertFolder(kind, "directory");

      if (options.detachedPath) {
        throw new Error("--map and --detached cannot be combined.");
      }

      return await verifyMapFolder(
        inputPath,
        resolveCliPath(options.mapPath),
        options,
        trustedKey,
      );
    }

    if (options.detachedPath) {
      assertFolder(kind, "file");

      return await verifyOneDetachedFile(
        inputPath,
        resolveCliPath(options.detachedPath),
        options,
        trustedKey,
      );
    }

    if (kind !== "file") {
      throw new Error(
        "Embedded verification currently requires a single file. " +
          "Use --map for folder verification.",
      );
    }

    return await verifyOneEmbeddedFile(inputPath, options, trustedKey);
  } finally {
    /**
     * Verification never requires private key material, so there is normally
     * nothing to wipe here. Keeping this branch makes the ownership explicit
     * if that changes later.
     */
    if (trustedKey?.isUnlocked) {
      lockKey(trustedKey);
    }
  }
}

export async function runSeal(options: SealCliOptions): Promise<CliResult> {
  const inputPath = resolveCliPath(options.input);

  const kind = await getPathKind(inputPath);

  assertFolder(kind, "file");

  const key = await loadSigningKey(options.keyPath);

  try {
    const isDetached = extname(inputPath).toLowerCase() === ".mjksig";

    if (isDetached) {
      let envelope = await readSignatureEnvelopeFromFile(inputPath);

      envelope = envelope.withSeal(key.fingerprint, options.timestamp);

      const outputPath = options.output
        ? resolveCliPath(options.output)
        : inputPath;

      await writeBlob(
        outputPath,
        envelope.toMJKSIG(),
        options.overwrite || outputPath === inputPath,
      );

      return result(
        "seal",
        {
          input: inputPath,
          output: outputPath,
          sealedBy: envelope.sealedBy,
          sealTimestamp: envelope.sealTimestamp,
          sealHash: envelope.sealHash,
        },
        true,
        "Detached envelope sealed successfully.",
      );
    }

    const source = await readBlob(inputPath);

    const sealed = await MajikSignature.seal(source, key, {
      mimeType: mimeTypeForPath(inputPath),
      timestamp: options.timestamp,
    });

    const outputPath = options.output
      ? resolveCliPath(options.output)
      : inputPath;

    await writeBlob(
      outputPath,
      sealed.blob,
      options.overwrite || outputPath === inputPath,
    );

    return result(
      "seal",
      {
        input: inputPath,
        output: outputPath,
        sealedBy: sealed.sealInfo.sealedBy,
        sealTimestamp: sealed.sealInfo.sealTimestamp,
        sealHash: sealed.sealInfo.sealHash,
      },
      true,
      "Embedded signature envelope sealed successfully.",
    );
  } finally {
    lockKey(key);
  }
}

export async function runCanSign(
  options: CanSignCliOptions,
): Promise<CliResult> {
  const inputPath = resolveCliPath(options.input);

  const kind = await getPathKind(inputPath);

  assertFolder(kind, "file");

  const key = await loadSigningKey(options.keyPath);

  try {
    const blob = await readBlob(inputPath);

    const permission = await MajikSignature.canSign(blob, key, {
      mimeType: mimeTypeForPath(inputPath),
    });

    return result(
      "can-sign",
      {
        input: inputPath,
        permitted: permission.permitted,
        reason: permission.reason,
      },
      permission.permitted,
      permission.permitted
        ? "The file can be signed by this key."
        : "The file cannot be signed by this key.",
    );
  } finally {
    lockKey(key);
  }
}

export async function runInspect(
  options: InspectCliOptions,
): Promise<CliResult> {
  const inputPath = resolveCliPath(options.input);

  const kind = await getPathKind(inputPath);

  assertFolder(kind, "file");

  const blob = await readBlob(inputPath);

  const isDetached = extname(inputPath).toLowerCase() === ".mjksig";

  if (isDetached) {
    const envelope = await MajikSignatureEnvelope.fromMJKSIG(blob);

    return result(
      "inspect",
      {
        input: inputPath,
        signed: envelope.signatures.length > 0,
        envelope: envelope.toJSON(),
      },
      true,
      "Detached signature envelope inspected successfully.",
    );
  }

  const envelopeInfo = await MajikSignature.getEnvelopeInfo(blob, {
    mimeType: mimeTypeForPath(inputPath),
  });

  return result(
    "inspect",
    {
      input: inputPath,
      signed: envelopeInfo !== null,
      envelope: envelopeInfo,
    },
    true,
    envelopeInfo
      ? "Embedded signature envelope inspected successfully."
      : "The file does not contain a Majik Signature envelope.",
  );
}

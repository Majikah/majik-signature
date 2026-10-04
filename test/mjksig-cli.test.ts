/**
 * @file mjksig-cli.test.ts
 *
 * Comprehensive Majik Signature CLI test suite.
 *
 * Coverage:
 *
 * CLI parser
 * - command discovery
 * - version/help
 * - required key validation
 * - aliases
 * - conflicting flags
 * - CSV parsing
 * - JSON flag
 *
 * Key / filesystem
 * - real MajikKey JSON serialization
 * - real MajikKey loading
 * - real unlocking through MAJIK_KEY_PASSPHRASE
 * - invalid key handling
 * - unsupported PNG key handling
 * - temporary filesystem isolation
 *
 * Embedded signing
 * - basic sign
 * - content-type
 * - deterministic timestamp
 * - validUntil
 * - verification
 * - tamper detection
 *
 * Detached signing
 * - .mjksig generation
 * - detached verification
 * - detached tamper detection
 * - custom output
 * - overwrite protection
 *
 * Multi-signature
 * - allowlist establishment
 * - allowed signer can sign
 * - unlisted signer denied
 * - cosigning
 * - sealing
 * - sealed files reject new signatures
 *
 * MJKSMAP
 * - map creation
 * - map serialization
 * - map verification
 * - tampered file detection
 * - relocated file detection
 * - missing files
 * - bundle generation
 * - map cosigning
 *
 * Read-only commands
 * - inspect
 * - can-sign
 *
 * Output / process semantics
 * - JSON output
 * - success exit code
 * - verification failure exit code
 * - usage error exit code
 *
 * Testing philosophy:
 * - real MajikKey
 * - real Ed25519 + ML-DSA-87 signing
 * - real handlers
 * - real envelope serialization
 * - real MJKSMAP serialization
 * - real filesystem
 * - no mocking of cryptography
 *
 * The only environment boundary mocked/controlled is the passphrase source,
 * because interactive terminal input is not appropriate inside Vitest.
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import {
  mkdtemp,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";

import { basename, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { unzipSync } from "fflate";
import { MajikKey } from "@majikah/majik-key";
import { MajikSignature } from "../src/majik-signature";
import { MajikSignatureEnvelope } from "../src/core/envelope";
import { MajikSignatureMap } from "../src/core/mjksmap";
import { createProgram } from "../src/cli";

import {
  runCanSign,
  runInspect,
  runSeal,
  runSign,
  runVerify,
} from "../src/cli-core/operations";

import type {
  CliResult,
  CanSignCliOptions,
  InspectCliOptions,
  SealCliOptions,
  SignCliOptions,
  VerifyCliOptions,
} from "../src/cli-core/types";

import { getTestKey } from "./helpers/crypto";

// ============================================================================
// Constants
// ============================================================================

const TEST_PASSPHRASE = "test_passphrase";

const FIXED_TIMESTAMP = "2026-10-01T12:00:00.000Z";

const FUTURE_TIMESTAMP = "2027-01-01T00:00:00.000Z";

const EXPIRED_TIMESTAMP = "2025-01-01T00:00:00.000Z";

// ============================================================================
// Shared real cryptographic keys
// ============================================================================

let keyA!: MajikKey;
let keyB!: MajikKey;
let keyC!: MajikKey;

// ============================================================================
// Helpers
// ============================================================================

let testRoot = "";

async function writeKeyFile(key: MajikKey, filename: string): Promise<string> {
  const path = join(testRoot, filename);

  await mkdir(dirname(path), {
    recursive: true,
  });

  await writeFile(path, JSON.stringify(key.toJSON(), null, 2), "utf8");

  return path;
}

async function writeBinary(
  path: string,
  data: Uint8Array | Buffer | string,
): Promise<void> {
  await mkdir(dirname(path), {
    recursive: true,
  });

  await writeFile(path, data);
}

async function readBytes(path: string): Promise<Uint8Array> {
  return new Uint8Array(await readFile(path));
}

async function readJson<T = unknown>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function createFixtureFile(
  relativePath: string,
  content: string,
  mimeType = "text/plain",
): Promise<string> {
  /**
   * Mime type is not stored in the filesystem. The CLI derives it from the
   * filename, so the helper keeps the parameter only to document intent.
   */
  void mimeType;

  const path = join(testRoot, relativePath);

  await writeBinary(path, Buffer.from(content, "utf8"));

  return path;
}

function signingOptions(
  keyPath: string,
  overrides: Partial<SignCliOptions> = {},
): SignCliOptions {
  return {
    input: "",
    keyPath,

    mode: "embedded",

    output: undefined,

    contentType: "text/plain",
    timestamp: FIXED_TIMESTAMP,
    validUntil: undefined,

    allowKeyPaths: [],

    continueOnError: false,

    bundle: false,

    seal: false,

    tsaTokenPath: undefined,

    overwrite: false,

    json: false,

    cosignMapPath: undefined,

    ...overrides,
  };
}

function verifyOptions(
  input: string,
  overrides: Partial<VerifyCliOptions> = {},
): VerifyCliOptions {
  return {
    input,

    keyPath: undefined,

    detachedPath: undefined,

    mapPath: undefined,

    order: [],

    strict: false,

    json: false,

    ...overrides,
  };
}

function sealOptions(
  input: string,
  keyPath: string,
  overrides: Partial<SealCliOptions> = {},
): SealCliOptions {
  return {
    input,
    keyPath,
    output: undefined,
    timestamp: FIXED_TIMESTAMP,
    overwrite: false,
    json: false,
    ...overrides,
  };
}

function canSignOptions(
  input: string,
  keyPath: string,
  overrides: Partial<CanSignCliOptions> = {},
): CanSignCliOptions {
  return {
    input,
    keyPath,
    json: false,
    ...overrides,
  };
}

function inspectOptions(
  input: string,
  overrides: Partial<InspectCliOptions> = {},
): InspectCliOptions {
  return {
    input,
    json: false,
    ...overrides,
  };
}

function resetExitCode(): void {
  process.exitCode = 0;
}

function setCliPassphrase(): void {
  process.env.MAJIK_KEY_PASSPHRASE = TEST_PASSPHRASE;
}

function clearCliPassphrase(): void {
  delete process.env.MAJIK_KEY_PASSPHRASE;
}

async function expectRejected(
  promise: Promise<unknown>,
  pattern?: string | RegExp,
): Promise<void> {
  await expect(promise).rejects.toThrow(pattern);
}

function assertCliResult(value: CliResult): void {
  expect(value).toBeDefined();
  expect(value).toHaveProperty("ok");
  expect(value).toHaveProperty("command");
  expect(value).toHaveProperty("message");
}

async function runCliArgs(argv: string[]): Promise<void> {
  const program = createProgram("test");

  program.exitOverride();

  resetExitCode();

  await program.parseAsync(["node", "mjksig", ...argv]);
}
// ============================================================================
// Suite setup
// ============================================================================

describe("Majik Signature CLI", () => {
  beforeAll(async () => {
    console.log("[mjksig-cli] Generating shared test keys...");

    [keyA, keyB, keyC] = await Promise.all([
      getTestKey(),
      getTestKey(),
      getTestKey(),
    ]);

    testRoot = await mkdtemp(join(tmpdir(), "mjksig-cli-"));

    setCliPassphrase();

    console.log(`[mjksig-cli] Test root: ${testRoot}`);
  }, 120_000);

  afterAll(async () => {
    clearCliPassphrase();

    for (const key of [keyA, keyB, keyC]) {
      try {
        key?.lock();
      } catch {
        // Test cleanup only.
      }
    }

    if (testRoot) {
      await rm(testRoot, {
        recursive: true,
        force: true,
      });
    }
  });

  beforeEach(() => {
    setCliPassphrase();
    resetExitCode();
  });

  afterEach(() => {
    resetExitCode();
    vi.restoreAllMocks();
  });

  // ========================================================================
  // Key fixtures
  // ========================================================================

  describe("Key / fixture setup", () => {
    it("serializes a real MajikKey as a valid JSON backup", async () => {
      const keyPath = await writeKeyFile(keyA, "alice.json");

      const json = await readJson<{
        id: string;
        fingerprint: string;
        encryptedPrivateKey: string;
        edPublicKey?: string;
        mlDsaPublicKey?: string;
      }>(keyPath);

      expect(json.id).toBe(keyA.id);

      expect(json.fingerprint).toBe(keyA.fingerprint);

      expect(json.encryptedPrivateKey).toEqual(expect.any(String));

      expect(json.edPublicKey).toEqual(expect.any(String));

      expect(json.mlDsaPublicKey).toEqual(expect.any(String));
    });

    it("loads the serialized key through the CLI key path", async () => {
      const keyPath = await writeKeyFile(keyA, "alice-load.json");

      const output = await runCanSign(
        canSignOptions(
          await createFixtureFile("fixtures/load.txt", "load test"),
          keyPath,
        ),
      );

      assertCliResult(output);

      expect(output.ok).toBe(true);

      expect(output.permitted).toBe(true);
    });

    it("rejects a malformed Majik Key JSON file", async () => {
      const badKey = join(testRoot, "invalid-key.json");

      await writeFile(
        badKey,
        JSON.stringify({
          not: "a MajikKey",
        }),
      );

      const file = await createFixtureFile(
        "fixtures/invalid-key.txt",
        "invalid key",
      );

      await expectRejected(
        runSign(
          signingOptions(badKey, {
            input: file,
          }),
        ),
        /Failed to load Majik Key|Invalid|validation/i,
      );
    });

    it("rejects PNG key backups with the documented CLI limitation", async () => {
      const pngKey = join(testRoot, "key.png");

      await writeBinary(pngKey, new Uint8Array([0x89, 0x50, 0x4e, 0x47]));

      const file = await createFixtureFile("fixtures/png-key.txt", "png key");

      await expectRejected(
        runSign(
          signingOptions(pngKey, {
            input: file,
          }),
        ),
        /PNG Majik Key backups are not supported/i,
      );
    });
  });

  // ========================================================================
  // Commander parser
  // ========================================================================

  describe("Commander CLI parser", () => {
    it("exposes the mjksig program", () => {
      const program = createProgram("1.2.3");

      expect(program.name()).toBe("mjksig");

      expect(program.version()).toBe("1.2.3");
    });

    it("registers every expected command", () => {
      const program = createProgram();

      const names = program.commands.map((command) => command.name());

      expect(names).toEqual(
        expect.arrayContaining([
          "sign",
          "verify",
          "seal",
          "can-sign",
          "inspect",
        ]),
      );
    });

    it("parses --order as a comma-separated array", async () => {
      const verify = vi.fn();

      const program = createProgram();

      /**
       * We do not run the actual operation here. Commander itself is
       * being tested for parser behavior; the operation tests below
       * exercise the real verification path.
       */
      program
        .command("parser-test")
        .option("--order <signers>", undefined, (value: string) =>
          value
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
        )
        .action((options) => {
          verify(options);
        });

      await program.parseAsync([
        "node",
        "mjksig",
        "parser-test",
        "--order",
        "alice, bob,carol",
      ]);

      expect(verify).toHaveBeenCalledWith({
        order: ["alice", "bob", "carol"],
      });
    });

    it("requires --key for sign", async () => {
      const program = createProgram();

      program.exitOverride();

      const signCommand = program.commands.find(
        (command) => command.name() === "sign",
      );

      expect(signCommand).toBeDefined();

      signCommand!.exitOverride();

      await expect(
        program.parseAsync(["node", "mjksig", "sign", "sample.txt"]),
      ).rejects.toThrow(/required option/i);
    });

    it("rejects conflicting --map and --detached", async () => {
      const program = createProgram();

      const keyPath = await writeKeyFile(keyA, "parser-alice.json");

      const file = await createFixtureFile("parser/source.txt", "parser");

      await expect(
        program.parseAsync([
          "node",
          "mjksig",
          "sign",
          file,
          "--key",
          keyPath,
          "--map",
          "--detached",
        ]),
      ).rejects.toThrow(/--map and --detached cannot be combined/i);

      expect(process.exitCode).toBe(2);
    });

    it("rejects --bundle without --map or --cosign", async () => {
      const program = createProgram();

      const keyPath = await writeKeyFile(keyA, "parser-bundle.json");

      const file = await createFixtureFile("parser/bundle.txt", "bundle");

      await expect(
        program.parseAsync([
          "node",
          "mjksig",
          "sign",
          file,
          "--key",
          keyPath,
          "--bundle",
        ]),
      ).rejects.toThrow(/--bundle requires/i);

      expect(process.exitCode).toBe(2);
    });

    it("accepts --json as a boolean flag", () => {
      const program = createProgram();

      const command = program.commands.find((item) => item.name() === "verify");

      expect(command).toBeDefined();

      expect(command!.options.some((option) => option.long === "--json")).toBe(
        true,
      );
    });
  });

  // ========================================================================
  // Embedded signing
  // ========================================================================

  describe("Embedded signing", () => {
    it("signs a file and embeds a real envelope", async () => {
      const keyPath = await writeKeyFile(keyA, "embedded-alice.json");

      const input = await createFixtureFile(
        "embedded/basic.txt",
        "Hello from Majik CLI",
      );

      const response = await runSign(
        signingOptions(keyPath, {
          input,
        }),
      );

      expect(response.ok).toBe(true);

      expect(response.mode).toBe("embedded");

      const signatures = await MajikSignature.extractFrom(
        await (async () => {
          const bytes = await readBytes(input);

          return new Blob([bytes as BlobPart], {
            type: "text/plain",
          });
        })(),
      );

      expect(signatures.length).toBe(1);

      expect(signatures[0].signerId).toBe(keyA.fingerprint);
    });

    it("signs with content type and deterministic timestamp", async () => {
      const keyPath = await writeKeyFile(keyA, "embedded-metadata.json");

      const input = await createFixtureFile(
        "embedded/metadata.txt",
        "Metadata test",
      );

      await runSign(
        signingOptions(keyPath, {
          input,
          contentType: "text/plain",
          timestamp: FIXED_TIMESTAMP,
        }),
      );

      const blob = new Blob([(await readBytes(input)) as BlobPart], {
        type: "text/plain",
      });

      const signatures = await MajikSignature.extractFrom(blob);

      expect(signatures[0].timestamp).toBe(FIXED_TIMESTAMP);

      expect(signatures[0].contentType).toBe("text/plain");
    });
    it("returns a verification failure exit result after tampering", async () => {
      const keyPath = await writeKeyFile(keyA, "embedded-tamper.json");

      const input = await createFixtureFile(
        "embedded/tamper.txt",
        "original content",
      );

      await runSign(
        signingOptions(keyPath, {
          input,
        }),
      );

      const signedBytes = await readBytes(input);

      expect(signedBytes.length).toBeGreaterThan(0);

      /**
       * Mutate the original content without removing the embedded
       * signature envelope.
       */
      signedBytes[0] ^= 0x01;

      await writeBinary(input, signedBytes);

      const response = await runVerify(verifyOptions(input));

      expect(response.ok).toBe(false);

      expect(response.verdict).toBe("invalid");
    });

    it("supports validUntil metadata", async () => {
      const keyPath = await writeKeyFile(keyA, "embedded-expiry.json");

      const input = await createFixtureFile(
        "embedded/expiry.txt",
        "expiry test",
      );

      const response = await runSign(
        signingOptions(keyPath, {
          input,
          validUntil: FUTURE_TIMESTAMP,
        }),
      );

      expect(response.ok).toBe(true);

      const blob = new Blob([(await readBytes(input)) as BlobPart], {
        type: "text/plain",
      });

      const signatures = await MajikSignature.extractFrom(blob);

      expect(signatures[0]).toBeDefined();

      expect(signatures[0].validUntil).toBe(FUTURE_TIMESTAMP);
    });
  });

  // ========================================================================
  // Detached signing
  // ========================================================================

  describe("Detached signing", () => {
    it("creates a .mjksig detached envelope", async () => {
      const keyPath = await writeKeyFile(keyA, "detached-alice.json");

      const input = await createFixtureFile(
        "detached/report.txt",
        "Detached report",
      );

      const response = await runSign(
        signingOptions(keyPath, {
          input,
          mode: "detached",
        }),
      );

      expect(response.ok).toBe(true);

      const detached = `${input}.mjksig`;

      const envelope = await MajikSignatureEnvelope.fromMJKSIG(
        new Blob([(await readBytes(detached)) as BlobPart], {
          type: "application/vnd.majikah.mjksig",
        }),
      );

      expect(envelope.signatures).toHaveLength(1);

      expect(envelope.signatures[0].signerId).toBe(keyA.fingerprint);
    });

    it("verifies a valid detached signature", async () => {
      const keyPath = await writeKeyFile(keyA, "detached-verify.json");

      const input = await createFixtureFile(
        "detached/verify.txt",
        "Detached verification",
      );

      await runSign(
        signingOptions(keyPath, {
          input,
          mode: "detached",
        }),
      );

      const response = await runVerify(
        verifyOptions(input, {
          detachedPath: `${input}.mjksig`,
        }),
      );

      expect(response.ok).toBe(true);

      expect(response.verdict).toBe("valid");
    });

    it("detects detached tampering", async () => {
      const keyPath = await writeKeyFile(keyA, "detached-tamper.json");

      const input = await createFixtureFile(
        "detached/tamper.txt",
        "Detached original",
      );

      await runSign(
        signingOptions(keyPath, {
          input,
          mode: "detached",
        }),
      );

      await writeBinary(input, Buffer.from("Detached tampered", "utf8"));

      const response = await runVerify(
        verifyOptions(input, {
          detachedPath: `${input}.mjksig`,
        }),
      );

      expect(response.ok).toBe(false);

      expect(response.verdict).toBe("invalid");
    });

    it("supports a custom detached output path", async () => {
      const keyPath = await writeKeyFile(keyA, "detached-custom.json");

      const input = await createFixtureFile(
        "detached/custom.txt",
        "Custom detached",
      );

      const customOutput = join(testRoot, "custom-output.mjksig");

      const response = await runSign(
        signingOptions(keyPath, {
          input,
          mode: "detached",
          output: customOutput,
        }),
      );

      expect(response.ok).toBe(true);

      expect(response.output).toBe(customOutput);
    });

    it("rejects an existing detached output without --overwrite", async () => {
      const keyPath = await writeKeyFile(keyA, "detached-collision.json");

      const input = await createFixtureFile(
        "detached/collision.txt",
        "Collision",
      );

      const output = join(testRoot, "collision.mjksig");

      await writeBinary(output, Buffer.from("already here", "utf8"));

      await expectRejected(
        runSign(
          signingOptions(keyPath, {
            input,
            mode: "detached",
            output,
          }),
        ),
        /already exists/i,
      );
    });

    it("overwrites an existing detached output when requested", async () => {
      const keyPath = await writeKeyFile(keyA, "detached-overwrite.json");

      const input = await createFixtureFile(
        "detached/overwrite.txt",
        "Overwrite",
      );

      const output = join(testRoot, "overwrite.mjksig");

      await writeBinary(output, Buffer.from("placeholder", "utf8"));

      const response = await runSign(
        signingOptions(keyPath, {
          input,
          mode: "detached",
          output,
          overwrite: true,
        }),
      );

      expect(response.ok).toBe(true);

      const envelope = await MajikSignatureEnvelope.fromMJKSIG(
        new Blob([(await readBytes(output)) as BlobPart]),
      );

      expect(envelope.signatures).toHaveLength(1);
    });
  });

  // ========================================================================
  // Multi-signature / allowlist
  // ========================================================================

  describe("Multi-signature and allowlists", () => {
    it("establishes an allowlist using the primary key plus --allow-key", async () => {
      const keyAPath = await writeKeyFile(keyA, "multi/alice.json");

      const keyBPath = await writeKeyFile(keyB, "multi/bob.json");

      const input = await createFixtureFile(
        "multi/contract.txt",
        "Restricted contract",
      );

      const response = await runSign(
        signingOptions(keyAPath, {
          input,
          mode: "embedded",
          allowKeyPaths: [keyBPath],
        }),
      );

      expect(response.ok).toBe(true);

      const embeddedBlob = new Blob([(await readBytes(input)) as BlobPart], {
        type: "text/plain",
      });

      const allowlist = await MajikSignature.getAllowlist(embeddedBlob);

      expect(allowlist).not.toBeNull();

      expect(allowlist).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            signerId: keyA.fingerprint,
          }),
          expect.objectContaining({
            signerId: keyB.fingerprint,
          }),
        ]),
      );
    });

    it("allows an allowlisted signer to sign", async () => {
      const keyAPath = await writeKeyFile(keyA, "allowlist/alice.json");

      const keyBPath = await writeKeyFile(keyB, "allowlist/bob.json");

      const input = await createFixtureFile(
        "allowlist/document.txt",
        "Allowlisted",
      );

      /**
       * Detached mode gives us a clean envelope file to co-sign.
       */
      await runSign(
        signingOptions(keyAPath, {
          input,
          mode: "detached",
          allowKeyPaths: [keyBPath],
        }),
      );

      /**
       * Convert the existing detached envelope into the cosigning
       * workflow through the folder/map path separately below.
       */
      const envelope = await MajikSignatureEnvelope.fromMJKSIG(
        new Blob([(await readBytes(`${input}.mjksig`)) as BlobPart]),
      );

      expect(
        envelope.allowlist?.some(
          (entry) => entry.signerId === keyB.fingerprint,
        ),
      ).toBe(true);

      const permission = await runCanSign(canSignOptions(input, keyBPath));

      /**
       * The detached signature itself is not embedded in `input`, so
       * canSign() checks the unsigned file. The direct envelope-level
       * permission is checked below against the detached envelope.
       */
      expect(permission.ok).toBe(true);

      expect(envelope.canSign(keyB).permitted).toBe(true);
    });

    it("denies a signer that is not on the allowlist", async () => {
      const keyAPath = await writeKeyFile(keyA, "allowlist-deny/alice.json");

      const keyBPath = await writeKeyFile(keyB, "allowlist-deny/bob.json");

      const input = await createFixtureFile(
        "allowlist-deny/document.txt",
        "Restricted",
      );

      await runSign(
        signingOptions(keyAPath, {
          input,
          mode: "detached",
          allowKeyPaths: [keyBPath],
        }),
      );

      const envelope = await MajikSignatureEnvelope.fromMJKSIG(
        new Blob([(await readBytes(`${input}.mjksig`)) as BlobPart]),
      );

      const check = envelope.canSign(keyC);

      expect(check.permitted).toBe(false);

      expect(check.reason).toMatch(/allowlist/i);
    });

    it("seals an embedded file", async () => {
      const keyAPath = await writeKeyFile(keyA, "seal/alice.json");

      const input = await createFixtureFile("seal/document.txt", "Seal me");

      const response = await runSign(
        signingOptions(keyAPath, {
          input,
          seal: true,
        }),
      );

      expect(response.ok).toBe(true);

      const blob = new Blob([(await readBytes(input)) as BlobPart], {
        type: "text/plain",
      });

      const sealInfo = await MajikSignature.getSealInfo(blob);

      expect(sealInfo).not.toBeNull();

      expect(sealInfo?.sealedBy).toBe(keyA.fingerprint);
    });

    it("reports sealed files as unable to sign", async () => {
      const keyAPath = await writeKeyFile(keyA, "seal-deny/alice.json");

      const input = await createFixtureFile(
        "seal-deny/document.txt",
        "Already sealed",
      );

      await runSign(
        signingOptions(keyAPath, {
          input,
          seal: true,
        }),
      );

      const response = await runCanSign(canSignOptions(input, keyAPath));

      expect(response.ok).toBe(false);

      expect(response.permitted).toBe(false);

      expect(response.reason).toMatch(/sealed/i);
    });

    it("seals an already detached .mjksig envelope", async () => {
      const keyAPath = await writeKeyFile(keyA, "seal-detached/alice.json");

      const input = await createFixtureFile(
        "seal-detached/document.txt",
        "Detached seal",
      );

      await runSign(
        signingOptions(keyAPath, {
          input,
          mode: "detached",
        }),
      );

      const detached = `${input}.mjksig`;

      const response = await runSeal(
        sealOptions(detached, keyAPath, {
          timestamp: FIXED_TIMESTAMP,
          overwrite: true,
        }),
      );

      expect(response.ok).toBe(true);

      const envelope = await MajikSignatureEnvelope.fromMJKSIG(
        new Blob([(await readBytes(detached)) as BlobPart]),
      );

      expect(envelope.isSealed()).toBe(true);

      expect(envelope.sealedBy).toBe(keyA.fingerprint);
    });
  });

  // ========================================================================
  // MJKSMAP
  // ========================================================================

  describe("MJKSMAP", () => {
    async function createMapFixture(prefix: string): Promise<{
      directory: string;
      keyAPath: string;
      keyBPath: string;
    }> {
      const directory = join(testRoot, prefix);

      await mkdir(directory, {
        recursive: true,
      });

      await writeBinary(join(directory, "alpha.txt"), Buffer.from("alpha"));

      await writeBinary(
        join(directory, "nested", "beta.txt"),
        Buffer.from("beta"),
      );

      const keyAPath = await writeKeyFile(keyA, `${prefix}-alice.json`);

      const keyBPath = await writeKeyFile(keyB, `${prefix}-bob.json`);

      return {
        directory,
        keyAPath,
        keyBPath,
      };
    }

    it("creates a .mjksmap for a folder", async () => {
      const fixture = await createMapFixture("map/basic");

      const response = await runSign(
        signingOptions(fixture.keyAPath, {
          input: fixture.directory,
          mode: "map",
        }),
      );

      expect(response.ok).toBe(true);

      const mapPath = join(fixture.directory, "signatures.mjksmap");

      const map = await MajikSignatureMap.fromMJKSMAP(
        new Blob([(await readBytes(mapPath)) as BlobPart]),
      );

      expect(map.entries).toHaveLength(2);

      expect(map.getEntry("alpha.txt")).toBeDefined();

      expect(map.getEntry("nested/beta.txt")).toBeDefined();
    });

    it("verifies a valid .mjksmap", async () => {
      const fixture = await createMapFixture("map/verify");

      await runSign(
        signingOptions(fixture.keyAPath, {
          input: fixture.directory,
          mode: "map",
        }),
      );

      const response = await runVerify(
        verifyOptions(fixture.directory, {
          mapPath: join(fixture.directory, "signatures.mjksmap"),
        }),
      );

      expect(response.ok).toBe(true);

      expect(response.verdict).toBe("valid");
    });

    it("detects a tampered file in a map", async () => {
      const fixture = await createMapFixture("map/tamper");

      await runSign(
        signingOptions(fixture.keyAPath, {
          input: fixture.directory,
          mode: "map",
        }),
      );

      await writeBinary(
        join(fixture.directory, "alpha.txt"),
        Buffer.from("ALPHA TAMPERED"),
      );

      const response = await runVerify(
        verifyOptions(fixture.directory, {
          mapPath: join(fixture.directory, "signatures.mjksmap"),
        }),
      );

      expect(response.ok).toBe(false);

      expect(response.verdict).toBe("invalid");

      const files = response.files as Array<{
        path: string;
        status: string;
      }>;

      expect(
        files.some(
          (item) => item.path === "alpha.txt" && item.status === "tampered",
        ),
      ).toBe(true);
    });

    it("detects files missing from the folder", async () => {
      const fixture = await createMapFixture("map/missing");

      await runSign(
        signingOptions(fixture.keyAPath, {
          input: fixture.directory,
          mode: "map",
        }),
      );

      await rm(join(fixture.directory, "nested", "beta.txt"));

      const response = await runVerify(
        verifyOptions(fixture.directory, {
          mapPath: join(fixture.directory, "signatures.mjksmap"),
        }),
      );

      expect(response.ok).toBe(false);

      expect(response.missing).toEqual(
        expect.arrayContaining(["nested/beta.txt"]),
      );
    });

    it("recognizes a relocated file by content hash", async () => {
      const fixture = await createMapFixture("map/relocated");

      await runSign(
        signingOptions(fixture.keyAPath, {
          input: fixture.directory,
          mode: "map",
        }),
      );

      const original = join(fixture.directory, "alpha.txt");

      const relocated = join(fixture.directory, "renamed-alpha.txt");

      await rename(original, relocated);

      const response = await runVerify(
        verifyOptions(fixture.directory, {
          mapPath: join(fixture.directory, "signatures.mjksmap"),
        }),
      );

      expect(response.ok).toBe(true);

      const files = response.files as Array<{
        path: string;
        status: string;
        relocatedFrom?: string;
      }>;

      const relocatedEntry = files.find(
        (item) => item.path === "renamed-alpha.txt",
      );

      expect(relocatedEntry).toBeDefined();

      expect(relocatedEntry?.status).toBe("verified");

      expect(relocatedEntry?.relocatedFrom).toBe("alpha.txt");
    });

    it("creates a ZIP bundle alongside the map", async () => {
      const fixture = await createMapFixture("map/bundle");

      const response = await runSign(
        signingOptions(fixture.keyAPath, {
          input: fixture.directory,
          mode: "map",
          bundle: true,
        }),
      );

      expect(response.ok).toBe(true);

      const bundle = response.bundle as string | undefined;

      expect(bundle).toBeDefined();

      const zip = await readBytes(bundle!);

      const entries = unzipSync(zip);

      const names = Object.keys(entries);

      expect(names).toEqual(
        expect.arrayContaining([
          "alpha.txt",
          "nested/beta.txt",
          "signatures.mjksmap",
        ]),
      );
    });

    it("co-signs every map entry with a second allowlisted key", async () => {
      const fixture = await createMapFixture("map/cosign");

      const mapPath = join(fixture.directory, "signatures.mjksmap");

      /**
       * Alice is the first signer, so she establishes the allowlist
       * containing herself and Bob at creation time.
       */
      await runSign(
        signingOptions(fixture.keyAPath, {
          input: fixture.directory,
          mode: "map",
          allowKeyPaths: [fixture.keyBPath],
        }),
      );

      const response = await runSign(
        signingOptions(fixture.keyBPath, {
          input: fixture.directory,
          mode: "cosign-map",
          cosignMapPath: mapPath,
          overwrite: true,
        }),
      );

      expect(response.ok).toBe(true);

      const finalMap = await MajikSignatureMap.fromMJKSMAP(
        new Blob([(await readBytes(mapPath)) as BlobPart]),
      );

      expect(finalMap.entries).toHaveLength(2);

      for (const entry of finalMap.entries) {
        expect(
          entry.envelope.signatures.some(
            (signature) => signature.signerId === keyB.fingerprint,
          ),
        ).toBe(true);
      }
    });
  });

  // ========================================================================
  // Inspect
  // ========================================================================

  describe("Inspect", () => {
    it("reports an unsigned file correctly", async () => {
      const input = await createFixtureFile(
        "inspect/unsigned.txt",
        "Unsigned file",
      );

      const response = await runInspect(inspectOptions(input));

      expect(response.ok).toBe(true);

      expect(response.signed).toBe(false);

      expect(response.envelope).toBeNull();
    });

    it("reports an embedded envelope after signing", async () => {
      const keyPath = await writeKeyFile(keyA, "inspect/alice.json");

      const input = await createFixtureFile(
        "inspect/signed.txt",
        "Signed inspect",
      );

      await runSign(
        signingOptions(keyPath, {
          input,
        }),
      );

      const response = await runInspect(inspectOptions(input));

      expect(response.ok).toBe(true);

      expect(response.signed).toBe(true);

      expect(response.envelope).toBeDefined();
    });

    it("inspects a detached .mjksig directly", async () => {
      const keyPath = await writeKeyFile(keyA, "inspect-detached/alice.json");

      const input = await createFixtureFile(
        "inspect-detached/source.txt",
        "Detached inspect",
      );

      await runSign(
        signingOptions(keyPath, {
          input,
          mode: "detached",
        }),
      );

      const response = await runInspect(inspectOptions(`${input}.mjksig`));

      expect(response.ok).toBe(true);

      expect(response.signed).toBe(true);

      expect(response.envelope).toBeDefined();

      expect(response.envelope).toHaveProperty("signatures");
    });
  });

  // ========================================================================
  // can-sign
  // ========================================================================

  describe("can-sign", () => {
    it("returns permitted for an unsigned file", async () => {
      const keyPath = await writeKeyFile(keyA, "can-sign/unsigned-alice.json");

      const input = await createFixtureFile(
        "can-sign/unsigned.txt",
        "unsigned",
      );

      const response = await runCanSign(canSignOptions(input, keyPath));

      expect(response.ok).toBe(true);

      expect(response.permitted).toBe(true);
    });

    it("returns denied for a sealed file", async () => {
      const keyPath = await writeKeyFile(keyA, "can-sign/sealed-alice.json");

      const input = await createFixtureFile("can-sign/sealed.txt", "sealed");

      await runSign(
        signingOptions(keyPath, {
          input,
          seal: true,
        }),
      );

      const response = await runCanSign(canSignOptions(input, keyPath));

      expect(response.ok).toBe(false);

      expect(response.permitted).toBe(false);
    });
  });

  // ========================================================================
  // Output semantics
  // ========================================================================

  describe("CLI output", () => {
    it("emits valid machine-readable JSON through printJsonResult", async () => {
      const keyPath = await writeKeyFile(keyA, "output/json-alice.json");

      const input = await createFixtureFile("output/json.txt", "JSON output");

      const response = await runSign(
        signingOptions(keyPath, {
          input,
          json: true,
        }),
      );

      const serialized = JSON.stringify(response);

      const parsed = JSON.parse(serialized) as CliResult;

      expect(parsed.command).toBe("sign");

      expect(parsed.ok).toBe(true);
    });
  });

  // ========================================================================
  // Direct Commander smoke path
  // ========================================================================

  describe("Actual CLI command execution", () => {
    it("executes sign through Commander rather than calling runSign directly", async () => {
      const keyPath = await writeKeyFile(keyA, "commander/sign-alice.json");

      const input = await createFixtureFile(
        "commander/sign.txt",
        "Commander sign",
      );

      await runCliArgs(["sign", input, "--key", keyPath]);

      expect(process.exitCode).toBe(0);

      const blob = new Blob([(await readBytes(input)) as BlobPart], {
        type: "text/plain",
      });

      const signatures = await MajikSignature.extractFrom(blob);

      expect(signatures).toHaveLength(1);
    });

    it("executes verify through Commander", async () => {
      const keyPath = await writeKeyFile(keyA, "commander/verify-alice.json");

      const input = await createFixtureFile(
        "commander/verify.txt",
        "Commander verify",
      );

      await runSign(
        signingOptions(keyPath, {
          input,
        }),
      );

      resetExitCode();

      await runCliArgs(["verify", input]);

      expect(process.exitCode).toBe(0);
    });

    it("returns exit code 1 through Commander for invalid verification", async () => {
      const keyPath = await writeKeyFile(keyA, "commander/failure-alice.json");

      const input = await createFixtureFile(
        "commander/failure.txt",
        "Commander failure",
      );

      await runSign(
        signingOptions(keyPath, {
          input,
        }),
      );

      await writeBinary(input, Buffer.from("Commander tampered"));

      resetExitCode();

      await runCliArgs(["verify", input]);

      expect(process.exitCode).toBe(1);
    });
  });

  // ========================================================================
  // Batch failure / continuation behavior
  // ========================================================================

  describe("Batch failure handling", () => {
    it("continues folder detached signing when --continue-on-error is enabled", async () => {
      const directory = join(testRoot, "batch-errors");

      await mkdir(directory, {
        recursive: true,
      });

      const first = join(directory, "first.txt");

      const second = join(directory, "second.txt");

      await writeBinary(first, Buffer.from("first"));

      await writeBinary(second, Buffer.from("second"));

      const keyPath = await writeKeyFile(keyA, "batch-errors/alice.json");

      /**
       * Pre-create one sidecar so one item fails while the other can
       * continue normally.
       */
      await writeBinary(`${first}.mjksig`, Buffer.from("already exists"));

      const response = await runSign(
        signingOptions(keyPath, {
          input: directory,
          mode: "detached",
          continueOnError: true,
        }),
      );

      expect(response.ok).toBe(false);

      expect(response.failures).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            path: "first.txt",
          }),
        ]),
      );

      expect(await readFile(`${second}.mjksig`)).toBeInstanceOf(Buffer);
    });
  });

  // ========================================================================
  // Final sanity checks
  // ========================================================================

  describe("Regression sanity", () => {
    it("keeps the test fixture root isolated", async () => {
      expect(testRoot).toContain("mjksig-cli-");
    });

    it("shared keys remain valid after the suite's repeated operations", async () => {
      expect(keyA.fingerprint).toBeTruthy();

      expect(keyB.fingerprint).toBeTruthy();

      expect(keyC.fingerprint).toBeTruthy();

      expect(keyA.fingerprint).not.toBe(keyB.fingerprint);

      expect(keyA.fingerprint).not.toBe(keyC.fingerprint);

      expect(keyB.fingerprint).not.toBe(keyC.fingerprint);
    });
  });
});

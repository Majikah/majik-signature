/**
 * src/cli.ts
 */

import { Command } from "commander";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import {
  runCanSign,
  runInspect,
  runSeal,
  runSign,
  runVerify,
} from "./cli-core/operations";

import { printFailure, printJsonResult, printResult } from "./cli-core/output";

import { getPackageVersion } from "./cli-core/io";

import type {
  CanSignCliOptions,
  InspectCliOptions,
  SealCliOptions,
  SignCliOptions,
  VerifyCliOptions,
} from "./cli-core/types";

function parseCsv(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function collectValue(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function failUsage(message: string): never {
  console.error(`✘ ${message}`);
  process.exitCode = 2;
  throw new Error(message);
}

function normalizeSignOptions(
  input: string,
  options: Record<string, any>,
): SignCliOptions {
  const map = Boolean(options.map || options.mjksmap || options.asMap);

  const cosignMap = options.cosign ?? options.cosignMap;

  if (map && options.detached) {
    failUsage("--map and --detached cannot be combined.");
  }

  if (map && cosignMap) {
    failUsage("--map and --cosign cannot be combined.");
  }

  if (options.detached && cosignMap) {
    failUsage("--detached and --cosign cannot be combined.");
  }

  if (options.bundle && !map && !cosignMap) {
    failUsage("--bundle requires --map or --cosign.");
  }

  if (options.tsaToken && !options.detached && !cosignMap) {
    failUsage("--tsa-token requires --detached or --cosign.");
  }

  if (options.allowKey.length > 0 && cosignMap) {
    failUsage("--allow-key cannot be used with --cosign.");
  }

  let mode: "embedded" | "detached" | "map" | "cosign-map";

  if (cosignMap) {
    mode = "cosign-map";
  } else if (map) {
    mode = "map";
  } else if (options.detached) {
    mode = "detached";
  } else {
    mode = "embedded";
  }

  return {
    input,
    keyPath: options.key,
    mode,
    output: options.output,
    contentType: options.contentType,
    timestamp: options.timestamp,
    validUntil: options.validUntil,
    allowKeyPaths: options.allowKey ?? [],
    continueOnError: Boolean(options.continueOnError),
    bundle: Boolean(options.bundle),
    seal: Boolean(options.seal),
    tsaTokenPath: options.tsaToken,
    overwrite: Boolean(options.overwrite),
    json: Boolean(options.json),
    cosignMapPath: cosignMap,
  };
}

/**
 * Build the Commander application.
 *
 * This is deliberately exported so Vitest can exercise the actual CLI
 * parser without spawning a second Node process.
 */
export function createProgram(version = "test"): Command {
  const program = new Command();

  program
    .name("mjksig")
    .description(
      "Majik Signature CLI — hybrid Ed25519 + ML-DSA-87 file signing, verification, sealing, and MJKSMAP workflows.",
    )
    .version(version)
    .showHelpAfterError()
    .showSuggestionAfterError();

  program
    .command("sign <input>")
    .description("Sign a file or folder. Embedded signing is the default.")
    .requiredOption(
      "-k, --key <path>",
      "Majik Key JSON backup used for signing.",
    )
    .option("-o, --output <path>", "Output file or output directory.")
    .option("--detached")
    .option("--map")
    .option("--mjksmap")
    .option("--as-map")
    .option("--cosign <path>")
    .option("--cosign-map <path>")
    .option("--bundle")
    .option("--seal")
    .option("--content-type <mime>")
    .option("--timestamp <iso>")
    .option("--valid-until <iso>")
    .option(
      "--allow-key <path>",
      "Additional Majik Key JSON used for the signing allowlist.",
      collectValue,
      [],
    )
    .option("--tsa-token <path>")
    .option("--continue-on-error")
    .option("--overwrite")
    .option("--json")
    .action(async (input: string, options: Record<string, any>) => {
      const normalized = normalizeSignOptions(input, options);

      try {
        const response = await runSign(normalized);

        if (normalized.json) {
          printJsonResult(response);
        } else {
          printResult(response);
        }

        process.exitCode = response.ok ? 0 : 1;
      } catch (error) {
        printFailure(error);
        process.exitCode = 1;
      }
    });

  program
    .command("verify <input>")
    .description("Verify an embedded signature, detached .mjksig, or .mjksmap.")
    .option("-k, --key <path>")
    .option("--detached <path>")
    .option("--map <path>")
    .option(
      "--order <signers>",
      "Comma-separated signer fingerprints.",
      parseCsv,
      [],
    )
    .option("--strict")
    .option("--json")
    .action(async (input: string, options: Record<string, any>) => {
      const normalized: VerifyCliOptions = {
        input,
        keyPath: options.key,
        detachedPath: options.detached,
        mapPath: options.map,
        order: options.order ?? [],
        strict: Boolean(options.strict),
        json: Boolean(options.json),
      };

      try {
        const response = await runVerify(normalized);

        if (normalized.json) {
          printJsonResult(response);
        } else {
          printResult(response);
        }

        process.exitCode = response.ok ? 0 : 1;
      } catch (error) {
        printFailure(error);
        process.exitCode = 1;
      }
    });

  program
    .command("seal <input>")
    .description("Seal an embedded signature envelope or detached .mjksig.")
    .requiredOption(
      "-k, --key <path>",
      "Majik Key JSON backup used to apply the seal.",
    )
    .option("-o, --output <path>")
    .option("--timestamp <iso>")
    .option("--overwrite")
    .option("--json")
    .action(async (input: string, options: Record<string, any>) => {
      const normalized: SealCliOptions = {
        input,
        keyPath: options.key,
        output: options.output,
        timestamp: options.timestamp,
        overwrite: Boolean(options.overwrite),
        json: Boolean(options.json),
      };

      try {
        const response = await runSeal(normalized);

        if (normalized.json) {
          printJsonResult(response);
        } else {
          printResult(response);
        }

        process.exitCode = response.ok ? 0 : 1;
      } catch (error) {
        printFailure(error);
        process.exitCode = 1;
      }
    });

  program
    .command("can-sign <input>")
    .description("Check whether a Majik Key is permitted to sign a file.")
    .requiredOption("-k, --key <path>", "Majik Key JSON backup to test.")
    .option("--json")
    .action(async (input: string, options: Record<string, any>) => {
      const normalized: CanSignCliOptions = {
        input,
        keyPath: options.key,
        json: Boolean(options.json),
      };

      try {
        const response = await runCanSign(normalized);

        if (normalized.json) {
          printJsonResult(response);
        } else {
          printResult(response);
        }

        process.exitCode = response.ok ? 0 : 1;
      } catch (error) {
        printFailure(error);
        process.exitCode = 1;
      }
    });

  program
    .command("inspect <input>")
    .description(
      "Inspect a Majik Signature envelope without modifying the file.",
    )
    .option("--json")
    .action(async (input: string, options: Record<string, any>) => {
      const normalized: InspectCliOptions = {
        input,
        json: Boolean(options.json),
      };

      try {
        const response = await runInspect(normalized);

        if (normalized.json) {
          printJsonResult(response);
        } else {
          printResult(response);
        }

        process.exitCode = response.ok ? 0 : 1;
      } catch (error) {
        printFailure(error);
        process.exitCode = 1;
      }
    });

  return program;
}

/**
 * Production entrypoint.
 */
export async function main(argv = process.argv): Promise<void> {
  const version = await getPackageVersion();

  const program = createProgram(version);

  await program.parseAsync(argv);
}

/**
 * Only execute automatically when this file itself is invoked.
 *
 * Importing `src/cli.ts` from Vitest therefore does not start Commander.
 */
const isDirectExecution =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectExecution) {
  main().catch((error) => {
    printFailure(error);
    process.exitCode = 2;
  });
}

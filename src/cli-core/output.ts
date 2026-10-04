/**
 * src/cli/output.ts
 *
 * Human-readable and machine-readable result presentation.
 */

import type { CliResult } from "./types";

function stringifyValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean" ||
    value === null
  ) {
    return String(value);
  }

  return JSON.stringify(value, null, 2);
}

function printField(label: string, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }

  console.log(`${label.padEnd(18)} ${stringifyValue(value)}`);
}

export function printResult(result: CliResult): void {
  if (!result.ok) {
    console.error(`✘ ${result.message}`);
    return;
  }

  console.log(`→ ${result.message}`);

  if (result.command === "sign") {
    printField("Mode", result.mode);
    printField("Input", result.input);
    printField("Output", result.output);
    printField("Signer", result.signerId);
    printField("Algorithm", result.algorithm);
    printField("SHA-256", result.sha256);
    printField("SHA3-512", result.sha3_512);
    printField("Files", result.files);
    printField("Failures", result.failures);
    printField("Map", result.map);
    printField("Bundle", result.bundle);
    printField("Sealed", result.sealed);
    return;
  }

  if (result.command === "verify") {
    printField("Input", result.input);
    printField("Verdict", result.verdict);
    printField("Signatures", result.signatures);
    printField("Reason", result.reason);
    printField("Relocated From", result.relocatedFrom);
    printField("Map", result.map);
    printField("Files", result.files);
    printField("Missing", result.missing);
    return;
  }

  if (result.command === "seal") {
    printField("Input", result.input);
    printField("Output", result.output);
    printField("Sealed By", result.sealedBy);
    printField("Seal Timestamp", result.sealTimestamp);
    printField("Seal Hash", result.sealHash);
    return;
  }

  if (result.command === "can-sign") {
    printField("Input", result.input);
    printField("Permitted", result.permitted);
    printField("Reason", result.reason);
    return;
  }

  if (result.command === "inspect") {
    printField("Input", result.input);
    printField("Signed", result.signed);
    printField("Envelope", result.envelope);
    return;
  }

  for (const [key, value] of Object.entries(result)) {
    if (key === "ok" || key === "command" || key === "message") {
      continue;
    }

    printField(key, value);
  }
}

export function printJsonResult(result: CliResult): void {
  console.log(JSON.stringify(result, null, 2));
}

export function printFailure(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);

  console.error(`✘ ${message}`);
}

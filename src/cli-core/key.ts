/**
 * src/cli/key.ts
 *
 * Majik Key loading/unlocking for the npm CLI.
 *
 * The npm CLI intentionally consumes explicit JSON key backups instead of
 * reaching into the desktop application's account store.
 */

import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

import { MajikKey } from "@majikah/majik-key";

import { readJsonFile, resolveCliPath } from "./io.js";

export type LoadedMajikKey = MajikKey;

/**
 * Read a passphrase without echoing it to the terminal.
 *
 * On Windows and Unix terminals we use raw TTY mode rather than relying on
 * readline's normal line editor, which would echo characters.
 */
export async function promptForPassphrase(
  message = "Majik Key passphrase: ",
): Promise<string> {
  /**
   * Non-interactive automation must take precedence over TTY detection.
   *
   * Vitest, CI, npm scripts, pipes, and other non-interactive environments
   * do not expose stdin/stdout as TTYs, but MAJIK_KEY_PASSPHRASE is explicitly
   * supported for exactly these cases.
   */
  const envPassphrase = process.env.MAJIK_KEY_PASSPHRASE;

  if (envPassphrase !== undefined) {
    return envPassphrase;
  }

  /**
   * Only require a TTY when we actually need to ask the user interactively.
   */
  if (!input.isTTY || !output.isTTY) {
    throw new Error(
      "A passphrase is required, but stdin is not an interactive terminal. " +
        "Set MAJIK_KEY_PASSPHRASE for non-interactive use.",
    );
  }

  const rl = createInterface({
    input,
    output,
  });

  /**
   * readline does not provide a portable hidden-input switch.
   * Temporarily switch stdin to raw mode and collect characters ourselves.
   */
  rl.pause();

  return new Promise<string>((resolve, reject) => {
    const stdin = input;

    let value = "";
    let cleanedUp = false;

    const cleanup = () => {
      if (cleanedUp) return;
      cleanedUp = true;

      stdin.setRawMode?.(false);
      stdin.pause();
      stdin.removeListener("data", onData);

      try {
        rl.close();
      } catch {
        // Cleanup only.
      }

      process.stdout.write("\n");
    };

    const onData = (chunk: Buffer | string) => {
      const text = chunk.toString("utf8");

      for (const character of text) {
        if (character === "\u0003") {
          cleanup();
          reject(new Error("Operation cancelled."));
          return;
        }

        if (character === "\r" || character === "\n") {
          const result = value;
          cleanup();
          resolve(result);
          return;
        }

        if (character === "\u0008" || character === "\u007f") {
          value = value.slice(0, -1);
          continue;
        }

        value += character;
      }
    };

    try {
      process.stdout.write(message);

      stdin.setEncoding("utf8");
      stdin.setRawMode?.(true);
      stdin.resume();
      stdin.on("data", onData);
    } catch (error) {
      cleanup();
      reject(error);
    }
  });
}

function assertSupportedKeyPath(path: string): void {
  const lower = path.toLowerCase();

  if (lower.endsWith(".json")) {
    return;
  }

  if (lower.endsWith(".png")) {
    throw new Error(
      "PNG Majik Key backups are not supported by the current npm SDK CLI " +
        "because @majikah/majik-key does not currently expose the PNG-backup " +
        "restore API used by the desktop application. Use a .json backup.",
    );
  }

  throw new Error(
    `Unsupported Majik Key file "${path}". Expected a .json backup.`,
  );
}

/**
 * Load a MajikKey without unlocking it.
 *
 * This is used by verification and allowlist construction because those
 * operations only need public-key material.
 */
export async function loadMajikKey(keyPath: string): Promise<LoadedMajikKey> {
  const resolvedPath = resolveCliPath(keyPath);

  assertSupportedKeyPath(resolvedPath);

  const json = await readJsonFile(resolvedPath);

  try {
    return MajikKey.fromJSON(json as never);
  } catch (error) {
    throw new Error(
      `Failed to load Majik Key "${resolvedPath}": ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/**
 * Load and unlock a signing-capable MajikKey.
 *
 * Passphrase resolution order:
 *
 * 1. MAJIK_KEY_PASSPHRASE
 * 2. interactive hidden terminal prompt
 */
export async function loadSigningKey(keyPath: string): Promise<LoadedMajikKey> {
  const key = await loadMajikKey(keyPath);

  if (!key.hasSigningKeys) {
    throw new Error(
      "The supplied Majik Key does not contain Ed25519 + ML-DSA-87 signing keys.",
    );
  }

  if (!key.isUnlocked) {
    const passphrase = await promptForPassphrase();
    await key.unlock(passphrase);
  }

  if (!key.isUnlocked) {
    throw new Error("Majik Key remained locked after unlock.");
  }

  return key;
}

/**
 * Explicitly lock a key after the operation.
 */
export function lockKey(key: LoadedMajikKey): void {
  try {
    if (key.isUnlocked) {
      key.lock();
    }
  } catch {
    /**
     * Cleanup should never replace the original operation result/error.
     */
  }
}

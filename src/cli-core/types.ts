/**
 * src/cli/types.ts
 *
 * Internal types used by the Majik Signature CLI.
 *
 * These types deliberately represent CLI intent rather than the lower-level
 * SDK request objects. The CLI parses argv into these shapes and the operation
 * layer translates them into calls against MajikSignature.
 */

export type SignMode = "embedded" | "detached" | "map" | "cosign-map";

export interface SignCliOptions {
  input: string;
  keyPath: string;

  mode: SignMode;

  output?: string;

  contentType?: string;
  timestamp?: string;
  validUntil?: string;

  /**
   * Additional key files used to establish the expected-signer allowlist.
   *
   * The primary signing key is always included automatically.
   */
  allowKeyPaths: string[];

  /**
   * Apply the signing operation to all files in a folder, continuing after
   * individual failures.
   */
  continueOnError: boolean;

  /**
   * Create a bundle alongside an MJKSMAP.
   */
  bundle: boolean;

  /**
   * Apply a seal after signing.
   */
  seal: boolean;

  /**
   * TSA token JSON containing an already-issued MajikTimestamp.
   */
  tsaTokenPath?: string;

  /**
   * Permit replacing existing files.
   */
  overwrite: boolean;

  /**
   * Emit JSON instead of human-readable output.
   */
  json: boolean;

  /**
   * Existing map to cosign.
   */
  cosignMapPath?: string;
}

export interface VerifyCliOptions {
  input: string;

  /**
   * Optional MajikKey JSON used as a trusted verification key.
   *
   * When omitted, verification uses the public keys carried inside the
   * signature envelope.
   */
  keyPath?: string;

  /**
   * Detached .mjksig sidecar.
   */
  detachedPath?: string;

  /**
   * .mjksmap manifest.
   */
  mapPath?: string;

  /**
   * Ordered signer fingerprints.
   */
  order: string[];

  /**
   * When true, additional signers outside --order cause failure.
   */
  strict: boolean;

  json: boolean;
}

export interface SealCliOptions {
  input: string;
  keyPath: string;
  output?: string;
  timestamp?: string;
  overwrite: boolean;
  json: boolean;
}

export interface CanSignCliOptions {
  input: string;
  keyPath: string;
  json: boolean;
}

export interface InspectCliOptions {
  input: string;
  json: boolean;
}

export interface CliResult {
  ok: boolean;
  command: string;
  message: string;

  [key: string]: unknown;
}

export interface FolderFile {
  absolutePath: string;
  relativePath: string;
  blob: Blob;
  size: number;
  mimeType: string;
}

export interface VerificationFileResult {
  path: string;
  status: "verified" | "invalid" | "tampered" | "not_in_map";
  reason?: string;
  relocatedFrom?: string;
  signatures?: unknown[];
  order?: unknown;
}

/**
 * canonical.ts — "the bytes we verified are the bytes in the file"
 *
 * Root cause of the 0.4.1 append-after-signature bug: extract() and strip()
 * parsed the file independently and strip() silently discarded bytes it could
 * not account for, so the hashed bytes differed from the file's bytes.
 *
 * Rule enforced here, once, for EVERY format handler:
 *
 *   A file that carries an embedded envelope is only accepted if it is
 *   byte-identical to  handler.embed(handler.strip(file), envelopeJson).
 *
 * i.e. the file is exactly "original content + the envelope we would write
 * ourselves". Any extra, reordered, duplicated, or re-encoded byte — trailing
 * junk, a flipped header flag, a second envelope segment, a resized RIFF
 * header, a ZIP comment — makes the round trip differ and the file is rejected
 * instead of being verified against a normalised view of itself.
 *
 * This relies on embed() being deterministic (Office pins mtime + level).
 */

import type { FormatHandler } from "../types";
import { bufferEqual } from "./utils";

export type CanonicalResult =
  | { ok: true; original: Uint8Array }
  | { ok: false; reason: string };

/**
 * Embedded-envelope path. `raw` is what handler.extract(bytes) returned.
 * On success `original` is the exact byte string the signatures cover.
 */
export async function assertCanonical(
  handler: FormatHandler,
  bytes: Uint8Array,
  raw: string,
): Promise<CanonicalResult> {
  let original: Uint8Array;
  let rebuilt: Uint8Array;
  try {
    original = await handler.strip(bytes);
    rebuilt = await handler.embed(original, raw);
  } catch (err) {
    return {
      ok: false,
      reason: `File is not in canonical signed form (${handler.name}): ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }

  if (!bufferEqual(rebuilt, bytes)) {
    return {
      ok: false,
      reason:
        `File is not in canonical signed form (${handler.name}): it contains ` +
        `bytes outside the signed content and signature envelope ` +
        `(${bytes.length} bytes on disk, ${rebuilt.length} expected). ` +
        `It may have been modified after signing.`,
    };
  }
  return { ok: true, original };
}

export interface DetachedPrepareOptions {
  /**
   * Also require a file WITHOUT an embedded envelope to already be in the
   * handler's canonical form (strip(file) === file). Recommended wherever the
   * caller distributes the exact blob returned by signFileDetached(). Off by
   * default because canonicalising handlers (Office, WAV, MP3) normalise raw
   * files, so a raw Word-saved .docx is not byte-equal to its canonical form.
   */
  requireCanonical?: boolean;
  /** Throws when `raw` is not a structurally valid envelope. */
  validateEnvelope: (raw: string) => void;
}

/**
 * Detached-verification path. Returns the bytes the detached envelope's
 * signatures must cover.
 *
 * If the file also carries an embedded block we only discard it when it is a
 * valid envelope AND the file is canonical. A lone marker, or a well-formed
 * block holding junk, is never silently thrown away.
 */
export async function prepareDetachedBytes(
  handler: FormatHandler,
  bytes: Uint8Array,
  options: DetachedPrepareOptions,
): Promise<CanonicalResult> {
  const raw = await handler.extract(bytes);

  if (raw !== null) {
    try {
      options.validateEnvelope(raw);
    } catch {
      return {
        ok: false,
        reason:
          "The file ends with a signature-shaped block that is not a valid " +
          "envelope; refusing to ignore it. The file may have been modified.",
      };
    }
    return assertCanonical(handler, bytes, raw);
  }

  const stripped = await handler.strip(bytes);
  if (options.requireCanonical && !bufferEqual(stripped, bytes)) {
    return {
      ok: false,
      reason:
        `File is not in canonical form for ${handler.name} ` +
        `(${bytes.length} bytes on disk, ${stripped.length} canonical). ` +
        `Verify the exact blob returned by signFileDetached().`,
    };
  }
  return { ok: true, original: stripped };
}

/** Reason to report when extract() found no envelope. */
export function noSignatureReason(
  handler: FormatHandler,
  bytes: Uint8Array,
): string {
  return handler.diagnose?.(bytes) ?? "No embedded signature found";
}

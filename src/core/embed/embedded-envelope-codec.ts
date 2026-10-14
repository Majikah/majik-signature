/**
 * embedded-envelope-codec.ts
 *
 * Centralized codec for envelopes embedded in files.
 *
 * New writes use a version-tagged, Base64-transported CBOR envelope.
 * Existing JSON-serialized envelopes remain readable.
 *
 * This transport wrapper is separate from the MJKSIG binary container
 * header and from MAJIK_ENVELOPE_VERSION.
 */

import { MajikSignatureEnvelope } from "../envelope.js";
import { base64ToBytes, bytesToBase64 } from "../hash.js";
import { MajikSignatureSerializationError } from "../errors.js";
import { MJKSIG_CBOR_VERSION } from "../constants.js";

/**
 * Identifies a CBOR-encoded embedded envelope.
 *
 * Existing embedded JSON envelopes do not start with this prefix.
 */
export const EMBEDDED_CBOR_PREFIX = `MJKSIG:CBOR:${MJKSIG_CBOR_VERSION}:` as const;

const STRICT_BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Serialize an envelope for embedding in a format handler's text payload.
 *
 * The envelope uses its existing CBOR wire adapter. Base64 is only the
 * transport layer required by the current string-based FormatHandler API.
 */
export function serializeEmbeddedEnvelope(
  envelope: MajikSignatureEnvelope,
): string {
  const cbor = envelope.toCBOR();

  if (cbor.byteLength === 0) {
    throw new MajikSignatureSerializationError(
      "Cannot embed an empty CBOR envelope payload",
    );
  }

  return `${EMBEDDED_CBOR_PREFIX}${bytesToBase64(cbor)}`;
}

/**
 * Deserialize an embedded payload.
 *
 * Prefixed payloads are decoded as CBOR.
 * Unprefixed payloads use the legacy JSON parser.
 *
 * An invalid prefixed CBOR payload is rejected; it is never silently
 * retried as JSON.
 */
export function parseEmbeddedEnvelope(payload: string): MajikSignatureEnvelope {
  if (typeof payload !== "string") {
    throw new MajikSignatureSerializationError(
      "Embedded envelope payload must be a string",
    );
  }

  // Backward compatibility: old files contain JSON envelope text.
  if (!payload.startsWith(EMBEDDED_CBOR_PREFIX)) {
    return MajikSignatureEnvelope.fromJSON(payload);
  }

  const encoded = payload.slice(EMBEDDED_CBOR_PREFIX.length);

  if (
    encoded.length === 0 ||
    encoded.length % 4 !== 0 ||
    !STRICT_BASE64_PATTERN.test(encoded)
  ) {
    throw new MajikSignatureSerializationError(
      "Malformed embedded CBOR envelope: invalid Base64 payload",
    );
  }

  let cbor: Uint8Array;

  try {
    cbor = base64ToBytes(encoded);
  } catch (err) {
    throw new MajikSignatureSerializationError(
      "Malformed embedded CBOR envelope: failed to decode Base64",
      err,
    );
  }

  // Require canonical Base64 instead of accepting alternative encodings.
  if (bytesToBase64(cbor) !== encoded) {
    throw new MajikSignatureSerializationError(
      "Malformed embedded CBOR envelope: non-canonical Base64 encoding",
    );
  }

  return MajikSignatureEnvelope.fromCBOR(cbor);
}

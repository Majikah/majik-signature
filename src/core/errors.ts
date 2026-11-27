/**
 * errors.ts
 * MajikSignature error hierarchy.
 */

/** Base error class for validation, key, serialization, and verification failures. */
export class MajikSignatureError extends Error {
  /** Original lower-level error, when one was wrapped. */
  cause?: unknown;
  /** @param message Human-readable error description. @param cause Optional lower-level failure. */
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "MajikSignatureError";
    this.cause = cause;
  }
}

/** Raised when input or an API option does not satisfy the library's validation rules. */
export class MajikSignatureValidationError extends MajikSignatureError {
  field?: string;
  /** @param message Validation failure description. @param field Optional field/path associated with the failure. @param cause Optional underlying failure. */
  constructor(message: string, field?: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureValidationError";
    this.field = field;
  }
}

/** Raised when a verification operation fails unexpectedly rather than returning an invalid result. */
export class MajikSignatureVerificationError extends MajikSignatureError {
  /** @param message Verification failure description. @param cause Optional underlying failure. */
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureVerificationError";
  }
}

/** Raised when a required signing key or public-key representation is missing or unusable. */
export class MajikSignatureKeyError extends MajikSignatureError {
  /** @param message Key failure description. @param cause Optional lower-level failure. */
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureKeyError";
  }
}

/** Raised when JSON, Base64, CBOR, MJKSIG, or MJKSMAP input cannot be decoded or encoded. */
export class MajikSignatureSerializationError extends MajikSignatureError {
  /** @param message Serialization failure description. @param cause Optional decoder/encoder failure. */
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureSerializationError";
  }
}

/**
 * Raised when a signer attempts to sign an envelope with an allowlist and
 * their fingerprint and public keys are not included. The normal signing
 * APIs reject the key before using its secret material.
 */
export class MajikSignatureAllowlistError extends MajikSignatureError {
  /** The fingerprint of the signer that was rejected. */
  readonly signerId: string;
  /** @param message Allowlist rejection description. @param signerId Fingerprint of the rejected signer. @param cause Optional underlying failure. */
  constructor(message: string, signerId: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureAllowlistError";
    this.signerId = signerId;
  }
}

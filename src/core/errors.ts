/**
 * errors.ts
 * MajikSignature error hierarchy.
 */

export class MajikSignatureError extends Error {
  cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "MajikSignatureError";
    this.cause = cause;
  }
}

export class MajikSignatureValidationError extends MajikSignatureError {
  field?: string;
  constructor(message: string, field?: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureValidationError";
    this.field = field;
  }
}

export class MajikSignatureVerificationError extends MajikSignatureError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureVerificationError";
  }
}

export class MajikSignatureKeyError extends MajikSignatureError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureKeyError";
  }
}

export class MajikSignatureSerializationError extends MajikSignatureError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureSerializationError";
  }
}

/**
 * Thrown when a signer attempts to sign a file that has an allowlist
 * and their key (fingerprint + edPublicKey + mlDsaPublicKey) is not on it.
 * Raised before any cryptographic operation — the key is never used.
 */
export class MajikSignatureAllowlistError extends MajikSignatureError {
  /** The fingerprint of the signer that was rejected. */
  readonly signerId: string;
  constructor(message: string, signerId: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikSignatureAllowlistError";
    this.signerId = signerId;
  }
}

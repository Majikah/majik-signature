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

/**
 * Mink SDK Error Base Classes
 * @module errors/base
 */

/**
 * Base error class for all Mink SDK errors
 */
export class MinkError extends Error {
  /** Error code for programmatic handling */
  readonly code: string;
  /** Whether this error is retryable */
  readonly retryable: boolean;
  /** Original error that caused this error */
  readonly cause?: Error;

  constructor(
    message: string,
    code: string,
    options?: { retryable?: boolean; cause?: Error }
  ) {
    super(message);
    this.name = 'MinkError';
    this.code = code;
    this.retryable = options?.retryable ?? false;
    this.cause = options?.cause;

    // Maintains proper stack trace in V8
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Error thrown when wallet is not connected or not initialized
 */
export class WalletError extends MinkError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, 'WALLET_ERROR', options);
    this.name = 'WalletError';
  }
}

/**
 * Error thrown when SDK is not initialized
 */
export class InitializationError extends MinkError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, 'INITIALIZATION_ERROR', options);
    this.name = 'InitializationError';
  }
}

/**
 * Error thrown during encryption/decryption operations
 */
export class EncryptionError extends MinkError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, 'ENCRYPTION_ERROR', options);
    this.name = 'EncryptionError';
  }
}

/**
 * Error thrown during ZK proof generation
 */
export class ProofError extends MinkError {
  constructor(message: string, options?: { retryable?: boolean; cause?: Error }) {
    super(message, 'PROOF_ERROR', options);
    this.name = 'ProofError';
  }
}

/**
 * Error thrown during network/relayer communication
 */
export class NetworkError extends MinkError {
  /** HTTP status code if applicable */
  readonly statusCode?: number;

  constructor(
    message: string,
    options?: { statusCode?: number; retryable?: boolean; cause?: Error }
  ) {
    super(message, 'NETWORK_ERROR', {
      retryable: options?.retryable ?? true,
      cause: options?.cause,
    });
    this.name = 'NetworkError';
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown for transaction-related failures
 */
export class TransactionError extends MinkError {
  /** Transaction signature if available */
  readonly signature?: string;

  constructor(
    message: string,
    options?: { signature?: string; retryable?: boolean; cause?: Error }
  ) {
    super(message, 'TRANSACTION_ERROR', {
      retryable: options?.retryable ?? false,
      cause: options?.cause,
    });
    this.name = 'TransactionError';
    this.signature = options?.signature;
  }
}

/**
 * Error thrown when insufficient balance
 */
export class InsufficientBalanceError extends MinkError {
  readonly required: bigint;
  readonly available: bigint;

  constructor(required: bigint, available: bigint) {
    super(
      `Insufficient balance: need ${required}, have ${available}`,
      'INSUFFICIENT_BALANCE'
    );
    this.name = 'InsufficientBalanceError';
    this.required = required;
    this.available = available;
  }
}

/**
 * Error thrown when operation times out
 */
export class TimeoutError extends MinkError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, 'TIMEOUT_ERROR', { retryable: true, ...options });
    this.name = 'TimeoutError';
  }
}

/**
 * Error for invalid parameters
 */
export class ValidationError extends MinkError {
  readonly field?: string;

  constructor(message: string, options?: { field?: string; cause?: Error }) {
    super(message, 'VALIDATION_ERROR', options);
    this.name = 'ValidationError';
    this.field = options?.field;
  }
}

/**
 * No-op Logger Implementation
 * @module logger/noop
 */

import type { ILogger } from './interface.js';

/**
 * Logger that does nothing (default)
 */
export class NoopLogger implements ILogger {
  debug(): void {}
  info(): void {}
  warn(): void {}
  error(): void {}
}

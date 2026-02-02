/**
 * @minkprivacy/react
 *
 * React bindings for the Mink Privacy SDK.
 *
 * @packageDocumentation
 */

// Provider
export { MinkProvider, MinkContext, useMinkContext } from './provider/index.js';

// Hooks
export {
  useMink,
  useMinkBalance,
  useMinkEvents,
  useMinkEventHandlers,
  useMinkStatus,
  useMinkAuth,
  useMinkInbox,
  useAutoForward,
  type MinkEventHandler,
  type ForwardResult,
  type UseAutoForwardReturn,
  type UseAutoForwardOptions,
} from './hooks/index.js';

// Types
export type {
  MinkProviderProps,
  MinkContextValue,
  OperationStatus,
  UseBalanceOptions,
  UseBalanceResult,
  UseStatusResult,
  UseAuthResult,
  UseInboxResult,
} from './types/index.js';

// Re-export core types for convenience
export type {
  MinkConfig,
  BalanceResult,
  TokenBalanceResult,
  AllBalancesResult,
  DepositParams,
  DepositResult,
  WithdrawParams,
  WithdrawResult,
  FeeEstimate,
  TokenName,
  PrivateInbox,
  CreateInboxParams,
  MinkEventType,
  MinkEventPayloads,
} from '@minkprivacy/core';

export { MinkError } from '@minkprivacy/core';

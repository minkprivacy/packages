/**
 * React Package Types
 * @module types
 */

import type { MinkSDK, MinkConfig, MinkError, BalanceResult, TokenBalanceResult, TokenName } from '@minkprivacy/core';

/**
 * Mink provider props
 */
export interface MinkProviderProps {
  /** SDK configuration */
  config: MinkConfig;
  /** Children components */
  children: React.ReactNode;
  /** Auto-initialize when wallet connects */
  autoInitialize?: boolean;
}

/**
 * Mink context value
 */
export interface MinkContextValue {
  /** SDK instance */
  sdk: MinkSDK | null;
  /** Whether SDK is initialized */
  isInitialized: boolean;
  /** Whether SDK is initializing */
  isInitializing: boolean;
  /** Initialization error */
  error: MinkError | null;
  /** Initialize the SDK */
  initialize: () => Promise<void>;
  /** Current operation status */
  status: OperationStatus;
}

/**
 * Operation status
 */
export type OperationStatus =
  | 'idle'
  | 'initializing'
  | 'depositing'
  | 'withdrawing'
  | 'scanning'
  | 'error';

/**
 * Balance hook options
 */
export interface UseBalanceOptions {
  /** Token to get balance for */
  token?: TokenName;
  /** Auto-refetch interval in ms (0 = disabled) */
  refetchInterval?: number;
  /** Whether to enable the query */
  enabled?: boolean;
}

/**
 * Balance hook result
 */
export interface UseBalanceResult {
  /** Balance data */
  balance: BalanceResult | TokenBalanceResult | null;
  /** Whether loading */
  isLoading: boolean;
  /** Whether refetching */
  isRefetching: boolean;
  /** Error */
  error: MinkError | null;
  /** Refetch balance */
  refetch: () => Promise<void>;
}

/**
 * Status hook result
 */
export interface UseStatusResult {
  /** Current status */
  status: OperationStatus;
  /** Whether any operation is in progress */
  isOperating: boolean;
  /** Status message */
  message: string | null;
}

/**
 * Auth hook result
 */
export interface UseAuthResult {
  /** Whether authenticated */
  isAuthenticated: boolean;
  /** Whether authenticating */
  isAuthenticating: boolean;
  /** Auth error */
  error: MinkError | null;
  /** Authenticate with relayer */
  authenticate: () => Promise<boolean>;
  /** Logout */
  logout: () => void;
}

/**
 * Inbox hook result
 */
export interface UseInboxResult {
  /** All inboxes */
  inboxes: import('@minkprivacy/core').PrivateInbox[];
  /** Whether loading */
  isLoading: boolean;
  /** Whether generating proof */
  isGeneratingProof: boolean;
  /** Whether submitting to relayer */
  isSubmitting: boolean;
  /** Error */
  error: MinkError | null;
  /** Create new inbox */
  create: (params?: import('@minkprivacy/core').CreateInboxParams) => Promise<{ inbox: import('@minkprivacy/core').PrivateInbox; signature: string }>;
  /** Forward inbox funds */
  forward: (inbox: import('@minkprivacy/core').PrivateInbox) => Promise<string>;
  /** Refresh inbox */
  refresh: (inbox: import('@minkprivacy/core').PrivateInbox) => Promise<import('@minkprivacy/core').PrivateInbox>;
  /** Fetch inboxes from API/on-chain (auto-discovery) */
  fetchInboxes: () => Promise<void>;
}

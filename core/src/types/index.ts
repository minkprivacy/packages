/**
 * Mink SDK Types
 * @module types
 */

export type {
  NetworkType,
  NetworkConfig,
  MinkConfig,
  ResolvedMinkConfig,
} from './config.js';

export type {
  TransactionSigner,
  MessageSigner,
  AuthTokenGetter,
  WalletAdapter,
  TokenName,
  TokenInfo,
  EncryptionKey,
} from './wallet.js';

export type {
  MinkEventType,
  MinkEventPayloads,
  MinkEventHandler,
  EventListenerOptions,
} from './events.js';

export type {
  NumericInput,
  DepositParams,
  DepositTokenParams,
  DepositResult,
  WithdrawParams,
  WithdrawResult,
  BalanceResult,
  TokenBalanceResult,
  AllBalancesResult,
  FeeEstimate,
  UTXOData,
  PrivateInbox,
  CreateInboxParams,
  CreateInboxResult,
  SerializedViewingKey,
  ProofResult,
} from './operations.js';

export { InboxStatus, ViewingScope } from './operations.js';

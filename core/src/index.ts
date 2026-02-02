/**
 * Mink Core SDK
 *
 * Core library for private Solana transactions.
 *
 * @packageDocumentation
 */

// Main SDK class
export {
  createMinkSDK,
  MinkSDK,
  type CloakParams,
  type CloakTokenParams,
  type CloakResult,
  type RevealParams,
  type RevealResult,
  type StealthBalance,
} from './MinkSDK.js';

// Network configuration
export {
  DEVNET_CONFIG,
  MAINNET_CONFIG,
  NETWORKS,
  DEFAULT_NETWORK,
  getNetworkConfig,
  getExplorerTxUrl,
  getExplorerAddressUrl,
} from './network/index.js';
export type { NetworkType, NetworkConfig } from './network/index.js';

// Operations
export { deposit, depositToken } from './operations/deposit.js';
export type { DepositParams, DepositTokenParams } from './operations/deposit.js';
export { getBalanceFromUtxos, getUtxos, isUtxoSpent, localStorageKey } from './operations/balance.js';
export type { GetUtxosParams } from './operations/balance.js';
export { withdraw, clearRelayerConfigCache } from './operations/withdraw.js';
export type { WithdrawParams } from './operations/withdraw.js';

// Crypto
export { Keypair } from './crypto/keypair.js';
export { EncryptionService, fromHex, serializeProofAndExtData, sha256, toHex } from './crypto/encryption.js';
export {
  deriveEncPrivKey,
  deriveEncPubKey,
  ecdhSharedSecret,
  deriveBlinding,
  deriveEncryptionKey,
  generateEphemeralKeypair,
  secureZeroKey,
  encryptNoteV3,
  decryptNoteV3,
  isV3Format,
  deriveBlindingFromV3,
} from './crypto/ecdh.js';

// Models
export { createEmptyUtxo, Utxo } from './models/utxo.js';
export type { UtxoParams } from './models/utxo.js';

// Helpers
export {
  bytesToHex,
  calculateDepositFee,
  calculateWithdrawalFee,
  fetchMerkleProof,
  findCrossCheckNullifierPDAs,
  findNullifierPDAs,
  getAssociatedTokenAddress,
  getExtDataHash,
  getMintAddressField,
  getProgramAccounts,
  getTokenVaultAccounts,
  hexToBytes,
  queryRemoteTreeState,
  sleep,
} from './operations/helpers.js';

// Proofs
export { MerkleTree } from './merkle/tree.js';
export {
  parseProofToBytesArray,
  parseToBytesArray,
  prove,
  proveWithBasePath,
} from './proofs/prover.js';
export type { FullProveResult, Proof } from './proofs/prover.js';

// Storage
export { BrowserStorage } from './storage/browser.js';
export type { IStorage } from './storage/interface.js';

// Logger
export type { ILogger, LogLevel } from './logger/interface.js';
export { ConsoleLogger } from './logger/console.js';
export { NoopLogger } from './logger/noop.js';

// Errors
export {
  MinkError,
  WalletError,
  InitializationError,
  EncryptionError,
  ProofError,
  NetworkError,
  TransactionError,
  InsufficientBalanceError,
  TimeoutError,
  ValidationError,
} from './errors/index.js';
export { ErrorCodes } from './errors/codes.js';

// Events
export { TypedEventEmitter } from './events/emitter.js';

// Constants
export {
  CLOAK_IX_DISCRIMINATOR,
  CLOAK_TOKEN_IX_DISCRIMINATOR,
  DEFAULT_ALT_ADDRESS,
  DEFAULT_PROGRAM_ID,
  DEFAULT_RELAYER_API_URL,
  DEFAULT_ZK_ASSETS_PATH,
  FETCH_UTXOS_GROUP_SIZE,
  FIELD_SIZE,
  getTokenByMint,
  getTokenMint,
  LSK_ENCRYPTED_OUTPUTS,
  LSK_FETCH_OFFSET,
  MERKLE_TREE_DEPTH,
  RELAYER_API_URL,
  REVEAL_IX_DISCRIMINATOR,
  REVEAL_TOKEN_IX_DISCRIMINATOR,
  SIGN_MESSAGE,
  SOL_MINT_ADDRESS,
  SUPPORTED_TOKENS,
  TOKENS,
} from './crypto/constants.js';
export type { TokenInfo, TokenName } from './crypto/constants.js';

// Viewing Keys
export { ViewingKeyManager, ViewingScope } from './viewing-keys/manager.js';
export type { ViewingKey, SerializedViewingKey } from './viewing-keys/manager.js';

// Private Inbox
export { PrivateInboxManager, InboxStatus } from './inbox/manager.js';
export type { PrivateInbox, CreateInboxParams, InboxConfig } from './inbox/manager.js';

// Timestamp Manager
export { TimestampManager } from './timestamp/manager.js';
export type { UserTimestamp } from './timestamp/manager.js';

// Auth Manager
export { AuthManager } from './auth/manager.js';
export type { AuthTokenData, AuthManagerConfig } from './auth/manager.js';

// Types re-exports
export type {
  MinkConfig,
  ResolvedMinkConfig,
} from './types/config.js';
export type {
  TransactionSigner,
  MessageSigner,
  AuthTokenGetter,
  WalletAdapter,
  EncryptionKey,
} from './types/wallet.js';

// Operation types
export type {
  DepositResult,
  WithdrawResult,
  BalanceResult,
  TokenBalanceResult,
  AllBalancesResult,
  FeeEstimate,
  CreateInboxResult,
} from './types/operations.js';

// Event types
export type {
  MinkEventType,
  MinkEventPayloads,
  MinkEventHandler,
} from './types/events.js';

// Error codes (alias for backwards compatibility)
export { ErrorCodes as MinkErrorCode } from './errors/codes.js';
export type { ErrorCode } from './errors/codes.js';

// Alias for MinkNotInitializedError (backwards compatibility)
export { InitializationError as MinkNotInitializedError } from './errors/base.js';

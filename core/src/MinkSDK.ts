/**
 * Mink SDK - Main Class
 *
 * Browser-compatible SDK for private Solana transactions.
 * Cloak your SOL/tokens into the StealthVault, reveal them when needed.
 */

import { Connection, PublicKey, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { WasmFactory, type LightWasm } from '@lightprotocol/hasher.rs';
import { EncryptionService } from './crypto/encryption.js';
import { BrowserStorage } from './storage/browser.js';
import type { IStorage } from './storage/interface.js';
import { ConsoleLogger } from './logger/console.js';
import {
  getNetworkConfig,
  DEFAULT_NETWORK,
  type NetworkType,
  type NetworkConfig,
} from './network/presets.js';
import { deposit, depositToken } from './operations/deposit.js';
import { withdraw } from './operations/withdraw.js';
import { getUtxos, getBalanceFromUtxos } from './operations/balance.js';
import { type TokenName, getTokenMint } from './crypto/constants.js';
import { ViewingKeyManager, ViewingScope, type SerializedViewingKey } from './viewing-keys/manager.js';
import { PrivateInboxManager, type PrivateInbox, type CreateInboxParams } from './inbox/manager.js';
import { TimestampManager, type UserTimestamp } from './timestamp/manager.js';
import { Keypair } from './crypto/keypair.js';
import { TypedEventEmitter } from './events/emitter.js';
import type { MinkEventPayloads, MinkEventType } from './types/events.js';
import { AuthManager } from './auth/manager.js';

// SDK-specific types defined inline
interface PrivacySDKConfig {
  network?: NetworkType;
  rpcUrl?: string;
  connection?: Connection;
  programId?: PublicKey;
  altAddress?: PublicKey;
  relayerUrl?: string;
  zkAssetsPath?: string;
  onStatusChange?: (status: string) => void;
  getAuthToken?: AuthTokenGetter;
  debug?: boolean;
}

interface WalletAdapter {
  publicKey: PublicKey | null;
  signTransaction: TransactionSigner;
  signMessage: MessageSigner;
  connected?: boolean;
}

type TransactionSigner = (transaction: any) => Promise<any>;
type MessageSigner = (message: Uint8Array) => Promise<Uint8Array>;
type AuthTokenGetter = () => Promise<string>;

interface DepositResult {
  signature: string;
  amount: bigint;
  commitment: string;
}

interface WithdrawResult {
  signature: string;
  amount: bigint;
  fee: bigint;
  recipient: string;
  isPartial: boolean;
}

interface BalanceResult {
  lamports: number;
  sol: number;
}

// Logger instance
const logger = new ConsoleLogger({ prefix: '[Mink]', minLevel: 'info' });

// Re-export types with Mink naming
export type CloakResult = DepositResult;
export type RevealResult = WithdrawResult;
export type StealthBalance = BalanceResult;

export interface CloakParams {
  /** Amount in lamports */
  amount: number;
  /** Optional referrer address */
  referrer?: string;
}

export interface RevealParams {
  /** Amount in lamports */
  amount: number;
  /** Recipient address (defaults to connected wallet) */
  recipientAddress?: string;
  /** Optional referrer address */
  referrer?: string;
}

export interface CloakTokenParams {
  /** Token name: 'USDC' or 'USDT' */
  token: TokenName;
  /** Amount in base units (e.g., 1 USDC = 1_000_000) */
  amount: number;
  /** Optional referrer address */
  referrer?: string;
}

/**
 * Mink SDK
 *
 * Main entry point for private Solana transactions.
 * Use `cloak` to hide your funds, `reveal` to withdraw them.
 *
 * @example
 * ```typescript
 * import { MinkSDK } from '@minkprivacy/core';
 *
 * // Simple: use network preset
 * const sdk = new MinkSDK({ network: 'devnet' });
 *
 * // Or with custom RPC
 * const sdk = new MinkSDK({
 *   network: 'devnet',
 *   rpcUrl: 'https://my-rpc.com',
 * });
 *
 * // Initialize with wallet
 * await sdk.initialize(wallet);
 *
 * // Check stealth balance
 * const balance = await sdk.getStealthBalance();
 *
 * // Cloak 1 SOL (make private)
 * await sdk.cloak({ amount: 1_000_000_000 });
 *
 * // Reveal 0.5 SOL (withdraw)
 * await sdk.reveal({ amount: 500_000_000 });
 * ```
 */
export class MinkSDK {
  private network: NetworkType;
  private networkConfig: NetworkConfig;
  private connection: Connection;
  private programId: PublicKey;
  private altAddress: PublicKey;
  private relayerUrl: string;
  private zkAssetsPath: string;
  private storage: IStorage;
  private encryptionService: EncryptionService;
  private lightWasm: LightWasm | null = null;
  private publicKey: PublicKey | null = null;
  private signTransaction: TransactionSigner | null = null;
  private signMessage: MessageSigner | null = null;
  private onStatusChange?: (status: string) => void;
  private getAuthToken?: AuthTokenGetter;
  private initialized = false;

  // New managers for Private Inbox, Viewing Keys, and Timestamps
  private viewingKeyManager: ViewingKeyManager | null = null;
  private privateInboxManager: PrivateInboxManager | null = null;
  private timestampManager: TimestampManager | null = null;
  private spendingKeypair: Keypair | null = null;

  // Event emitter for SDK events
  private eventEmitter = new TypedEventEmitter<MinkEventPayloads>();

  // Auth manager
  private authManager: AuthManager | null = null;

  /**
   * Create a new MinkSDK instance
   *
   * @param config - SDK configuration. At minimum, specify `network: 'devnet'` or `network: 'mainnet'`
   */
  constructor(config: PrivacySDKConfig = {}) {
    // Get network config (defaults to devnet)
    this.network = config.network || DEFAULT_NETWORK;
    this.networkConfig = getNetworkConfig(this.network);

    // Create connection from config or network defaults
    if (config.connection) {
      this.connection = config.connection;
    } else {
      const rpcUrl = config.rpcUrl || this.networkConfig.rpcUrl;
      this.connection = new Connection(rpcUrl, 'confirmed');
    }

    // Use overrides or network defaults
    this.programId = config.programId || this.networkConfig.programId;
    this.altAddress = config.altAddress || this.networkConfig.altAddress;
    this.relayerUrl = config.relayerUrl || this.networkConfig.relayerUrl;
    this.zkAssetsPath = config.zkAssetsPath || this.networkConfig.zkAssetsPath;
    this.onStatusChange = config.onStatusChange;
    this.getAuthToken = config.getAuthToken;

    // Initialize storage and encryption service
    this.storage = new BrowserStorage('mink_');
    this.encryptionService = new EncryptionService();

    logger.info(`Mink SDK configured for ${this.network}`);
  }

  /**
   * Initialize the SDK with a wallet
   *
   * Must be called before any other operations.
   * Derives encryption keys from wallet signature.
   */
  async initialize(wallet: WalletAdapter): Promise<void> {
    logger.info('SDK initialize called');

    if (!wallet.publicKey) {
      throw new Error('Wallet not connected');
    }

    if (!wallet.signMessage) {
      throw new Error('Wallet does not support signMessage');
    }

    if (!wallet.signTransaction) {
      throw new Error('Wallet does not support signTransaction');
    }

    this.publicKey = wallet.publicKey;
    // Don't rebind - just use the function directly
    this.signTransaction = wallet.signTransaction;
    this.signMessage = wallet.signMessage;

    // Initialize WASM
    this.updateStatus('Initializing WASM...');
    logger.info('Loading WASM...');
    this.lightWasm = await WasmFactory.getInstance();
    logger.info('WASM loaded');

    // Derive encryption keys from wallet signature (uses cache if available)
    this.updateStatus('Deriving encryption keys...');
    logger.info('Deriving encryption keys...');
    await this.encryptionService.deriveEncryptionKeyFromWallet(
      this.signMessage,
      this.publicKey.toBase58()
    );
    logger.info('Encryption keys derived');

    // Initialize spending keypair and managers
    const utxoPrivateKey = this.encryptionService.getUtxoPrivateKey('v2');
    this.spendingKeypair = new Keypair(utxoPrivateKey, this.lightWasm);

    // Configure encPrivKey for V3 decryption (ECDH-based UTXOs from inbox forwards)
    // This is required to decrypt UTXOs created by forward_to_pool
    const { deriveEncPrivKey } = await import('./crypto/ecdh.js');
    const encPrivKey = deriveEncPrivKey(this.spendingKeypair.privkey);
    this.encryptionService.setEncPrivKey(encPrivKey);

    // Initialize ViewingKeyManager
    this.viewingKeyManager = new ViewingKeyManager(this.lightWasm, this.spendingKeypair);

    // Initialize AuthManager FIRST (needed by PrivateInboxManager)
    this.authManager = new AuthManager({
      relayerUrl: this.relayerUrl,
      onAuthenticated: () => {
        this.emit('auth:authenticated', { walletAddress: this.publicKey!.toBase58() });
      },
      onExpired: () => {
        this.emit('auth:expired', { walletAddress: this.publicKey!.toBase58() });
      },
    });

    // Initialize PrivateInboxManager
    // Use a getter that tries AuthManager first, then falls back to config
    this.privateInboxManager = new PrivateInboxManager({
      lightWasm: this.lightWasm,
      connection: this.connection,
      programId: this.programId,
      spendingKeypair: this.spendingKeypair,
      relayerUrl: this.relayerUrl,
      getAuthToken: async () => {
        // First try the built-in AuthManager
        const authToken = this.authManager?.getToken();
        if (authToken) {
          return authToken;
        }
        // Fall back to config-provided getter
        if (this.getAuthToken) {
          return this.getAuthToken();
        }
        throw new Error('Not authenticated. Call sdk.auth.authenticate() first.');
      },
    });

    // Initialize TimestampManager
    this.timestampManager = new TimestampManager({
      storage: this.storage,
      relayerUrl: this.relayerUrl,
      zkPubkey: this.spendingKeypair.pubkey.toString(),
    });

    this.initialized = true;
    this.updateStatus('SDK initialized');
    logger.info('Mink SDK initialized successfully');

    // Emit initialized event
    this.emit('initialized', { timestamp: Date.now() });
    this.emit('keysDerived', { zkPubkey: this.spendingKeypair.pubkey.toString() });
  }

  /**
   * Check if SDK is initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Get connected wallet public key
   */
  getPublicKey(): PublicKey | null {
    return this.publicKey;
  }

  // ============================================
  // EVENT EMITTER API
  // ============================================

  /**
   * Subscribe to an SDK event
   *
   * @param event - Event type
   * @param handler - Event handler
   * @returns Unsubscribe function
   */
  on<E extends MinkEventType>(
    event: E,
    handler: (payload: MinkEventPayloads[E]) => void
  ): () => void {
    return this.eventEmitter.on(event, handler);
  }

  /**
   * Unsubscribe from an SDK event
   *
   * @param event - Event type
   * @param handler - Event handler
   */
  off<E extends MinkEventType>(
    event: E,
    handler: (payload: MinkEventPayloads[E]) => void
  ): void {
    this.eventEmitter.off(event, handler);
  }

  /**
   * Subscribe to an SDK event (fires once)
   *
   * @param event - Event type
   * @param handler - Event handler
   * @returns Unsubscribe function
   */
  once<E extends MinkEventType>(
    event: E,
    handler: (payload: MinkEventPayloads[E]) => void
  ): () => void {
    return this.eventEmitter.once(event, handler);
  }

  /**
   * Emit an SDK event
   *
   * @param event - Event type
   * @param payload - Event payload
   */
  protected emit<E extends MinkEventType>(
    event: E,
    payload: MinkEventPayloads[E]
  ): void {
    this.eventEmitter.emit(event, payload);
  }

  // ============================================
  // AUTH API
  // ============================================

  /**
   * Auth manager for relayer authentication
   */
  get auth(): {
    isAuthenticated: () => boolean;
    authenticate: (signMessage: MessageSigner, walletAddress: string) => Promise<boolean>;
    logout: () => void;
    getToken: () => string | null;
  } {
    const manager = this.authManager;
    return {
      isAuthenticated: () => manager?.isAuthenticated() ?? false,
      authenticate: async (signMessage, walletAddress) => {
        if (!manager) return false;
        return manager.authenticate(signMessage, walletAddress);
      },
      logout: () => manager?.logout(),
      getToken: () => manager?.getToken() ?? null,
    };
  }

  // ============================================
  // INBOX API (Convenience Wrapper)
  // ============================================

  /**
   * Inbox manager for private inbox operations
   */
  get inbox(): {
    getAllInboxes: () => PrivateInbox[];
    getInboxes: (mint?: PublicKey) => Promise<PrivateInbox[]>;
    getPendingInboxes: (minAmount?: bigint) => Promise<PrivateInbox[]>;
    create: (params?: CreateInboxParams) => Promise<{ inbox: PrivateInbox; signature: string }>;
    forward: (inbox: PrivateInbox) => Promise<string>;
    refresh: (inbox: PrivateInbox) => Promise<PrivateInbox>;
  } {
    const manager = this.privateInboxManager;
    const self = this;
    return {
      getAllInboxes: () => manager?.getAllInboxes() ?? [],
      getInboxes: async (mint?) => {
        self.ensureInitialized();
        if (!manager) throw new Error('Inbox manager not initialized');
        return manager.getInboxes(mint);
      },
      getPendingInboxes: async (minAmount?) => {
        self.ensureInitialized();
        if (!manager) throw new Error('Inbox manager not initialized');
        return manager.getPendingInboxes(minAmount);
      },
      create: async (params?) => {
        self.ensureInitialized();
        if (!manager) throw new Error('Inbox manager not initialized');
        await self.recordFirstSeenTimestamp();
        self.emit('inbox:create:proofGenerating', { nonce: 0 });
        const result = await manager.createInbox(params ?? {});
        self.emit('inbox:created', { address: result.inbox.address.toBase58(), nonce: result.inbox.nonce });
        return result;
      },
      forward: async (inbox) => {
        self.ensureInitialized();
        if (!manager) throw new Error('Inbox manager not initialized');
        self.emit('inbox:forward:start', { inboxAddress: inbox.address.toBase58(), amount: BigInt(inbox.pendingBalance.toString()) });
        self.emit('inbox:forward:proofGenerating', { inboxAddress: inbox.address.toBase58(), amount: BigInt(inbox.pendingBalance.toString()) });
        try {
          const result = await manager.forwardToPool(inbox);
          self.emit('inbox:forward:proofGenerated', { inboxAddress: inbox.address.toBase58() });
          self.emit('inbox:forward:submitting', { inboxAddress: inbox.address.toBase58() });
          self.emit('inbox:forward:confirmed', { signature: result.signature, amount: BigInt(result.amountForwarded.toString()) });
          return result.signature;
        } catch (error) {
          self.emit('inbox:forward:proofGenerated', { inboxAddress: inbox.address.toBase58() });
          throw error;
        }
      },
      refresh: async (inbox) => {
        self.ensureInitialized();
        if (!manager) throw new Error('Inbox manager not initialized');
        return manager.refreshInbox(inbox);
      },
    };
  }

  // ============================================
  // CLEANUP
  // ============================================

  /**
   * Dispose of the SDK and clean up resources
   */
  dispose(): void {
    this.authManager?.dispose();
    this.authManager = null;
    this.privateInboxManager = null;
    this.viewingKeyManager = null;
    this.timestampManager = null;
    this.spendingKeypair = null;
    this.lightWasm = null;
    this.publicKey = null;
    this.signTransaction = null;
    this.signMessage = null;
    this.initialized = false;
    this.eventEmitter.removeAllListeners();
    this.emit('disposed', { timestamp: Date.now() });
    logger.info('SDK disposed');
  }

  // ============================================
  // PRIMARY API - Stealth Operations
  // ============================================

  /**
   * Cloak SOL into the StealthVault (make private)
   *
   * Converts public SOL to private UTXOs in the stealth pool.
   */
  async cloak(params: CloakParams): Promise<CloakResult> {
    this.ensureInitialized();

    // Record timestamp BEFORE the on-chain action (so UTXOs from this tx are included)
    await this.recordFirstSeenTimestamp();

    return deposit({
      publicKey: this.publicKey!,
      connection: this.connection,
      amountLamports: params.amount,
      storage: this.storage,
      encryptionService: this.encryptionService,
      zkAssetsPath: this.zkAssetsPath,
      lightWasm: this.lightWasm!,
      transactionSigner: this.signTransaction!,
      programId: this.programId,
      altAddress: this.altAddress,
      relayerUrl: this.relayerUrl,
      referrer: params.referrer,
      onStatusChange: this.onStatusChange,
      getAuthToken: this.getAuthTokenGetter(),
    });
  }

  /**
   * Cloak SPL tokens into the StealthVault (make private)
   *
   * Converts public SPL tokens to private UTXOs in the stealth pool.
   */
  async cloakToken(params: CloakTokenParams): Promise<CloakResult> {
    this.ensureInitialized();

    if (params.token === 'SOL') {
      throw new Error('Use cloak() for SOL deposits, not cloakToken()');
    }

    // Record timestamp BEFORE the on-chain action (so UTXOs from this tx are included)
    await this.recordFirstSeenTimestamp();

    // Get the correct mint for the network
    const networkType = this.network === 'mainnet' ? 'mainnet' : 'devnet';
    const mint = getTokenMint(params.token, networkType);

    return depositToken({
      publicKey: this.publicKey!,
      connection: this.connection,
      amount: params.amount,
      mint,
      storage: this.storage,
      encryptionService: this.encryptionService,
      zkAssetsPath: this.zkAssetsPath,
      lightWasm: this.lightWasm!,
      transactionSigner: this.signTransaction!,
      programId: this.programId,
      altAddress: this.altAddress,
      relayerUrl: this.relayerUrl,
      referrer: params.referrer,
      onStatusChange: this.onStatusChange,
      getAuthToken: this.getAuthTokenGetter(),
      tokenName: params.token,
    });
  }

  /**
   * Reveal SOL from the StealthVault (withdraw)
   *
   * Converts private UTXOs back to public SOL.
   */
  async reveal(params: RevealParams): Promise<RevealResult> {
    this.ensureInitialized();

    const recipient = params.recipientAddress
      ? new PublicKey(params.recipientAddress)
      : this.publicKey!;

    return withdraw({
      publicKey: this.publicKey!,
      connection: this.connection,
      amountLamports: params.amount,
      recipient,
      storage: this.storage,
      encryptionService: this.encryptionService,
      zkAssetsPath: this.zkAssetsPath,
      lightWasm: this.lightWasm!,
      programId: this.programId,
      altAddress: this.altAddress,
      relayerUrl: this.relayerUrl,
      referrer: params.referrer,
      onStatusChange: this.onStatusChange,
      getAuthToken: this.getAuthTokenGetter(),
    });
  }

  /**
   * Get stealth SOL balance
   *
   * Returns the total balance of private UTXOs owned by this wallet.
   */
  async getStealthBalance(): Promise<StealthBalance> {
    this.ensureInitialized();

    // Optimization: Skip UTXO fetch if user has never transacted
    if (!this.shouldFetchUtxos()) {
      logger.debug('No timestamp found - user has no UTXOs');
      return { lamports: 0, sol: 0 };
    }

    // Get timestamp for filtering
    const fromTimestamp = this.timestampManager?.getFirstSeenTimestamp() ?? undefined;

    const utxos = await getUtxos({
      publicKey: this.publicKey!,
      connection: this.connection,
      encryptionService: this.encryptionService,
      storage: this.storage,
      lightWasm: this.lightWasm!,
      programId: this.programId,
      relayerUrl: this.relayerUrl,
      fromTimestamp,
    });

    const { lamports } = getBalanceFromUtxos(utxos);

    return {
      lamports,
      sol: lamports / 1_000_000_000,
    };
  }

  /**
   * Get stealth balance for a specific SPL token
   *
   * Returns the total balance of private UTXOs for the specified token.
   *
   * @param token - Token name ('USDC', 'USDT') or mint address
   */
  async getStealthBalanceForToken(token: TokenName | string): Promise<{ amount: number; formatted: number }> {
    this.ensureInitialized();

    // Optimization: Skip UTXO fetch if user has never transacted
    if (!this.shouldFetchUtxos()) {
      logger.debug('No timestamp found - user has no UTXOs');
      return { amount: 0, formatted: 0 };
    }

    // Get the mint address
    let mint: string;
    let decimals = 6; // Default for stablecoins

    if (token === 'USDC' || token === 'USDT') {
      const networkType = this.network === 'mainnet' ? 'mainnet' : 'devnet';
      mint = getTokenMint(token, networkType).toBase58();
    } else {
      // Assume it's a mint address
      mint = token;
    }

    // Get timestamp for filtering
    const fromTimestamp = this.timestampManager?.getFirstSeenTimestamp() ?? undefined;

    const utxos = await getUtxos({
      publicKey: this.publicKey!,
      connection: this.connection,
      encryptionService: this.encryptionService,
      storage: this.storage,
      lightWasm: this.lightWasm!,
      programId: this.programId,
      relayerUrl: this.relayerUrl,
      mint,
      fromTimestamp,
    });

    const { lamports: amount } = getBalanceFromUtxos(utxos);

    return {
      amount,
      formatted: amount / Math.pow(10, decimals),
    };
  }

  /**
   * Get all stealth balances (SOL + all supported tokens)
   *
   * Returns balances for SOL and all configured SPL tokens.
   */
  async getAllStealthBalances(): Promise<{
    SOL: StealthBalance;
    USDC: { amount: number; formatted: number };
    USDT: { amount: number; formatted: number };
  }> {
    this.ensureInitialized();

    const [solBalance, usdcBalance, usdtBalance] = await Promise.all([
      this.getStealthBalance(),
      this.getStealthBalanceForToken('USDC'),
      this.getStealthBalanceForToken('USDT'),
    ]);

    return {
      SOL: solBalance,
      USDC: usdcBalance,
      USDT: usdtBalance,
    };
  }

  // ============================================
  // ALIASES - Familiar naming
  // ============================================

  /** @alias cloak - Deposit SOL into privacy pool */
  deposit = this.cloak.bind(this);

  /** @alias cloakToken - Deposit SPL tokens into privacy pool */
  depositToken = this.cloakToken.bind(this);

  /** @alias reveal - Withdraw SOL from privacy pool */
  withdraw = this.reveal.bind(this);

  /** @alias getStealthBalance */
  getPrivateBalance = this.getStealthBalance.bind(this);

  /**
   * Get private balance (React SDK compatible)
   *
   * @returns Balance result with bigint lamports
   */
  async getBalance(): Promise<{ lamports: bigint; sol: number }> {
    const balance = await this.getStealthBalance();
    return {
      lamports: BigInt(balance.lamports),
      sol: balance.sol,
    };
  }

  /**
   * Get private token balance (React SDK compatible)
   *
   * @param token - Token name
   * @returns Token balance result
   */
  async getTokenBalance(token: TokenName): Promise<{ amount: bigint; formatted: number; token: TokenName }> {
    const balance = await this.getStealthBalanceForToken(token);
    return {
      amount: BigInt(balance.amount),
      formatted: balance.formatted,
      token,
    };
  }

  // ============================================
  // PRIVATE INBOX API
  // ============================================

  /**
   * Create a new Private Inbox
   *
   * Private Inboxes are stealth addresses that receive tokens and
   * auto-forward them to the privacy pool.
   *
   * @param params - Optional inbox parameters
   */
  async createPrivateInbox(params?: CreateInboxParams): Promise<{ inbox: PrivateInbox; signature: string }> {
    this.ensureInitialized();

    if (!this.privateInboxManager) {
      throw new Error('PrivateInboxManager not initialized');
    }

    // Record timestamp BEFORE the on-chain action (so UTXOs from this tx are included)
    await this.recordFirstSeenTimestamp();

    this.updateStatus('Creating private inbox...');
    const result = await this.privateInboxManager.createInbox(params || {});

    this.updateStatus('Private inbox created');
    return result;
  }

  /**
   * Get all private inboxes for the current user
   *
   * @param mint - Optional token mint filter
   */
  async getPrivateInboxes(mint?: PublicKey): Promise<PrivateInbox[]> {
    this.ensureInitialized();

    if (!this.privateInboxManager) {
      throw new Error('PrivateInboxManager not initialized');
    }

    return this.privateInboxManager.getInboxes(mint);
  }

  /**
   * Get receive address for an inbox (for sharing with senders)
   */
  getInboxReceiveAddress(inbox: PrivateInbox): string {
    this.ensureInitialized();
    return this.privateInboxManager!.getReceiveAddress(inbox);
  }

  /**
   * Manually forward inbox balance to privacy pool
   */
  async forwardInboxToPool(inbox: PrivateInbox): Promise<{ signature: string }> {
    this.ensureInitialized();

    if (!this.privateInboxManager) {
      throw new Error('PrivateInboxManager not initialized');
    }

    this.updateStatus('Forwarding inbox to pool...');
    const result = await this.privateInboxManager.forwardToPool(inbox);
    this.updateStatus('Forward complete');

    return { signature: result.signature };
  }

  /**
   * Get pending inboxes with balance waiting to be forwarded
   *
   * Used for auto-forward functionality. Returns inboxes that have
   * pending balance above the minimum threshold.
   *
   * @param minAmount - Minimum pending balance in lamports (default: 1_000_000)
   */
  async getPendingInboxes(minAmount?: bigint): Promise<PrivateInbox[]> {
    this.ensureInitialized();

    if (!this.privateInboxManager) {
      throw new Error('PrivateInboxManager not initialized');
    }

    return this.privateInboxManager.getPendingInboxes(minAmount);
  }

  // ============================================
  // VIEWING KEYS API
  // ============================================

  /**
   * Get a viewing key for sharing with auditors/compliance
   *
   * @param scope - Viewing scope (Proxy, Pool, or Full)
   */
  async getViewingKey(scope: ViewingScope): Promise<SerializedViewingKey> {
    this.ensureInitialized();

    if (!this.viewingKeyManager) {
      throw new Error('ViewingKeyManager not initialized');
    }

    const viewingKey = this.viewingKeyManager.deriveViewingKey(scope);
    return this.viewingKeyManager.serializeViewingKey(viewingKey);
  }

  /**
   * Get viewing key for Private Inbox only
   */
  async getProxyViewingKey(): Promise<SerializedViewingKey> {
    return this.getViewingKey(ViewingScope.Proxy);
  }

  /**
   * Get viewing key for Privacy Pool only
   */
  async getPoolViewingKey(): Promise<SerializedViewingKey> {
    return this.getViewingKey(ViewingScope.Pool);
  }

  /**
   * Get full viewing key (both Proxy and Pool)
   */
  async getFullViewingKey(): Promise<SerializedViewingKey> {
    return this.getViewingKey(ViewingScope.Full);
  }

  // ============================================
  // TIMESTAMP / IDENTITY API
  // ============================================

  /**
   * Get user's timestamp (first interaction time)
   *
   * Returns null if user has never transacted.
   */
  async getUserTimestamp(): Promise<UserTimestamp | null> {
    this.ensureInitialized();

    if (!this.timestampManager) {
      throw new Error('TimestampManager not initialized');
    }

    return this.timestampManager.getTimestamp();
  }

  /**
   * Check if user should fetch UTXOs
   *
   * Returns false if user has never transacted (no need to scan).
   */
  shouldFetchUtxos(): boolean {
    this.ensureInitialized();
    return this.timestampManager?.shouldFetchUtxos() ?? false;
  }

  /**
   * Get the ZK public key for this wallet
   */
  getZkPubkey(): string | null {
    if (!this.spendingKeypair) {
      return null;
    }
    return this.spendingKeypair.pubkey.toString();
  }

  // ============================================
  // CACHE MANAGEMENT
  // ============================================

  /**
   * Clear cached UTXOs and fetch fresh data
   */
  clearCache(): void {
    if (this.publicKey) {
      const prefix = this.programId.toString().substring(0, 6) + this.publicKey.toString();
      this.storage.removeItem('fetch_offset' + prefix);
      this.storage.removeItem('encrypted_outputs' + prefix);
      this.storage.removeItem('tradeHistory' + prefix);
    }
    logger.info('Cache cleared');
  }

  /**
   * Clear encryption key cache (will require re-signing on next init)
   */
  clearEncryptionCache(): void {
    if (this.publicKey) {
      this.encryptionService.clearCache(this.publicKey.toBase58());
    }
    logger.info('Encryption cache cleared');
  }

  // ============================================
  // CONFIGURATION & UTILITIES
  // ============================================

  /**
   * Get relayer config (fee rates, etc.)
   * Returns fee rate in basis points and rent fee in lamports to match on-chain calculation
   */
  async getRelayerConfig(): Promise<{
    withdraw_fee_rate_bps: number;
    withdraw_rent_fee: number;
  }> {
    try {
      const response = await fetch(`${this.relayerUrl}/config`);
      if (response.ok) {
        const responseJson = await response.json() as { success?: boolean; data?: Record<string, unknown> } & Record<string, unknown>;

        // Handle both envelope format {success, data} and direct format
        const config = responseJson.data ?? responseJson;

        const rawRate = typeof config.withdraw_fee_rate === 'number' ? config.withdraw_fee_rate : 50;

        // Convert to basis points if needed
        let feeRateBps: number;
        if (rawRate < 1) {
          // Decimal format (e.g., 0.005 = 0.5%) - convert to basis points
          feeRateBps = Math.round(rawRate * 10000);
        } else {
          // Already in basis points
          feeRateBps = rawRate;
        }

        // Rent fee in lamports (default to 2M lamports = 0.002 SOL to cover nullifier rents + tx fee)
        const rentFee = typeof config.withdraw_rent_fee === 'number' ? config.withdraw_rent_fee : 2_000_000;

        return { withdraw_fee_rate_bps: feeRateBps, withdraw_rent_fee: rentFee };
      }
    } catch {
      // Fallback to defaults
    }
    return { withdraw_fee_rate_bps: 50, withdraw_rent_fee: 2_000_000 }; // 0.5% + 0.002 SOL default
  }

  /**
   * Calculate reveal fee for a given amount
   * Matches on-chain calculation: fee = (amount * rate / 10000) + rent_fee
   */
  async calculateRevealFee(amountLamports: number): Promise<{
    feeLamports: number;
    feeSol: number;
    netAmountLamports: number;
    netAmountSol: number;
  }> {
    const config = await this.getRelayerConfig();
    // Match on-chain: fee = (amount * rate / 10000) + rent_fee
    const percentageFee = Math.floor(amountLamports * config.withdraw_fee_rate_bps / 10000);
    const feeLamports = percentageFee + config.withdraw_rent_fee;
    return {
      feeLamports,
      feeSol: feeLamports / LAMPORTS_PER_SOL,
      netAmountLamports: amountLamports - feeLamports,
      netAmountSol: (amountLamports - feeLamports) / LAMPORTS_PER_SOL,
    };
  }

  /** @alias calculateRevealFee */
  calculateWithdrawFee = this.calculateRevealFee.bind(this);

  /**
   * Set custom logger function (no-op, use ConsoleLogger directly)
   */
  setLogger(_loggerFn: unknown): void {
    // No-op: logger is configured via ConsoleLogger
  }

  /**
   * Enable/disable debug logging (no-op, configure ConsoleLogger directly)
   */
  setDebug(_enabled: boolean): void {
    // No-op: configure ConsoleLogger minLevel directly
  }

  /**
   * Get current network
   */
  getNetwork(): NetworkType {
    return this.network;
  }

  /**
   * Get network config
   */
  getNetworkConfig(): NetworkConfig {
    return this.networkConfig;
  }

  /**
   * Get SDK configuration
   */
  getConfig(): {
    network: NetworkType;
    programId: string;
    altAddress: string;
    relayerUrl: string;
    zkAssetsPath: string;
  } {
    return {
      network: this.network,
      programId: this.programId.toString(),
      altAddress: this.altAddress.toString(),
      relayerUrl: this.relayerUrl,
      zkAssetsPath: this.zkAssetsPath,
    };
  }

  // ============================================
  // INTERNAL
  // ============================================

  /**
   * Record the first seen timestamp if not already set.
   * This should be called BEFORE any on-chain action so that
   * UTXOs created by that action are included in future scans.
   */
  private async recordFirstSeenTimestamp(): Promise<void> {
    if (!this.timestampManager) {
      return;
    }

    const existing = await this.timestampManager.getTimestamp();
    if (existing) {
      // Already has a timestamp, no need to record
      return;
    }

    // First interaction - get current slot/time BEFORE the transaction
    const slot = await this.connection.getSlot();
    const blockTime = await this.connection.getBlockTime(slot);

    if (blockTime) {
      await this.timestampManager.saveTimestamp(
        TimestampManager.createTimestamp(
          this.spendingKeypair!.pubkey.toString(),
          slot,
          blockTime
        )
      );
      logger.debug(`Recorded first seen timestamp: slot=${slot}, time=${blockTime}`);
    }
  }

  /**
   * Get auth token getter function that tries AuthManager first, then config
   */
  private getAuthTokenGetter(): AuthTokenGetter | undefined {
    // If we have AuthManager with a valid token, use it
    if (this.authManager?.isAuthenticated()) {
      return async () => {
        const token = this.authManager?.getToken();
        if (token) return token;
        // Fall back to config if AuthManager token expired
        if (this.getAuthToken) return this.getAuthToken();
        throw new Error('Not authenticated. Call sdk.auth.authenticate() first.');
      };
    }
    // Fall back to config-provided getter
    return this.getAuthToken;
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('SDK not initialized. Call initialize() first.');
    }

    if (!this.publicKey) {
      throw new Error('Wallet not connected');
    }

    if (!this.lightWasm) {
      throw new Error('WASM not loaded');
    }

    if (!this.encryptionService.isInitialized()) {
      throw new Error('Encryption service not initialized');
    }
  }

  private updateStatus(status: string): void {
    logger.debug(status);
    this.onStatusChange?.(status);
  }
}

/**
 * Create a new MinkSDK instance (convenience function)
 */
export function createMinkSDK(config: PrivacySDKConfig): MinkSDK {
  return new MinkSDK(config);
}

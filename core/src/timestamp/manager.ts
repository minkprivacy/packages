/**
 * Timestamp Manager for Privacy SDK
 *
 * Tracks the first interaction timestamp for a ZK identity.
 * This enables efficient UTXO scanning by filtering out UTXOs
 * created before the user's first transaction.
 *
 * Timestamp flow:
 * 1. On first transaction, timestamp is recorded on-chain and locally
 * 2. When fetching UTXOs, SDK first checks local timestamp
 * 3. If no local timestamp, SDK queries relayer (might be new device)
 * 4. If no timestamp anywhere, user has no UTXOs (no need to fetch)
 * 5. When fetching, use from_timestamp parameter to filter on backend
 */

import type { IStorage } from '../storage/interface.js';
import { ConsoleLogger } from '../logger/console.js';

const logger = new ConsoleLogger({ prefix: '[Mink]', minLevel: 'info' });

/**
 * User timestamp data
 */
export interface UserTimestamp {
  /** ZK public key */
  zkPubkey: string;
  /** First seen slot number */
  firstSeenSlot: number;
  /** First seen Unix timestamp (seconds) */
  firstSeenTimestamp: number;
  /** Total transaction count */
  txCount: number;
}

/**
 * Local storage key prefix for timestamps
 */
const TIMESTAMP_STORAGE_KEY = 'mink_user_timestamp_';

/**
 * Manager for user identity timestamps
 *
 * This enables UTXO scanning optimization:
 * - Only fetch UTXOs created after user's first interaction
 * - Skip fetching entirely if user has never transacted
 */
export class TimestampManager {
  private storage: IStorage;
  private relayerUrl: string;
  private localTimestamp: UserTimestamp | null = null;
  private zkPubkey: string;

  constructor(params: {
    storage: IStorage;
    relayerUrl: string;
    zkPubkey: string;
  }) {
    this.storage = params.storage;
    this.relayerUrl = params.relayerUrl;
    this.zkPubkey = params.zkPubkey;

    // Load from local storage on init
    this.loadFromLocal();
  }

  /**
   * Get storage key for this zkPubkey
   */
  private getStorageKey(): string {
    return TIMESTAMP_STORAGE_KEY + this.zkPubkey;
  }

  /**
   * Load timestamp from local storage
   */
  private loadFromLocal(): void {
    try {
      const stored = this.storage.getItem(this.getStorageKey());
      if (stored) {
        this.localTimestamp = JSON.parse(stored) as UserTimestamp;
        logger.debug(`Loaded local timestamp: ${this.localTimestamp.firstSeenTimestamp}`);
      }
    } catch (error) {
      logger.debug(`Failed to load local timestamp: ${error}`);
    }
  }

  /**
   * Save timestamp to local storage
   */
  private saveToLocal(timestamp: UserTimestamp): void {
    try {
      this.storage.setItem(this.getStorageKey(), JSON.stringify(timestamp));
      this.localTimestamp = timestamp;
      logger.debug(`Saved local timestamp: ${timestamp.firstSeenTimestamp}`);
    } catch (error) {
      logger.warn(`Failed to save local timestamp: ${error}`);
    }
  }

  /**
   * Get timestamp for the user
   *
   * Priority:
   * 1. Local storage (fast, no network)
   * 2. Relayer API (for new devices)
   * 3. Returns null if user never transacted
   *
   * @returns User timestamp or null if never transacted
   */
  async getTimestamp(): Promise<UserTimestamp | null> {
    // Check local cache first
    if (this.localTimestamp) {
      return this.localTimestamp;
    }

    // Query relayer
    try {
      const response = await fetch(
        `${this.relayerUrl}/identity/timestamp?zkPubkey=${encodeURIComponent(this.zkPubkey)}`,
        { method: 'GET' }
      );

      if (!response.ok) {
        if (response.status === 404) {
          // User has never transacted
          logger.debug('User has no timestamp (never transacted)');
          return null;
        }
        throw new Error(`Relayer returned ${response.status}`);
      }

      const result = await response.json() as {
        success: boolean;
        data: UserTimestamp | null;
      };

      if (!result.success || !result.data) {
        return null;
      }

      // Save to local storage for future use
      this.saveToLocal(result.data);

      return result.data;
    } catch (error) {
      logger.warn(`Failed to fetch timestamp from relayer: ${error}`);
      // Return local cache if available, even if stale
      return this.localTimestamp;
    }
  }

  /**
   * Save timestamp after first transaction
   *
   * This should be called after the user's first deposit or inbox registration.
   * The timestamp is immutable - it won't be updated if already set.
   *
   * @param timestamp - Timestamp data from the transaction
   */
  async saveTimestamp(timestamp: UserTimestamp): Promise<void> {
    // Don't overwrite existing timestamp (it's immutable)
    if (this.localTimestamp) {
      logger.debug('Timestamp already exists, not updating');
      return;
    }

    // Validate zkPubkey matches
    if (timestamp.zkPubkey !== this.zkPubkey) {
      throw new Error('zkPubkey mismatch');
    }

    this.saveToLocal(timestamp);
  }

  /**
   * Check if SDK should fetch UTXOs
   *
   * IMPORTANT: If the user has no timestamp, they have never transacted,
   * so there's no need to try decrypting any UTXOs.
   *
   * @returns true if should fetch, false if no need (no transactions)
   */
  shouldFetchUtxos(): boolean {
    return this.localTimestamp !== null;
  }

  /**
   * Get the first seen timestamp for UTXO filtering
   *
   * @returns Unix timestamp in seconds, or null if not set
   */
  getFirstSeenTimestamp(): number | null {
    return this.localTimestamp?.firstSeenTimestamp ?? null;
  }

  /**
   * Get the first seen slot for on-chain filtering
   *
   * @returns Slot number, or null if not set
   */
  getFirstSeenSlot(): number | null {
    return this.localTimestamp?.firstSeenSlot ?? null;
  }

  /**
   * Get transaction count
   *
   * @returns Number of transactions, or 0 if not tracked
   */
  getTxCount(): number {
    return this.localTimestamp?.txCount ?? 0;
  }

  /**
   * Increment transaction count locally
   * This is a hint; the authoritative count is on-chain
   */
  incrementTxCount(): void {
    if (this.localTimestamp) {
      this.localTimestamp.txCount += 1;
      this.saveToLocal(this.localTimestamp);
    }
  }

  /**
   * Clear local timestamp cache
   * Use this when switching wallets or for debugging
   */
  clearCache(): void {
    this.storage.removeItem(this.getStorageKey());
    this.localTimestamp = null;
    logger.debug('Cleared local timestamp cache');
  }

  /**
   * Create timestamp from transaction data
   *
   * @param slot - Solana slot number
   * @param blockTime - Unix timestamp from block
   */
  static createTimestamp(
    zkPubkey: string,
    slot: number,
    blockTime: number
  ): UserTimestamp {
    return {
      zkPubkey,
      firstSeenSlot: slot,
      firstSeenTimestamp: blockTime,
      txCount: 1,
    };
  }

  /**
   * Check if a timestamp is valid
   */
  static isValidTimestamp(timestamp: unknown): timestamp is UserTimestamp {
    if (typeof timestamp !== 'object' || timestamp === null) {
      return false;
    }

    const ts = timestamp as Record<string, unknown>;

    return (
      typeof ts.zkPubkey === 'string' &&
      typeof ts.firstSeenSlot === 'number' &&
      typeof ts.firstSeenTimestamp === 'number' &&
      typeof ts.txCount === 'number'
    );
  }
}

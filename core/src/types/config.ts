/**
 * Mink SDK Configuration Types
 * @module types/config
 */

import type { Connection, PublicKey } from '@solana/web3.js';
import type { IStorage } from '../storage/interface.js';
import type { ILogger } from '../logger/interface.js';

/**
 * Network type for Mink SDK
 */
export type NetworkType = 'devnet' | 'mainnet';

/**
 * Network configuration
 */
export interface NetworkConfig {
  /** Network identifier */
  network: NetworkType;
  /** Solana cluster */
  cluster: 'devnet' | 'mainnet-beta';
  /** Default RPC URL */
  rpcUrl: string;
  /** Program ID */
  programId: PublicKey;
  /** Address Lookup Table */
  altAddress: PublicKey;
  /** Relayer API URL */
  relayerUrl: string;
  /** ZK assets base URL */
  zkAssetsUrl: string;
  /** Explorer URL base */
  explorerUrl: string;
}

/**
 * Mink SDK Configuration
 */
export interface MinkConfig {
  /** Network to use: 'devnet' or 'mainnet' */
  network: NetworkType;

  /** Custom RPC URL (overrides network default) */
  rpcUrl?: string;

  /** Custom Solana connection (overrides rpcUrl) */
  connection?: Connection;

  /** Program ID (overrides network default) */
  programId?: PublicKey;

  /** Relayer API URL (overrides network default) */
  relayerUrl?: string;

  /** ZK assets base URL (overrides network default) */
  zkAssetsUrl?: string;

  /** Address Lookup Table (overrides network default) */
  altAddress?: PublicKey;

  /** Storage adapter (default: MemoryStorage) */
  storage?: IStorage;

  /** Logger instance (default: NoopLogger) */
  logger?: ILogger;

  /** Enable debug mode */
  debug?: boolean;
}

/**
 * Resolved SDK configuration with all defaults applied
 */
export interface ResolvedMinkConfig {
  network: NetworkType;
  connection: Connection;
  programId: PublicKey;
  altAddress: PublicKey;
  relayerUrl: string;
  zkAssetsUrl: string;
  storage: IStorage;
  logger: ILogger;
  debug: boolean;
}

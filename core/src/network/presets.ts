/**
 * Network Configuration
 *
 * Defines network-specific settings for devnet and mainnet.
 * Program ID is the same across networks.
 */

import { PublicKey, clusterApiUrl } from "@solana/web3.js";

export type NetworkType = "devnet" | "mainnet";

export interface NetworkConfig {
  /** Network identifier */
  network: NetworkType;
  /** Solana cluster */
  cluster: "devnet" | "mainnet-beta";
  /** Default RPC URL */
  rpcUrl: string;
  /** Program ID (same across networks) */
  programId: PublicKey;
  /** Address Lookup Table */
  altAddress: PublicKey;
  /** Relayer API URL */
  relayerUrl: string;
  /** Default ZK assets path */
  zkAssetsPath: string;
  /** Explorer URL base */
  explorerUrl: string;
}

// Program ID is the same for both networks
const PROGRAM_ID = new PublicKey("MinkoCW871q3LjoJ1yHuGikT1BwgyeP1VimZha5ecm6");

/**
 * Devnet configuration
 */
export const DEVNET_CONFIG: NetworkConfig = {
  network: "devnet",
  cluster: "devnet",
  rpcUrl: clusterApiUrl("devnet"),
  programId: PROGRAM_ID,
  altAddress: new PublicKey("J46Z1ZoTsZ9qc3HAPQVEH8mSaPn1GjjtZvNQwyGs9xxA"),
  relayerUrl: "https://devnet-api.minkprivacy.com",
  zkAssetsPath: "https://cdn.minkprivacy.com/zk-assets",
  explorerUrl: "https://explorer.solana.com",
};

/**
 * Mainnet configuration
 */
export const MAINNET_CONFIG: NetworkConfig = {
  network: "mainnet",
  cluster: "mainnet-beta",
  rpcUrl: clusterApiUrl("mainnet-beta"),
  programId: PROGRAM_ID,
  altAddress: new PublicKey("8DEtfaht61uEgqJAPfXdvYHQFsnpS4puBJg1vm8ScVd2"),
  relayerUrl: "https://api.minkprivacy.com",
  zkAssetsPath: "https://cdn.minkprivacy.com/zk-assets",
  explorerUrl: "https://explorer.solana.com",
};

/**
 * All network configs
 */
export const NETWORKS: Record<NetworkType, NetworkConfig> = {
  devnet: DEVNET_CONFIG,
  mainnet: MAINNET_CONFIG,
};

/**
 * Get network config by name
 */
export function getNetworkConfig(network: NetworkType): NetworkConfig {
  const config = NETWORKS[network];
  if (!config) {
    throw new Error(`Unknown network: ${network}. Use 'devnet' or 'mainnet'.`);
  }
  return config;
}

/**
 * Get explorer URL for transaction
 */
export function getExplorerTxUrl(
  signature: string,
  network: NetworkType,
): string {
  const config = getNetworkConfig(network);
  const suffix = network === "devnet" ? "?cluster=devnet" : "";
  return `${config.explorerUrl}/tx/${signature}${suffix}`;
}

/**
 * Get explorer URL for address
 */
export function getExplorerAddressUrl(
  address: string,
  network: NetworkType,
): string {
  const config = getNetworkConfig(network);
  const suffix = network === "devnet" ? "?cluster=devnet" : "";
  return `${config.explorerUrl}/address/${address}${suffix}`;
}

/**
 * Default network (for development)
 */
export const DEFAULT_NETWORK: NetworkType = "devnet";

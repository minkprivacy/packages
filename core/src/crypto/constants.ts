import { PublicKey } from '@solana/web3.js';
import BN from 'bn.js';
import { DEVNET_CONFIG } from '../network/presets.js';

// Field size for ZK circuits (BN254 scalar field)
export const FIELD_SIZE = new BN('21888242871839275222246405745257275088548364400416034343698204186575808495617');

// Skit Program ID (same across networks)
export const DEFAULT_PROGRAM_ID = DEVNET_CONFIG.programId;

// UTXO fetching configuration
export const FETCH_UTXOS_GROUP_SIZE = 20_000;

// Skit instruction discriminators (Anchor: sha256('global:<method>')[0..8])
export const CLOAK_IX_DISCRIMINATOR = new Uint8Array([0, 173, 127, 247, 68, 198, 111, 130]);
export const CLOAK_TOKEN_IX_DISCRIMINATOR = new Uint8Array([205, 29, 125, 28, 72, 223, 138, 145]);
export const REVEAL_IX_DISCRIMINATOR = new Uint8Array([9, 35, 59, 190, 167, 249, 76, 115]);
export const REVEAL_TOKEN_IX_DISCRIMINATOR = new Uint8Array([86, 131, 227, 146, 65, 221, 222, 86]);
export const INITIALIZE_VAULT_IX_DISCRIMINATOR = new Uint8Array([48, 191, 163, 44, 71, 129, 63, 164]);

// Merkle tree configuration
export const MERKLE_TREE_DEPTH = 26;

// Address Lookup Table (network-specific, prefer using SDK config)
export const DEFAULT_ALT_ADDRESS = DEVNET_CONFIG.altAddress;

// Relayer API (network-specific, prefer using SDK config)
export const DEFAULT_RELAYER_API_URL = DEVNET_CONFIG.relayerUrl;
export const RELAYER_API_URL = DEFAULT_RELAYER_API_URL;

// SOL mint address (wrapped SOL mint for consistency with SPL tokens)
export const SOL_MINT_ADDRESS = 'So11111111111111111111111111111111111111112';

// Sign message for encryption key derivation
export const SIGN_MESSAGE = 'Mink stealth account sign in';

// localStorage cache keys
export const LSK_FETCH_OFFSET = 'fetch_offset';
export const LSK_ENCRYPTED_OUTPUTS = 'encrypted_outputs';

// Default ZK assets path
export const DEFAULT_ZK_ASSETS_PATH = DEVNET_CONFIG.zkAssetsPath;

// Token definitions
export type TokenName = 'SOL' | 'USDC' | 'USDT';

export interface TokenInfo {
  name: TokenName;
  mint: PublicKey;
  mintDevnet?: PublicKey; // Devnet mint (if different from mainnet)
  prefix: string;
  decimals: number;
  unitsPerToken: number;
}

export const TOKENS: Record<TokenName, TokenInfo> = {
  SOL: {
    name: 'SOL',
    mint: new PublicKey('So11111111111111111111111111111111111111112'),
    prefix: '',
    decimals: 9,
    unitsPerToken: 1e9,
  },
  USDC: {
    name: 'USDC',
    mint: new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'), // Mainnet
    mintDevnet: new PublicKey('Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr'), // Devnet
    prefix: 'usdc_',
    decimals: 6,
    unitsPerToken: 1e6,
  },
  USDT: {
    name: 'USDT',
    mint: new PublicKey('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB'), // Mainnet
    mintDevnet: new PublicKey('EcFc2cMyZxaKBkFK1XooxiyDyCPneLXiMwSJiVY6eTad'), // Devnet
    prefix: 'usdt_',
    decimals: 6,
    unitsPerToken: 1e6,
  },
};

// Helper to get token info by mint address
export function getTokenByMint(mint: PublicKey | string): TokenInfo | undefined {
  const mintStr = typeof mint === 'string' ? mint : mint.toBase58();
  return Object.values(TOKENS).find(t =>
    t.mint.toBase58() === mintStr ||
    t.mintDevnet?.toBase58() === mintStr
  );
}

// Get token mint for a specific network
export function getTokenMint(token: TokenName, network: 'devnet' | 'mainnet' = 'devnet'): PublicKey {
  const tokenInfo = TOKENS[token];
  if (network === 'devnet' && tokenInfo.mintDevnet) {
    return tokenInfo.mintDevnet;
  }
  return tokenInfo.mint;
}

// Supported tokens list
export const SUPPORTED_TOKENS = Object.keys(TOKENS) as TokenName[];

/**
 * Viewing Key Manager for Privacy SDK
 *
 * Viewing keys allow third parties (auditors, compliance) to see transaction
 * details without being able to spend funds.
 *
 * Derivation hierarchy:
 * 1. masterViewing = Poseidon(spendingPrivateKey, domain)
 * 2. scopedViewingKey = Poseidon(masterViewing, scope)
 *
 * Scopes:
 * - 0: Proxy (Private Inbox only)
 * - 1: Pool (Privacy Pool only)
 * - 2: Full (Both Proxy and Pool)
 */

import BN from 'bn.js';
import bs58 from 'bs58';
import type { LightWasm } from '@lightprotocol/hasher.rs';
import { Keypair } from '../crypto/keypair.js';
import { DEFAULT_ZK_ASSETS_PATH } from '../crypto/constants.js';
import { ConsoleLogger } from '../logger/console.js';
import { prove, parseProofToBytesArray } from '../proofs/prover.js';

const logger = new ConsoleLogger({ prefix: '[Mink]', minLevel: 'info' });

/**
 * Viewing key scope
 */
export enum ViewingScope {
  /** Private Inbox only - can see inbox deposits/forwards */
  Proxy = 0,
  /** Privacy Pool only - can see pool transactions */
  Pool = 1,
  /** Full access - can see both inbox and pool transactions */
  Full = 2,
}

/**
 * Viewing key structure
 */
export interface ViewingKey {
  /** The actual viewing key (BabyJubjub field element) */
  key: BN;
  /** Scope of the viewing key */
  scope: ViewingScope;
  /** Hash of the viewing key (for on-chain verification) */
  keyHash: BN;
  /** Associated ZK public key */
  zkPubkey: BN;
}

/**
 * Serialized viewing key for sharing
 */
export interface SerializedViewingKey {
  /** Base58-encoded viewing key data */
  base58: string;
  /** URL-safe format for sharing */
  url: string;
  /** QR code data (same as base58) */
  qr: string;
  /** Scope of the viewing key */
  scope: ViewingScope;
}

/**
 * Viewing key data structure for serialization
 */
interface ViewingKeyData {
  /** Version byte (1 byte) */
  version: number;
  /** Scope byte (1 byte) */
  scope: ViewingScope;
  /** ZK public key (32 bytes) */
  zkPubkey: Uint8Array;
  /** Viewing key (32 bytes) */
  viewingKey: Uint8Array;
}

// Domain separator for viewing key derivation
// "view_key" as hex: 0x766965775f6b6579
const VIEWING_KEY_DOMAIN = '8390354499556742009'; // BigInt version

/**
 * Manager for deriving and managing viewing keys
 */
export class ViewingKeyManager {
  private lightWasm: LightWasm;
  private spendingKeypair: Keypair;
  private masterViewingKey: BN | null = null;
  private cachedViewingKeys: Map<ViewingScope, ViewingKey> = new Map();

  /**
   * Create a new ViewingKeyManager
   *
   * @param lightWasm - LightWasm instance for Poseidon hashing
   * @param spendingKeypair - User's spending keypair
   */
  constructor(lightWasm: LightWasm, spendingKeypair: Keypair) {
    this.lightWasm = lightWasm;
    this.spendingKeypair = spendingKeypair;
  }

  /**
   * Create ViewingKeyManager from spending private key
   *
   * @param lightWasm - LightWasm instance
   * @param spendingPrivateKey - Hex-encoded spending private key
   */
  static fromSpendingKey(lightWasm: LightWasm, spendingPrivateKey: string): ViewingKeyManager {
    const keypair = Keypair.fromPrivateKey(spendingPrivateKey, lightWasm);
    return new ViewingKeyManager(lightWasm, keypair);
  }

  /**
   * Get the ZK public key
   */
  getZkPubkey(): BN {
    return this.spendingKeypair.pubkey;
  }

  /**
   * Derive the master viewing key (lazy initialization)
   */
  private deriveMasterViewingKey(): BN {
    if (this.masterViewingKey) {
      return this.masterViewingKey;
    }

    // masterViewing = Poseidon(spendingPrivateKey, domain)
    const masterHash = this.lightWasm.poseidonHashString([
      this.spendingKeypair.privkey.toString(),
      VIEWING_KEY_DOMAIN,
    ]);

    this.masterViewingKey = new BN(masterHash);
    logger.debug('Derived master viewing key');
    return this.masterViewingKey;
  }

  /**
   * Derive a scoped viewing key
   *
   * @param scope - The scope for the viewing key
   */
  deriveViewingKey(scope: ViewingScope): ViewingKey {
    // Check cache first
    const cached = this.cachedViewingKeys.get(scope);
    if (cached) {
      return cached;
    }

    const masterKey = this.deriveMasterViewingKey();

    // scopedViewingKey = Poseidon(masterViewing, scope)
    const scopedKeyHash = this.lightWasm.poseidonHashString([
      masterKey.toString(),
      scope.toString(),
    ]);

    const key = new BN(scopedKeyHash);

    // keyHash = Poseidon(viewingKey) - for on-chain verification
    const keyHashStr = this.lightWasm.poseidonHashString([key.toString()]);

    const viewingKey: ViewingKey = {
      key,
      scope,
      keyHash: new BN(keyHashStr),
      zkPubkey: this.spendingKeypair.pubkey,
    };

    // Cache the result
    this.cachedViewingKeys.set(scope, viewingKey);

    logger.debug(`Derived viewing key for scope ${ViewingScope[scope]}`);
    return viewingKey;
  }

  /**
   * Serialize a viewing key for sharing
   *
   * Format: version (1) + scope (1) + zkPubkey (32) + viewingKey (32) = 66 bytes
   *
   * @param viewingKey - The viewing key to serialize
   */
  serializeViewingKey(viewingKey: ViewingKey): SerializedViewingKey {
    const data: ViewingKeyData = {
      version: 1,
      scope: viewingKey.scope,
      zkPubkey: viewingKey.zkPubkey.toArray('be', 32) as unknown as Uint8Array,
      viewingKey: viewingKey.key.toArray('be', 32) as unknown as Uint8Array,
    };

    // Serialize to bytes
    const buffer = new Uint8Array(66);
    buffer[0] = data.version;
    buffer[1] = data.scope;
    buffer.set(data.zkPubkey, 2);
    buffer.set(data.viewingKey, 34);

    // Encode to base58
    const base58Encoded = bs58.encode(buffer);

    // Create URL-safe format
    const urlFormat = `mink://view/${base58Encoded}`;

    return {
      base58: base58Encoded,
      url: urlFormat,
      qr: base58Encoded,
      scope: viewingKey.scope,
    };
  }

  /**
   * Deserialize a viewing key from base58 string
   *
   * @param encoded - Base58-encoded viewing key
   */
  static deserializeViewingKey(encoded: string): {
    version: number;
    scope: ViewingScope;
    zkPubkey: BN;
    viewingKey: BN;
  } {
    // Handle URL format
    let base58Data = encoded;
    if (encoded.startsWith('mink://view/')) {
      base58Data = encoded.slice('mink://view/'.length);
    }

    // Decode from base58
    const buffer = bs58.decode(base58Data);

    if (buffer.length !== 66) {
      throw new Error(`Invalid viewing key length: expected 66, got ${buffer.length}`);
    }

    const version = buffer[0];
    if (version !== 1) {
      throw new Error(`Unsupported viewing key version: ${version}`);
    }

    const scope = buffer[1] as ViewingScope;
    if (scope < 0 || scope > 2) {
      throw new Error(`Invalid viewing key scope: ${scope}`);
    }

    const zkPubkeyBytes = buffer.slice(2, 34);
    const viewingKeyBytes = buffer.slice(34, 66);

    return {
      version,
      scope,
      zkPubkey: new BN(Array.from(zkPubkeyBytes), 'be'),
      viewingKey: new BN(Array.from(viewingKeyBytes), 'be'),
    };
  }

  /**
   * Verify that a serialized viewing key belongs to an expected ZK pubkey
   *
   * This performs client-side validation:
   * 1. Checks the viewing key format is valid
   * 2. Verifies the embedded zkPubkey matches the expected one
   *
   * Note: Full cryptographic verification requires the ZK proof
   * (use generateViewingKeyProof for on-chain verification)
   *
   * @param serializedKey - The serialized viewing key to verify
   * @param expectedZkPubkey - Expected ZK public key
   * @returns true if the viewing key appears valid for this zkPubkey
   */
  static verifySerializedViewingKey(serializedKey: string, expectedZkPubkey: BN): boolean {
    try {
      const parsed = ViewingKeyManager.deserializeViewingKey(serializedKey);
      return parsed.zkPubkey.eq(expectedZkPubkey);
    } catch {
      return false;
    }
  }

  /**
   * Check if a viewing key hash matches what would be derived from a viewing key
   * Useful for verifying viewing key proofs without the private key
   *
   * @param viewingKey - The viewing key value
   * @param expectedHash - The expected hash of the viewing key
   */
  verifyViewingKeyHash(viewingKey: BN, expectedHash: BN): boolean {
    const computedHash = this.lightWasm.poseidonHashString([viewingKey.toString()]);
    return new BN(computedHash).eq(expectedHash);
  }

  /**
   * Check if a viewing key can access data for a given scope
   *
   * @param viewingKey - The viewing key
   * @param requiredScope - The scope being accessed
   */
  static canAccess(viewingKey: ViewingKey, requiredScope: ViewingScope): boolean {
    // Full scope can access everything
    if (viewingKey.scope === ViewingScope.Full) {
      return true;
    }

    // Exact scope match
    return viewingKey.scope === requiredScope;
  }

  /**
   * Generate a ZK proof that a viewing key was correctly derived
   * This can be submitted on-chain for verification
   *
   * @param scope - The scope of the viewing key
   * @param zkAssetsPath - Path/URL to ZK circuit assets
   */
  async generateViewingKeyProof(
    scope: ViewingScope,
    zkAssetsPath: string = DEFAULT_ZK_ASSETS_PATH
  ): Promise<{
    zkPubkey: string;
    viewingKeyHash: string;
    scope: number;
    proof: {
      proofA: number[];
      proofB: number[];
      proofC: number[];
    };
  }> {
    const viewingKey = this.deriveViewingKey(scope);

    logger.debug(`Generating viewing key proof for scope ${ViewingScope[scope]}`);

    // Prepare circuit inputs
    const circuitInput = {
      // Public inputs
      zkPubkey: viewingKey.zkPubkey.toString(),
      viewingKeyHash: viewingKey.keyHash.toString(),
      scope: scope.toString(),
      // Private input
      spendingPrivateKey: this.spendingKeypair.privkey.toString(),
    };

    // Generate proof using viewing_key circuit
    const wasmUrl = `${zkAssetsPath}/viewing_key.wasm`;
    const zkeyUrl = `${zkAssetsPath}/viewing_key.zkey`;

    const { proof } = await prove(circuitInput, wasmUrl, zkeyUrl);

    // Parse proof to byte arrays
    const { proofA, proofB, proofC } = parseProofToBytesArray(proof);

    logger.debug('Viewing key proof generated successfully');

    return {
      zkPubkey: viewingKey.zkPubkey.toString(),
      viewingKeyHash: viewingKey.keyHash.toString(),
      scope: viewingKey.scope,
      proof: {
        proofA,
        proofB,
        proofC,
      },
    };
  }

  /**
   * Clear cached viewing keys
   */
  clearCache(): void {
    this.cachedViewingKeys.clear();
    this.masterViewingKey = null;
  }
}

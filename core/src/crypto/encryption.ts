/**
 * Browser-compatible encryption service using Web Crypto API
 * Adapted from privacycash SDK for browser environments
 */

import { keccak256 } from 'ethers';
import { ConsoleLogger } from '../logger/console.js';
import BN from 'bn.js';
import {
  CLOAK_IX_DISCRIMINATOR,
  CLOAK_TOKEN_IX_DISCRIMINATOR,
  REVEAL_IX_DISCRIMINATOR,
  REVEAL_TOKEN_IX_DISCRIMINATOR,
  SIGN_MESSAGE
} from './constants.js';
import type { MessageSigner, EncryptionKey } from '../types/index.js';
import {
  ecdhSharedSecret,
  deriveEncryptionKey,
  deriveBlinding,
} from './ecdh.js';

const logger = new ConsoleLogger({ prefix: '[Mink]', minLevel: 'info' });

// Version identifier for encryption scheme (8-byte version)
const ENCRYPTION_VERSION_V2 = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);

// V3 version byte (ECDH-based encryption)
const ENCRYPTION_VERSION_V3 = 0x03;

/**
 * Convert Uint8Array to hex string
 */
function toHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to Uint8Array
 */
function fromHex(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Timing-safe comparison of two Uint8Arrays
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Check if two Uint8Arrays are equal
 */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Compute SHA-256 hash using Web Crypto API
 */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data.buffer as ArrayBuffer);
  return new Uint8Array(hashBuffer);
}

/**
 * Compute HMAC-SHA256 using Web Crypto API
 */
async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key.buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data.buffer as ArrayBuffer);
  return new Uint8Array(signature);
}

/**
 * Service for handling encryption and decryption of UTXO data
 * Browser-compatible version using Web Crypto API
 *
 * SECURITY: Keys are stored encrypted in localStorage using AES-256-GCM.
 * - Uses localStorage by default (persists UTXOs across sessions)
 * - Can optionally use sessionStorage for higher security (cleared on browser close)
 * - All cached data is encrypted with a key derived from wallet address via PBKDF2
 */
export class EncryptionService {
  private encryptionKeyV1: Uint8Array | null = null;
  private encryptionKeyV2: Uint8Array | null = null;
  private utxoPrivateKeyV1: string | null = null;
  private utxoPrivateKeyV2: string | null = null;
  private static CACHE_KEY_PREFIX = 'privacy_sdk_enc_';
  private static CACHE_SALT = 'mink_privacy_cache_v1';

  // X25519 private key for ECDH V3 decryption (derived from spending key)
  private encPrivKey: Uint8Array | null = null;

  // Use localStorage by default to persist UTXOs across browser sessions
  // Data is encrypted with AES-256-GCM before storage
  private useSecureStorage: boolean = false;

  /**
   * Derive encryption key from a signature
   * Works with signatures from wallet adapter signMessage
   */
  public async deriveEncryptionKeyFromSignature(signature: Uint8Array): Promise<EncryptionKey> {
    // Extract the first 31 bytes of the signature for V1 key (legacy)
    const encryptionKeyV1 = signature.slice(0, 31);
    this.encryptionKeyV1 = encryptionKeyV1;

    // Compute V1 UTXO private key
    const hashedSeedV1 = await sha256(encryptionKeyV1);
    this.utxoPrivateKeyV1 = '0x' + toHex(hashedSeedV1);

    // Use Keccak256 to derive a full 32-byte V2 encryption key
    const encryptionKeyV2 = fromHex(keccak256(signature));
    this.encryptionKeyV2 = encryptionKeyV2;

    // Compute V2 UTXO private key
    const hashedSeedV2 = fromHex(keccak256(encryptionKeyV2));
    this.utxoPrivateKeyV2 = '0x' + toHex(hashedSeedV2);

    return {
      key: this.encryptionKeyV2,
      iv: new Uint8Array(12), // Placeholder, actual IV is generated per encryption
    };
  }

  /**
   * SECURITY: Derive a cache encryption key from wallet address
   * This provides basic protection against casual inspection
   */
  private async deriveCacheKey(walletAddress: string): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(walletAddress + EncryptionService.CACHE_SALT),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode(EncryptionService.CACHE_SALT),
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * SECURITY: Encrypt cache data before storing
   */
  private async encryptCacheData(data: string, walletAddress: string): Promise<string> {
    const key = await this.deriveCacheKey(walletAddress);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(data)
    );

    // Return IV + encrypted data as hex
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return toHex(combined);
  }

  /**
   * SECURITY: Decrypt cache data after loading
   */
  private async decryptCacheData(encryptedHex: string, walletAddress: string): Promise<string | null> {
    try {
      const key = await this.deriveCacheKey(walletAddress);
      const combined = fromHex(encryptedHex);
      const iv = combined.slice(0, 12);
      const encrypted = combined.slice(12);

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encrypted
      );

      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch {
      return null;
    }
  }

  /**
   * Get the appropriate storage based on security mode
   */
  private getStorage(): Storage {
    return this.useSecureStorage ? sessionStorage : localStorage;
  }

  /**
   * Enable persistent storage (localStorage) - less secure but persists across sessions
   * WARNING: Use only if you understand the security implications
   */
  public enablePersistentStorage(): void {
    this.useSecureStorage = false;
  }

  /**
   * Enable secure storage (sessionStorage) - more secure but cleared on browser close
   * This is the default mode
   */
  public enableSecureStorage(): void {
    this.useSecureStorage = true;
  }

  /**
   * Save encryption keys to storage (cached by wallet address)
   * SECURITY: Data is encrypted before storing
   */
  private async saveToCache(walletAddress: string): Promise<void> {
    if (!this.encryptionKeyV1 || !this.encryptionKeyV2 || !this.utxoPrivateKeyV1 || !this.utxoPrivateKeyV2) {
      return;
    }

    try {
      const cacheData = {
        v1: toHex(this.encryptionKeyV1),
        v2: toHex(this.encryptionKeyV2),
        pk1: this.utxoPrivateKeyV1,
        pk2: this.utxoPrivateKeyV2,
      };

      // Encrypt the cache data before storing
      const encrypted = await this.encryptCacheData(JSON.stringify(cacheData), walletAddress);
      this.getStorage().setItem(EncryptionService.CACHE_KEY_PREFIX + walletAddress, encrypted);
    } catch {
      // Storage not available or quota exceeded
    }
  }

  /**
   * Load encryption keys from storage cache
   * SECURITY: Data is decrypted after loading
   */
  private async loadFromCache(walletAddress: string): Promise<boolean> {
    try {
      const storage = this.getStorage();
      const cached = storage.getItem(EncryptionService.CACHE_KEY_PREFIX + walletAddress);
      if (!cached) return false;

      // Decrypt the cache data
      const decrypted = await this.decryptCacheData(cached, walletAddress);
      if (!decrypted) {
        // Failed to decrypt - might be old unencrypted format, clear it
        storage.removeItem(EncryptionService.CACHE_KEY_PREFIX + walletAddress);
        return false;
      }

      const cacheData = JSON.parse(decrypted);
      if (!cacheData.v1 || !cacheData.v2 || !cacheData.pk1 || !cacheData.pk2) {
        return false;
      }

      this.encryptionKeyV1 = fromHex(cacheData.v1);
      this.encryptionKeyV2 = fromHex(cacheData.v2);
      this.utxoPrivateKeyV1 = cacheData.pk1;
      this.utxoPrivateKeyV2 = cacheData.pk2;
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Clear cached encryption keys for a wallet from all storage types
   */
  public clearCache(walletAddress: string): void {
    try {
      const key = EncryptionService.CACHE_KEY_PREFIX + walletAddress;
      localStorage.removeItem(key);
      sessionStorage.removeItem(key);
    } catch {
      // Ignore errors
    }
  }

  /**
   * Clear all cached encryption keys (all wallets)
   * Use this on logout or for security purposes
   */
  public clearAllCaches(): void {
    try {
      // Clear from both storage types
      const keysToRemove: string[] = [];

      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key?.startsWith(EncryptionService.CACHE_KEY_PREFIX)) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => localStorage.removeItem(key));

      keysToRemove.length = 0;
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key?.startsWith(EncryptionService.CACHE_KEY_PREFIX)) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => sessionStorage.removeItem(key));

      // Clear in-memory keys
      this.encryptionKeyV1 = null;
      this.encryptionKeyV2 = null;
      this.utxoPrivateKeyV1 = null;
      this.utxoPrivateKeyV2 = null;
    } catch {
      // Ignore errors
    }
  }

  /**
   * Derive encryption key from wallet adapter signMessage
   * This is the primary method for browser usage
   * Caches the derived key to avoid repeated signature requests
   */
  public async deriveEncryptionKeyFromWallet(
    signMessage: MessageSigner,
    walletAddress?: string
  ): Promise<EncryptionKey> {
    logger.debug('[EncryptionService] deriveEncryptionKeyFromWallet called, walletAddress:', walletAddress);

    // Try to load from cache first (async - encrypted storage)
    if (walletAddress && await this.loadFromCache(walletAddress)) {
      logger.debug('[EncryptionService] Loaded from cache');
      return {
        key: this.encryptionKeyV2!,
        iv: new Uint8Array(12),
      };
    }

    logger.debug('[EncryptionService] Cache miss, requesting signature...');
    logger.debug('[EncryptionService] SIGN_MESSAGE:', SIGN_MESSAGE);

    // Request signature from wallet
    const message = new TextEncoder().encode(SIGN_MESSAGE);
    logger.debug('[EncryptionService] Calling signMessage with message length:', message.length);

    const signature = await signMessage(message);
    logger.debug('[EncryptionService] Got signature, length:', signature.length);

    const result = await this.deriveEncryptionKeyFromSignature(signature);

    // Cache the derived keys (async - encrypted storage)
    if (walletAddress) {
      await this.saveToCache(walletAddress);
      logger.debug('[EncryptionService] Saved to cache');
    }

    return result;
  }

  /**
   * Encrypt data using AES-256-GCM (V2 format)
   */
  public async encrypt(data: string | Uint8Array): Promise<Uint8Array> {
    if (!this.encryptionKeyV2) {
      throw new Error('Encryption key not set. Call deriveEncryptionKeyFromWallet first.');
    }

    const dataBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;

    // Generate random IV (12 bytes for GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Import key for AES-256-GCM
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      this.encryptionKeyV2.buffer as ArrayBuffer,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    // Encrypt with AES-256-GCM
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      dataBuffer.buffer as ArrayBuffer
    );

    // AES-GCM returns ciphertext + authTag (16 bytes) concatenated
    const encrypted = new Uint8Array(encryptedBuffer);
    const encryptedData = encrypted.slice(0, -16);
    const authTag = encrypted.slice(-16);

    // V2 format: [version(8)] + [IV(12)] + [authTag(16)] + [encryptedData]
    const result = new Uint8Array(8 + 12 + 16 + encryptedData.length);
    result.set(ENCRYPTION_VERSION_V2, 0);
    result.set(iv, 8);
    result.set(authTag, 20);
    result.set(encryptedData, 36);

    return result;
  }

  /**
   * Decrypt data - automatically detects V1, V2, or V3 format
   */
  public async decrypt(encryptedData: Uint8Array): Promise<Uint8Array> {
    // Check if V3 format (starts with 0x03 version byte)
    if (encryptedData.length >= 1 && encryptedData[0] === ENCRYPTION_VERSION_V3) {
      if (!this.encPrivKey) {
        throw new Error('Encryption private key not set for V3 decryption.');
      }
      return this.decryptV3(encryptedData);
    }

    // Check if V2 format (starts with version identifier)
    if (encryptedData.length >= 8 && arraysEqual(encryptedData.slice(0, 8), ENCRYPTION_VERSION_V2)) {
      if (!this.encryptionKeyV2) {
        throw new Error('Encryption key V2 not set.');
      }
      return this.decryptV2(encryptedData);
    } else {
      // V1 format
      if (!this.encryptionKeyV1) {
        throw new Error('Encryption key V1 not set.');
      }
      return this.decryptV1(encryptedData);
    }
  }

  /**
   * Decrypt V1 format (AES-128-CTR with HMAC)
   */
  private async decryptV1(encryptedData: Uint8Array): Promise<Uint8Array> {
    if (!this.encryptionKeyV1) {
      throw new Error('Encryption key V1 not set.');
    }

    // Extract IV (16 bytes), authTag (16 bytes), and data
    const iv = encryptedData.slice(0, 16);
    const authTag = encryptedData.slice(16, 32);
    const data = encryptedData.slice(32);

    // Verify HMAC
    const hmacKey = this.encryptionKeyV1.slice(16, 31);
    const hmacData = new Uint8Array(iv.length + data.length);
    hmacData.set(iv, 0);
    hmacData.set(data, iv.length);

    const calculatedTag = (await hmacSha256(hmacKey, hmacData)).slice(0, 16);

    if (!timingSafeEqual(authTag, calculatedTag)) {
      throw new Error('Failed to decrypt data. Invalid encryption key or corrupted data.');
    }

    // Decrypt with AES-128-CTR
    const key = this.encryptionKeyV1.slice(0, 16);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(key).buffer,
      { name: 'AES-CTR' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CTR', counter: iv, length: 128 },
      cryptoKey,
      data
    );

    return new Uint8Array(decrypted);
  }

  /**
   * Decrypt V2 format (AES-256-GCM)
   */
  private async decryptV2(encryptedData: Uint8Array): Promise<Uint8Array> {
    if (!this.encryptionKeyV2) {
      throw new Error('Encryption key V2 not set.');
    }

    // Extract components: skip version (8), IV (12), authTag (16), then data
    const iv = encryptedData.slice(8, 20);
    const authTag = encryptedData.slice(20, 36);
    const data = encryptedData.slice(36);

    // Import key for AES-256-GCM
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      this.encryptionKeyV2.buffer as ArrayBuffer,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // Reconstruct ciphertext with authTag appended (Web Crypto expects this format)
    const ciphertext = new Uint8Array(data.length + 16);
    ciphertext.set(data, 0);
    ciphertext.set(authTag, data.length);

    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        ciphertext
      );
      return new Uint8Array(decrypted);
    } catch {
      throw new Error('Failed to decrypt data. Invalid encryption key or corrupted data.');
    }
  }

  /**
   * Get encryption key version from encrypted data
   */
  public getEncryptionKeyVersion(encryptedData: Uint8Array | string): 'v1' | 'v2' | 'v3' {
    const buffer = typeof encryptedData === 'string'
      ? fromHex(encryptedData)
      : encryptedData;

    // Check V3 first (single byte version)
    if (buffer.length >= 1 && buffer[0] === ENCRYPTION_VERSION_V3) {
      return 'v3';
    }

    if (buffer.length >= 8 && arraysEqual(buffer.slice(0, 8), ENCRYPTION_VERSION_V2)) {
      return 'v2';
    }
    return 'v1';
  }

  /**
   * Set the X25519 private key for ECDH V3 decryption
   *
   * This is derived from the spending private key and used to decrypt
   * V3 encrypted outputs from inbox forwards.
   *
   * @param encPrivKey - X25519 private key (32 bytes)
   */
  public setEncPrivKey(encPrivKey: Uint8Array): void {
    if (encPrivKey.length !== 32) {
      throw new Error('Invalid enc private key length - must be 32 bytes');
    }
    this.encPrivKey = encPrivKey;
  }

  /**
   * Check if V3 decryption is available
   */
  public hasEncPrivKey(): boolean {
    return this.encPrivKey !== null;
  }

  /**
   * Decrypt V3 format (ECDH-based)
   *
   * V3 Format (86 bytes):
   * - Version: 1 byte (0x03)
   * - Ephemeral Public Key: 32 bytes
   * - AES-GCM IV: 12 bytes
   * - AES-GCM Auth Tag: 16 bytes
   * - Encrypted Data: 12 bytes (amount:8 + index:4)
   * - Zero Padding: 13 bytes
   */
  private async decryptV3(encryptedData: Uint8Array): Promise<Uint8Array> {
    if (!this.encPrivKey) {
      throw new Error('V3 encryption private key not set. Call setEncPrivKey first.');
    }

    if (encryptedData.length !== 86) {
      throw new Error(`Invalid V3 encrypted data length: ${encryptedData.length}`);
    }

    if (encryptedData[0] !== ENCRYPTION_VERSION_V3) {
      throw new Error(`Invalid V3 version byte: ${encryptedData[0]}`);
    }

    // Extract components
    const ephemeralPubKey = encryptedData.slice(1, 33);
    const iv = encryptedData.slice(33, 45);
    const authTag = encryptedData.slice(45, 61);
    const ciphertext = encryptedData.slice(61, 73);
    // Bytes 73-85 are padding (ignored)

    // ECDH to derive shared secret
    const sharedSecret = ecdhSharedSecret(this.encPrivKey, ephemeralPubKey);

    // Derive encryption key
    const encKey = deriveEncryptionKey(sharedSecret);

    // Import key for AES-256-GCM
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(encKey).buffer,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // Reconstruct ciphertext with authTag appended (Web Crypto expects this format)
    const ciphertextWithTag = new Uint8Array(ciphertext.length + authTag.length);
    ciphertextWithTag.set(ciphertext, 0);
    ciphertextWithTag.set(authTag, ciphertext.length);

    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        ciphertextWithTag
      );
      return new Uint8Array(decrypted);
    } catch {
      throw new Error('Failed to decrypt V3 data. Invalid key or corrupted data.');
    }
  }

  /**
   * Derive blinding from V3 encrypted data without full decryption
   *
   * Useful for commitment verification.
   *
   * @param encryptedData - V3 encrypted output (86 bytes)
   * @returns Blinding value as BN
   */
  public deriveBlindingFromV3(encryptedData: Uint8Array): BN {
    if (!this.encPrivKey) {
      throw new Error('V3 encryption private key not set. Call setEncPrivKey first.');
    }

    if (encryptedData.length < 33 || encryptedData[0] !== ENCRYPTION_VERSION_V3) {
      throw new Error('Invalid V3 encrypted data');
    }

    // Extract ephemeral public key
    const ephemeralPubKey = encryptedData.slice(1, 33);

    // ECDH to derive shared secret
    const sharedSecret = ecdhSharedSecret(this.encPrivKey, ephemeralPubKey);

    // Derive blinding from shared secret
    const blinding = deriveBlinding(sharedSecret);

    return blinding;
  }

  /**
   * Encrypt a UTXO (always uses V2 format)
   * Uses compact binary format:
   * - amount: 8 bytes (u64 little-endian)
   * - blinding: 32 bytes (raw bytes)
   * - index: 4 bytes (u32 little-endian)
   * - padding: 6 bytes (zeros for alignment)
   * Total: 50 bytes plaintext + 36 bytes overhead = 86 bytes (exact fit, no external padding needed)
   */
  public async encryptUtxo(utxo: {
    amount: bigint | string;
    blinding: bigint | string;
    index: number;
  }): Promise<Uint8Array> {
    // Pack data in compact binary format (50 bytes to get exactly 86 bytes encrypted)
    const buffer = new Uint8Array(50);
    const view = new DataView(buffer.buffer);

    // Amount: 8 bytes (u64 little-endian)
    const amountBigInt = typeof utxo.amount === 'string' ? BigInt(utxo.amount) : utxo.amount;
    view.setBigUint64(0, amountBigInt, true);

    // Blinding: 32 bytes (BN to bytes, big-endian, padded)
    const blindingBN = new BN(utxo.blinding.toString());
    const blindingBytes = blindingBN.toArray('be', 32);
    buffer.set(blindingBytes, 8);

    // Index: 4 bytes (u32 little-endian)
    view.setUint32(40, utxo.index, true);

    // Padding: 6 bytes (zeros) - reserved for future use
    // buffer bytes 44-49 are already zero

    return this.encrypt(buffer);
  }

  /**
   * Decrypt a UTXO
   * Supports:
   * - V3 format (86 bytes): ECDH-based, returns amount + index, blinding derived from ECDH
   * - Binary format (44 or 50 bytes): amount(8) + blinding(32) + index(4) + padding(6)
   * - Legacy string format: "amount|blinding|index|mintAddress"
   *
   * Note: mintAddress is passed from the API filter, not stored in the encrypted data
   */
  public async decryptUtxoData(
    encryptedData: Uint8Array | string,
    mintAddress: string = 'So11111111111111111111111111111111111111112'
  ): Promise<{
    amount: string;
    blinding: string;
    index: number;
    mintAddress: string;
    version: 'v1' | 'v2' | 'v3';
  }> {
    const buffer = typeof encryptedData === 'string'
      ? fromHex(encryptedData)
      : encryptedData;

    const version = this.getEncryptionKeyVersion(buffer);

    // V3 format: ECDH-based encryption (86 bytes total)
    if (version === 'v3') {
      const decrypted = await this.decrypt(buffer);

      // V3 decrypted payload: 12 bytes (amount:8 + index:4)
      if (decrypted.length !== 12) {
        throw new Error(`Invalid V3 decrypted length: ${decrypted.length}`);
      }

      const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);

      // Amount: 8 bytes (u64 little-endian)
      const amount = view.getBigUint64(0, true).toString();

      // Index: 4 bytes (u32 little-endian)
      const index = view.getUint32(8, true);

      // Blinding is derived from ECDH shared secret, not stored in payload
      const blinding = this.deriveBlindingFromV3(buffer).toString();

      return {
        amount,
        blinding,
        index,
        mintAddress,
        version,
      };
    }

    const decrypted = await this.decrypt(buffer);

    // Compact binary format: 44 bytes (old) or 50 bytes (with padding)
    if (decrypted.length === 44 || decrypted.length === 50) {
      const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);

      // Amount: 8 bytes (u64 little-endian)
      const amount = view.getBigUint64(0, true).toString();

      // Blinding: 32 bytes (big-endian) - must use 'be' to match encryption format
      const blindingBytes = Array.from(decrypted.slice(8, 40));
      const blinding = new BN(blindingBytes, 'be').toString();

      // Index: 4 bytes (u32 little-endian)
      const index = view.getUint32(40, true);

      // Bytes 44-49 are padding (ignored)

      return {
        amount,
        blinding,
        index,
        mintAddress,
        version,
      };
    }

    // Legacy string format: "amount|blinding|index|mintAddress"
    const decryptedStr = new TextDecoder().decode(decrypted);
    const parts = decryptedStr.split('|');

    if (parts.length !== 4) {
      throw new Error('Invalid UTXO format after decryption');
    }

    const [amount, blinding, indexStr, legacyMintAddress] = parts;
    if (!amount || !blinding || indexStr === undefined || legacyMintAddress === undefined) {
      throw new Error('Invalid UTXO format after decryption');
    }

    return {
      amount,
      blinding,
      index: Number(indexStr),
      mintAddress: legacyMintAddress,
      version,
    };
  }

  /**
   * Get UTXO private key for the specified version
   */
  public getUtxoPrivateKey(version: 'v1' | 'v2' = 'v2'): string {
    if (version === 'v1') {
      if (!this.utxoPrivateKeyV1) {
        throw new Error('V1 encryption key not set.');
      }
      return this.utxoPrivateKeyV1;
    }
    if (!this.utxoPrivateKeyV2) {
      throw new Error('V2 encryption key not set.');
    }
    return this.utxoPrivateKeyV2;
  }

  /**
   * Check if encryption keys are set
   */
  public isInitialized(): boolean {
    return this.encryptionKeyV2 !== null;
  }

  /**
   * Reset encryption keys
   */
  public reset(): void {
    this.encryptionKeyV1 = null;
    this.encryptionKeyV2 = null;
    this.utxoPrivateKeyV1 = null;
    this.utxoPrivateKeyV2 = null;
    // Securely clear enc private key
    if (this.encPrivKey) {
      this.encPrivKey.fill(0);
      this.encPrivKey = null;
    }
  }
}

/**
 * Serialize proof and external data for the Solana program instruction
 *
 * Anchor program expects: NullifierInputs, ZkProof, ExtData
 *
 * @param txType - 'deposit' for cloak instruction, 'withdraw' for reveal instruction
 */
export function serializeProofAndExtData(
  proof: {
    proofA: Uint8Array;
    proofB: Uint8Array;
    proofC: Uint8Array;
    root: Uint8Array;
    publicAmount: Uint8Array;
    extDataHash: Uint8Array;
    inputNullifiers: Uint8Array[];
    outputCommitments: Uint8Array[];
  },
  extData: {
    extAmount: bigint | number;
    fee: bigint | number;
    encryptedOutput1: Uint8Array;
    encryptedOutput2: Uint8Array;
    recipient?: Uint8Array; // 32 bytes pubkey
    relayer?: Uint8Array; // 32 bytes pubkey
    mint?: Uint8Array; // 32 bytes pubkey (zero for SOL)
  },
  isSpl: boolean = false,
  txType: 'deposit' | 'withdraw' = 'deposit'
): Uint8Array {
  // Select correct discriminator based on transaction type
  let discriminator: Uint8Array;
  if (txType === 'withdraw') {
    discriminator = isSpl ? REVEAL_TOKEN_IX_DISCRIMINATOR : REVEAL_IX_DISCRIMINATOR;
  } else {
    discriminator = isSpl ? CLOAK_TOKEN_IX_DISCRIMINATOR : CLOAK_IX_DISCRIMINATOR;
  }

  // Convert extAmount to i128 (16 bytes, little-endian, two's complement)
  const extAmount = new BN(extData.extAmount.toString());
  const extAmountBytes = new Uint8Array(16);
  const extAmountArray = extAmount.toTwos(128).toArray('le', 16);
  extAmountBytes.set(extAmountArray);

  // Fee as u64 (8 bytes)
  const fee = new BN(extData.fee.toString());
  const feeBytes = new Uint8Array(fee.toArray('le', 8));

  // Pad encrypted outputs to exactly 86 bytes
  const encOutput1Padded = new Uint8Array(86);
  const encOutput2Padded = new Uint8Array(86);
  encOutput1Padded.set(extData.encryptedOutput1.slice(0, 86));
  encOutput2Padded.set(extData.encryptedOutput2.slice(0, 86));

  // Default pubkeys (32 bytes of zeros)
  const zeroPubkey = new Uint8Array(32);
  const recipient = extData.recipient || zeroPubkey;
  const relayer = extData.relayer || zeroPubkey;
  const mint = extData.mint || zeroPubkey;

  // Build instruction data in Anchor's expected order:
  // 1. discriminator (8 bytes)
  // 2. NullifierInputs: nullifier0 (32) + nullifier1 (32) = 64 bytes
  // 3. ZkProof: proof_a (64) + proof_b (128) + proof_c (64) + root (32) +
  //            input_nullifiers (64) + output_commitments (64) + public_amount (32) + ext_data_hash (32) = 480 bytes
  // 4. ExtData: recipient (32) + ext_amount (16) + relayer (32) + fee (8) +
  //            encrypted_output1 (86) + encrypted_output2 (86) + mint (32) = 292 bytes
  // Note: output_commitments removed from ExtData - using proof.output_commitments on-chain (saves 64 bytes)

  const parts = [
    discriminator,                    // 8 bytes
    // NullifierInputs
    proof.inputNullifiers[0],         // 32 bytes - nullifier0
    proof.inputNullifiers[1],         // 32 bytes - nullifier1
    // ZkProof
    proof.proofA,                     // 64 bytes
    proof.proofB,                     // 128 bytes
    proof.proofC,                     // 64 bytes
    proof.root,                       // 32 bytes
    proof.inputNullifiers[0],         // 32 bytes - input_nullifiers[0]
    proof.inputNullifiers[1],         // 32 bytes - input_nullifiers[1]
    proof.outputCommitments[0],       // 32 bytes - output_commitments[0]
    proof.outputCommitments[1],       // 32 bytes - output_commitments[1]
    proof.publicAmount,               // 32 bytes
    proof.extDataHash,                // 32 bytes
    // ExtData (output_commitments now taken from ZkProof on-chain)
    recipient,                        // 32 bytes
    extAmountBytes,                   // 16 bytes (i128)
    relayer,                          // 32 bytes
    feeBytes,                         // 8 bytes
    encOutput1Padded,                 // 86 bytes (fixed)
    encOutput2Padded,                 // 86 bytes (fixed)
    mint,                             // 32 bytes
  ];

  const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

// Export utility functions
export { toHex, fromHex, sha256, hmacSha256 };

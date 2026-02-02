/**
 * ECDH (Elliptic Curve Diffie-Hellman) utilities for secure key exchange
 *
 * Used for Private Inbox Forward encryption:
 * 1. Owner derives encPubKey from spending key, stores in inbox registration
 * 2. Relayer generates ephemeral keypair, does ECDH to derive shared secret
 * 3. Blinding and encryption key derived deterministically from shared secret
 * 4. Owner scans outputs, does ECDH with ephemeralPub, recovers blinding
 */

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import BN from 'bn.js';
import { FIELD_SIZE } from './constants.js';

// Domain separation tags for key derivation
const DOMAIN_ENC_KEY = 'mink_enc_v1';
const DOMAIN_BLINDING = 'mink_blinding_v1';
const DOMAIN_ENCRYPTION = 'mink_encryption_v1';

// X25519 curve order (2^252 + 27742317777372353535851937790883648493)
const X25519_ORDER = new BN('7237005577332262213973186563042994240857116359379907606001950938285454250989');

/**
 * Derive X25519 encryption private key from ZK private key
 *
 * SECURITY: Uses domain separation to prevent key reuse attacks
 *
 * @param zkPrivKey - BabyJubjub private key from spending keypair
 * @returns X25519 private key (32 bytes)
 */
export function deriveEncPrivKey(zkPrivKey: BN): Uint8Array {
  // Convert BN to 32-byte big-endian array
  const zkPrivKeyBytes = new Uint8Array(zkPrivKey.toArray('be', 32));

  // Domain separation: SHA256(zkPrivKey || domain_tag)
  const encoder = new TextEncoder();
  const domainTag = encoder.encode(DOMAIN_ENC_KEY);

  const input = new Uint8Array(zkPrivKeyBytes.length + domainTag.length);
  input.set(zkPrivKeyBytes, 0);
  input.set(domainTag, zkPrivKeyBytes.length);

  const hash = sha256(input);

  // Reduce mod X25519 order to ensure valid key
  const hashBN = new BN(Array.from(hash), 'be');
  const reduced = hashBN.mod(X25519_ORDER);

  return new Uint8Array(reduced.toArray('be', 32));
}

/**
 * Derive X25519 public key from private key
 *
 * @param encPrivKey - X25519 private key (32 bytes)
 * @returns X25519 public key (32 bytes)
 */
export function deriveEncPubKey(encPrivKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(encPrivKey);
}

/**
 * Compute ECDH shared secret
 *
 * SECURITY: The shared secret is symmetric - Alice and Bob compute the same value
 * Alice: ECDH(alicePriv, bobPub) === Bob: ECDH(bobPriv, alicePub)
 *
 * @param myPrivKey - My X25519 private key (32 bytes)
 * @param theirPubKey - Their X25519 public key (32 bytes)
 * @returns Shared secret (32 bytes)
 */
export function ecdhSharedSecret(myPrivKey: Uint8Array, theirPubKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(myPrivKey, theirPubKey);
}

/**
 * Derive blinding value from ECDH shared secret
 *
 * Uses HKDF to derive a value suitable for use as UTXO blinding factor.
 * The result is reduced mod FIELD_SIZE to ensure it's a valid field element.
 *
 * @param sharedSecret - ECDH shared secret (32 bytes)
 * @param index - Optional output index for deriving multiple blindings (default: 0)
 * @returns Blinding value as BN (valid field element)
 */
export function deriveBlinding(sharedSecret: Uint8Array, index: number = 0): BN {
  // HKDF expansion with domain separation (index appended for multi-output support)
  const encoder = new TextEncoder();
  const info = encoder.encode(`${DOMAIN_BLINDING}_${index}`);

  // HKDF: Extract-and-Expand to get 32 bytes
  const derived = hkdf(sha256, sharedSecret, undefined, info, 32);

  // Reduce mod FIELD_SIZE to ensure valid field element
  const derivedBN = new BN(Array.from(derived), 'be');
  return derivedBN.mod(FIELD_SIZE);
}

/**
 * Derive AES-256-GCM encryption key from ECDH shared secret
 *
 * Uses HKDF with different domain separation than blinding derivation.
 *
 * @param sharedSecret - ECDH shared secret (32 bytes)
 * @returns AES-256-GCM key (32 bytes)
 */
export function deriveEncryptionKey(sharedSecret: Uint8Array): Uint8Array {
  const encoder = new TextEncoder();
  const info = encoder.encode(DOMAIN_ENCRYPTION);

  // HKDF: Extract-and-Expand to get 32 bytes for AES-256
  return hkdf(sha256, sharedSecret, undefined, info, 32);
}

/**
 * Generate fresh ephemeral X25519 keypair
 *
 * CRITICAL: Generate a NEW keypair for EACH forward operation!
 * Reusing ephemeral keys breaks the security of the scheme.
 *
 * @returns Ephemeral keypair with privateKey and publicKey (32 bytes each)
 */
export function generateEphemeralKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Securely clear sensitive key material from memory
 *
 * SECURITY: Call this after using ephemeral private keys to reduce
 * the window for memory extraction attacks.
 *
 * Note: JavaScript does not guarantee immediate memory clearing,
 * but this is best-effort defense-in-depth.
 *
 * @param key - Key buffer to clear
 */
export function secureZeroKey(key: Uint8Array): void {
  key.fill(0);
}

/**
 * Encrypt note data using derived encryption key (V3 format)
 *
 * V3 Format (86 bytes total, fixed for compatibility):
 * - Version: 1 byte (0x03)
 * - Ephemeral Public Key: 32 bytes
 * - AES-GCM IV: 12 bytes
 * - AES-GCM Auth Tag: 16 bytes
 * - Encrypted Data: 12 bytes (amount:8 + index:4)
 * - Zero Padding: 13 bytes
 *
 * @param ephemeralPubKey - Ephemeral X25519 public key (32 bytes)
 * @param encryptionKey - AES-256-GCM key derived from shared secret (32 bytes)
 * @param noteData - Data to encrypt { amount: bigint, index: number }
 * @returns Encrypted output (86 bytes)
 */
export async function encryptNoteV3(
  ephemeralPubKey: Uint8Array,
  encryptionKey: Uint8Array,
  noteData: { amount: bigint; index: number }
): Promise<Uint8Array> {
  // Pack note data: amount (8 bytes LE) + index (4 bytes LE) = 12 bytes
  const plaintext = new Uint8Array(12);
  const view = new DataView(plaintext.buffer);
  view.setBigUint64(0, noteData.amount, true); // little-endian
  view.setUint32(8, noteData.index, true); // little-endian

  // Generate random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Import key for AES-256-GCM
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(encryptionKey).buffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  // Encrypt with AES-256-GCM
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    plaintext
  );

  // AES-GCM returns ciphertext + authTag (16 bytes) concatenated
  const encrypted = new Uint8Array(encryptedBuffer);
  const ciphertext = encrypted.slice(0, -16);
  const authTag = encrypted.slice(-16);

  // Build V3 format (86 bytes total)
  const result = new Uint8Array(86);
  let offset = 0;

  // Version byte
  result[offset++] = 0x03;

  // Ephemeral public key (32 bytes)
  result.set(ephemeralPubKey, offset);
  offset += 32;

  // IV (12 bytes)
  result.set(iv, offset);
  offset += 12;

  // Auth tag (16 bytes)
  result.set(authTag, offset);
  offset += 16;

  // Encrypted data (12 bytes)
  result.set(ciphertext, offset);
  offset += 12;

  // Zero padding (13 bytes) - already zero-initialized

  return result;
}

/**
 * Decrypt V3 encrypted note data
 *
 * @param encryptedData - V3 encrypted output (86 bytes)
 * @param encPrivKey - X25519 private key for ECDH
 * @returns Decrypted note data { amount: bigint, index: number }
 */
export async function decryptNoteV3(
  encryptedData: Uint8Array,
  encPrivKey: Uint8Array
): Promise<{ amount: bigint; index: number }> {
  if (encryptedData.length !== 86) {
    throw new Error(`Invalid V3 encrypted data length: ${encryptedData.length}`);
  }

  if (encryptedData[0] !== 0x03) {
    throw new Error(`Invalid V3 version byte: ${encryptedData[0]}`);
  }

  // Extract components
  const ephemeralPubKey = encryptedData.slice(1, 33);
  const iv = encryptedData.slice(33, 45);
  const authTag = encryptedData.slice(45, 61);
  const ciphertext = encryptedData.slice(61, 73);
  // Bytes 73-85 are padding (ignored)

  // ECDH to derive shared secret
  const sharedSecret = ecdhSharedSecret(encPrivKey, ephemeralPubKey);

  // Derive encryption key
  const encryptionKey = deriveEncryptionKey(sharedSecret);

  // Import key for AES-256-GCM
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(encryptionKey).buffer,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  // Reconstruct ciphertext with authTag appended (Web Crypto expects this format)
  const ciphertextWithTag = new Uint8Array(ciphertext.length + authTag.length);
  ciphertextWithTag.set(ciphertext, 0);
  ciphertextWithTag.set(authTag, ciphertext.length);

  // Decrypt
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertextWithTag
  );

  // Unpack note data
  const decrypted = new Uint8Array(decryptedBuffer);
  const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);

  return {
    amount: view.getBigUint64(0, true),
    index: view.getUint32(8, true),
  };
}

/**
 * Check if encrypted data is V3 format
 *
 * @param data - Encrypted data
 * @returns true if V3 format (first byte is 0x03)
 */
export function isV3Format(data: Uint8Array): boolean {
  return data.length >= 1 && data[0] === 0x03;
}

/**
 * Derive blinding from V3 encrypted data
 *
 * This allows recovering the blinding value without decrypting the note,
 * useful for commitment verification.
 *
 * @param encryptedData - V3 encrypted output (86 bytes)
 * @param encPrivKey - X25519 private key for ECDH
 * @param index - Optional output index (must match the index used during encryption)
 * @returns Blinding value as BN
 */
export function deriveBlindingFromV3(encryptedData: Uint8Array, encPrivKey: Uint8Array, index: number = 0): BN {
  if (encryptedData.length < 33 || encryptedData[0] !== 0x03) {
    throw new Error('Invalid V3 encrypted data');
  }

  // Extract ephemeral public key
  const ephemeralPubKey = encryptedData.slice(1, 33);

  // ECDH to derive shared secret
  const sharedSecret = ecdhSharedSecret(encPrivKey, ephemeralPubKey);

  // Derive blinding from shared secret with the same index
  return deriveBlinding(sharedSecret, index);
}

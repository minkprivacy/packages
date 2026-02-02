# Crypto Module

`@minkprivacy/core/crypto`

Cryptographic primitives for zero-knowledge proofs, encryption, and key management.

## Key Hierarchy

```
Wallet Signature (64 bytes)
├── V1 Encryption Key: first 31 bytes
├── V2 Encryption Key: Keccak256(signature)
├── UTXO Private Key V1: first 31 bytes (hex)
├── UTXO Private Key V2: Keccak256(signature) (hex)
└── X25519 Enc Private Key: SHA256(zkPrivKey || domain) mod X25519_ORDER
    └── X25519 Enc Public Key: x25519.getPublicKey(encPrivKey)
```

## `Keypair`

ZK keypair for UTXO ownership. Uses BabyJubjub / BN254 field arithmetic with Poseidon hashing.

```typescript
import { Keypair } from '@minkprivacy/core/crypto';

// From private key hex
const kp = new Keypair(privkeyHex, lightWasm);

// Generate random
const kp = await Keypair.generateNew(lightWasm);

// Properties
kp.privkey  // BN — private key (mod FIELD_SIZE)
kp.pubkey   // BN — Poseidon(privkey)

// Sign for ZK proof
const sig = kp.sign(commitment, merklePath);
// → Poseidon(privkey || commitment || merklePath)
```

## `EncryptionService`

Multi-version encryption service with persistent cache.

```typescript
import { EncryptionService } from '@minkprivacy/core/crypto';

const enc = new EncryptionService();

// Initialize from wallet
await enc.deriveEncryptionKeyFromWallet(signMessage, walletAddress);

// Or from raw signature
await enc.deriveEncryptionKeyFromSignature(signatureBytes);

// Encrypt/decrypt
const encrypted = await enc.encrypt(data);
const decrypted = await enc.decrypt(encrypted);

// UTXO-specific
const encUtxo = await enc.encryptUtxo({ amount, blinding, index });
const utxoData = await enc.decryptUtxoData(encUtxo, mintAddress);
// → { amount, blinding, index, mintAddress, version: 'v1'|'v2'|'v3' }
```

### Encryption Versions

| Version | Format | Algorithm | Size |
|---------|--------|-----------|------|
| V1 | `[IV(16) \| authTag(16) \| data]` | AES-128-CTR + HMAC-SHA256 | variable |
| V2 | `[version(8) \| IV(12) \| authTag(16) \| ciphertext]` | AES-256-GCM | 86 bytes (UTXO) |
| V3 | `[0x03 \| ephPub(32) \| IV(12) \| authTag(16) \| ct(12) \| pad(13)]` | ECDH + AES-256-GCM | 86 bytes |

V3 is ECDH-based — no pre-shared key required. Used for inbox stealth forwards.

### V3 Support

```typescript
// Set X25519 private key for V3 decryption
enc.setEncPrivKey(encPrivKey);
enc.hasEncPrivKey(); // → boolean

// Version detection
enc.getEncryptionKeyVersion(data); // → 'v1' | 'v2' | 'v3'
```

### Cache Management

```typescript
enc.enablePersistentStorage();   // localStorage (default)
enc.enableSecureStorage();       // sessionStorage
enc.clearCache(walletAddress);   // per wallet
enc.clearAllCaches();
enc.reset();                     // clear in-memory keys
```

Cache is encrypted with PBKDF2(walletAddress, 100K iterations) → AES-256-GCM.

## ECDH Functions

X25519 Diffie-Hellman for stealth address encryption.

```typescript
import {
  deriveEncPrivKey,
  deriveEncPubKey,
  ecdhSharedSecret,
  deriveBlinding,
  deriveEncryptionKey,
  generateEphemeralKeypair,
  encryptNoteV3,
  decryptNoteV3,
  secureZeroKey,
} from '@minkprivacy/core/crypto';

// Derive persistent keys from ZK spending key
const encPriv = deriveEncPrivKey(zkPrivKey);     // Uint8Array(32)
const encPub  = deriveEncPubKey(encPriv);         // Uint8Array(32)

// Ephemeral operation (sender)
const eph = generateEphemeralKeypair();
const shared = ecdhSharedSecret(eph.privateKey, recipientEncPub);
const blind  = deriveBlinding(shared, 0);         // BN (field element)
const encKey = deriveEncryptionKey(shared);        // Uint8Array(32)
const encrypted = await encryptNoteV3(eph.publicKey, encKey, { amount, index });
secureZeroKey(eph.privateKey);                     // clear from memory

// Decryption (recipient)
const { amount, index } = await decryptNoteV3(encrypted, encPriv);
```

### Domain Separation

| Domain | Purpose |
|--------|---------|
| `mink_enc_v1` | X25519 private key derivation |
| `mink_blinding_v1` | UTXO blinding factor |
| `mink_encryption_v1` | AES encryption key |

## `serializeProofAndExtData()`

Serializes ZK proof + external data into an 836-byte Solana instruction.

```typescript
const ixData = serializeProofAndExtData(proof, extData, isSpl, txType);
// txType: 'deposit' → CLOAK discriminator
// txType: 'withdraw' → REVEAL discriminator
```

**Layout (836 bytes):**
- Discriminator: 8 bytes
- NullifierInputs: 64 bytes
- ZkProof: 480 bytes (proofA 64 + proofB 128 + proofC 64 + root 32 + nullifiers 64 + commitments 64 + publicAmount 32 + extDataHash 32)
- ExtData: 292 bytes (recipient 32 + extAmount 16 + relayer 32 + fee 8 + encOutput1 86 + encOutput2 86 + mint 32)

## Utility Functions

```typescript
import { toHex, fromHex, sha256, hmacSha256 } from '@minkprivacy/core/crypto';

toHex(bytes);                        // Uint8Array → hex string
fromHex(hex);                        // hex string → Uint8Array
await sha256(data);                  // Web Crypto SHA-256
await hmacSha256(key, data);         // Web Crypto HMAC-SHA256
```

## Constants

```typescript
import {
  FIELD_SIZE,              // BN254 scalar field (BN)
  MERKLE_TREE_DEPTH,       // 26
  SIGN_MESSAGE,            // 'Mink stealth account sign in'
  SOL_MINT_ADDRESS,        // 'So11111111111111111111111111111111111111112'
  TOKENS,                  // Record<TokenName, TokenInfo>
  SUPPORTED_TOKENS,        // ['SOL', 'USDC', 'USDT']
  getTokenByMint,          // (mint) → TokenInfo | undefined
  getTokenMint,            // (token, network) → PublicKey
  DEFAULT_PROGRAM_ID,      // PublicKey
  RELAYER_API_URL,         // string
  FETCH_UTXOS_GROUP_SIZE,  // 20_000
} from '@minkprivacy/core/crypto';
```

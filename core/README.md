# @minkprivacy/core

[![npm version](https://img.shields.io/npm/v/@minkprivacy/core.svg)](https://www.npmjs.com/package/@minkprivacy/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

Core SDK for private transactions on Solana using zero-knowledge proofs.

## Install

```bash
npm install @minkprivacy/core
# or
pnpm add @minkprivacy/core
```

**Peer dependencies:**

```bash
npm install @solana/web3.js @lightprotocol/hasher.rs
```

## Quick Start

```typescript
import { MinkSDK } from '@minkprivacy/core';

const sdk = await MinkSDK.create({
  connection,        // @solana/web3.js Connection
  wallet,            // Wallet adapter (signMessage + signTransaction)
  network: 'devnet', // 'devnet' | 'mainnet'
});

await sdk.authenticate();

// Deposit SOL into the privacy pool
const deposit = await sdk.cloak({ amount: 0.1 });

// Withdraw from the privacy pool
const withdraw = await sdk.reveal({ amount: 0.05, recipientAddress: '...' });

// Check stealth balance
const balance = await sdk.getStealthBalance();
```

## Architecture

```
@minkprivacy/core
├── MinkSDK           ← High-level facade
├── crypto/           ← Keypairs, encryption (V1/V2/V3), ECDH
├── operations/       ← deposit, withdraw, balance, helpers
├── proofs/           ← ZK proof generation (snarkjs/Groth16)
├── merkle/           ← Poseidon-based Merkle tree
├── models/           ← Utxo, token definitions
├── storage/          ← IStorage, BrowserStorage, MemoryStorage
├── errors/           ← Typed error hierarchy
├── network/          ← Devnet/Mainnet config
├── inbox/            ← Private Inbox (stealth addresses)
├── viewing-keys/     ← Scoped viewing keys for auditing
├── logger/           ← ConsoleLogger, NoopLogger
├── auth/             ← Relayer authentication
├── events/           ← SDK event system
└── timestamp/        ← UTXO timestamp tracking
```

## API Reference

### `MinkSDK`

Main entry point. Created via `MinkSDK.create(config)` or `createMinkSDK(config)`.

```typescript
interface PrivacySDKConfig {
  connection: Connection;
  wallet: WalletAdapter;
  network?: 'devnet' | 'mainnet'; // default: 'devnet'
  storage?: IStorage;              // default: BrowserStorage
}
```

#### Core Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `authenticate()` | `Promise<void>` | Derive encryption keys from wallet signature |
| `cloak(params)` | `Promise<CloakResult>` | Deposit SOL into the privacy pool |
| `cloakToken(params)` | `Promise<CloakResult>` | Deposit SPL token (USDC/USDT) |
| `reveal(params)` | `Promise<RevealResult>` | Withdraw from the pool to any address |
| `getStealthBalance()` | `Promise<StealthBalance>` | Fetch and decrypt SOL balance |
| `getTokenBalance(token)` | `Promise<TokenBalanceResult>` | Fetch token balance |
| `getAllBalances()` | `Promise<AllBalancesResult>` | Fetch SOL + all token balances |
| `estimateWithdrawFee(amount)` | `Promise<FeeEstimate>` | Estimate withdrawal fee |
| `dispose()` | `void` | Clean up resources |

#### Inbox Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `inbox.create(params?)` | `Promise<CreateInboxResult>` | Create a private inbox |
| `inbox.forward(inbox)` | `Promise<{signature, amountForwarded}>` | Forward to pool |
| `inbox.getInboxes(mint?)` | `Promise<PrivateInbox[]>` | List inboxes |
| `inbox.getPendingInboxes()` | `Promise<PrivateInbox[]>` | Inboxes with balance |

#### Auth Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `auth.authenticate(signMessage, walletAddress)` | `Promise<boolean>` | Authenticate with relayer |
| `auth.isAuthenticated()` | `boolean` | Check auth status |
| `auth.logout()` | `void` | Clear auth token |

#### Events

```typescript
sdk.on('deposit:confirmed', ({ signature, amount }) => { ... });
sdk.on('withdraw:confirmed', ({ signature, amount, fee }) => { ... });
sdk.on('balance:updated', ({ lamports }) => { ... });
sdk.on('error', ({ error }) => { ... });
```

See [docs/events.md](./docs/events.md) for the full event list.

---

### Cloak / Reveal Params

```typescript
// Deposit SOL
await sdk.cloak({ amount: 0.5 });             // in SOL

// Deposit SPL token
await sdk.cloakToken({ token: 'USDC', amount: 1_000_000 }); // base units

// Withdraw SOL
await sdk.reveal({ amount: 0.3 });                           // to self
await sdk.reveal({ amount: 0.3, recipientAddress: '...' });  // to any address
```

---

## Subpath Exports

The package exposes granular subpath imports for tree-shaking:

```typescript
import { EncryptionService, Keypair } from '@minkprivacy/core/crypto';
import { prove }                       from '@minkprivacy/core/proofs';
import { MerkleTree }                  from '@minkprivacy/core/merkle';
import { Utxo }                        from '@minkprivacy/core/models';
import { deposit, withdraw, getUtxos } from '@minkprivacy/core/operations';
import { BrowserStorage }              from '@minkprivacy/core/storage';
import { MinkError, NetworkError }     from '@minkprivacy/core/errors';
import { getNetworkConfig }            from '@minkprivacy/core/network';
import { PrivateInboxManager }         from '@minkprivacy/core/inbox';
import { ViewingKeyManager }           from '@minkprivacy/core/viewing-keys';
```

Full details for each module below.

---

## Module Reference

### `crypto/` — Encryption & Key Management

See [docs/crypto.md](./docs/crypto.md)

**Key exports:**

| Export | Type | Description |
|--------|------|-------------|
| `Keypair` | class | ZK keypair (Poseidon-based) for UTXO ownership |
| `EncryptionService` | class | Multi-version encryption (V1/V2/V3) |
| `serializeProofAndExtData` | function | Serialize ZK proof for Solana instruction |
| `ecdhSharedSecret` | function | X25519 ECDH shared secret |
| `deriveEncPrivKey` | function | Derive X25519 key from ZK spending key |
| `generateEphemeralKeypair` | function | Fresh ephemeral keypair per operation |
| `encryptNoteV3` / `decryptNoteV3` | functions | V3 ECDH-based encryption |
| `FIELD_SIZE` | constant | BN254 scalar field |
| `TOKENS` | constant | SOL, USDC, USDT token definitions |

**Encryption versions:**

| Version | Algorithm | Key Size | Use Case |
|---------|-----------|----------|----------|
| V1 | AES-128-CTR + HMAC | 31 bytes | Legacy (deprecated) |
| V2 | AES-256-GCM | 32 bytes | UTXO storage |
| V3 | ECDH + AES-256-GCM | ephemeral | Stealth forwards (inbox) |

---

### `operations/` — Deposit, Withdraw, Balance

See [docs/operations.md](./docs/operations.md)

**`deposit(params)`** — Deposit SOL into privacy pool.
- Fetches existing UTXOs, generates ZK proof, creates on-chain transaction
- Supports fresh deposits and consolidation (merging existing UTXOs)

**`depositToken(params)`** — Deposit SPL token (USDC/USDT).

**`withdraw(params)`** — Withdraw SOL from privacy pool.
- Selects best UTXOs, validates Merkle root, generates ZK proof
- Submitted to relayer which executes the on-chain transaction
- Fee: `(amount × rate_bps / 10000) + rent_fee`

**`getUtxos(params)`** — Fetch and decrypt all UTXOs for a wallet.
- Supports V1/V2/V3 encrypted outputs
- Checks spent status via nullifier PDAs
- Caches results in storage

**`getBalanceFromUtxos(utxos)`** — Sum UTXO amounts.

---

### `proofs/` — ZK Proof Generation

See [docs/proofs.md](./docs/proofs.md)

```typescript
import { prove, parseProofToBytesArray } from '@minkprivacy/core/proofs';

const { proof, publicSignals } = await prove(
  circuitInput,
  'https://cdn.example.com/stealth.wasm',
  'https://cdn.example.com/stealth.zkey',
);

const bytes = parseProofToBytesArray(proof);
// bytes.proofA (64 bytes), bytes.proofB (128 bytes), bytes.proofC (64 bytes)
```

- Uses snarkjs for Groth16 proof generation
- Proof A is auto-negated for Solana BN254 verifier
- Browser-compatible (loads circuit files from URLs)

---

### `merkle/` — Merkle Tree

```typescript
import { MerkleTree } from '@minkprivacy/core/merkle';

const tree = new MerkleTree(26, lightWasm);
tree.insert(commitment);
const { pathElements, pathIndices } = tree.path(0);
```

- 26-level Poseidon Merkle tree (capacity: 2²⁶ = 67M leaves)
- Supports `insert`, `bulkInsert`, `update`, `path`, `serialize`/`deserialize`

---

### `models/` — Utxo & Tokens

```typescript
import { Utxo, createEmptyUtxo } from '@minkprivacy/core/models';

const utxo = new Utxo({ lightWasm, amount: 1_000_000, keypair, blinding, index: 42 });
const commitment = await utxo.getCommitment();
const nullifier = await utxo.getNullifier();
```

**Supported tokens:** SOL, USDC, USDT (devnet + mainnet mints).

---

### `storage/` — Pluggable Storage

```typescript
import { BrowserStorage, MemoryStorage } from '@minkprivacy/core/storage';
import type { IStorage } from '@minkprivacy/core/storage';
```

| Class | Persistence | Use Case |
|-------|-------------|----------|
| `BrowserStorage` | localStorage | Default (browser) |
| `SessionStorage` | sessionStorage | Sensitive contexts |
| `MemoryStorage` | in-memory only | Tests, SSR |

Implements `IStorage`: `getItem(key)`, `setItem(key, value)`, `removeItem(key)`.

---

### `errors/` — Error Hierarchy

```typescript
import { MinkError, InsufficientBalanceError, ErrorCodes } from '@minkprivacy/core/errors';

try {
  await sdk.reveal({ amount: 999 });
} catch (e) {
  if (e instanceof InsufficientBalanceError) {
    console.log(`Need ${e.required}, have ${e.available}`);
  }
}
```

| Error Class | Code | Retryable |
|-------------|------|-----------|
| `WalletError` | WALLET_ERROR | no |
| `InitializationError` | INITIALIZATION_ERROR | no |
| `EncryptionError` | ENCRYPTION_ERROR | no |
| `ProofError` | PROOF_ERROR | configurable |
| `NetworkError` | NETWORK_ERROR | yes |
| `TransactionError` | TRANSACTION_ERROR | configurable |
| `InsufficientBalanceError` | INSUFFICIENT_BALANCE | no |
| `TimeoutError` | TIMEOUT_ERROR | yes |
| `ValidationError` | VALIDATION_ERROR | no |

See `ErrorCodes` for all granular codes (e.g., `WALLET_NOT_CONNECTED`, `UNKNOWN_ROOT`).

---

### `network/` — Network Configuration

```typescript
import { getNetworkConfig, DEVNET_CONFIG, MAINNET_CONFIG } from '@minkprivacy/core/network';
import type { NetworkType, NetworkConfig } from '@minkprivacy/core/network';

const config = getNetworkConfig('devnet');
// { rpcUrl, programId, relayerUrl, zkAssetsPath, explorerUrl, ... }
```

Program ID is the same on both networks: `MinkoCW871q3LjoJ1yHuGikT1BwgyeP1VimZha5ecm6`.

---

### `inbox/` — Private Inbox (Stealth Addresses)

See [docs/inbox.md](./docs/inbox.md)

Private inboxes are stealth addresses that receive tokens from any source and auto-forward them into the privacy pool.

```typescript
import { PrivateInboxManager } from '@minkprivacy/core/inbox';

const manager = new PrivateInboxManager({ lightWasm, connection, spendingKeypair, relayerUrl });
const { inbox } = await manager.createInbox();
const address = manager.getReceiveAddress(inbox); // share this
await manager.forwardToPool(inbox);               // forward to pool
```

- Registration uses ZK proof (proves ownership without revealing private key)
- Forward uses ECDH-derived blinding for output encryption
- Supports multiple inboxes per (wallet, mint) pair

---

### `viewing-keys/` — Scoped Viewing Keys

See [docs/viewing-keys.md](./docs/viewing-keys.md)

Viewing keys allow third parties to audit transactions without spending authority.

```typescript
import { ViewingKeyManager, ViewingScope } from '@minkprivacy/core/viewing-keys';

const vkm = new ViewingKeyManager(lightWasm, spendingKeypair);
const vk = vkm.deriveViewingKey(ViewingScope.Full);
const serialized = vkm.serializeViewingKey(vk);
// serialized.url → "mink://view/..."
// serialized.qr  → base58 string for QR codes
```

| Scope | Access |
|-------|--------|
| `Proxy` | Inbox deposits/forwards only |
| `Pool` | Privacy pool transactions only |
| `Full` | Both inbox and pool |

---

### `logger/` — Logging

```typescript
import { ConsoleLogger, NoopLogger } from '@minkprivacy/core';

const logger = new ConsoleLogger({ prefix: '[MyApp]', minLevel: 'warn' });
```

SDK uses `ConsoleLogger` internally. Use `NoopLogger` to suppress output.

---

## Network Details

| | Devnet | Mainnet |
|---|--------|---------|
| Program ID | `MinkoCW871q3LjoJ1yHuGikT1BwgyeP1VimZha5ecm6` | Same |
| Relayer | `https://devnet-api.minkprivacy.com` | `https://api.minkprivacy.com` |
| ZK Assets | `https://cdn.minkprivacy.com/zk-assets` | Same |

## License

[MIT](../LICENSE)

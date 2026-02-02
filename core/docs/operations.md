# Operations Module

`@minkprivacy/core/operations`

Core operations: deposit, withdraw, balance queries, and helpers.

## Deposit

```typescript
import { deposit, depositToken } from '@minkprivacy/core/operations';
import type { DepositParams, DepositTokenParams } from '@minkprivacy/core/operations';
```

### `deposit(params: DepositParams): Promise<DepositResult>`

Deposits SOL into the privacy pool.

**Parameters:**

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `publicKey` | `PublicKey` | yes | Wallet public key |
| `connection` | `Connection` | yes | Solana RPC connection |
| `amountLamports` | `number` | yes | Amount in lamports |
| `storage` | `IStorage` | yes | Storage for UTXO cache |
| `encryptionService` | `EncryptionService` | yes | Initialized encryption |
| `zkAssetsPath` | `string` | yes | URL base for circuit files |
| `lightWasm` | `LightWasm` | yes | Poseidon hasher |
| `transactionSigner` | `TransactionSigner` | yes | Wallet signer |
| `programId` | `PublicKey` | no | Protocol program ID |
| `altAddress` | `PublicKey` | no | Address Lookup Table |
| `relayerUrl` | `string` | no | Relayer API URL |
| `referrer` | `string` | no | Referral address |
| `onStatusChange` | `(status: string) => void` | no | Progress callback |
| `getAuthToken` | `() => Promise<string \| null>` | no | Auth token getter |

**Returns:** `{ signature: string, amount: BigInt, commitment: string }`

**Flow:**
1. Check deposit limit from on-chain config
2. Verify wallet balance
3. Fetch existing UTXOs (consolidation if any)
4. Create output UTXOs
5. Generate ZK proof (stealth.wasm / stealth.zkey)
6. Build and simulate transaction
7. Sign and relay to indexer
8. Poll for confirmation

### `depositToken(params: DepositTokenParams)`

Same as deposit but for SPL tokens. Additional params: `amount`, `mint`, `tokenName`.

---

## Withdraw

```typescript
import { withdraw, clearRelayerConfigCache } from '@minkprivacy/core/operations';
import type { WithdrawParams } from '@minkprivacy/core/operations';
```

### `withdraw(params: WithdrawParams): Promise<WithdrawResult>`

Withdraws SOL from the privacy pool.

**Key params:** `publicKey`, `connection`, `amountLamports`, `recipient`, plus same infra params as deposit.

**Returns:** `{ signature, amount, fee, recipient, isPartial }`

**Fee formula:**
```
fee = (amount × rate_bps / 10000) + rent_fee
```
Default: 0.5% + 0.002 SOL rent fee.

**Flow:**
1. Fetch relayer fee config
2. Select 2 largest unspent UTXOs
3. Validate Merkle root in on-chain history
4. Generate ZK proof with negative extAmount
5. Submit to relayer `/withdraw` endpoint
6. Poll job status until completed
7. Poll for change UTXO confirmation

`isPartial` is `true` when available balance < requested amount.

### `clearRelayerConfigCache()`

Clears cached relayer configuration (fee rates, etc.).

---

## Balance

```typescript
import { getUtxos, getBalanceFromUtxos, isUtxoSpent } from '@minkprivacy/core/operations';
import type { GetUtxosParams } from '@minkprivacy/core/operations';
```

### `getUtxos(params: GetUtxosParams): Promise<Utxo[]>`

Fetches and decrypts all UTXOs for a wallet.

**Key params:**

| Param | Type | Description |
|-------|------|-------------|
| `publicKey` | `PublicKey` | Wallet public key |
| `connection` | `Connection` | Solana RPC |
| `encryptionService` | `EncryptionService` | For decryption |
| `storage` | `IStorage` | Cache layer |
| `lightWasm` | `LightWasm` | Poseidon hasher |
| `mint` | `string` | Token mint (default: SOL) |
| `fromTimestamp` | `number` | Unix seconds — filter UTXOs after this time |
| `abortSignal` | `AbortSignal` | Cancellation |
| `onProgress` | `(current, total) => void` | Progress callback |

**Process:**
1. Fetch encrypted outputs from relayer (`/utxos/range`)
2. Attempt decryption with V1, V2, V3 keys
3. Check nullifier PDAs for spent status
4. Deduplicate and cache results
5. Filter by mint

### `getBalanceFromUtxos(utxos): { lamports: number }`

Sums all UTXO amounts.

### `isUtxoSpent(connection, utxo, programId): Promise<boolean>`

Checks nullifier0/nullifier1 PDAs on-chain.

---

## Helper Functions

```typescript
import {
  fetchMerkleProof,
  queryRemoteTreeState,
  validateMerkleRoot,
  calculateDepositFee,
  calculateWithdrawalFee,
  findNullifierPDAs,
  getExtDataHash,
  getMintAddressField,
  getProgramAccounts,
  getTokenVaultAccounts,
  getAssociatedTokenAddress,
  hexToBytes,
  bytesToHex,
  sleep,
} from '@minkprivacy/core/operations';
```

| Function | Description |
|----------|-------------|
| `fetchMerkleProof(commitment, mint?, relayerUrl?)` | Get Merkle path from relayer |
| `queryRemoteTreeState(mint?, relayerUrl?)` | Get current root + nextIndex |
| `validateMerkleRoot(root, mint?, relayerUrl?)` | Check if root exists in on-chain history |
| `calculateDepositFee(amount, feeBps?)` | Compute deposit fee (currently 0) |
| `calculateWithdrawalFee(amount, feeBps?)` | Compute withdrawal fee in basis points |
| `findNullifierPDAs(nullifiers, programId)` | Derive nullifier0/1 PDAs |
| `findCrossCheckNullifierPDAs(nullifiers, programId)` | Derive cross-check nullifier PDAs |
| `getProgramAccounts(programId)` | Get treeAccount, treeTokenAccount, globalConfig PDAs |
| `getTokenVaultAccounts(mint, programId)` | Get SPL token vault PDAs |
| `getAssociatedTokenAddress(mint, owner)` | Derive ATA address |
| `getExtDataHash(extData)` | Hash external data for circuit |
| `getMintAddressField(mint)` | Convert mint to field element string |

---

## Relayer API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/config` | GET | Fee config |
| `/merkle/root?mint=` | GET | Current root + nextIndex |
| `/merkle/proof/{commitment}?mint=` | GET | Merkle proof |
| `/merkle/validate-root/{root}?mint=` | GET | Root validation |
| `/utxos/range?start=&end=&mint=` | GET | Encrypted outputs |
| `/utxos/indices` | POST | Tree indices for outputs |
| `/utxos/check?hex=&mint=` | GET | UTXO confirmation |
| `/deposit` | POST | Submit deposit tx |
| `/withdraw` | POST | Submit withdrawal job |
| `/transactions/{jobId}/status` | GET | Job status |

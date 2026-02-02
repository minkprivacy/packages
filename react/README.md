# @minkprivacy/react

[![npm version](https://img.shields.io/npm/v/@minkprivacy/react.svg)](https://www.npmjs.com/package/@minkprivacy/react)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

React bindings for the Mink Privacy SDK. Provides a context provider and hooks for building privacy-enabled Solana dApps.

## Install

```bash
npm install @minkprivacy/react
# or
pnpm add @minkprivacy/react
```

**Peer dependencies:**

```bash
npm install react @minkprivacy/core @solana/wallet-adapter-react @solana/web3.js
```

## Quick Start

```tsx
import { MinkProvider, useMink, useMinkBalance, useMinkAuth } from '@minkprivacy/react';

function App() {
  return (
    <MinkProvider config={{ network: 'devnet', connection }}>
      <Dashboard />
    </MinkProvider>
  );
}

function Dashboard() {
  const { sdk, isInitialized } = useMink();
  const { isAuthenticated, authenticate } = useMinkAuth();
  const { balance, isLoading } = useMinkBalance();

  if (!isInitialized) return <p>Connecting...</p>;

  if (!isAuthenticated) {
    return <button onClick={authenticate}>Authenticate</button>;
  }

  if (isLoading) return <p>Loading balance...</p>;

  return (
    <div>
      <p>Stealth balance: {balance?.sol} SOL</p>
      <button onClick={() => sdk?.cloak({ amount: 0.1 })}>
        Deposit 0.1 SOL
      </button>
    </div>
  );
}
```

## Architecture

```
@minkprivacy/react
├── MinkProvider       ← Context provider (wraps wallet adapter)
├── hooks/
│   ├── useMink            ← SDK instance + init state
│   ├── useMinkBalance     ← Balance with caching + auto-refresh
│   ├── useMinkAuth        ← Relayer authentication
│   ├── useMinkInbox       ← Inbox CRUD + forwarding
│   ├── useAutoForward     ← Automatic inbox polling + forward
│   ├── useMinkEvents      ← Single event subscription
│   ├── useMinkEventHandlers ← Multi-event subscription
│   └── useMinkStatus      ← Operation status + messages
├── types/             ← TypeScript interfaces
└── cache/             ← Request deduplication (internal)
```

---

## Provider

### `MinkProvider`

Wraps your app to provide SDK context. Must be nested inside a Solana `WalletProvider`.

```tsx
import { MinkProvider } from '@minkprivacy/react';

<WalletProvider wallets={wallets}>
  <MinkProvider
    config={{ network: 'devnet', connection }}
    autoInitialize={true}  // default: auto-init when wallet connects
  >
    <App />
  </MinkProvider>
</WalletProvider>
```

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `config` | `MinkConfig` | required | SDK configuration |
| `children` | `ReactNode` | required | Child components |
| `autoInitialize` | `boolean` | `true` | Auto-initialize SDK when wallet connects |

**Lifecycle:**
1. SDK instance created on mount via `createMinkSDK(config)`
2. When wallet connects (and `autoInitialize` is true), calls `sdk.initialize()` with wallet adapter
3. On wallet disconnect, resets state and clears request cache
4. On unmount, calls `sdk.dispose()`

---

## Hooks

### `useMink()`

Primary hook for accessing the SDK instance and initialization state.

```tsx
const { sdk, isInitialized, isInitializing, error, initialize, status } = useMink();
```

| Field | Type | Description |
|-------|------|-------------|
| `sdk` | `MinkSDK \| null` | SDK instance |
| `isInitialized` | `boolean` | SDK ready to use |
| `isInitializing` | `boolean` | Initialization in progress |
| `error` | `MinkError \| null` | Initialization error |
| `initialize` | `() => Promise<void>` | Manual initialization |
| `status` | `OperationStatus` | Current operation status |

---

### `useMinkBalance(options?)`

Fetches stealth balance with caching and optional auto-refresh.

```tsx
const { balance, isLoading, isRefetching, error, refetch } = useMinkBalance();

// Token balance
const { balance } = useMinkBalance({ token: 'USDC' });

// Auto-refresh every 10s
const { balance } = useMinkBalance({ refetchInterval: 10_000 });
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `token` | `TokenName` | — | Token to query (`'USDC'` or `'USDT'`). Omit for SOL. |
| `refetchInterval` | `number` | `0` | Auto-refresh interval in ms. `0` = disabled. |
| `enabled` | `boolean` | `true` | Enable/disable the query |

| Return | Type | Description |
|--------|------|-------------|
| `balance` | `BalanceResult \| TokenBalanceResult \| null` | Balance data |
| `isLoading` | `boolean` | Initial loading |
| `isRefetching` | `boolean` | Refetching in background |
| `error` | `MinkError \| null` | Error state |
| `refetch` | `() => Promise<void>` | Manual refetch (invalidates cache) |

**Caching:** Uses a built-in `RequestCache` (5s TTL) with deduplication — concurrent calls for the same balance share a single request.

---

### `useMinkAuth()`

Manages relayer authentication state.

```tsx
const { isAuthenticated, isAuthenticating, error, authenticate, logout } = useMinkAuth();
```

| Return | Type | Description |
|--------|------|-------------|
| `isAuthenticated` | `boolean` | Current auth state |
| `isAuthenticating` | `boolean` | Auth in progress |
| `error` | `MinkError \| null` | Auth error |
| `authenticate` | `() => Promise<boolean>` | Authenticate (requires wallet) |
| `logout` | `() => void` | Clear auth token |

Subscribes to `auth:authenticated` and `auth:expired` SDK events automatically.

---

### `useMinkInbox()`

Full inbox lifecycle — create, list, forward, refresh.

```tsx
const {
  inboxes,
  isLoading,
  isGeneratingProof,
  isSubmitting,
  error,
  create,
  forward,
  refresh,
  fetchInboxes,
} = useMinkInbox();

// Create inbox
const { inbox, signature } = await create();

// Share address
const address = inbox.address.toBase58();

// Forward pending balance to pool
const sig = await forward(inbox);
```

| Return | Type | Description |
|--------|------|-------------|
| `inboxes` | `PrivateInbox[]` | All discovered inboxes |
| `isLoading` | `boolean` | Loading/operating |
| `isGeneratingProof` | `boolean` | ZK proof generation in progress |
| `isSubmitting` | `boolean` | Submitting to relayer |
| `error` | `MinkError \| null` | Error state |
| `create` | `(params?) => Promise<{inbox, signature}>` | Create new inbox |
| `forward` | `(inbox) => Promise<string>` | Forward inbox to pool |
| `refresh` | `(inbox) => Promise<PrivateInbox>` | Refresh inbox state |
| `fetchInboxes` | `() => Promise<void>` | Re-fetch all inboxes |

Subscribes to 8 inbox SDK events for granular progress tracking.

---

### `useAutoForward(options?)`

Automatically polls for pending inboxes and forwards them to the privacy pool.

```tsx
const {
  isForwarding,
  isGeneratingProof,
  lastForwardTime,
  forwardResult,
  clearForwardResult,
  checkPending,
  setEnabled,
  isEnabled,
} = useAutoForward({
  minAmount: BigInt(1_000_000),  // 0.001 SOL
  pollInterval: 30_000,
});

// Show toast on forward
if (forwardResult?.success) {
  toast(`Forwarded ${forwardResult.amount} SOL`);
}
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `minAmount` | `bigint` | `1_000_000n` | Minimum lamports to trigger forward |
| `pollInterval` | `number` | `30_000` | Poll interval in ms |
| `successClearDelay` | `number` | `5_000` | Auto-clear success result (ms) |
| `errorClearDelay` | `number` | `8_000` | Auto-clear error result (ms) |
| `startEnabled` | `boolean` | `true` | Start polling on mount |

| Return | Type | Description |
|--------|------|-------------|
| `isForwarding` | `boolean` | Forward operation in progress |
| `isGeneratingProof` | `boolean` | ZK proof generation in progress |
| `lastForwardTime` | `Date \| null` | Timestamp of last forward |
| `forwardResult` | `ForwardResult \| null` | Latest result (auto-clears) |
| `clearForwardResult` | `() => void` | Manually dismiss result |
| `checkPending` | `() => Promise<void>` | Trigger immediate check |
| `setEnabled` | `(enabled: boolean) => void` | Pause/resume polling |
| `isEnabled` | `boolean` | Current polling state |

---

### `useMinkEvents(event, handler, deps?)`

Subscribe to a single SDK event with automatic cleanup.

```tsx
useMinkEvents('deposit:confirmed', ({ signature, amount }) => {
  console.log(`Deposited ${amount} — tx: ${signature}`);
});
```

### `useMinkEventHandlers(handlers, deps?)`

Subscribe to multiple SDK events at once.

```tsx
useMinkEventHandlers({
  'deposit:confirmed': ({ signature }) => toast(`Deposit: ${signature}`),
  'withdraw:confirmed': ({ signature }) => toast(`Withdraw: ${signature}`),
  'error': ({ error }) => toast.error(error.message),
});
```

---

### `useMinkStatus()`

Human-readable operation status.

```tsx
const { status, isOperating, message } = useMinkStatus();

if (isOperating) {
  return <Spinner label={message} />;
}
```

| Return | Type | Description |
|--------|------|-------------|
| `status` | `OperationStatus` | `'idle'` `'initializing'` `'depositing'` `'withdrawing'` `'scanning'` `'error'` |
| `isOperating` | `boolean` | `true` if not idle/error |
| `message` | `string \| null` | Human-readable status message |

| Status | Message |
|--------|---------|
| `idle` | `null` |
| `initializing` | `"Initializing SDK..."` |
| `depositing` | `"Processing deposit..."` |
| `withdrawing` | `"Processing withdrawal..."` |
| `scanning` | `"Scanning for UTXOs..."` |
| `error` | `"An error occurred"` |

---

## Types

All types are exported from the package root:

```tsx
import type {
  // React types
  MinkProviderProps,
  MinkContextValue,
  OperationStatus,
  UseBalanceOptions,
  UseBalanceResult,
  UseStatusResult,
  UseAuthResult,
  UseInboxResult,
  MinkEventHandler,
  ForwardResult,
  UseAutoForwardReturn,
  UseAutoForwardOptions,

  // Re-exported from @minkprivacy/core
  MinkConfig,
  BalanceResult,
  TokenBalanceResult,
  AllBalancesResult,
  DepositParams,
  DepositResult,
  WithdrawParams,
  WithdrawResult,
  FeeEstimate,
  TokenName,
  PrivateInbox,
  CreateInboxParams,
  MinkEventType,
  MinkEventPayloads,
} from '@minkprivacy/react';

// MinkError is also re-exported as a value
import { MinkError } from '@minkprivacy/react';
```

---

## Peer Dependencies

| Package | Version |
|---------|---------|
| `react` | >= 18.0.0 |
| `@minkprivacy/core` | >= 0.1.0 |
| `@solana/wallet-adapter-react` | >= 0.15.0 |
| `@solana/web3.js` | >= 1.98.0 |

## License

[MIT](../LICENSE)

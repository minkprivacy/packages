# Mink Privacy SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

Private transactions on Solana using zero-knowledge proofs.

## Packages

| Package | Description |
|---------|-------------|
| [`@minkprivacy/core`](./core/) | Core library — crypto, proofs, UTXO management, network operations |
| [`@minkprivacy/react`](./react/) | React bindings — hooks and providers for building privacy-enabled dApps |

## Install

```bash
# Core only
pnpm add @minkprivacy/core

# React bindings (includes core as peer dep)
pnpm add @minkprivacy/react
```

---

## `@minkprivacy/core`

High-level SDK for private SOL and SPL token transactions via ZK proofs (Groth16/BN254).

```typescript
const sdk = await MinkSDK.create({ connection, wallet, network: 'devnet' });
await sdk.authenticate();
await sdk.cloak({ amount: 0.1 });               // deposit SOL
await sdk.reveal({ amount: 0.05, recipientAddress: '...' }); // withdraw
const balance = await sdk.getStealthBalance();   // { lamports, sol }
```

**Modules:** `crypto/` (keypairs, ECDH, encryption V1/V2/V3), `operations/` (deposit, withdraw, balance), `proofs/` (snarkjs Groth16), `merkle/` (Poseidon tree), `models/` (UTXO, tokens), `storage/` (Browser, Session, Memory), `errors/` (typed hierarchy), `network/` (devnet/mainnet config), `inbox/` (stealth addresses), `viewing-keys/` (scoped audit keys), `logger/`, `auth/`, `events/`, `timestamp/`.

See [core/README.md](./core/README.md) and [core/docs/](./core/docs/) for full API reference.

---

## `@minkprivacy/react`

React context provider and hooks for integrating Mink into dApps. Requires `@solana/wallet-adapter-react`.

```tsx
<MinkProvider config={{ network: 'devnet', connection }}>
  <App />
</MinkProvider>
```

**Hooks:** `useMink()` (SDK access), `useMinkBalance()` (cached balance with auto-refresh), `useMinkAuth()` (relayer auth), `useMinkInbox()` (inbox CRUD), `useAutoForward()` (automatic inbox forwarding), `useMinkEvents()` / `useMinkEventHandlers()` (event subscriptions), `useMinkStatus()` (operation status).

See [react/README.md](./react/README.md) for full hook reference.

---

## Development

```bash
git clone https://github.com/minkprivacy/packages.git
cd packages
pnpm install
pnpm build
```

## Documentation

- [Core README](./core/README.md) — SDK API, modules, types
- [Core Docs](./core/docs/) — crypto, operations, proofs, events, inbox, viewing keys
- [React README](./react/README.md) — Provider, hooks, types

## License

[MIT](./LICENSE)

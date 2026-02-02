# Contributing to Mink Privacy SDK

## Prerequisites

- Node.js >= 18
- pnpm >= 9

## Setup

```bash
git clone https://github.com/minkprivacy/packages.git
cd packages
pnpm install
pnpm build
```

## Guidelines

- **No `console.log`** — use `ConsoleLogger` from `@minkprivacy/core`
- **Strict TypeScript** — no `any`, no `@ts-ignore` without justification
- **Focused PRs** — one feature or fix per pull request
- Run `pnpm typecheck` before submitting

## Reporting Issues

Open an issue at [github.com/minkprivacy/packages/issues](https://github.com/minkprivacy/packages/issues).

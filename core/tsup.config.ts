import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'crypto/index': 'src/crypto/index.ts',
    'proofs/index': 'src/proofs/index.ts',
    'merkle/index': 'src/merkle/index.ts',
    'storage/index': 'src/storage/index.ts',
    'errors/index': 'src/errors/index.ts',
    'network/index': 'src/network/index.ts',
    'models/index': 'src/models/index.ts',
    'operations/index': 'src/operations/index.ts',
    'inbox/index': 'src/inbox/index.ts',
    'viewing-keys/index': 'src/viewing-keys/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: false,
  clean: true,
  splitting: false,
  treeshake: true,
  external: [
    '@solana/web3.js',
    '@lightprotocol/hasher.rs',
  ],
  esbuildOptions(options) {
    options.platform = 'neutral';
  },
});

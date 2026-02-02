import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: false,
  clean: true,
  splitting: false,
  treeshake: true,
  external: [
    'react',
    '@solana/web3.js',
    '@solana/wallet-adapter-react',
    '@minkprivacy/core',
  ],
  esbuildOptions(options) {
    options.jsx = 'automatic';
  },
});

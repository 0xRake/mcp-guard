import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: false,
  shims: true,
  skipNodeModulesBundle: true,
  clean: true,
  target: 'node20'
});
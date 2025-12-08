import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/server.ts'],
  format: ['cjs', 'esm'],
  dts: false, // Disable temporarily
  shims: true,
  skipNodeModulesBundle: true,
  clean: true,
  target: 'node20',
  external: ['@modelcontextprotocol/sdk', '@mcp-guard/core']
});
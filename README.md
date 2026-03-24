# MCP-Guard

[![CI](https://github.com/0xRake/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/0xRake/mcp-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org/)

Security scanner for MCP server configs. Catches hardcoded API keys, command injection vectors, auth misconfigurations, SSRF, and compliance gaps before they hit production.

```bash
pnpm add -g @mcp-guard/cli
mcp-guard scan claude_desktop_config.json
```

That's it. You get a score (0-100), a grade, and a list of everything wrong.

## What it catches

MCP-Guard scans your config JSON and flags:

- **Leaked secrets** -- OpenAI keys in args, database URLs with passwords, GitHub tokens in env vars, private keys, bearer tokens. 20+ regex patterns covering AWS, Stripe, Anthropic, and more.
- **Injection risks** -- shell metacharacters in commands, prompt injection vectors, tool poisoning via malicious descriptions, path traversal in args.
- **Auth problems** -- missing auth on database servers, weak passwords, OAuth without PKCE, localhost authorization servers.
- **SSRF** -- internal IP ranges, cloud metadata endpoints (169.254.169.254), dangerous protocols (gopher://, file://), URL parameter injection.
- **Compliance** -- maps findings to GDPR, SOC2, HIPAA, ISO 27001, and PCI DSS controls.

Everything runs locally. Nothing leaves your machine.

## Use with Claude Desktop

Add MCP-Guard as an MCP server so Claude can scan configs for you:

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "npx",
      "args": ["@mcp-guard/mcp-server"]
    }
  }
}
```

This gives Claude access to `scan_config`, `check_vulnerabilities`, `monitor_traffic`, and `generate_report` tools.

## CLI

```bash
mcp-guard scan config.json                          # standard scan
mcp-guard scan config.json --depth comprehensive    # deep scan
mcp-guard scan config.json -o sarif -f results.sarif  # SARIF output for GitHub
mcp-guard fix config.json --dry-run                 # preview fixes
mcp-guard watch config.json -i 30                   # rescan every 30s on file change
mcp-guard report config.json --format pdf --output report.pdf
mcp-guard init                                      # generate example config
mcp-guard list                                      # show available scanners
```

Exit code 0 means clean. Exit code 1 means vulnerabilities found.

See [docs/cli.md](docs/cli.md) for the full flag reference.

## Programmatic usage

```typescript
import { MCPGuard } from '@mcp-guard/core';

const guard = new MCPGuard();
const result = await guard.scan({
  command: 'node',
  args: ['server.js', '--api-key', 'sk-live-oops'],
  env: { DATABASE_URL: 'postgres://admin:pass@localhost/db' }
});

console.log(result.summary.score);  // 35
console.log(result.summary.grade);  // "F"
console.log(result.vulnerabilities.length);  // 3
```

Works with single configs or the full Claude Desktop format (`{ mcpServers: { ... } }`).

## CI/CD

```yaml
- name: Scan MCP config
  run: mcp-guard scan mcp-config.json --format sarif --output results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

Output formats: `json`, `sarif`, `markdown`, `html`, `csv`, `xml`, `pdf`.

## REST API

The `@mcp-guard/api` package runs a Fastify server:

```bash
pnpm server  # starts on :3001
```

```
POST /api/scan    -- scan a config
POST /api/fix     -- apply automated fixes
GET  /health      -- health check
GET  /docs        -- Swagger UI
```

## Packages

| Package | What it does |
|---------|-------------|
| `@mcp-guard/core` | Scanning engine, types, domain scanners |
| `@mcp-guard/cli` | Command-line interface |
| `@mcp-guard/mcp-server` | MCP server for Claude Desktop integration |
| `@mcp-guard/api` | REST API (Fastify) |
| `@mcp-guard/web` | Dashboard (Next.js) |

## Development

```bash
git clone https://github.com/0xrake/mcp-guard.git
cd mcp-guard
pnpm install
pnpm build
pnpm test    # 355 tests
```

Monorepo managed with pnpm workspaces and Turborepo. Each package builds with tsup.

## Docs

- [CLI reference](docs/cli.md)
- [API reference](docs/api-reference.md)
- [Architecture](docs/architecture.md)

## License

MIT

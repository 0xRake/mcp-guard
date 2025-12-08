# MCP-Guard

Enterprise-grade security scanner for Model Context Protocol (MCP) servers.

[![npm version](https://badge.fury.io/js/%40mcp-guard%2Fcli.svg)](https://www.npmjs.com/package/@mcp-guard/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/0xrake/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/0xrake/mcp-guard/actions/workflows/ci.yml)

## Features

- **11 Security Scanners** - Comprehensive vulnerability detection for MCP servers
- **CLI Tool** - Scan configurations with watch mode and auto-fix capabilities
- **MCP Server** - Real-time security monitoring for Claude Desktop
- **Multi-Format Reports** - JSON, SARIF, HTML, Markdown, CSV, XML output
- **Compliance Checks** - GDPR, SOC2, HIPAA, ISO 27001, PCI DSS

## Installation

```bash
# Using npm
npm install -g @mcp-guard/cli

# Using pnpm
pnpm add -g @mcp-guard/cli

# Using npx (no install)
npx @mcp-guard/cli scan config.json
```

## Quick Start

### Scan a Configuration File

```bash
# Scan Claude Desktop config
mcp-guard scan ~/.config/claude/claude_desktop_config.json

# Quick scan (faster, fewer checks)
mcp-guard quick config.json

# Watch mode (continuous monitoring)
mcp-guard watch config.json
```

### Output Formats

```bash
# JSON output
mcp-guard scan config.json --format json --output report.json

# SARIF (for GitHub Security)
mcp-guard scan config.json --format sarif --output results.sarif

# HTML report
mcp-guard scan config.json --format html --output report.html

# Markdown
mcp-guard scan config.json --format markdown --output report.md
```

## CLI Usage

```bash
mcp-guard <command> [options]

Commands:
  scan <file>     Scan MCP server configuration
  quick <file>    Quick security scan (essential checks only)
  watch <file>    Watch configuration for changes
  fix <file>      Auto-fix detected vulnerabilities
  list            List available scanners

Options:
  --format, -f    Output format (json|sarif|html|markdown|csv|xml)
  --output, -o    Output file path
  --severity, -s  Minimum severity to report (info|low|medium|high|critical)
  --scanner       Run specific scanner only
  --verbose, -v   Verbose output
  --help, -h      Show help
```

## MCP Server Setup

Add MCP-Guard to Claude Desktop for real-time security monitoring:

### macOS / Linux

Edit `~/.config/claude/claude_desktop_config.json`:

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

### Windows

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "npx.cmd",
      "args": ["@mcp-guard/mcp-server"]
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `scan_config` | Scan MCP configuration for vulnerabilities |
| `quick_scan` | Fast security scan with essential checks |
| `check_server` | Check a specific server configuration |
| `list_scanners` | List available security scanners |
| `get_recommendations` | Get security recommendations |
| `generate_badge` | Generate security score badge |

## Security Scanners

| Scanner | Description | Severity |
|---------|-------------|----------|
| `api-keys` | Detects exposed API keys, secrets, and credentials | Critical |
| `authentication` | Checks for weak or missing authentication | High |
| `command-injection` | Detects shell/SQL/template injection risks | Critical |
| `tool-poisoning` | Identifies malicious tool definitions | Critical |
| `data-exfiltration` | Detects data leak paths and exfiltration attempts | Critical |
| `prompt-injection` | Identifies LLM manipulation vulnerabilities | High |
| `oauth-security` | Validates OAuth 2.1 compliance | High |
| `confused-deputy` | Detects authorization and privilege issues | High |
| `rate-limiting` | Checks for missing DoS protection | High |
| `ssrf` | Detects Server-Side Request Forgery risks | Critical |
| `compliance` | GDPR, SOC2, HIPAA, ISO 27001, PCI DSS checks | Medium |

## Programmatic Usage

```typescript
import { MCPGuardScanner } from '@mcp-guard/core';

const scanner = new MCPGuardScanner();

const result = await scanner.scan({
  mcpServers: {
    'my-server': {
      command: 'node',
      args: ['server.js'],
      env: {
        API_KEY: process.env.API_KEY
      }
    }
  }
});

console.log(`Security Score: ${result.summary.score}/100`);
console.log(`Grade: ${result.summary.grade}`);
console.log(`Vulnerabilities: ${result.summary.vulnerabilitiesFound}`);
```

## Example Output

```
MCP-Guard Security Scan Report
==============================

Security Score: 72/100 (Grade: C)
Servers Scanned: 3
Vulnerabilities Found: 8

CRITICAL (2)
  - Exposed OpenAI API Key in environment
  - Command injection risk in arguments

HIGH (3)
  - Missing authentication configuration
  - Rate limiting not configured
  - OAuth PKCE not enabled

MEDIUM (2)
  - GDPR: No consent mechanism detected
  - SOC2: Missing audit logging

LOW (1)
  - Verbose error messages enabled

Recommendations:
  1. Move API keys to secure secret management
  2. Enable OAuth 2.1 with PKCE
  3. Configure rate limiting for all endpoints
  4. Implement audit logging
```

## Packages

| Package | Description |
|---------|-------------|
| [@mcp-guard/core](packages/core) | Core scanning engine |
| [@mcp-guard/cli](packages/cli) | Command-line interface |
| [@mcp-guard/mcp-server](packages/mcp-server) | MCP server for Claude Desktop |
| [@mcp-guard/api](packages/api) | REST API server |

## Development

```bash
# Clone repository
git clone https://github.com/0xrake/mcp-guard.git
cd mcp-guard

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Development mode
pnpm dev
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to the `main` branch.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Security

If you discover a security vulnerability, please report it responsibly by emailing security@example.com instead of opening a public issue.

## References

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Security Specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)

# @mcp-guard/mcp-server

MCP server implementation for real-time security monitoring and protection of Model Context Protocol servers.

## Installation

```bash
npm install @mcp-guard/mcp-server
# or
pnpm add @mcp-guard/mcp-server
```

## Configuration

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "npx",
      "args": ["-y", "@mcp-guard/mcp-server"]
    }
  }
}
```

Or run directly:

```bash
npx @mcp-guard/mcp-server
```

## Available Tools

### scan_config
Scan MCP server configuration for security vulnerabilities.

**Parameters:**
- `config` (object, required) - MCP server configuration to scan
- `depth` (string) - Scan depth: quick, standard, comprehensive, paranoid

**Example:**
```json
{
  "tool": "scan_config",
  "arguments": {
    "config": {
      "command": "node",
      "args": ["server.js"],
      "env": { "API_KEY": "sk-..." }
    },
    "depth": "comprehensive"
  }
}
```

### check_vulnerabilities
Check for specific vulnerability types in configuration.

**Parameters:**
- `config` (object, required) - Configuration to check
- `types` (array) - Vulnerability types: api-keys, authentication, command-injection, tool-poisoning

**Example:**
```json
{
  "tool": "check_vulnerabilities",
  "arguments": {
    "config": { ... },
    "types": ["api-keys", "authentication"]
  }
}
```

### monitor_config
Start monitoring configuration for security issues.

**Parameters:**
- `path` (string, required) - Path to configuration file
- `interval` (number) - Check interval in seconds (default: 30)

**Example:**
```json
{
  "tool": "monitor_config",
  "arguments": {
    "path": "/path/to/config.json",
    "interval": 60
  }
}
```

### auto_fix
Automatically fix detected vulnerabilities.

**Parameters:**
- `config` (object, required) - Configuration with vulnerabilities
- `dryRun` (boolean) - Preview fixes without applying (default: false)

**Example:**
```json
{
  "tool": "auto_fix",
  "arguments": {
    "config": { ... },
    "dryRun": true
  }
}
```

### generate_report
Generate security report for MCP configuration.

**Parameters:**
- `config` (object, required) - Configuration to analyze
- `format` (string) - Report format: json, markdown, html, sarif

**Example:**
```json
{
  "tool": "generate_report",
  "arguments": {
    "config": { ... },
    "format": "markdown"
  }
}
```

### risk_score
Calculate security risk score for configuration.

**Parameters:**
- `config` (object, required) - Configuration to score

**Returns:**
```json
{
  "score": 75,
  "grade": "C",
  "risk_level": "MEDIUM",
  "vulnerabilities": {
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 1
  }
}
```

## Usage with Claude

Once configured, you can use MCP-Guard tools in Claude:

```
Use the scan_config tool to check this MCP server configuration for vulnerabilities:
{
  "command": "python",
  "args": ["server.py"],
  "env": {
    "DATABASE_URL": "postgresql://user:pass@localhost/db"
  }
}
```

Claude will use the MCP-Guard server to scan the configuration and report any security issues found.

## Features

- **Real-time Scanning** - Scan configurations on demand
- **Continuous Monitoring** - Watch configuration files for changes
- **Auto-remediation** - Fix vulnerabilities automatically
- **Multiple Report Formats** - JSON, Markdown, HTML, SARIF
- **Risk Scoring** - Calculate security risk scores
- **Selective Scanning** - Check specific vulnerability types

## Security Scanners

The MCP server includes all scanners from @mcp-guard/core:

1. **API Key Scanner** - Detects exposed secrets and credentials
2. **Authentication Scanner** - Checks for missing or weak authentication
3. **Command Injection Scanner** - Identifies injection vulnerabilities
4. **Tool Poisoning Scanner** - Detects malicious tool definitions

## Integration

### GitHub Actions

```yaml
- name: Scan MCP Configuration
  run: |
    npx @mcp-guard/mcp-server scan-config config.json
```

### Pre-commit Hook

```bash
#!/bin/sh
npx @mcp-guard/mcp-server scan-config claude_desktop_config.json || exit 1
```

## License

MIT
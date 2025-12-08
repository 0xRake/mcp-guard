# MCP-Guard Server

A Model Context Protocol (MCP) server that provides real-time security scanning and monitoring capabilities for MCP configurations.

## Features

- 🔍 **Real-time Security Scanning** - Comprehensive vulnerability detection
- 🛡️ **11 Security Scanners** - API keys, authentication, injection attacks, and more
- 📊 **Traffic Monitoring** - Real-time anomaly detection
- 📄 **Multi-format Reports** - JSON, Markdown, HTML, SARIF, PDF
- 🔧 **Multiple Transports** - Stdio and WebSocket support

## Installation

### For Claude Desktop

Run the installation script:

```bash
./install-mcp.sh
```

Or manually configure by adding to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "node",
      "args": ["/path/to/mcp-guard/packages/mcp-server/dist/server.js"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

### For Other MCP Clients

1. Build the server:
```bash
pnpm install
pnpm build
```

2. Run with stdio transport:
```bash
node dist/server.js
```

3. Or run with WebSocket transport:
```bash
node dist/server.js --websocket --port 8080
```

## Available Tools

### 1. scan_config
Performs comprehensive security scanning of MCP configurations.

**Parameters:**
- `config` (object, required): MCP server configuration to scan
- `depth` (string): Scan depth - `quick`, `standard`, `comprehensive`, `paranoid`

**Example:**
```json
{
  "name": "scan_config",
  "arguments": {
    "config": {
      "name": "my-server",
      "tools": [...]
    },
    "depth": "comprehensive"
  }
}
```

### 2. check_vulnerabilities
Checks for specific vulnerability types.

**Parameters:**
- `config` (object, required): Configuration to check
- `types` (array): Vulnerability types to check
  - `api-keys`
  - `authentication`
  - `command-injection`
  - `tool-poisoning`
  - `data-exfiltration`
  - `prompt-injection`
  - `oauth-security`
  - `confused-deputy`
  - `rate-limiting`
  - `ssrf`
  - `compliance`

### 3. monitor_traffic
Monitors real-time traffic and detects anomalies.

**Parameters:**
- `config` (object, required): Configuration to monitor
- `interval` (number): Monitoring interval in milliseconds (default: 5000)
- `metrics` (array): Metrics to track (default: ["all"])

### 4. generate_report
Generates security reports in various formats.

**Parameters:**
- `config` (object, required): Configuration to analyze
- `format` (string): Report format - `json`, `markdown`, `html`, `sarif`, `pdf`
- `includeRemediation` (boolean): Include remediation steps (default: true)
- `includeCompliance` (boolean): Include compliance checks (default: false)

## Transport Options

### Stdio Transport (Default)
Used by Claude Desktop and CLI tools:
```bash
node dist/server.js
```

### WebSocket Transport
For web applications and remote connections:
```bash
node dist/server.js --websocket --port 8080
```

## Configuration

### Environment Variables
- `NODE_ENV`: Set to `production` for production use
- `MCP_GUARD_LOG_LEVEL`: Logging level (`debug`, `info`, `warn`, `error`)

### MCP Configuration (mcp.json)
```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "node",
      "args": ["./dist/server.js"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

## Security Scanners

The server includes 11 specialized security scanners:

1. **API Keys Scanner** - Detects exposed API keys and secrets
2. **Authentication Scanner** - Identifies authentication vulnerabilities
3. **Command Injection Scanner** - Detects command injection risks
4. **Tool Poisoning Scanner** - Identifies malicious tool configurations
5. **Data Exfiltration Scanner** - Detects potential data leaks
6. **Prompt Injection Scanner** - Identifies prompt manipulation attempts
7. **OAuth Security Scanner** - Checks OAuth implementation security
8. **Confused Deputy Scanner** - Detects privilege escalation risks
9. **Rate Limiting Scanner** - Identifies missing rate limits
10. **SSRF Scanner** - Detects server-side request forgery vulnerabilities
11. **Compliance Scanner** - Checks regulatory compliance (GDPR, HIPAA, etc.)

## Development

### Building from Source
```bash
# Install dependencies
pnpm install

# Build the server
pnpm build

# Run in development mode
pnpm dev
```

### Testing
```bash
# Run simple test
node test-simple.js

# Run MCP protocol test
node test-mcp.js
```

## License

MIT
# @mcp-guard/core

Core security scanning engine for MCP-Guard. Detects vulnerabilities, security misconfigurations, and compliance violations in Model Context Protocol (MCP) server configurations.

## Features

- 🔑 **API Key Detection**: Identifies 20+ types of exposed secrets and credentials
- 🔐 **Authentication Scanner**: Detects missing, weak, or misconfigured authentication
- 💉 **Command Injection**: Finds shell injection, path traversal, and code execution risks
- 🔧 **Tool Poisoning**: Identifies dangerous or malicious MCP tool definitions
- 📊 **Security Scoring**: CVSS 3.1 based vulnerability scoring (0-10)
- 📋 **Compliance Mapping**: GDPR, SOC2, HIPAA, ISO27001 compliance checks
- 🔧 **Auto-remediation**: Automated fixes for common vulnerabilities
- 📊 **Detailed Reports**: Comprehensive vulnerability reports with evidence

## Installation

```bash
npm install @mcp-guard/core
# or
pnpm add @mcp-guard/core
```

## Usage

```typescript
import mcpGuard from '@mcp-guard/core';

// Scan a single MCP server configuration
const config = {
  command: "node",
  args: ["server.js"],
  env: {
    API_KEY: "sk-abc123..." // Will be detected as vulnerability
  }
};

const result = await mcpGuard.scan(config);
console.log(`Security Score: ${result.summary.score}/100 (Grade: ${result.summary.grade})`);
console.log(`Vulnerabilities Found: ${result.summary.vulnerabilitiesFound}`);
console.log(`Critical: ${result.summary.critical}, High: ${result.summary.high}`);

// Scan Claude Desktop configuration
const claudeConfig = {
  mcpServers: {
    "github": {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-github"],
      env: {
        GITHUB_TOKEN: "ghp_..." // Will be detected
      }
    }
  }
};

const results = await mcpGuard.scan(claudeConfig.mcpServers);
```

## Implemented Scanners (4 Total)

### 1. API Key Scanner (CRITICAL)
Detects 20+ types of exposed secrets:
- OpenAI/Anthropic API keys
- AWS/Google Cloud credentials
- GitHub/GitLab tokens
- Database connection strings
- OAuth client secrets
- Stripe/PayPal keys
- JWT secrets and private keys

### 2. Authentication Scanner (HIGH)
Identifies authentication vulnerabilities:
- Missing authentication on sensitive servers
- Weak/default credentials (admin/admin)
- Basic auth instead of OAuth 2.1
- Missing PKCE in OAuth flows
- Authentication bypass flags
- Insecure protocols (HTTP, telnet)
- Debug mode bypasses

### 3. Command Injection Scanner (CRITICAL)
Detects injection and execution risks:
- Shell metacharacters (; | & $ `)
- Command substitution patterns
- Path traversal (../, /etc/passwd)
- SQL injection patterns
- Template injection
- Code execution (eval, exec)
- Dangerous commands (rm, curl | sh)

### 4. Tool Poisoning Scanner (CRITICAL)
Identifies dangerous MCP tools:
- Malicious tool names (execute_command, delete_all)
- Tools without authentication
- Unrestricted parameters (command, query)
- Data exfiltration capabilities
- Bulk tool exposure (expose_all)
- Missing rate limiting/audit logs
- Dangerous capability combinations

## Vulnerability Severity Levels

| Severity | CVSS Score | Description |
|----------|------------|-------------|
| CRITICAL | 9.0-10.0 | Immediate action required |
| HIGH | 7.0-8.9 | Should be fixed ASAP |
| MEDIUM | 4.0-6.9 | Fix in next release |
| LOW | 0.1-3.9 | Can be deferred |
| INFO | 0.0 | Informational only |

## API

### `mcpGuard.scan(config, options?)`
Scans MCP configuration for vulnerabilities.

**Parameters:**
- `config`: Single MCP server config or multiple configs
- `options`: Optional scan configuration
  - `depth`: 'quick' | 'standard' | 'comprehensive' | 'paranoid'
  - `excludeTypes`: Array of vulnerability types to skip
  - `autoFix`: Enable automatic remediation
  - `outputFormat`: 'json' | 'sarif' | 'pdf' | 'markdown' | 'html'

**Returns:** `ScanResult` with score, grade, vulnerabilities, and recommendations

### `mcpGuard.quickScan(config)`
Fast scan with minimal checks.

### `mcpGuard.comprehensiveScan(config)`
Full scan including compliance checks.

## Testing

```bash
# Run all tests (60+ test cases)
pnpm test

# Run specific scanner tests
pnpm test api-keys
pnpm test authentication
pnpm test command-injection
pnpm test tool-poisoning

# Watch mode
pnpm test:watch

# Coverage report
pnpm test --coverage
```

## Examples

```bash
# Run demos
npx tsx examples/scan-demo.ts          # Basic API key detection
npx tsx examples/complete-demo.ts      # Authentication + API keys
npx tsx examples/all-scanners-demo.ts  # All 4 scanners showcase
```

## Example Output

```
🔐 MCP-Guard Complete Security Scanner v1.0

📦 Loaded Security Scanners:
  ✓ API Key Scanner        - Detects exposed secrets
  ✓ Authentication Scanner - Finds auth weaknesses
  ✓ Command Injection     - Identifies injection risks
  ✓ Tool Poisoning        - Detects dangerous tools

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           SECURITY ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 Security Score:
  [████████░░░░░░░░░░░░░░░░░░░░] 25/100 (F)

📊 Scan Statistics:
  • Duration: 127ms
  • Servers: 6
  • Scanners: 4
  • Checks: 150+

⚠️ Vulnerability Distribution:
  Exposed Api Key          ▓▓▓▓▓▓▓▓▓▓ 5
  Command Injection        ▓▓▓▓▓▓▓▓ 4
  Missing Authentication   ▓▓▓▓▓▓ 3
  Tool Poisoning          ▓▓▓▓▓▓ 3

🚨 Severity Breakdown:
  💀 CRITICAL   12
  🔴 HIGH       8
  🟡 MEDIUM     5

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        SERVER-BY-SERVER ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💀 nightmare-server
  🔑 API Keys:
    [CRITICAL] Exposed AWS Secret Key
  🔐 Authentication:
    [CRITICAL] Default credentials detected
    [HIGH] Authentication bypass enabled
  💉 Command Injection:
    [CRITICAL] Command substitution detected
  🔧 Tool Poisoning:
    [HIGH] Permissive tool allowlist

✅ Secure Memory Server
  No vulnerabilities detected!
```

## License

MIT

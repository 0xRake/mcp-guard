# API Reference

## Core library (`@mcp-guard/core`)

### `MCPGuard`

Main entry point. Creates an instance with all five scanner domains registered.

```typescript
import { MCPGuard } from '@mcp-guard/core';

const guard = new MCPGuard();
```

#### `scan(config, options?)`

```typescript
scan(config: MCPServerConfig | Record<string, MCPServerConfig>, options?: ScanConfig): Promise<ScanResult>
```

Runs all registered scanners against the config. Accepts a single server config or a multi-server map (like Claude Desktop's `mcpServers` object).

#### `quickScan(config)`

Shorthand for `scan(config, { depth: 'quick' })`.

#### `comprehensiveScan(config)`

Shorthand for `scan(config, { depth: 'comprehensive', includeCompliance: true })`.

#### `registerScanner(scanner)`

Add a custom scanner. It needs to implement the `Scanner` interface.

#### `initializeDistributed(config?)`

Set up worker pool for scanning multiple servers in parallel. Enterprise use case.

#### `distributedScan(config, options?)`

Run scans across the worker pool. Requires `initializeDistributed()` first.

---

### `MCPServerConfig`

The input shape. This is what you're scanning.

```typescript
interface MCPServerConfig {
  command: string;                // e.g., "node", "python", "npx"
  args?: string[];                // command-line arguments
  env?: Record<string, string>;   // environment variables
  auth?: AuthConfig;              // authentication setup
  oauth?: OAuthConfig;            // OAuth 2.1 config
  capabilities?: ServerCapabilities;
  metadata?: ServerMetadata;
}
```

**`AuthConfig`:**

```typescript
interface AuthConfig {
  type: 'bearer' | 'basic' | 'apikey' | 'custom';
  token?: string;
  credentials?: { username: string; password: string };
}
```

**`OAuthConfig`:**

```typescript
interface OAuthConfig {
  authorizationServer: string;
  clientId?: string;
  scopes?: string[];
  pkce?: boolean;
  metadata?: OAuthMetadata;
}
```

You can also pass a Claude Desktop config directly -- the scanner detects the `mcpServers` wrapper and iterates over each server.

---

### `ScanConfig`

Controls scan behavior.

```typescript
interface ScanConfig {
  depth: 'quick' | 'standard' | 'comprehensive' | 'paranoid';
  targets?: string[];
  excludeServers?: string[];
  excludeTypes?: VulnerabilityType[];
  includeCompliance?: boolean;
  autoFix?: boolean;
  outputFormat?: 'json' | 'sarif' | 'pdf' | 'markdown' | 'html';
  silent?: boolean;
  parallel?: boolean;
  timeout?: number;
}
```

`depth` affects how many checks run. `quick` skips compliance and does basic pattern matching. `comprehensive` and `paranoid` run everything.

---

### `ScanResult`

What you get back.

```typescript
interface ScanResult {
  id: string;
  timestamp: Date;
  duration: number;              // milliseconds
  config: ScanConfig;
  summary: {
    score: number;               // 0-100 (100 = clean)
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
    serversScanned: number;
    vulnerabilitiesFound: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  vulnerabilities: Vulnerability[];
  metadata: { scanner: string; version: string; signatures: string; rules: number };
  recommendations: string[];
}
```

The score starts at 100 and subtracts: -20 per critical, -10 per high, -5 per medium, -2 per low.

---

### `Vulnerability`

Individual finding.

```typescript
interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;             // CRITICAL | HIGH | MEDIUM | LOW | INFO
  score: number;                  // CVSS 0-10
  server: string;
  title: string;
  description: string;
  location?: { file?: string; line?: number; path?: string };
  evidence?: { code?: string; value?: string; pattern?: string };
  remediation: {
    description: string;
    automated: boolean;
    commands?: string[];
  };
  cwe?: string[];
  compliance?: { gdpr?: boolean; soc2?: boolean; hipaa?: boolean; iso27001?: boolean };
  discoveredAt: Date;
}
```

---

### `VulnerabilityType` enum

```
EXPOSED_API_KEY          COMMAND_INJECTION        TOOL_POISONING
MISSING_AUTHENTICATION   PROMPT_INJECTION         ANSI_ESCAPE_SEQUENCE
WEAK_AUTHENTICATION      SQL_INJECTION            CONFUSED_DEPUTY
OAUTH_TOKEN_LEAKAGE      PATH_TRAVERSAL           CROSS_SERVER_CONTAMINATION
INVALID_JWT_CONFIGURATION DATA_EXFILTRATION       MISCONFIGURATION
SSRF                     UNENCRYPTED_STORAGE      EXCESSIVE_PERMISSIONS
MISSING_RATE_LIMITING    INSECURE_TRANSMISSION    CORS_MISCONFIGURATION
GDPR_VIOLATION           SOC2_VIOLATION           HIPAA_VIOLATION
COMPLIANCE_VIOLATION     TENANT_ISOLATION_FAILURE RESOURCE_SHARING_VIOLATION
```

---

### `Scanner` interface

Implement this to add your own scanner domain.

```typescript
interface Scanner {
  name: string;
  description: string;
  version: string;
  enabled: boolean;
  scan(config: MCPServerConfig, options?: ScanConfig): Promise<Vulnerability[]>;
  canAutoFix?: boolean;
  autoFix?(vulnerability: Vulnerability): Promise<boolean>;
}
```

Register it with `guard.registerScanner(yourScanner)`.

---

## MCP Server tools

When running as an MCP server (`@mcp-guard/mcp-server`), these tools are exposed:

| Tool | Input | What it does |
|------|-------|-------------|
| `scan_config` | `config` (object), `depth` (string) | Full vulnerability scan |
| `check_vulnerabilities` | `config`, `types[]` | Scan for specific vulnerability types only |
| `monitor_traffic` | `config`, `interval` (ms), `metrics[]` | Real-time anomaly detection |
| `generate_report` | `config`, `format` (string) | Produce a formatted security report |

Transport: stdio (default) or WebSocket (`--websocket --port 8080`).

---

## REST API (`@mcp-guard/api`)

Runs on port 3001 by default. Swagger docs at `/docs`.

### `POST /api/scan`

```json
{
  "config": { "command": "node", "args": ["server.js"] },
  "options": { "depth": "comprehensive" }
}
```

Returns `{ success: true, result: ScanResult }`.

### `POST /api/fix`

```json
{
  "vulnerabilities": [
    { "id": "vuln-abc123", "automated": true }
  ]
}
```

### `GET /health`

Returns `{ status: "healthy", timestamp: "..." }`.

### `GET /api/scanners`

Lists all registered scanner domains.

### `GET /api/stats`

Dashboard statistics (scans today, vulnerability counts, trends).

### `WebSocket /ws`

Send `{ type: "subscribe" }` to get real-time scan updates pushed to you.

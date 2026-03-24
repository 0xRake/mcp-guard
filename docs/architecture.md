# Architecture

## Why it's built this way

The original version had 11 separate scanners -- one for API keys, one for auth, one for command injection, and so on. Each one parsed the same config independently, maintained its own vulnerability types, and ran in sequence. It worked, but it was slow and half the scanners were duplicating each other's pattern matching.

v2 collapsed those 11 scanners into 5 domains. Each domain owns a coherent area of security (data protection, execution control, etc.) and runs in parallel with the others via `Promise.all`. The config gets parsed once, and every domain sees the same data.

## How a scan works

```
config JSON
  |
  v
MCPGuard.scan()
  |
  +-- Is it a multi-server config? (has mcpServers key?)
  |     yes -> iterate over each server
  |     no  -> treat as single server
  |
  +-- For each server config:
  |     Run all 5 domains in parallel (Promise.all)
  |     Each domain returns Vulnerability[]
  |
  +-- Flatten all vulnerabilities
  +-- Calculate score (start at 100, subtract per severity)
  +-- Assign grade (A/B/C/D/F)
  +-- Generate recommendations
  |
  v
ScanResult
```

The whole thing is synchronous from the caller's perspective -- you `await` the scan and get a result. Internally, the domains run concurrently.

## The Scanner interface

Every domain implements this:

```typescript
interface Scanner {
  name: string;
  version: string;
  enabled: boolean;
  scan(config: MCPServerConfig, options?: ScanConfig): Promise<Vulnerability[]>;
  canAutoFix?: boolean;
  autoFix?(vulnerability: Vulnerability): Promise<boolean>;
}
```

You can add custom scanners with `guard.registerScanner(myScanner)`. If `enabled` is false, it gets skipped.

## Domains

**Data Protection** (`data-protection.ts`) -- the biggest domain. Scans for hardcoded secrets using 20+ regex patterns (OpenAI, AWS, GitHub, Stripe, database URLs, private keys). Also checks for data exfiltration targets (paste sites, cloud storage, tunneling services like ngrok) and SSRF vectors (internal IPs, metadata endpoints, dangerous protocols).

**Execution Control** (`execution-control.ts`) -- looks at `command` and `args` for shell injection patterns (pipes, backticks, subshells). Checks tool definitions for poisoning (misleading descriptions that could trick an LLM). Scans for prompt injection vectors and verifies rate limiting.

**Identity & Access Control** (`identity-access-control.ts`) -- flags servers that handle sensitive data but have no auth configured. Checks for weak passwords, OAuth misconfigurations (missing PKCE, localhost auth servers), and confused deputy scenarios.

**Configuration Assurance** (`configuration-assurance.ts`) -- catches misconfigurations: overly broad permissions, missing security headers, insecure TLS settings, debug mode left on in production.

**Compliance & Governance** (`compliance-governance.ts`) -- maps findings to regulatory frameworks. Checks for GDPR data handling requirements, SOC2 controls, HIPAA PHI indicators, PCI DSS card data patterns, and ISO 27001 security controls.

## Distributed scanning

For scanning many servers at once, there's an enterprise mode:

```typescript
const guard = new MCPGuard();
guard.initializeDistributed({ workerCount: 4 });
const result = await guard.distributedScan(multiServerConfig);
await guard.shutdownDistributed();
```

This spins up a worker pool that partitions configs across workers, scans them in parallel, and aggregates the results. The `DistributedScanningManager` handles partitioning, the `ScannerWorker` runs individual scans, and the `ResultAggregator` merges everything back together.

You don't need this for a handful of servers. It's there for when you're scanning dozens or hundreds.

## Codebase layout

```
packages/
  core/src/
    index.ts                  -- MCPGuard class (main export)
    types/index.ts            -- all TypeScript interfaces and enums
    domains/
      data-protection.ts      -- secrets, exfiltration, SSRF
      execution-control.ts    -- injection, tool poisoning, prompt injection
      identity-access-control.ts -- auth, OAuth, confused deputy
      configuration-assurance.ts -- misconfiguration detection
      compliance-governance.ts   -- regulatory compliance
    distributed/
      distributed-scanner.ts  -- worker pool manager
      worker/scanner-worker.ts -- individual scan worker
      utils/                  -- partitioning, aggregation, fault tolerance
    validators/               -- config validation, secret pattern matching
    utils/                    -- report generation, config loading
  cli/src/index.ts            -- Commander-based CLI
  api/src/index.ts            -- Fastify REST server
  mcp-server/src/
    server.ts                 -- MCP protocol server with tool definitions
    tools/                    -- tool implementations
    transport/                -- stdio and WebSocket transports
  web/                        -- Next.js dashboard
```

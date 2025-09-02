# MCP-Guard Project Knowledge Base
*Complete context for Claude Project - Last Updated: January 2025*

## 🎯 Project Overview

**MCP-Guard** is an enterprise-grade security scanner and real-time protection system for Model Context Protocol (MCP) servers. It provides both a CLI tool for scanning and an MCP server for active protection.

**Repository Path:** `/Users/rake/Developer/GitHub/mcp-guard`

## 📋 Configuration Decisions

```yaml
Security Focus: Comprehensive Enterprise
- All vulnerability types including compliance
- OAuth 2.1 compliant authentication
- Multi-tenancy support

Operation Mode: Hybrid
- CLI for detection and reporting
- MCP Server for real-time protection

Target Audience: All segments
- Individual developers
- Teams/Startups  
- Enterprise organizations

Data Handling: Hybrid Secure
- Local scanning by default
- Optional cloud for ML detection
- Encrypted telemetry

Monetization: Freemium
- Free: Basic scanning (3 servers)
- Pro: $99/month (auto-fixes, monitoring)
- Enterprise: $499/month (compliance, SLA)

Implementation: TypeScript
- Node.js 20+ required
- Strict TypeScript configuration
- OAuth 2.1 specification compliance
```

## 🏗️ Architecture

### Monorepo Structure
```
mcp-guard/
├── packages/
│   ├── core/           # Scanning engine (in progress)
│   ├── cli/            # Command-line tool (pending)
│   ├── mcp-server/     # MCP server (pending)
│   └── web/            # Dashboard & API (pending)
├── .github/
│   └── workflows/      # GitHub Actions
├── .mcp-guard-build/   # Build memory system
└── docs/               # Documentation
```

### Package Dependencies

#### @mcp-guard/core
- ajv: Schema validation
- chalk: Colored output
- fast-glob: File system scanning
- joi/zod: Validation
- jsonwebtoken: JWT handling
- crypto-js: Encryption

#### @mcp-guard/cli  
- commander: CLI framework
- ora: Spinners
- inquirer: Prompts
- pdf-lib: PDF generation
- terminal-kit: Terminal UI

#### @mcp-guard/mcp-server
- @modelcontextprotocol/sdk: MCP SDK
- jose/oauth4webapi: OAuth 2.1
- jsonwebtoken: Token validation

#### @mcp-guard/web
- next: React framework
- tailwindcss: Styling
- stripe: Payments
- @tanstack/react-query: Data fetching

## 🔍 Vulnerability Scanners (11 Types)

### Critical Priority
1. **API Key Scanner** - Detect exposed secrets (sk-, api_key, token)
2. **Command Injection** - Detect command execution risks
3. **Tool Poisoning** - Identify malicious tool definitions
4. **Data Exfiltration** - Find data leak paths

### High Priority  
5. **Authentication Scanner** - Missing/weak auth
6. **OAuth Security** - Token leakage, misconfigurations
7. **Prompt Injection** - LLM manipulation risks
8. **Confused Deputy** - Permission escalation

### Medium Priority
9. **ANSI Escape** - Terminal manipulation
10. **Multi-tenancy** - Tenant isolation failures
11. **Compliance** - SOC2, GDPR, HIPAA violations

## 📁 Files Created

### Root Configuration
- `/package.json` - Monorepo setup with turbo
- `/pnpm-workspace.yaml` - PNPM workspace config
- `/turbo.json` - Turbo build configuration
- `/tsconfig.json` - Strict TypeScript settings

### Core Package
- `/packages/core/package.json` - Core dependencies
- `/packages/core/src/types/index.ts` - Complete type definitions

### Build Memory System
- `/.mcp-guard-build/build-memory.json` - Persistent state
- `/.mcp-guard-build/resume.ts` - Resume script

## 💾 Build Memory State

```json
{
  "currentPhase": "setup",
  "currentStep": "core_package_setup",
  "completedSteps": [
    "project_initialization",
    "directory_structure", 
    "root_configuration",
    "core_package_setup"
  ],
  "nextSteps": [
    "core_scanner_implementation",
    "cli_implementation",
    "mcp_server_implementation",
    "web_dashboard"
  ],
  "packagesStatus": {
    "@mcp-guard/core": "in_progress",
    "@mcp-guard/cli": "pending",
    "@mcp-guard/mcp-server": "pending",
    "@mcp-guard/web": "pending"
  }
}
```

## 🛠️ MCP Server Tools to Implement

### Essential Tools
- `scan_config` - Scan MCP configurations
- `check_vulnerabilities` - Real-time checks

### Advanced Tools
- `monitor_traffic` - Watch MCP calls
- `block_tool` - Prevent dangerous execution
- `sandbox_execution` - Safe testing
- `audit_log` - Activity tracking

### Compliance Tools
- `generate_report` - SOC2/GDPR reports
- `policy_enforcement` - Custom rules
- `risk_scoring` - Security posture

## 📊 Features to Implement

### Must-Have (MVP)
- [x] Project structure
- [x] Type definitions
- [x] Build memory system
- [ ] Core scanners (3 minimum)
- [ ] Basic CLI
- [ ] Simple MCP server
- [ ] NPM publishing

### Planned Features
- [ ] GitHub Action for CI/CD
- [ ] VS Code Extension
- [ ] PDF Report Generation
- [ ] Web Dashboard
- [ ] Auto-remediation
- [ ] Real-time Monitoring
- [ ] Vulnerability Database
- [ ] Security Badges
- [ ] API for Integrations

## 🚀 Implementation Commands

### Setup Project
```bash
cd /Users/rake/Developer/GitHub/mcp-guard
pnpm install
```

### Resume Build
```bash
# Check current status
node .mcp-guard-build/resume.ts

# Continue from saved state
cat .mcp-guard-build/build-memory.json
```

### Build Commands
```bash
pnpm build        # Build all packages
pnpm dev          # Development mode
pnpm test         # Run tests
pnpm cli          # Run CLI
pnpm server       # Run MCP server
pnpm web          # Run web dashboard
```

### Publish to NPM
```bash
pnpm build
npm login
npm publish packages/cli --access public
npm publish packages/mcp-server --access public
```

## 📝 Next Implementation Steps

### 1. Complete Core Package (Priority)
```typescript
// Implement scanners in packages/core/src/scanners/
- api-keys.ts
- authentication.ts  
- command-injection.ts
- tool-poisoning.ts
- oauth-security.ts
```

### 2. CLI Package
```typescript
// packages/cli/src/index.ts
- Parse arguments with commander
- Load configuration
- Run scanners from core
- Format output (colors, tables)
- Generate reports (PDF, JSON)
```

### 3. MCP Server
```typescript
// packages/mcp-server/src/index.ts
- Implement MCP SDK server
- OAuth 2.1 authentication
- Expose security tools
- Real-time monitoring
- WebSocket connections
```

### 4. Web Dashboard
```typescript
// packages/web/
- Next.js 14 with App Router
- Dashboard UI with Tailwind
- API routes for scanning
- Stripe payment integration
- Security badge generation
```

## 🎯 MVP Shortcuts (2-3 hours)

If time constrained, implement only:
1. API key scanner
2. Basic CLI with colored output
3. Simple MCP server (no OAuth)
4. README with usage
5. NPM publish

## 📚 Reference Documentation

### MCP Security Resources
- [MCP Security Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [OAuth 2.1 for MCP](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [Google MCP Security](https://google.github.io/mcp-security/)
- [GitHub MCP Security Guide](https://github.blog/ai-and-ml/generative-ai/how-to-build-secure-and-scalable-remote-mcp-servers/)
- [Awesome MCP Security](https://github.com/Puliczek/awesome-mcp-security)

### Implementation Patterns

#### OAuth 2.1 Discovery
```typescript
// Server announces OAuth requirement
response.status(401).header('WWW-Authenticate', 
  'Bearer realm="mcp-guard", metadata_url="/.well-known/oauth-protected-resource"'
);
```

#### Human-in-the-Loop
```typescript
// Critical operations require confirmation
if (requiresHumanInLoop(vulnerability.type)) {
  await promptUser("Confirm dangerous operation");
}
```

#### Multi-tenancy Isolation
```typescript
// Scope all operations to authenticated user
const userId = validateJWT(token).sub;
const results = await scan(config, { userId });
```

## 🔄 Session Resume Instructions

When starting a new Claude conversation:

1. **Reference this document**: "Continue building MCP-Guard using PROJECT_KNOWLEDGE.md"

2. **Check status**: "What's the current build status from build-memory.json?"

3. **Resume specific task**: 
   - "Implement the next scanner from the list"
   - "Continue with CLI implementation"
   - "Build the MCP server with saved configuration"

4. **Update memory**: "Update build-memory.json with progress"

## 💡 Key Decisions for Next Session

1. **MVP vs Full Build**: Recommend MVP first (3 scanners, basic features)
2. **OAuth Implementation**: Can defer to v2 for faster launch
3. **Web Dashboard**: Static landing page first, full dashboard later
4. **Monetization**: Start with "Buy me a coffee", add Stripe later

## 🎯 Success Metrics

- **Day 1**: Working scanner on NPM
- **Week 1**: 100 GitHub stars
- **Month 1**: 1000 weekly scans
- **Month 3**: $5K MRR
- **Year 1**: Acquisition target

---

# End of Project Knowledge

*Use this document as the foundation for continuing MCP-Guard development in any Claude conversation.*

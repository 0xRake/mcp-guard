# Changelog

All notable changes to this project will be documented in this file.

This project uses [Changesets](https://github.com/changesets/changesets) for release management.

## [2.0.0] - 2025-09-02

### Changed

- Consolidated 11 individual scanners into 5 security domains:
  - Data Protection (secrets, exfiltration, SSRF)
  - Execution Control (command injection, tool poisoning)
  - Identity & Access Control (authentication, OAuth, confused deputy)
  - Configuration Assurance (misconfiguration detection)
  - Compliance Governance (GDPR, SOC2, HIPAA, PCI DSS, ISO 27001)
- Replaced Logger singleton with injectable `Logger` interface
- All diagnostic output writes to stderr (safe for piped JSON and MCP transport)
- Enabled TypeScript declaration generation across all packages

### Added

- `--debug` flag for CLI verbose output
- `MCPGuardOptions` interface with dependency injection for logger
- `noopLogger` default and `createStderrLogger` factory
- Distributed scanning module with worker threads, fault tolerance, and circuit breakers
- Test suites for CLI (7 tests), API (11 tests), and MCP server (14 tests)
- SARIF, CSV, and XML report output formats
- MIT LICENSE file

### Fixed

- 58 dependency vulnerabilities resolved (0 remaining)
- CLI JSON output no longer corrupted by log messages
- API `buildApp()` exported for testability, server only starts when run directly
- `check-vulnerabilities` type filter now matches domain-based vulnerability types
- CI workflow uses `pnpm audit` instead of `npm audit`

### Removed

- `console.log` calls from core library
- Tracked build artifacts from git history
- Stale documentation files

## [1.0.0] - 2025-08-30

### Added

- Initial release with 11 security scanners
- CLI with scan, fix, report, watch, list, and init commands
- REST API with Fastify
- MCP server implementation
- Web dashboard (Next.js)
- CI/CD pipeline with GitHub Actions
- Docker image builds
- NPM package publishing

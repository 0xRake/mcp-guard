# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | Yes                |
| 1.x     | Security fixes only|
| < 1.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in MCP-Guard, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@mcp-guard.dev** with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. The potential impact
4. Any suggested fixes (optional)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity
  - Critical: patch release within 7 days
  - High: patch release within 14 days
  - Medium/Low: included in next scheduled release

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available, we will:

1. Release the patched version
2. Publish a security advisory on GitHub
3. Credit the reporter (unless they prefer anonymity)

We ask that reporters allow us reasonable time to address the issue before public disclosure.

## Scope

This policy covers:

- `@mcp-guard/core` — scanning engine
- `@mcp-guard/cli` — command-line interface
- `@mcp-guard/mcp-server` — MCP protocol server
- `@mcp-guard/api` — REST API server

The web dashboard (`@mcp-guard/web`) is not intended for public deployment and is excluded from this policy.

# MCP-Guard

Static analysis framework for identifying security vulnerabilities in Model Context Protocol (MCP) server configurations.

[![npm version](https://badge.fury.io/js/%40mcp-guard%2Fcli.svg)](https://www.npmjs.com/package/@mcp-guard/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/0xrake/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/0xrake/mcp-guard/actions/workflows/ci.yml)
[![Test Status](https://img.shields.io/badge/tests-355%2F355%20passing-brightgreen.svg)](https://github.com/0xrake/mcp-guard)

## Overview

MCP-Guard implements a unified security architecture that consolidates multiple security scanning capabilities into a single-pass analysis engine. The system operates across five security domains with parallel execution, providing comprehensive vulnerability detection for MCP server configurations.

## Installation

```bash
npm install -g @mcp-guard/cli
```

## Quick Start

```bash
# Scan MCP server configuration
mcp-guard scan config.json

# Quick scan
mcp-guard quick config.json

# Automated remediation
mcp-guard fix config.json
```

## Security Domains

| Domain | Coverage |
|--------|----------|
| **Data Protection** | API Keys, Data Exfiltration, SSRF |
| **Execution Control** | Command Injection, Tool Poisoning, Prompt Injection |
| **Identity & Access Control** | Authentication, OAuth Security |
| **Configuration Assurance** | Misconfiguration Detection |
| **Compliance & Governance** | GDPR, SOC2, HIPAA, ISO 27001, PCI DSS |

## Documentation

- [System Architecture](docs/SYSTEM_ARCHITECTURE.md) - Technical architecture and implementation details
- [Technical Reference](docs/technical-reference.md) - API reference and usage examples

## License

MIT License
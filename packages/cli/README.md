# @mcp-guard/cli

Command-line interface for MCP-Guard security scanner. Scan MCP server configurations for vulnerabilities, generate reports, and auto-fix security issues.

## Installation

```bash
npm install -g @mcp-guard/cli
# or
pnpm add -g @mcp-guard/cli
```

## Usage

### Basic Scan

```bash
# Scan Claude Desktop configuration automatically
mcp-guard scan

# Scan a specific config file
mcp-guard scan config.json

# Scan with specific depth
mcp-guard scan --depth comprehensive
```

### Quick Scan

```bash
# Run a quick security check
mcp-guard quick

# Quick scan specific file
mcp-guard quick myconfig.json
```

### Watch Mode

```bash
# Monitor configuration for changes
mcp-guard watch

# Check every 60 seconds
mcp-guard watch --interval 60
```

### Auto-Fix Vulnerabilities

```bash
# Fix vulnerabilities automatically
mcp-guard fix

# Preview what would be fixed
mcp-guard fix --dry-run
```

### Export Reports

```bash
# Export as JSON
mcp-guard scan --format json --output report.json

# Export as Markdown
mcp-guard scan --format markdown --output report.md

# Export as HTML
mcp-guard scan --format html --output report.html

# Export as SARIF (for CI/CD)
mcp-guard scan --format sarif --output report.sarif
```

## Commands

| Command | Description |
|---------|-------------|
| `scan [path]` | Scan MCP server configuration for vulnerabilities |
| `quick [path]` | Run a quick security scan |
| `watch [path]` | Watch config files for changes |
| `fix [path]` | Auto-fix vulnerabilities |
| `list` | List available scanners |

## Options

### scan command
- `-c, --config <path>` - Path to MCP config file
- `-d, --depth <level>` - Scan depth (quick, standard, comprehensive, paranoid)
- `-f, --format <format>` - Output format (console, json, markdown, html, sarif)
- `-o, --output <path>` - Output file path
- `--auto-fix` - Automatically fix vulnerabilities
- `--no-banner` - Hide the banner
- `--quiet` - Minimal output

### watch command
- `-i, --interval <seconds>` - Check interval in seconds (default: 30)

### fix command
- `--dry-run` - Show what would be fixed without making changes

## Examples

### Scan Claude Desktop Configuration
```bash
mcp-guard scan
```

### Comprehensive Scan with HTML Report
```bash
mcp-guard scan --depth comprehensive --format html --output security-report.html
```

### CI/CD Integration
```bash
# Generate SARIF report for GitHub Actions
mcp-guard scan --format sarif --output results.sarif --quiet

# Exit with code 1 if critical/high vulnerabilities found
mcp-guard scan || exit 1
```

### Auto-Fix with Preview
```bash
# See what would be fixed
mcp-guard fix --dry-run

# Apply fixes
mcp-guard fix
```

## Output Formats

### Console (default)
Displays formatted output with colors, tables, and recommendations.

### JSON
Complete scan results in JSON format for programmatic processing.

### Markdown
Formatted report suitable for documentation or GitHub issues.

### HTML
Interactive HTML report with styling and vulnerability details.

### SARIF
Static Analysis Results Interchange Format for CI/CD integration.

## Exit Codes

- `0` - No critical or high vulnerabilities found
- `1` - Critical or high vulnerabilities detected
- `2` - Configuration or runtime error

## License

MIT
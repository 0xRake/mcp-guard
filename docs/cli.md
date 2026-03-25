# CLI Reference

## Global Options

| Flag | Description |
|------|-------------|
| `-V, --version` | Print version |
| `--debug` | Enable debug logging |
| `-h, --help` | Show help |

## Commands

### `mcp-guard scan <config>`

Run a security scan against an MCP server config file.

```bash
mcp-guard scan config.json
mcp-guard scan ~/.config/claude/claude_desktop_config.json
mcp-guard scan config.json --depth comprehensive -v
mcp-guard scan config.json -o sarif -f results.sarif
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `-v, --verbose` | Show detailed output | off |
| `-o, --output <format>` | Output format: `json`, `markdown`, `html`, `sarif`, `csv`, `xml` | `console` |
| `-f, --file <path>` | Write output to a file instead of stdout | -- |
| `--depth <level>` | Scan depth: `quick`, `standard`, `comprehensive` | `standard` |
| `--exclude <types>` | Skip specific scanners (comma-separated) | -- |

The config file can be plain JSON or a Claude Desktop config with `mcpServers`. Both work.

**Exit codes:** `0` = no vulnerabilities, `1` = vulnerabilities found or scan error.

### `mcp-guard fix <config>`

Interactive security hardening for MCP configurations. Scans for vulnerabilities and environmental issues, then presents a categorized hardening plan. Fixes are selected interactively (or all at once with `--auto`).

```bash
mcp-guard fix config.json                # interactive — pick fixes from a checklist
mcp-guard fix config.json --dry-run      # preview the hardening plan without writing anything
mcp-guard fix config.json --backup       # create a timestamped backup before applying
mcp-guard fix config.json --auto         # apply all recommended fixes without prompting
```

**Options:**

| Flag | Description |
|------|-------------|
| `--auto` | Apply all recommended fixes without prompting |
| `--dry-run` | Show the hardening plan without making changes |
| `--backup` | Save a timestamped `.backup.<timestamp>` copy before modifying |

**Fix categories:**

| Category | What it does |
|----------|-------------|
| Secrets & Credentials | Replaces hardcoded API keys and passwords with `${ENV_VAR}` placeholders. Prints the `export` commands you need to set afterwards. |
| File Permissions | Sets `chmod 600` on config files that contain secrets. Scans 11 known MCP config locations (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf) beyond the target file. |
| Tool Restrictions | Generates `permissions.deny` rules in Claude Code `settings.json` to block dangerous tool patterns (`shell_exec`, `run_command`, `execute`, `rm`, `delete`, `write_file`). |
| Config Hygiene | Detects configs at silently-ignored paths (e.g., `~/.claude/mcp.json` instead of `~/.claude.json`). Adds secret-containing config filenames to `.gitignore`. |
| Transport Security | Flags servers using deprecated SSE transport (deprecated since March 2025) and recommends migration to Streamable HTTP. |

Fixes that cannot be applied automatically are reported as manual steps at the end of the run.

### `mcp-guard report <config>`

Generate a formatted report from a scan.

```bash
mcp-guard report config.json --format html --output report.html
mcp-guard report config.json --pdf report.pdf
mcp-guard report config.json --format sarif --output results.sarif
```

| Flag | Description | Default |
|------|-------------|---------|
| `--format <type>` | `json`, `markdown`, `html`, `pdf`, `sarif`, `csv`, `xml` | `markdown` |
| `--output <path>` | File path for the report | stdout |
| `--pdf <path>` | Shorthand for `--format pdf --output <path>` | -- |

PDF reports include a title page, summary, vulnerability breakdown, and recommendations.

### `mcp-guard watch <config>`

Watch a config file and rescan when it changes. Also rescans on a timer.

```bash
mcp-guard watch config.json                # default 60s interval
mcp-guard watch config.json -i 30          # every 30 seconds
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interval <seconds>` | Time between scheduled rescans | `60` |

File changes trigger an immediate rescan (debounced to 5s). Ctrl+C to stop.

### `mcp-guard dashboard <config>`

Interactive terminal dashboard. Displays a score visualization with severity counts, then provides a menu-driven interface for browsing and acting on vulnerabilities.

```bash
mcp-guard dashboard config.json
mcp-guard dashboard config.json -d comprehensive
```

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --depth <level>` | Scan depth: `quick`, `standard`, `comprehensive` | `standard` |

**Dashboard features:**

- Score and grade display with visual bar
- Severity breakdown (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Filter vulnerabilities by severity level
- Paginated vulnerability browser with drill-down details
- Inline fix for auto-fixable vulnerabilities
- Rescan without leaving the dashboard

### `mcp-guard list`

Show available scanners and their status.

```bash
mcp-guard list
```

Prints a table of all 11 scanner domains with enabled/coming-soon status.

### `mcp-guard init`

Generate an example config file to get started.

```bash
mcp-guard init                        # creates mcp-config.json
mcp-guard init -o my-servers.json     # custom path
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <path>` | Where to write the example config | `mcp-config.json` |

The generated config uses `${ENV_VAR}` placeholders for secrets -- scan it and you'll get a clean result.

## Supported config formats

- `.json` -- standard JSON
- `.js` / `.mjs` -- CommonJS or ESM modules that export a config object

YAML support isn't implemented yet.

## Using in CI

```yaml
steps:
  - name: Scan MCP servers
    run: |
      npx @mcp-guard/cli scan mcp-config.json -o sarif -f results.sarif

  - name: Upload SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@v2
    with:
      sarif_file: results.sarif
```

The exit code lets you gate deployments -- if `mcp-guard scan` exits 1, the build fails.

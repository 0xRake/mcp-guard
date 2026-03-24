# CLI Reference

## Commands

### `mcp-guard scan <config>`

Run a security scan against an MCP server config file.

```bash
mcp-guard scan config.json
mcp-guard scan ~/.config/claude/claude_desktop_config.json
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `-v, --verbose` | Show all vulnerabilities (default caps at 10) | off |
| `-o, --output <format>` | Output format: `json`, `markdown`, `html`, `sarif`, `csv`, `xml` | `console` |
| `-f, --file <path>` | Write output to a file instead of stdout | -- |
| `--depth <level>` | Scan depth: `quick`, `standard`, `comprehensive` | `standard` |
| `--exclude <types>` | Skip specific scanners (comma-separated) | -- |

The config file can be plain JSON or a Claude Desktop config with `mcpServers`. Both work.

**Exit codes:** `0` = no vulnerabilities, `1` = vulnerabilities found or scan error.

### `mcp-guard fix <config>`

Scan, then apply automated fixes to the config file.

```bash
mcp-guard fix config.json --dry-run   # see what would change
mcp-guard fix config.json --backup    # fix and save a .backup copy
mcp-guard fix config.json --auto      # skip the confirmation prompt
```

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview fixes without writing anything |
| `--auto` | Don't prompt for confirmation |
| `--backup` | Save a timestamped backup before modifying |

Only vulnerabilities marked as auto-fixable get touched. The rest show up as "manual remediation required."

### `mcp-guard report <config>`

Generate a formatted report from a scan.

```bash
mcp-guard report config.json --format html --output report.html
mcp-guard report config.json --pdf report.pdf
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

### `mcp-guard list`

Show available scanners and their status.

```bash
mcp-guard list
```

Prints a table of all scanner domains with enabled/coming-soon status.

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

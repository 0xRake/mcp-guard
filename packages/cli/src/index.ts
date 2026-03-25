import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import figlet from 'figlet';
import Table from 'cli-table3';
import fs from 'fs-extra';
import path from 'path';
import { glob } from 'glob';
import PDFDocument from 'pdfkit';
import {
  MCPGuard,
  ReportGenerator,
  ReportFormat,
  ConfigLoader,
  createStderrLogger,
  LogLevel,
} from '@mcp-guard/core';
import { Severity } from '@mcp-guard/core';
import type { ScanResult, Vulnerability, MCPServerConfig, Logger } from '@mcp-guard/core';

const program = new Command();

// Version from package.json
const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf-8'));

// Helper function to format severity with colors
function formatSeverity(severity: Severity | string): string {
  switch (severity) {
    case 'CRITICAL':
      return chalk.red.bold('CRITICAL');
    case 'HIGH':
      return chalk.red('HIGH');
    case 'MEDIUM':
      return chalk.yellow('MEDIUM');
    case 'LOW':
      return chalk.blue('LOW');
    case 'INFO':
      return chalk.gray('INFO');
    default:
      return severity;
  }
}

// Helper function to format score with color
function formatScore(score: number): string {
  if (score >= 80) return chalk.green.bold(`${score}/100`);
  if (score >= 60) return chalk.yellow.bold(`${score}/100`);
  if (score >= 40) return chalk.red(`${score}/100`);
  return chalk.red.bold(`${score}/100`);
}

// Helper function to format grade with color
function formatGrade(grade: string): string {
  if (grade === 'A' || grade === 'A+') return chalk.green.bold(grade);
  if (grade === 'B' || grade === 'B+') return chalk.green(grade);
  if (grade === 'C' || grade === 'C+') return chalk.yellow(grade);
  if (grade === 'D' || grade === 'D+') return chalk.red(grade);
  return chalk.red.bold(grade);
}

// Display banner
function displayBanner() {
  console.log(chalk.cyan(figlet.textSync('MCP-Guard', { horizontalLayout: 'full' })));
  console.log(chalk.gray('Security Scanner for Model Context Protocol Servers\n'));
}

// Load configuration from file
async function loadConfig(
  configPath: string,
  stream?: NodeJS.WritableStream,
): Promise<MCPServerConfig | Record<string, MCPServerConfig>> {
  const spinner = ora({
    text: 'Loading configuration...',
    stream: stream || process.stdout,
  }).start();
  try {
    if (!(await fs.pathExists(configPath))) {
      spinner.fail(`Configuration file not found: ${configPath}`);
      process.exit(1);
    }

    const ext = path.extname(configPath).toLowerCase();
    let config: any;

    if (ext === '.json') {
      config = await fs.readJSON(configPath);
    } else if (ext === '.js' || ext === '.mjs') {
      config = require(path.resolve(configPath));
    } else if (ext === '.yaml' || ext === '.yml') {
      // For YAML support, we'd need to add js-yaml
      spinner.fail('YAML support coming soon. Please use JSON format.');
      process.exit(1);
    } else {
      spinner.fail(`Unsupported configuration format: ${ext}`);
      process.exit(1);
    }

    spinner.succeed('Configuration loaded successfully');
    return config;
  } catch (error) {
    spinner.fail(`Failed to load configuration: ${error}`);
    process.exit(1);
  }
}

// Display scan results
function displayResults(result: ScanResult, verbose: boolean = false) {
  console.log('\n' + chalk.bold('📊 Scan Results'));
  console.log('='.repeat(50));

  // Summary
  console.log(chalk.bold('\n📈 Summary:'));
  console.log(`  Score: ${formatScore(result.summary.score)}`);
  console.log(`  Grade: ${formatGrade(result.summary.grade)}`);
  console.log(`  Servers Scanned: ${result.summary.serversScanned}`);
  console.log(`  Vulnerabilities Found: ${result.summary.vulnerabilitiesFound}`);

  if (result.summary.vulnerabilitiesFound > 0) {
    console.log(chalk.bold('\n🔍 Breakdown:'));
    if (result.summary.critical > 0)
      console.log(`  ${formatSeverity('CRITICAL')}: ${result.summary.critical}`);
    if (result.summary.high > 0) console.log(`  ${formatSeverity('HIGH')}: ${result.summary.high}`);
    if (result.summary.medium > 0)
      console.log(`  ${formatSeverity('MEDIUM')}: ${result.summary.medium}`);
    if (result.summary.low > 0) console.log(`  ${formatSeverity('LOW')}: ${result.summary.low}`);
    if (result.summary.info > 0) console.log(`  ${formatSeverity('INFO')}: ${result.summary.info}`);

    // Vulnerability table
    console.log(chalk.bold('\n⚠️  Vulnerabilities:'));
    const table = new Table({
      head: ['ID', 'Severity', 'Type', 'Server', 'Title'],
      colWidths: [12, 10, 20, 15, 40],
    });

    const vulnsToShow = verbose ? result.vulnerabilities : result.vulnerabilities.slice(0, 10);
    vulnsToShow.forEach((vuln) => {
      table.push([
        vuln.id.substring(0, 10),
        formatSeverity(vuln.severity),
        vuln.type,
        vuln.server || 'N/A',
        vuln.title.substring(0, 38),
      ]);
    });

    console.log(table.toString());

    if (!verbose && result.vulnerabilities.length > 10) {
      console.log(
        chalk.gray(
          `\n  ... and ${result.vulnerabilities.length - 10} more. Use --verbose to see all.`,
        ),
      );
    }
  }

  // Recommendations
  if (result.recommendations && result.recommendations.length > 0) {
    console.log(chalk.bold('\n💡 Recommendations:'));
    result.recommendations.forEach((rec, i) => {
      console.log(`  ${i + 1}. ${rec}`);
    });
  }

  console.log('\n' + '='.repeat(50));
  console.log(`✅ Scan completed in ${result.duration}ms\n`);
}

// Generate PDF report
async function generatePDFReport(result: ScanResult, outputPath: string): Promise<void> {
  const doc = new PDFDocument();
  const stream = fs.createWriteStream(outputPath);
  doc.pipe(stream);

  // Title
  doc.fontSize(24).text('MCP-Guard Security Report', { align: 'center' });
  doc.fontSize(12).text(`Generated: ${new Date().toISOString()}`, { align: 'center' });
  doc.moveDown();

  // Summary
  doc.fontSize(16).text('Summary', { underline: true });
  doc.fontSize(12);
  doc.text(`Score: ${result.summary.score}/100`);
  doc.text(`Grade: ${result.summary.grade}`);
  doc.text(`Servers Scanned: ${result.summary.serversScanned}`);
  doc.text(`Vulnerabilities Found: ${result.summary.vulnerabilitiesFound}`);
  doc.moveDown();

  // Vulnerability Breakdown
  if (result.summary.vulnerabilitiesFound > 0) {
    doc.fontSize(16).text('Vulnerability Breakdown', { underline: true });
    doc.fontSize(12);
    doc.text(`Critical: ${result.summary.critical}`);
    doc.text(`High: ${result.summary.high}`);
    doc.text(`Medium: ${result.summary.medium}`);
    doc.text(`Low: ${result.summary.low}`);
    doc.text(`Info: ${result.summary.info}`);
    doc.moveDown();

    // Vulnerability Details
    doc.fontSize(16).text('Vulnerability Details', { underline: true });
    doc.fontSize(10);

    result.vulnerabilities.forEach((vuln, index) => {
      if (index > 0) doc.moveDown();
      doc.fontSize(12).text(`${index + 1}. [${vuln.severity}] ${vuln.title}`, { underline: true });
      doc.fontSize(10);
      doc.text(`ID: ${vuln.id}`);
      doc.text(`Type: ${vuln.type}`);
      doc.text(`Server: ${vuln.server || 'N/A'}`);
      doc.text(`Description: ${vuln.description}`);
      if (vuln.remediation) {
        doc.text(`Remediation: ${vuln.remediation.description}`);
      }
    });
  }

  // Recommendations
  if (result.recommendations && result.recommendations.length > 0) {
    doc.addPage();
    doc.fontSize(16).text('Recommendations', { underline: true });
    doc.fontSize(12);
    result.recommendations.forEach((rec, i) => {
      doc.text(`${i + 1}. ${rec}`);
    });
  }

  doc.end();

  return new Promise((resolve) => {
    stream.on('finish', resolve);
  });
}

// Main program setup
program
  .name('mcp-guard')
  .description('Security scanner for Model Context Protocol servers')
  .version(packageJson.version)
  .option('--debug', 'Enable debug logging');

// Helper to create MCPGuard instance with optional debug logger
function createGuard(): MCPGuard {
  const logger = program.opts().debug ? createStderrLogger(LogLevel.DEBUG) : undefined;
  return new MCPGuard({ logger });
}

// Scan command
program
  .command('scan <config>')
  .description('Scan MCP server configuration for vulnerabilities')
  .option('-v, --verbose', 'Show detailed output')
  .option(
    '-o, --output <format>',
    'Output format (json, markdown, html, sarif, csv, xml)',
    'console',
  )
  .option('-f, --file <path>', 'Save output to file')
  .option('--depth <level>', 'Scan depth (quick, standard, comprehensive)', 'standard')
  .option('--exclude <types>', 'Exclude scanner types (comma-separated)')
  .action(async (configPath, options) => {
    const structuredOutput = options.output !== 'console';

    if (!structuredOutput) {
      displayBanner();
    }

    // Load configuration
    const config = await loadConfig(configPath, structuredOutput ? process.stderr : undefined);

    // Prepare scan options
    const scanOptions: any = {
      depth: options.depth,
    };

    if (options.exclude) {
      scanOptions.excludeTypes = options.exclude.split(',').map((t: string) => t.trim());
    }

    // Run scan — send spinner to stderr when piping structured output
    const spinner = ora({
      text: 'Running security scan...',
      stream: structuredOutput ? process.stderr : process.stdout,
    }).start();

    try {
      const result = await createGuard().scan(config, scanOptions);
      spinner.succeed('Scan completed successfully');

      // Handle output
      if (!structuredOutput) {
        displayResults(result, options.verbose);
      } else {
        const formatMap: Record<string, ReportFormat> = {
          json: ReportFormat.JSON,
          markdown: ReportFormat.MARKDOWN,
          html: ReportFormat.HTML,
          sarif: ReportFormat.SARIF,
          csv: ReportFormat.CSV,
          xml: ReportFormat.XML,
        };
        const format = formatMap[options.output.toLowerCase()];
        if (!format) {
          throw new Error(`Unsupported format: ${options.output}`);
        }
        const report = await ReportGenerator.generate(result, format);

        if (options.file) {
          await fs.writeFile(options.file, report);
          console.log(chalk.green(`✅ Report saved to ${options.file}`));
        } else {
          console.log(report);
        }
      }

      // Exit with appropriate code
      process.exit(result.summary.vulnerabilitiesFound > 0 ? 1 : 0);
    } catch (error) {
      spinner.fail(`Scan failed: ${error}`);
      process.exit(1);
    }
  });

// Fix command
program
  .command('fix <config>')
  .description('Interactive security hardening for MCP configurations')
  .option('--auto', 'Apply all recommended fixes without prompting')
  .option('--dry-run', 'Show what would be fixed without making changes')
  .option('--backup', 'Create backup before fixing')
  .action(async (configPath, options) => {
    displayBanner();
    const { default: inquirer } = await import('inquirer');

    const config = await loadConfig(configPath);

    const spinner = ora('Scanning for vulnerabilities...').start();
    try {
      const result = await createGuard().scan(config);
      spinner.succeed(`Found ${result.summary.vulnerabilitiesFound} vulnerabilities`);

      // Build fix proposals from scan + environment analysis
      const proposals = await buildFixProposals(configPath, config, result);

      if (proposals.length === 0) {
        console.log(chalk.green('\nNo issues found. Configuration looks secure.'));
        process.exit(0);
      }

      // Display proposals grouped by category
      console.log(chalk.bold('\nSecurity Hardening Plan:\n'));
      const categories = [...new Set(proposals.map((p) => p.category))];
      for (const cat of categories) {
        const catProposals = proposals.filter((p) => p.category === cat);
        console.log(chalk.bold(`  ${categoryLabel(cat)} (${catProposals.length})`));
        for (const p of catProposals) {
          const sev = formatSeverity(p.severity);
          console.log(`    ${sev} ${p.description}`);
          if (p.detail) console.log(chalk.gray(`         ${p.detail}`));
        }
        console.log();
      }

      if (options.dryRun) {
        console.log(chalk.yellow('DRY RUN — no changes applied.'));
        process.exit(0);
      }

      // Backup
      if (options.backup) {
        const backupPath = `${configPath}.backup.${Date.now()}`;
        await fs.copy(configPath, backupPath);
        console.log(chalk.gray(`Backup: ${backupPath}`));
      }

      // Select fixes
      let selected: FixProposal[];
      if (options.auto) {
        selected = proposals;
      } else {
        const { picks } = await inquirer.prompt([
          {
            type: 'checkbox',
            name: 'picks',
            message: 'Select fixes to apply:',
            choices: proposals.map((p, i) => ({
              name: `${formatSeverity(p.severity)} ${p.description}`,
              value: i,
              checked: p.severity === 'CRITICAL' || p.severity === 'HIGH',
            })),
            pageSize: 20,
          },
        ]);
        selected = picks
          .map((i: number) => proposals[i])
          .filter((p: FixProposal | undefined): p is FixProposal => p !== undefined);
      }

      if (selected.length === 0) {
        console.log('No fixes selected.');
        process.exit(0);
      }

      // Apply selected fixes
      const applySpinner = ora('Applying fixes...').start();
      const results = await executeFixProposals(selected, configPath, config);
      applySpinner.succeed(`Applied ${results.applied} of ${results.total} fixes`);

      if (results.envVars.length > 0) {
        console.log(
          chalk.bold('\nSet these environment variables before running your MCP servers:\n'),
        );
        for (const ev of results.envVars) {
          console.log(chalk.cyan(`  export ${ev.name}="${ev.placeholder}"`));
        }
        console.log();
      }

      if (results.manualSteps.length > 0) {
        console.log(chalk.bold('Manual steps remaining:\n'));
        results.manualSteps.forEach((step, i) => {
          console.log(`  ${i + 1}. ${step}`);
        });
        console.log();
      }

      process.exit(0);
    } catch (error) {
      spinner.fail(`Fix operation failed: ${error}`);
      process.exit(1);
    }
  });

// ── Fix Engine ───────────────────────────────────────────────────────────────

type FixCategory = 'secrets' | 'permissions' | 'tools' | 'transport' | 'hygiene';

interface FixProposal {
  category: FixCategory;
  severity: Severity;
  description: string;
  detail?: string;
  apply: () => Promise<FixOutcome>;
}

interface FixOutcome {
  applied: boolean;
  envVars?: Array<{ name: string; placeholder: string }>;
  manualStep?: string;
}

function categoryLabel(cat: FixCategory): string {
  const labels: Record<FixCategory, string> = {
    secrets: 'Secrets & Credentials',
    permissions: 'File Permissions',
    tools: 'Tool Restrictions',
    transport: 'Transport Security',
    hygiene: 'Config Hygiene',
  };
  return labels[cat];
}

// Known MCP config locations to discover and harden
function discoverConfigPaths(): Array<{ path: string; label: string }> {
  const home = process.env.HOME || '';
  return [
    {
      path: path.join(
        home,
        'Library',
        'Application Support',
        'Claude',
        'claude_desktop_config.json',
      ),
      label: 'Claude Desktop',
    },
    { path: path.join(home, '.claude.json'), label: 'Claude Code (user MCP servers)' },
    { path: path.join(home, '.claude', 'settings.json'), label: 'Claude Code (user settings)' },
    {
      path: path.join(home, '.claude', 'settings.local.json'),
      label: 'Claude Code (user local settings)',
    },
    { path: path.resolve('.mcp.json'), label: 'Project MCP servers (.mcp.json)' },
    { path: path.resolve('.claude', 'settings.json'), label: 'Project settings' },
    { path: path.resolve('.claude', 'settings.local.json'), label: 'Project local settings' },
    { path: path.join(home, '.cursor', 'mcp.json'), label: 'Cursor (global)' },
    { path: path.resolve('.cursor', 'mcp.json'), label: 'Cursor (project)' },
    { path: path.resolve('.vscode', 'mcp.json'), label: 'VS Code / Copilot' },
    { path: path.join(home, '.codeium', 'windsurf', 'mcp_config.json'), label: 'Windsurf' },
  ];
}

// Configs at silently-ignored paths
function discoverMisplacedConfigs(): Array<{ path: string; correctPath: string; label: string }> {
  const home = process.env.HOME || '';
  return [
    {
      path: path.join(home, '.claude', 'mcp.json'),
      correctPath: path.join(home, '.claude.json'),
      label: '~/.claude/mcp.json is silently ignored — servers must be in ~/.claude.json',
    },
    {
      path: path.resolve('.claude', '.mcp.json'),
      correctPath: path.resolve('.mcp.json'),
      label: '.claude/.mcp.json is silently ignored — must be at project root as .mcp.json',
    },
  ];
}

async function buildFixProposals(
  configPath: string,
  config: MCPServerConfig | Record<string, MCPServerConfig>,
  result: ScanResult,
): Promise<FixProposal[]> {
  const proposals: FixProposal[] = [];

  // ── 1. Secrets: extract hardcoded values to env vars ───────────────────
  const secretVulns = result.vulnerabilities.filter(
    (v) => v.type === 'EXPOSED_API_KEY' && v.location?.path,
  );
  for (const vuln of secretVulns) {
    const locationPath = vuln.location!.path!;
    proposals.push({
      category: 'secrets',
      severity: Severity.CRITICAL,
      description: `Replace hardcoded secret at ${vuln.server}:${locationPath}`,
      detail: `Current value will be replaced with \${ENV_VAR} placeholder`,
      apply: async () => {
        const serverConfig =
          (config as Record<string, MCPServerConfig>)[vuln.server] || (config as MCPServerConfig);
        let envVarName = '';

        if (locationPath.startsWith('env.') && serverConfig.env) {
          const envKey = locationPath.slice(4);
          if (serverConfig.env[envKey]) {
            envVarName = envKey.toUpperCase();
            serverConfig.env[envKey] = `\${${envVarName}}`;
          }
        } else if (locationPath === 'auth.token' && serverConfig.auth) {
          envVarName = 'AUTH_TOKEN';
          (serverConfig.auth as any).token = `\${${envVarName}}`;
        } else if (locationPath === 'auth.credentials.password' && serverConfig.auth?.credentials) {
          envVarName = 'AUTH_PASSWORD';
          (serverConfig.auth.credentials as any).password = `\${${envVarName}}`;
        } else if (locationPath === 'oauth.clientSecret' && serverConfig.oauth) {
          envVarName = 'OAUTH_CLIENT_SECRET';
          (serverConfig.oauth as any).clientSecret = `\${${envVarName}}`;
        } else {
          return { applied: false, manualStep: `Manually externalize secret at ${locationPath}` };
        }

        await fs.writeJSON(configPath, config, { spaces: 2 });
        return {
          applied: true,
          envVars: [{ name: envVarName, placeholder: '<your-secret-here>' }],
        };
      },
    });
  }

  // ── 2. File permissions: chmod 600 on config files with secrets ────────
  const resolvedPath = path.resolve(configPath);
  try {
    const stat = await fs.stat(resolvedPath);
    const mode = stat.mode & 0o777;
    if (mode !== 0o600 && secretVulns.length > 0) {
      proposals.push({
        category: 'permissions',
        severity: Severity.HIGH,
        description: `Restrict file permissions on ${path.basename(configPath)}`,
        detail: `Current: ${mode.toString(8)} → Recommended: 600 (owner read/write only)`,
        apply: async () => {
          await fs.chmod(resolvedPath, 0o600);
          return { applied: true };
        },
      });
    }
  } catch {
    /* file stat failed, skip */
  }

  // Check other discovered config files
  for (const { path: cfgPath, label } of discoverConfigPaths()) {
    if (cfgPath === resolvedPath) continue;
    try {
      if (await fs.pathExists(cfgPath)) {
        const stat = await fs.stat(cfgPath);
        const mode = stat.mode & 0o777;
        // Any config with secrets (check for common secret patterns)
        const content = await fs.readFile(cfgPath, 'utf-8');
        const hasSecrets =
          /sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|password|secret|token/i.test(
            content,
          );
        if (mode !== 0o600 && hasSecrets) {
          proposals.push({
            category: 'permissions',
            severity: Severity.HIGH,
            description: `Restrict permissions on ${label}`,
            detail: `${cfgPath} is ${mode.toString(8)} and contains secrets → 600`,
            apply: async () => {
              await fs.chmod(cfgPath, 0o600);
              return { applied: true };
            },
          });
        }
      }
    } catch {
      /* skip inaccessible */
    }
  }

  // ── 3. Tool restrictions: generate permissions config ──────────────────
  const home = process.env.HOME || '';
  const settingsPath = path.join(home, '.claude', 'settings.json');
  try {
    let settings: any = {};
    if (await fs.pathExists(settingsPath)) {
      settings = await fs.readJSON(settingsPath);
    }

    // Check for missing or empty permissions
    if (!settings.permissions || (!settings.permissions.deny && !settings.permissions.allow)) {
      // Gather server names from the config
      const serverNames: string[] = [];
      if (typeof config === 'object' && !('command' in config)) {
        serverNames.push(...Object.keys(config as Record<string, MCPServerConfig>));
      }

      proposals.push({
        category: 'tools',
        severity: Severity.MEDIUM,
        description: 'Add tool permission restrictions to Claude Code settings',
        detail: `${settingsPath} has no permissions block — all MCP tools are unrestricted`,
        apply: async () => {
          const existing = (await fs.pathExists(settingsPath))
            ? await fs.readJSON(settingsPath)
            : {};

          // Build deny rules for dangerous patterns
          const denyRules = [
            'mcp__*__shell_exec',
            'mcp__*__run_command',
            'mcp__*__execute',
            'mcp__*__rm',
            'mcp__*__delete',
            'mcp__*__write_file',
          ];

          existing.permissions = existing.permissions || {};
          existing.permissions.deny = [
            ...(existing.permissions.deny || []),
            ...denyRules.filter((r: string) => !(existing.permissions.deny || []).includes(r)),
          ];

          await fs.writeJSON(settingsPath, existing, { spaces: 2 });
          return {
            applied: true,
            manualStep: `Review deny rules in ${settingsPath} and adjust for your workflow`,
          };
        },
      });
    }
  } catch {
    /* settings access failed */
  }

  // ── 4. Transport: flag SSE or HTTP ─────────────────────────────────────
  const configs =
    typeof config === 'object' && !('command' in config)
      ? (config as Record<string, MCPServerConfig>)
      : {};
  for (const [name, serverCfg] of Object.entries(configs)) {
    const args = serverCfg.args?.join(' ') || '';
    const hasSSE = args.includes('--transport sse') || args.includes('transport=sse');
    if (hasSSE) {
      proposals.push({
        category: 'transport',
        severity: Severity.HIGH,
        description: `Server "${name}" uses deprecated SSE transport`,
        detail: 'SSE is deprecated since March 2025 — migrate to Streamable HTTP',
        apply: async () => ({
          applied: false,
          manualStep: `Migrate "${name}" from SSE to Streamable HTTP transport (see MCP spec)`,
        }),
      });
    }
  }

  // ── 5. Config hygiene: misplaced configs, .gitignore ───────────────────
  for (const misplaced of discoverMisplacedConfigs()) {
    try {
      if (await fs.pathExists(misplaced.path)) {
        proposals.push({
          category: 'hygiene',
          severity: Severity.MEDIUM,
          description: misplaced.label,
          detail: `Found: ${misplaced.path} → Should be: ${misplaced.correctPath}`,
          apply: async () => ({
            applied: false,
            manualStep: `Move ${misplaced.path} to ${misplaced.correctPath}`,
          }),
        });
      }
    } catch {
      /* skip */
    }
  }

  // Check if config file with secrets is tracked by git
  if (secretVulns.length > 0) {
    try {
      const gitignorePath = path.resolve('.gitignore');
      const basename = path.basename(configPath);
      let gitignoreContent = '';
      if (await fs.pathExists(gitignorePath)) {
        gitignoreContent = await fs.readFile(gitignorePath, 'utf-8');
      }
      if (!gitignoreContent.includes(basename)) {
        proposals.push({
          category: 'hygiene',
          severity: Severity.HIGH,
          description: `Add ${basename} to .gitignore`,
          detail: 'Config file contains secrets and may be committed to version control',
          apply: async () => {
            const existing = (await fs.pathExists(gitignorePath))
              ? await fs.readFile(gitignorePath, 'utf-8')
              : '';
            const newContent =
              existing.trimEnd() + `\n\n# MCP config (contains secrets)\n${basename}\n`;
            await fs.writeFile(gitignorePath, newContent);
            return { applied: true };
          },
        });
      }
    } catch {
      /* skip */
    }
  }

  // Sort: CRITICAL first, then HIGH, MEDIUM, LOW, INFO
  const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  proposals.sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

  return proposals;
}

async function executeFixProposals(
  proposals: FixProposal[],
  configPath: string,
  config: MCPServerConfig | Record<string, MCPServerConfig>,
): Promise<{
  applied: number;
  total: number;
  envVars: Array<{ name: string; placeholder: string }>;
  manualSteps: string[];
}> {
  let applied = 0;
  const envVars: Array<{ name: string; placeholder: string }> = [];
  const manualSteps: string[] = [];

  for (const proposal of proposals) {
    try {
      const outcome = await proposal.apply();
      if (outcome.applied) {
        console.log(chalk.green(`  Fixed: ${proposal.description}`));
        applied++;
      } else {
        console.log(chalk.yellow(`  Deferred: ${proposal.description}`));
      }
      if (outcome.envVars) envVars.push(...outcome.envVars);
      if (outcome.manualStep) manualSteps.push(outcome.manualStep);
    } catch (error) {
      console.log(chalk.red(`  Failed: ${proposal.description} — ${error}`));
    }
  }

  return { applied, total: proposals.length, envVars, manualSteps };
}

// ── End Fix Engine ───────────────────────────────────────────────────────────

// Report command
program
  .command('report <config>')
  .description('Generate security report')
  .option(
    '--format <type>',
    'Report format (json, markdown, html, pdf, sarif, csv, xml)',
    'markdown',
  )
  .option('--output <path>', 'Output file path')
  .option('--pdf <path>', 'Generate PDF report (shorthand for --format pdf --output <path>)')
  .action(async (configPath, options) => {
    displayBanner();

    // Load configuration
    const config = await loadConfig(configPath);

    // Run scan
    const spinner = ora('Generating security report...').start();

    try {
      const result = await createGuard().scan(config);
      spinner.succeed('Scan completed');

      // Determine format and output path
      let format = options.format;
      let outputPath = options.output;

      if (options.pdf) {
        format = 'pdf';
        outputPath = options.pdf;
      }

      // Generate report
      if (format === 'pdf') {
        if (!outputPath) {
          outputPath = `mcp-guard-report-${Date.now()}.pdf`;
        }
        await generatePDFReport(result, outputPath);
        console.log(chalk.green(`✅ PDF report saved to ${outputPath}`));
      } else {
        const formatMap: Record<string, ReportFormat> = {
          json: ReportFormat.JSON,
          markdown: ReportFormat.MARKDOWN,
          html: ReportFormat.HTML,
          sarif: ReportFormat.SARIF,
          csv: ReportFormat.CSV,
          xml: ReportFormat.XML,
        };
        const reportFormat = formatMap[format.toLowerCase()];
        if (!reportFormat) {
          throw new Error(`Unsupported format: ${format}`);
        }
        const report = await ReportGenerator.generate(result, reportFormat);

        if (outputPath) {
          await fs.writeFile(outputPath, report);
          console.log(chalk.green(`✅ Report saved to ${outputPath}`));
        } else {
          console.log('\n' + report);
        }
      }

      process.exit(0);
    } catch (error) {
      spinner.fail(`Report generation failed: ${error}`);
      process.exit(1);
    }
  });

// Watch command
program
  .command('watch <config>')
  .description('Watch configuration for changes and auto-scan')
  .option('-i, --interval <seconds>', 'Scan interval in seconds', '60')
  .action(async (configPath, options) => {
    displayBanner();

    console.log(chalk.cyan(`👁️  Watching ${configPath} for changes...`));
    console.log(chalk.gray(`Scan interval: ${options.interval} seconds\n`));

    let lastScanTime = 0;

    const runScan = async () => {
      const config = await loadConfig(configPath);
      const spinner = ora('Running security scan...').start();

      try {
        const result = await createGuard().scan(config);
        spinner.succeed(`Scan completed - Score: ${result.summary.score}/100`);

        if (result.summary.vulnerabilitiesFound > 0) {
          console.log(
            chalk.yellow(`⚠️  Found ${result.summary.vulnerabilitiesFound} vulnerabilities`),
          );
          displayResults(result, false);
        } else {
          console.log(chalk.green('✅ No vulnerabilities detected'));
        }

        lastScanTime = Date.now();
      } catch (error) {
        spinner.fail(`Scan failed: ${error}`);
      }
    };

    // Initial scan
    await runScan();

    // Set up file watcher
    const chokidar = require('chokidar');
    const watcher = chokidar.watch(configPath, {
      persistent: true,
      ignoreInitial: true,
    });

    watcher.on('change', async () => {
      const timeSinceLastScan = Date.now() - lastScanTime;
      if (timeSinceLastScan > 5000) {
        // Debounce to avoid rapid rescans
        console.log(chalk.yellow('\n📝 Configuration changed, rescanning...'));
        await runScan();
      }
    });

    // Set up interval scanning
    setInterval(runScan, parseInt(options.interval) * 1000);

    // Handle exit
    process.on('SIGINT', () => {
      console.log(chalk.yellow('\n\n👋 Stopping watch mode...'));
      watcher.close();
      process.exit(0);
    });
  });

// List command
program
  .command('list')
  .description('List available scanners')
  .action(() => {
    displayBanner();

    console.log(chalk.bold('📋 Available Scanners:\n'));

    const scanners = [
      { name: 'api-keys', status: '✅', description: 'Detects exposed API keys and secrets' },
      { name: 'authentication', status: '✅', description: 'Checks authentication configuration' },
      {
        name: 'command-injection',
        status: '✅',
        description: 'Detects command injection vulnerabilities',
      },
      {
        name: 'tool-poisoning',
        status: '✅',
        description: 'Identifies malicious tool definitions',
      },
      { name: 'data-exfiltration', status: '✅', description: 'Detects data leak paths' },
      { name: 'oauth-security', status: '✅', description: 'OAuth 2.1 compliance checking' },
      { name: 'prompt-injection', status: '✅', description: 'Prompt injection detection' },
      { name: 'confused-deputy', status: '✅', description: 'Permission escalation detection' },
      { name: 'rate-limiting', status: '✅', description: 'Rate limiting verification' },
      { name: 'ssrf', status: '✅', description: 'Server-side request forgery detection' },
      { name: 'compliance', status: '✅', description: 'Regulatory compliance checking' },
    ];

    const table = new Table({
      head: ['Status', 'Scanner', 'Description'],
      colWidths: [8, 20, 50],
    });

    scanners.forEach((scanner) => {
      table.push([scanner.status, scanner.name, scanner.description]);
    });

    console.log(table.toString());
    console.log('\nAll 11 scanners enabled.\n');
  });

// Init command - creates example configuration
program
  .command('init')
  .description('Create example configuration file')
  .option('-o, --output <path>', 'Output file path', 'mcp-config.json')
  .action(async (options) => {
    displayBanner();

    const exampleConfig = {
      'test-server': {
        command: 'node',
        args: ['server.js', '--port', '3000'],
        env: {
          NODE_ENV: 'production',
          API_KEY: '${API_KEY}',
          DATABASE_URL: '${DATABASE_URL}',
        },
        capabilities: {
          tools: true,
          prompts: true,
          resources: true,
        },
        metadata: {
          name: 'test-server',
          version: '1.0.0',
        },
      },
      'python-server': {
        command: 'python',
        args: ['mcp_server.py'],
        env: {
          PYTHONPATH: './src',
          FLASK_ENV: 'production',
        },
        auth: {
          type: 'bearer',
          token: '${AUTH_TOKEN}',
        },
      },
    };

    try {
      await fs.writeJSON(options.output, exampleConfig, { spaces: 2 });
      console.log(chalk.green(`✅ Example configuration created: ${options.output}`));
      console.log(chalk.gray('\nEdit this file with your MCP server configurations, then run:'));
      console.log(chalk.cyan(`  mcp-guard scan ${options.output}`));
    } catch (error) {
      console.error(chalk.red(`Failed to create configuration: ${error}`));
      process.exit(1);
    }
  });

// Interactive TUI dashboard
program
  .command('dashboard <config>')
  .description('Interactive terminal dashboard for scan results')
  .option('-d, --depth <level>', 'Scan depth (quick|standard|comprehensive)', 'standard')
  .action(async (configPath, options) => {
    displayBanner();

    const config = await loadConfig(configPath);
    const guard = new MCPGuard();
    const spinner = ora('Running security scan...').start();

    let result: ScanResult;
    try {
      if (typeof config === 'object' && !('command' in config)) {
        const configs = config as Record<string, MCPServerConfig>;
        const allVulns: Vulnerability[] = [];
        let totalScore = 0;
        let serverCount = 0;

        for (const [name, serverConfig] of Object.entries(configs)) {
          const r = await guard.scan(serverConfig);
          allVulns.push(...r.vulnerabilities);
          totalScore += r.summary.score;
          serverCount++;
        }

        const avgScore = serverCount > 0 ? Math.round(totalScore / serverCount) : 100;
        result = buildAggregateResult(allVulns, avgScore, serverCount);
      } else {
        result = await guard.scan(config as MCPServerConfig);
      }
      spinner.succeed('Scan complete');
    } catch (error) {
      spinner.fail(`Scan failed: ${error}`);
      process.exit(1);
    }

    const { default: inquirer } = await import('inquirer');

    // Main dashboard loop
    let running = true;
    while (running) {
      console.clear();
      displayBanner();

      // Score header
      const scoreBar = renderScoreBar(result.summary.score);
      console.log(chalk.bold('  Security Dashboard'));
      console.log(chalk.gray('  ' + '─'.repeat(60)));
      console.log(
        `  Score: ${formatScore(result.summary.score)}  Grade: ${formatGrade(result.summary.grade)}  Servers: ${result.summary.serversScanned}`,
      );
      console.log(`  ${scoreBar}`);
      console.log();

      // Severity summary row
      const sevRow = [
        result.summary.critical > 0
          ? chalk.red.bold(`CRIT: ${result.summary.critical}`)
          : chalk.gray('CRIT: 0'),
        result.summary.high > 0 ? chalk.red(`HIGH: ${result.summary.high}`) : chalk.gray('HIGH: 0'),
        result.summary.medium > 0
          ? chalk.yellow(`MED: ${result.summary.medium}`)
          : chalk.gray('MED: 0'),
        result.summary.low > 0 ? chalk.blue(`LOW: ${result.summary.low}`) : chalk.gray('LOW: 0'),
        result.summary.info > 0
          ? chalk.white(`INFO: ${result.summary.info}`)
          : chalk.gray('INFO: 0'),
      ].join('  │  ');
      console.log(`  ${sevRow}`);
      console.log(chalk.gray('  ' + '─'.repeat(60)));
      console.log();

      // Build menu choices
      const choices: Array<{ name: string; value: string }> = [];

      const fixable = result.vulnerabilities.filter((v) => v.remediation?.automated);

      if (result.vulnerabilities.length > 0) {
        choices.push({ name: 'View all vulnerabilities', value: 'all' });
        if (fixable.length > 0)
          choices.push({
            name: chalk.green(`Fix all auto-fixable (${fixable.length})`),
            value: 'fix-all',
          });
        if (result.summary.critical > 0)
          choices.push({ name: chalk.red('Filter: CRITICAL'), value: 'filter-CRITICAL' });
        if (result.summary.high > 0)
          choices.push({ name: chalk.red('Filter: HIGH'), value: 'filter-HIGH' });
        if (result.summary.medium > 0)
          choices.push({ name: chalk.yellow('Filter: MEDIUM'), value: 'filter-MEDIUM' });
        if (result.summary.low > 0)
          choices.push({ name: chalk.blue('Filter: LOW'), value: 'filter-LOW' });
      }
      choices.push({ name: 'Rescan', value: 'rescan' });
      choices.push({ name: 'Exit', value: 'exit' });

      const { action } = await inquirer.prompt([
        {
          type: 'list',
          name: 'action',
          message: 'Select an action:',
          choices,
        },
      ]);

      if (action === 'exit') {
        running = false;
      } else if (action === 'fix-all') {
        const freshConfig = await loadConfig(configPath, process.stderr);
        const proposals = await buildFixProposals(configPath, freshConfig, result);

        if (proposals.length === 0) {
          console.log(chalk.green('\n  No fixable issues found.'));
          await waitForKey(inquirer);
          continue;
        }

        // Let user pick which fixes to apply
        const { picks } = await inquirer.prompt([
          {
            type: 'checkbox',
            name: 'picks',
            message: 'Select fixes to apply:',
            choices: proposals.map((p, i) => ({
              name: `${formatSeverity(p.severity)} ${p.description}`,
              value: i,
              checked: p.severity === 'CRITICAL' || p.severity === 'HIGH',
            })),
            pageSize: 15,
          },
        ]);

        const selected = (picks as number[])
          .map((i) => proposals[i])
          .filter((p): p is FixProposal => p !== undefined);
        if (selected.length > 0) {
          const fixResults = await executeFixProposals(selected, configPath, freshConfig);
          console.log(
            chalk.green(`\n  Applied ${fixResults.applied} of ${fixResults.total} fixes`),
          );
          if (fixResults.envVars.length > 0) {
            console.log(chalk.bold('\n  Set these env vars:'));
            fixResults.envVars.forEach((ev) =>
              console.log(chalk.cyan(`    export ${ev.name}="${ev.placeholder}"`)),
            );
          }
          if (fixResults.manualSteps.length > 0) {
            console.log(chalk.bold('\n  Manual steps:'));
            fixResults.manualSteps.forEach((s, i) => console.log(`    ${i + 1}. ${s}`));
          }
        }
        await waitForKey(inquirer);

        // Auto-rescan after fix
        if (selected.length > 0) {
          const rescanSpinner = ora('Rescanning...').start();
          try {
            const updatedConfig = await loadConfig(configPath, process.stderr);
            if (typeof updatedConfig === 'object' && !('command' in updatedConfig)) {
              const configs = updatedConfig as Record<string, MCPServerConfig>;
              const allVulns: Vulnerability[] = [];
              let totalScore = 0;
              let serverCount = 0;
              for (const [, sc] of Object.entries(configs)) {
                const r = await guard.scan(sc);
                allVulns.push(...r.vulnerabilities);
                totalScore += r.summary.score;
                serverCount++;
              }
              const avgScore = serverCount > 0 ? Math.round(totalScore / serverCount) : 100;
              result = buildAggregateResult(allVulns, avgScore, serverCount);
            } else {
              result = await guard.scan(updatedConfig as MCPServerConfig);
            }
            rescanSpinner.succeed('Rescan complete');
          } catch (error) {
            rescanSpinner.fail(`Rescan failed: ${error}`);
          }
        }
      } else if (action === 'rescan') {
        const rescanSpinner = ora('Rescanning...').start();
        try {
          const freshConfig = await loadConfig(configPath, process.stderr);
          if (typeof freshConfig === 'object' && !('command' in freshConfig)) {
            const configs = freshConfig as Record<string, MCPServerConfig>;
            const allVulns: Vulnerability[] = [];
            let totalScore = 0;
            let serverCount = 0;
            for (const [name, serverConfig] of Object.entries(configs)) {
              const r = await guard.scan(serverConfig);
              allVulns.push(...r.vulnerabilities);
              totalScore += r.summary.score;
              serverCount++;
            }
            const avgScore = serverCount > 0 ? Math.round(totalScore / serverCount) : 100;
            result = buildAggregateResult(allVulns, avgScore, serverCount);
          } else {
            result = await guard.scan(freshConfig as MCPServerConfig);
          }
          rescanSpinner.succeed('Rescan complete');
        } catch (error) {
          rescanSpinner.fail(`Rescan failed: ${error}`);
        }
        await waitForKey(inquirer);
      } else {
        // View vulnerabilities (all or filtered)
        const filter = action.startsWith('filter-') ? action.replace('filter-', '') : null;
        const vulns = filter
          ? result.vulnerabilities.filter((v) => v.severity === filter)
          : result.vulnerabilities;

        await browseVulnerabilities(vulns, filter, inquirer, configPath);
      }
    }

    console.log(chalk.gray('\nDashboard closed.\n'));
  });

// Render a visual score bar
function renderScoreBar(score: number): string {
  const width = 40;
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  const color = score >= 80 ? chalk.green : score >= 60 ? chalk.yellow : chalk.red;
  return color('█'.repeat(filled)) + chalk.gray('░'.repeat(empty)) + ` ${score}%`;
}

// Build an aggregate ScanResult from merged vulnerabilities
function buildAggregateResult(
  vulns: Vulnerability[],
  avgScore: number,
  serverCount: number,
): ScanResult {
  return {
    id: `dashboard-${Date.now()}`,
    timestamp: new Date(),
    duration: 0,
    config: { depth: 'standard' },
    vulnerabilities: vulns,
    summary: {
      score: avgScore,
      grade:
        avgScore >= 90
          ? 'A'
          : avgScore >= 80
            ? 'B'
            : avgScore >= 70
              ? 'C'
              : avgScore >= 60
                ? 'D'
                : 'F',
      serversScanned: serverCount,
      vulnerabilitiesFound: vulns.length,
      critical: vulns.filter((v) => v.severity === 'CRITICAL').length,
      high: vulns.filter((v) => v.severity === 'HIGH').length,
      medium: vulns.filter((v) => v.severity === 'MEDIUM').length,
      low: vulns.filter((v) => v.severity === 'LOW').length,
      info: vulns.filter((v) => v.severity === 'INFO').length,
    },
    recommendations: [],
    metadata: { scanner: 'mcp-guard', version: '1.0.0', signatures: '', rules: 0 },
  };
}

// Browse vulnerability list with drill-down
async function browseVulnerabilities(
  vulns: Vulnerability[],
  filter: string | null,
  inquirer: any,
  configPath?: string,
): Promise<void> {
  let page = 0;
  const pageSize = 10;

  while (true) {
    console.clear();
    const title = filter ? `Vulnerabilities (${filter})` : 'All Vulnerabilities';
    console.log(chalk.bold(`\n  ${title} — ${vulns.length} found\n`));

    const start = page * pageSize;
    const pageVulns = vulns.slice(start, start + pageSize);

    const table = new Table({
      head: ['#', 'Severity', 'Type', 'Server', 'Title'],
      colWidths: [5, 10, 22, 15, 40],
    });

    pageVulns.forEach((vuln, i) => {
      table.push([
        String(start + i + 1),
        formatSeverity(vuln.severity),
        vuln.type,
        vuln.server || 'N/A',
        vuln.title.substring(0, 38),
      ]);
    });

    console.log(table.toString());

    const totalPages = Math.ceil(vulns.length / pageSize);
    console.log(chalk.gray(`  Page ${page + 1} of ${totalPages}`));

    const choices: Array<{ name: string; value: string }> = [];

    pageVulns.forEach((vuln, i) => {
      choices.push({
        name: `Details: #${start + i + 1} ${vuln.title.substring(0, 50)}`,
        value: `detail-${start + i}`,
      });
    });

    if (page < totalPages - 1) choices.push({ name: 'Next page →', value: 'next' });
    if (page > 0) choices.push({ name: '← Previous page', value: 'prev' });
    choices.push({ name: 'Back to dashboard', value: 'back' });

    const { choice } = await inquirer.prompt([
      {
        type: 'list',
        name: 'choice',
        message: 'Select:',
        choices,
        pageSize: 15,
      },
    ]);

    if (choice === 'back') return;
    if (choice === 'next') {
      page++;
      continue;
    }
    if (choice === 'prev') {
      page--;
      continue;
    }

    if (choice.startsWith('detail-')) {
      const idx = parseInt(choice.replace('detail-', ''));
      const selectedVuln = vulns[idx];
      if (selectedVuln) {
        await showVulnDetail(selectedVuln, inquirer, configPath);
      }
    }
  }
}

// Show detailed vulnerability view
async function showVulnDetail(
  vuln: Vulnerability,
  inquirer: any,
  configPath?: string,
): Promise<void> {
  console.clear();
  console.log(chalk.bold('\n  Vulnerability Detail'));
  console.log(chalk.gray('  ' + '─'.repeat(60)));
  console.log(`  ${chalk.bold('Title:')}    ${vuln.title}`);
  console.log(`  ${chalk.bold('ID:')}       ${vuln.id}`);
  console.log(`  ${chalk.bold('Severity:')} ${formatSeverity(vuln.severity)}`);
  console.log(`  ${chalk.bold('Type:')}     ${vuln.type}`);
  console.log(`  ${chalk.bold('Server:')}   ${vuln.server || 'N/A'}`);
  console.log();
  console.log(`  ${chalk.bold('Description:')}`);
  console.log(`  ${vuln.description}`);

  if (vuln.location) {
    console.log();
    console.log(`  ${chalk.bold('Location:')}`);
    if (vuln.location.path) console.log(`    Path: ${vuln.location.path}`);
  }

  if (vuln.remediation) {
    console.log();
    console.log(`  ${chalk.bold('Remediation:')}`);
    console.log(`  ${vuln.remediation.description}`);
    if (vuln.remediation.commands && vuln.remediation.commands.length > 0) {
      console.log(`  ${chalk.bold('Commands:')}`);
      vuln.remediation.commands.forEach((cmd) => {
        console.log(`    ${chalk.cyan('$')} ${cmd}`);
      });
    }
    if (vuln.remediation.automated) {
      console.log(`  ${chalk.green('Auto-fixable')}`);
    }
  }

  if (vuln.compliance) {
    const frameworks = Object.entries(vuln.compliance)
      .filter(([, v]) => v)
      .map(([k]) => k.toUpperCase());
    if (frameworks.length > 0) {
      console.log();
      console.log(`  ${chalk.bold('Compliance:')} ${frameworks.join(', ')}`);
    }
  }

  if (vuln.evidence?.value) {
    console.log();
    console.log(`  ${chalk.bold('Evidence:')} ${chalk.red(vuln.evidence.value)}`);
  }

  console.log(chalk.gray('\n  ' + '─'.repeat(60)));

  const detailChoices: Array<{ name: string; value: string }> = [];
  if (vuln.remediation?.automated && configPath) {
    detailChoices.push({ name: chalk.green('Fix this vulnerability'), value: 'fix' });
  }
  detailChoices.push({ name: 'Back', value: 'back' });

  const { detailAction } = await inquirer.prompt([
    {
      type: 'list',
      name: 'detailAction',
      message: 'Action:',
      choices: detailChoices,
    },
  ]);

  if (detailAction === 'fix' && configPath) {
    const config = await loadConfig(configPath, process.stderr);
    // Build a minimal ScanResult for the single vuln
    const miniResult: ScanResult = {
      id: 'fix-single',
      timestamp: new Date(),
      duration: 0,
      config: { depth: 'standard' },
      vulnerabilities: [vuln],
      summary: {
        score: 0,
        grade: 'F',
        serversScanned: 1,
        vulnerabilitiesFound: 1,
        critical: vuln.severity === 'CRITICAL' ? 1 : 0,
        high: vuln.severity === 'HIGH' ? 1 : 0,
        medium: vuln.severity === 'MEDIUM' ? 1 : 0,
        low: vuln.severity === 'LOW' ? 1 : 0,
        info: vuln.severity === 'INFO' ? 1 : 0,
      },
      recommendations: [],
      metadata: { scanner: 'mcp-guard', version: '1.0.0', signatures: '', rules: 0 },
    };
    const proposals = await buildFixProposals(configPath, config, miniResult);
    if (proposals.length > 0) {
      const fixResult = await executeFixProposals(proposals, configPath, config);
      if (fixResult.applied > 0) {
        console.log(chalk.green('\n  Fixed. Rescan to verify.'));
      }
      if (fixResult.envVars.length > 0) {
        fixResult.envVars.forEach((ev) =>
          console.log(chalk.cyan(`  export ${ev.name}="${ev.placeholder}"`)),
        );
      }
    } else {
      console.log(chalk.yellow('\n  No automated fix available for this vulnerability.'));
    }
    await waitForKey(inquirer);
  }
}

// Wait for user acknowledgment
async function waitForKey(inquirer: any): Promise<void> {
  await inquirer.prompt([
    {
      type: 'list',
      name: 'continue',
      message: 'Press enter to continue',
      choices: [{ name: 'Continue', value: 'ok' }],
    },
  ]);
}

// Parse arguments
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  displayBanner();
  program.outputHelp();
}

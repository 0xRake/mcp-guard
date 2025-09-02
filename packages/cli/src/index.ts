#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import figlet from 'figlet';
import Table from 'cli-table3';
import fs from 'fs-extra';
import path from 'path';
import { glob } from 'glob';
import mcpGuard from '@mcp-guard/core';
import type { ScanResult, Vulnerability, Severity, MCPServerConfig } from '@mcp-guard/core';

const program = new Command();

// Helper function to format severity with colors
function formatSeverity(severity: Severity): string {
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
function showBanner(): void {
  console.log(
    chalk.cyan(
      figlet.textSync('MCP-Guard', {
        font: 'Standard',
        horizontalLayout: 'default',
        verticalLayout: 'default'
      })
    )
  );
  console.log(chalk.gray('  Enterprise-grade security scanner for MCP servers\n'));
}

// Load Claude Desktop config
async function loadClaudeConfig(): Promise<Record<string, MCPServerConfig> | null> {
  const configPaths = [
    path.join(process.env.HOME || '', 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    path.join(process.env.APPDATA || '', 'Claude', 'claude_desktop_config.json'),
    path.join(process.env.HOME || '', '.config', 'Claude', 'claude_desktop_config.json')
  ];

  for (const configPath of configPaths) {
    if (await fs.pathExists(configPath)) {
      try {
        const config = await fs.readJson(configPath);
        return config.mcpServers || {};
      } catch (error) {
        console.error(chalk.red(`Error reading config from ${configPath}:`, error));
      }
    }
  }
  
  return null;
}

// Display scan results in a table
function displayResults(result: ScanResult): void {
  // Summary section
  console.log(chalk.bold('\n📊 Scan Summary'));
  console.log(chalk.gray('─'.repeat(50)));
  
  const summaryTable = new Table({
    chars: { 'mid': '', 'left-mid': '', 'mid-mid': '', 'right-mid': '' }
  });
  
  summaryTable.push(
    ['Security Score', formatScore(result.summary.score)],
    ['Grade', formatGrade(result.summary.grade)],
    ['Servers Scanned', result.summary.serversScanned],
    ['Vulnerabilities Found', result.summary.vulnerabilitiesFound],
    ['Critical', chalk.red(result.summary.critical)],
    ['High', chalk.red(result.summary.high)],
    ['Medium', chalk.yellow(result.summary.medium)],
    ['Low', chalk.blue(result.summary.low)],
    ['Duration', `${result.summary.duration}ms`]
  );
  
  console.log(summaryTable.toString());

  // Vulnerabilities section
  if (result.vulnerabilities.length > 0) {
    console.log(chalk.bold('\n⚠️  Vulnerabilities'));
    console.log(chalk.gray('─'.repeat(50)));
    
    const vulnTable = new Table({
      head: ['Severity', 'Type', 'Server', 'Description'],
      colWidths: [12, 20, 20, 50],
      wordWrap: true
    });
    
    for (const vuln of result.vulnerabilities) {
      vulnTable.push([
        formatSeverity(vuln.severity),
        vuln.type,
        vuln.server,
        vuln.title
      ]);
    }
    
    console.log(vulnTable.toString());
  } else {
    console.log(chalk.green.bold('\n✅ No vulnerabilities found!'));
  }

  // Recommendations
  if (result.recommendations.length > 0) {
    console.log(chalk.bold('\n💡 Recommendations'));
    console.log(chalk.gray('─'.repeat(50)));
    result.recommendations.forEach((rec, index) => {
      console.log(chalk.cyan(`${index + 1}. ${rec}`));
    });
  }
}

// Export results to different formats
async function exportResults(result: ScanResult, format: string, outputPath: string): Promise<void> {
  const spinner = ora(`Exporting results to ${format.toUpperCase()}...`).start();
  
  try {
    let content: string;
    
    switch (format) {
      case 'json':
        content = JSON.stringify(result, null, 2);
        break;
        
      case 'markdown':
        content = generateMarkdownReport(result);
        break;
        
      case 'html':
        content = generateHtmlReport(result);
        break;
        
      case 'sarif':
        content = JSON.stringify(generateSarifReport(result), null, 2);
        break;
        
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
    
    await fs.writeFile(outputPath, content);
    spinner.succeed(chalk.green(`Results exported to ${outputPath}`));
  } catch (error) {
    spinner.fail(chalk.red(`Failed to export: ${error}`));
  }
}

// Generate Markdown report
function generateMarkdownReport(result: ScanResult): string {
  let markdown = '# MCP-Guard Security Scan Report\n\n';
  
  markdown += '## Summary\n\n';
  markdown += `- **Security Score:** ${result.summary.score}/100 (${result.summary.grade})\n`;
  markdown += `- **Servers Scanned:** ${result.summary.serversScanned}\n`;
  markdown += `- **Vulnerabilities:** ${result.summary.vulnerabilitiesFound}\n`;
  markdown += `  - Critical: ${result.summary.critical}\n`;
  markdown += `  - High: ${result.summary.high}\n`;
  markdown += `  - Medium: ${result.summary.medium}\n`;
  markdown += `  - Low: ${result.summary.low}\n\n`;
  
  if (result.vulnerabilities.length > 0) {
    markdown += '## Vulnerabilities\n\n';
    for (const vuln of result.vulnerabilities) {
      markdown += `### [${vuln.severity}] ${vuln.title}\n\n`;
      markdown += `- **Server:** ${vuln.server}\n`;
      markdown += `- **Type:** ${vuln.type}\n`;
      markdown += `- **Description:** ${vuln.description}\n`;
      if (vuln.location) {
        markdown += `- **Location:** ${vuln.location.path}\n`;
      }
      if (vuln.remediation) {
        markdown += `- **Remediation:** ${vuln.remediation.description}\n`;
      }
      markdown += '\n';
    }
  }
  
  if (result.recommendations.length > 0) {
    markdown += '## Recommendations\n\n';
    result.recommendations.forEach((rec, index) => {
      markdown += `${index + 1}. ${rec}\n`;
    });
  }
  
  return markdown;
}

// Generate HTML report
function generateHtmlReport(result: ScanResult): string {
  const severityColors = {
    CRITICAL: '#dc2626',
    HIGH: '#ef4444',
    MEDIUM: '#f59e0b',
    LOW: '#3b82f6',
    INFO: '#6b7280'
  };
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP-Guard Security Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f9fafb; }
    h1 { color: #1f2937; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }
    h2 { color: #374151; margin-top: 30px; }
    .summary { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .score { font-size: 48px; font-weight: bold; color: ${result.summary.score >= 60 ? '#10b981' : '#ef4444'}; }
    .grade { font-size: 32px; font-weight: bold; margin-left: 20px; }
    .vulnerability { background: white; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid; }
    .critical { border-color: #dc2626; }
    .high { border-color: #ef4444; }
    .medium { border-color: #f59e0b; }
    .low { border-color: #3b82f6; }
    .info { border-color: #6b7280; }
    .severity-badge { display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 12px; }
    table { width: 100%; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    th { background: #f3f4f6; padding: 12px; text-align: left; font-weight: 600; }
    td { padding: 12px; border-top: 1px solid #e5e7eb; }
  </style>
</head>
<body>
  <h1>🔐 MCP-Guard Security Scan Report</h1>
  
  <div class="summary">
    <h2>Summary</h2>
    <div>
      <span class="score">${result.summary.score}/100</span>
      <span class="grade">Grade: ${result.summary.grade}</span>
    </div>
    <table style="margin-top: 20px;">
      <tr><th>Metric</th><th>Value</th></tr>
      <tr><td>Servers Scanned</td><td>${result.summary.serversScanned}</td></tr>
      <tr><td>Total Vulnerabilities</td><td>${result.summary.vulnerabilitiesFound}</td></tr>
      <tr><td>Critical</td><td style="color: #dc2626; font-weight: bold;">${result.summary.critical}</td></tr>
      <tr><td>High</td><td style="color: #ef4444; font-weight: bold;">${result.summary.high}</td></tr>
      <tr><td>Medium</td><td style="color: #f59e0b; font-weight: bold;">${result.summary.medium}</td></tr>
      <tr><td>Low</td><td style="color: #3b82f6;">${result.summary.low}</td></tr>
      <tr><td>Scan Duration</td><td>${result.summary.duration}ms</td></tr>
    </table>
  </div>
  
  ${result.vulnerabilities.length > 0 ? `
  <h2>Vulnerabilities</h2>
  ${result.vulnerabilities.map(vuln => `
    <div class="vulnerability ${vuln.severity.toLowerCase()}">
      <span class="severity-badge" style="background: ${severityColors[vuln.severity]};">${vuln.severity}</span>
      <h3 style="margin: 10px 0;">${vuln.title}</h3>
      <p><strong>Server:</strong> ${vuln.server}</p>
      <p><strong>Type:</strong> ${vuln.type}</p>
      <p>${vuln.description}</p>
      ${vuln.remediation ? `<p><strong>Remediation:</strong> ${vuln.remediation.description}</p>` : ''}
    </div>
  `).join('')}
  ` : '<h2 style="color: #10b981;">✅ No vulnerabilities found!</h2>'}
  
  ${result.recommendations.length > 0 ? `
  <h2>Recommendations</h2>
  <ol>
    ${result.recommendations.map(rec => `<li>${rec}</li>`).join('')}
  </ol>
  ` : ''}
  
  <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 14px;">
    Generated by MCP-Guard v1.0.0 on ${new Date().toLocaleString()}
  </footer>
</body>
</html>`;
}

// Generate SARIF report for CI/CD integration
function generateSarifReport(result: ScanResult): any {
  return {
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'MCP-Guard',
          version: '1.0.0',
          informationUri: 'https://github.com/mcp-guard/mcp-guard',
          rules: result.vulnerabilities.map(vuln => ({
            id: vuln.id,
            name: vuln.type,
            shortDescription: { text: vuln.title },
            fullDescription: { text: vuln.description },
            defaultConfiguration: {
              level: vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH' ? 'error' : 
                     vuln.severity === 'MEDIUM' ? 'warning' : 'note'
            }
          }))
        }
      },
      results: result.vulnerabilities.map(vuln => ({
        ruleId: vuln.id,
        level: vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH' ? 'error' : 
               vuln.severity === 'MEDIUM' ? 'warning' : 'note',
        message: { text: vuln.description },
        locations: vuln.location ? [{
          physicalLocation: {
            artifactLocation: { uri: vuln.server },
            region: { startLine: 1 }
          }
        }] : []
      }))
    }]
  };
}

// Main scan command
program
  .name('mcp-guard')
  .description('Enterprise-grade security scanner for MCP servers')
  .version('1.0.0');

program
  .command('scan [path]')
  .description('Scan MCP server configuration for vulnerabilities')
  .option('-c, --config <path>', 'Path to MCP config file')
  .option('-d, --depth <level>', 'Scan depth (quick, standard, comprehensive, paranoid)', 'standard')
  .option('-f, --format <format>', 'Output format (json, markdown, html, sarif)', 'console')
  .option('-o, --output <path>', 'Output file path')
  .option('--auto-fix', 'Automatically fix vulnerabilities where possible')
  .option('--no-banner', 'Hide the banner')
  .option('--quiet', 'Minimal output')
  .action(async (scanPath, options) => {
    if (!options.noBanner && !options.quiet) {
      showBanner();
    }

    const spinner = ora('Loading configuration...').start();

    try {
      let configs: Record<string, MCPServerConfig> = {};

      // Load configuration
      if (options.config) {
        spinner.text = `Loading config from ${options.config}...`;
        const configContent = await fs.readJson(options.config);
        configs = configContent.mcpServers || configContent;
      } else if (scanPath) {
        spinner.text = `Loading config from ${scanPath}...`;
        const configContent = await fs.readJson(scanPath);
        configs = configContent.mcpServers || configContent;
      } else {
        spinner.text = 'Looking for Claude Desktop configuration...';
        const claudeConfig = await loadClaudeConfig();
        if (claudeConfig) {
          configs = claudeConfig;
          spinner.succeed('Found Claude Desktop configuration');
        } else {
          spinner.fail('No configuration found. Please specify a config file with --config');
          process.exit(1);
        }
      }

      // Run scan
      spinner.start(`Scanning ${Object.keys(configs).length} server(s)...`);
      
      const scanOptions = {
        depth: options.depth,
        autoFix: options.autoFix
      };

      const result = await mcpGuard.scan(configs, scanOptions);
      
      spinner.succeed(chalk.green('Scan completed successfully'));

      // Display or export results
      if (options.format === 'console' && !options.quiet) {
        displayResults(result);
      }

      if (options.output) {
        await exportResults(result, options.format === 'console' ? 'json' : options.format, options.output);
      } else if (options.format !== 'console') {
        const output = options.format === 'json' ? JSON.stringify(result, null, 2) :
                      options.format === 'markdown' ? generateMarkdownReport(result) :
                      options.format === 'html' ? generateHtmlReport(result) :
                      JSON.stringify(generateSarifReport(result), null, 2);
        console.log(output);
      }

      // Exit with appropriate code
      if (result.summary.critical > 0 || result.summary.high > 0) {
        process.exit(1);
      }
    } catch (error) {
      spinner.fail(chalk.red(`Scan failed: ${error}`));
      process.exit(1);
    }
  });

// Quick scan command
program
  .command('quick [path]')
  .description('Run a quick security scan')
  .action(async (path) => {
    showBanner();
    const configs = path ? await fs.readJson(path) : await loadClaudeConfig();
    if (!configs) {
      console.error(chalk.red('No configuration found'));
      process.exit(1);
    }
    const result = await mcpGuard.quickScan(configs);
    displayResults(result);
  });

// Watch command for continuous monitoring
program
  .command('watch [path]')
  .description('Watch configuration files for changes and scan automatically')
  .option('-i, --interval <seconds>', 'Check interval in seconds', '30')
  .action(async (watchPath, options) => {
    showBanner();
    console.log(chalk.cyan(`Watching for changes every ${options.interval} seconds...`));
    
    setInterval(async () => {
      const spinner = ora('Checking for changes...').start();
      try {
        const configs = watchPath ? await fs.readJson(watchPath) : await loadClaudeConfig();
        if (configs) {
          const result = await mcpGuard.quickScan(configs);
          if (result.summary.vulnerabilitiesFound > 0) {
            spinner.warn(chalk.yellow(`Found ${result.summary.vulnerabilitiesFound} vulnerabilities`));
            displayResults(result);
          } else {
            spinner.succeed(chalk.green('No vulnerabilities found'));
          }
        }
      } catch (error) {
        spinner.fail(chalk.red(`Watch error: ${error}`));
      }
    }, parseInt(options.interval) * 1000);
  });

// Fix command to auto-remediate vulnerabilities
program
  .command('fix [path]')
  .description('Automatically fix vulnerabilities where possible')
  .option('--dry-run', 'Show what would be fixed without making changes')
  .action(async (fixPath, options) => {
    showBanner();
    const spinner = ora('Loading configuration...').start();
    
    try {
      const configs = fixPath ? await fs.readJson(fixPath) : await loadClaudeConfig();
      if (!configs) {
        spinner.fail('No configuration found');
        process.exit(1);
      }

      spinner.text = 'Scanning for vulnerabilities...';
      const result = await mcpGuard.scan(configs, { autoFix: !options.dryRun });
      
      const fixable = result.vulnerabilities.filter(v => v.remediation?.automated);
      
      if (fixable.length === 0) {
        spinner.succeed(chalk.green('No automatically fixable vulnerabilities found'));
      } else {
        spinner.succeed(chalk.green(`${options.dryRun ? 'Would fix' : 'Fixed'} ${fixable.length} vulnerabilities`));
        
        console.log(chalk.bold('\n🔧 Fixed Vulnerabilities:'));
        fixable.forEach(vuln => {
          console.log(chalk.cyan(`  • ${vuln.title}`));
        });
      }
    } catch (error) {
      spinner.fail(chalk.red(`Fix failed: ${error}`));
      process.exit(1);
    }
  });

// List command to show available scanners
program
  .command('list')
  .description('List available security scanners')
  .action(() => {
    showBanner();
    console.log(chalk.bold('Available Scanners:\n'));
    
    const scanners = [
      { name: 'API Keys', description: 'Detects exposed API keys and secrets', severity: 'CRITICAL' },
      { name: 'Authentication', description: 'Checks for missing or weak authentication', severity: 'HIGH' },
      { name: 'Command Injection', description: 'Identifies command injection risks', severity: 'CRITICAL' },
      { name: 'Tool Poisoning', description: 'Detects malicious tool definitions', severity: 'CRITICAL' }
    ];
    
    const table = new Table({
      head: ['Scanner', 'Description', 'Severity'],
      colWidths: [20, 50, 12]
    });
    
    scanners.forEach(scanner => {
      table.push([scanner.name, scanner.description, formatSeverity(scanner.severity as Severity)]);
    });
    
    console.log(table.toString());
  });

// Parse command line arguments
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
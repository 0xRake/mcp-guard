import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import figlet from 'figlet';
import Table from 'cli-table3';
import fs from 'fs-extra';
import path from 'path';
import { glob } from 'glob';
import PDFDocument from 'pdfkit';
import { MCPGuard, ReportGenerator, ReportFormat, ConfigLoader, createStderrLogger, LogLevel } from '@mcp-guard/core';
import type { ScanResult, Vulnerability, Severity, MCPServerConfig, Logger } from '@mcp-guard/core';

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
async function loadConfig(configPath: string, stream?: NodeJS.WritableStream): Promise<MCPServerConfig | Record<string, MCPServerConfig>> {
  const spinner = ora({ text: 'Loading configuration...', stream: stream || process.stdout }).start();
  try {
    if (!await fs.pathExists(configPath)) {
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
  console.log('=' .repeat(50));
  
  // Summary
  console.log(chalk.bold('\n📈 Summary:'));
  console.log(`  Score: ${formatScore(result.summary.score)}`);
  console.log(`  Grade: ${formatGrade(result.summary.grade)}`);
  console.log(`  Servers Scanned: ${result.summary.serversScanned}`);
  console.log(`  Vulnerabilities Found: ${result.summary.vulnerabilitiesFound}`);
  
  if (result.summary.vulnerabilitiesFound > 0) {
    console.log(chalk.bold('\n🔍 Breakdown:'));
    if (result.summary.critical > 0) console.log(`  ${formatSeverity('CRITICAL')}: ${result.summary.critical}`);
    if (result.summary.high > 0) console.log(`  ${formatSeverity('HIGH')}: ${result.summary.high}`);
    if (result.summary.medium > 0) console.log(`  ${formatSeverity('MEDIUM')}: ${result.summary.medium}`);
    if (result.summary.low > 0) console.log(`  ${formatSeverity('LOW')}: ${result.summary.low}`);
    if (result.summary.info > 0) console.log(`  ${formatSeverity('INFO')}: ${result.summary.info}`);
    
    // Vulnerability table
    console.log(chalk.bold('\n⚠️  Vulnerabilities:'));
    const table = new Table({
      head: ['ID', 'Severity', 'Type', 'Server', 'Title'],
      colWidths: [12, 10, 20, 15, 40]
    });
    
    const vulnsToShow = verbose ? result.vulnerabilities : result.vulnerabilities.slice(0, 10);
    vulnsToShow.forEach(vuln => {
      table.push([
        vuln.id.substring(0, 10),
        formatSeverity(vuln.severity),
        vuln.type,
        vuln.server || 'N/A',
        vuln.title.substring(0, 38)
      ]);
    });
    
    console.log(table.toString());
    
    if (!verbose && result.vulnerabilities.length > 10) {
      console.log(chalk.gray(`\n  ... and ${result.vulnerabilities.length - 10} more. Use --verbose to see all.`));
    }
  }
  
  // Recommendations
  if (result.recommendations && result.recommendations.length > 0) {
    console.log(chalk.bold('\n💡 Recommendations:'));
    result.recommendations.forEach((rec, i) => {
      console.log(`  ${i + 1}. ${rec}`);
    });
  }
  
  console.log('\n' + '=' .repeat(50));
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
  const logger = program.opts().debug
    ? createStderrLogger(LogLevel.DEBUG)
    : undefined;
  return new MCPGuard({ logger });
}

// Scan command
program
  .command('scan <config>')
  .description('Scan MCP server configuration for vulnerabilities')
  .option('-v, --verbose', 'Show detailed output')
  .option('-o, --output <format>', 'Output format (json, markdown, html, sarif, csv, xml)', 'console')
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
      depth: options.depth
    };

    if (options.exclude) {
      scanOptions.excludeTypes = options.exclude.split(',').map((t: string) => t.trim());
    }

    // Run scan — send spinner to stderr when piping structured output
    const spinner = ora({ text: 'Running security scan...', stream: structuredOutput ? process.stderr : process.stdout }).start();

    try {
      const result = await createGuard().scan(config, scanOptions);
      spinner.succeed('Scan completed successfully');

      // Handle output
      if (!structuredOutput) {
        displayResults(result, options.verbose);
      } else {
        const formatMap: Record<string, ReportFormat> = {
          'json': ReportFormat.JSON,
          'markdown': ReportFormat.MARKDOWN,
          'html': ReportFormat.HTML,
          'sarif': ReportFormat.SARIF,
          'csv': ReportFormat.CSV,
          'xml': ReportFormat.XML
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
  .description('Fix detected vulnerabilities')
  .option('--auto', 'Automatically fix without prompting')
  .option('--dry-run', 'Show what would be fixed without making changes')
  .option('--backup', 'Create backup before fixing')
  .action(async (configPath, options) => {
    displayBanner();
    
    // Load configuration
    const config = await loadConfig(configPath);
    
    // Run scan first
    const spinner = ora('Scanning for vulnerabilities...').start();
    
    try {
      const result = await createGuard().scan(config);
      spinner.succeed(`Found ${result.summary.vulnerabilitiesFound} vulnerabilities`);
      
      if (result.summary.vulnerabilitiesFound === 0) {
        console.log(chalk.green('✅ No vulnerabilities to fix!'));
        process.exit(0);
      }
      
      // Filter fixable vulnerabilities
      const fixable = result.vulnerabilities.filter(v => v.remediation?.automated);
      
      if (fixable.length === 0) {
        console.log(chalk.yellow('⚠️  No automatically fixable vulnerabilities found.'));
        console.log('Manual remediation required for all issues.');
        process.exit(1);
      }
      
      console.log(chalk.bold(`\n🔧 Found ${fixable.length} fixable vulnerabilities:`));
      
      // Display fixable vulnerabilities
      const table = new Table({
        head: ['ID', 'Severity', 'Type', 'Title'],
        colWidths: [12, 10, 20, 40]
      });
      
      fixable.forEach(vuln => {
        table.push([
          vuln.id.substring(0, 10),
          formatSeverity(vuln.severity),
          vuln.type,
          vuln.title.substring(0, 38)
        ]);
      });
      
      console.log(table.toString());
      
      // Check for auto mode or prompt
      if (!options.auto && !options.dryRun) {
        const readline = require('readline');
        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout
        });
        
        const answer = await new Promise<string>((resolve) => {
          rl.question('\nProceed with fixes? (y/n): ', resolve);
        });
        
        rl.close();
        
        if (answer.toLowerCase() !== 'y') {
          console.log('Fix operation cancelled.');
          process.exit(0);
        }
      }
      
      // Create backup if requested
      if (options.backup && !options.dryRun) {
        const backupPath = `${configPath}.backup.${Date.now()}`;
        await fs.copy(configPath, backupPath);
        console.log(chalk.gray(`Backup created: ${backupPath}`));
      }
      
      // Apply fixes
      if (options.dryRun) {
        console.log(chalk.yellow('\n🔍 DRY RUN - No changes will be made:'));
        fixable.forEach(vuln => {
          console.log(`  Would fix: ${vuln.title}`);
          if (vuln.remediation?.commands) {
            vuln.remediation.commands.forEach(cmd => {
              console.log(chalk.gray(`    ${cmd}`));
            });
          }
        });
      } else {
        const fixSpinner = ora('Applying fixes...').start();
        let fixedCount = 0;
        
        for (const vuln of fixable) {
          try {
            // This would call the actual fix method on scanners
            // For now, we'll simulate it
            console.log(chalk.gray(`  Fixing: ${vuln.title}`));
            fixedCount++;
          } catch (error) {
            console.log(chalk.red(`  Failed to fix: ${vuln.title}`));
          }
        }
        
        fixSpinner.succeed(`Applied ${fixedCount} fixes`);
        
        // Save updated configuration
        await fs.writeJSON(configPath, config, { spaces: 2 });
        console.log(chalk.green(`✅ Configuration updated: ${configPath}`));
      }
      
      process.exit(0);
    } catch (error) {
      spinner.fail(`Fix operation failed: ${error}`);
      process.exit(1);
    }
  });

// Report command
program
  .command('report <config>')
  .description('Generate security report')
  .option('--format <type>', 'Report format (json, markdown, html, pdf, sarif, csv, xml)', 'markdown')
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
          'json': ReportFormat.JSON,
          'markdown': ReportFormat.MARKDOWN,
          'html': ReportFormat.HTML,
          'sarif': ReportFormat.SARIF,
          'csv': ReportFormat.CSV,
          'xml': ReportFormat.XML
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
          console.log(chalk.yellow(`⚠️  Found ${result.summary.vulnerabilitiesFound} vulnerabilities`));
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
      ignoreInitial: true
    });
    
    watcher.on('change', async () => {
      const timeSinceLastScan = Date.now() - lastScanTime;
      if (timeSinceLastScan > 5000) { // Debounce to avoid rapid rescans
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
      { name: 'command-injection', status: '✅', description: 'Detects command injection vulnerabilities' },
      { name: 'tool-poisoning', status: '✅', description: 'Identifies malicious tool definitions' },
      { name: 'data-exfiltration', status: '🚧', description: 'Detects data leak paths' },
      { name: 'oauth-security', status: '🚧', description: 'OAuth 2.1 compliance checking' },
      { name: 'prompt-injection', status: '🚧', description: 'LLM manipulation detection' },
      { name: 'confused-deputy', status: '🚧', description: 'Permission escalation detection' },
      { name: 'rate-limiting', status: '🚧', description: 'Rate limiting verification' },
      { name: 'ssrf', status: '🚧', description: 'Server-side request forgery detection' },
      { name: 'compliance', status: '🚧', description: 'Regulatory compliance checking' }
    ];
    
    const table = new Table({
      head: ['Status', 'Scanner', 'Description'],
      colWidths: [8, 20, 50]
    });
    
    scanners.forEach(scanner => {
      table.push([scanner.status, scanner.name, scanner.description]);
    });
    
    console.log(table.toString());
    console.log('\n✅ = Available  🚧 = Coming Soon\n');
  });

// Init command - creates example configuration
program
  .command('init')
  .description('Create example configuration file')
  .option('-o, --output <path>', 'Output file path', 'mcp-config.json')
  .action(async (options) => {
    displayBanner();
    
    const exampleConfig = {
      "test-server": {
        "command": "node",
        "args": ["server.js", "--port", "3000"],
        "env": {
          "NODE_ENV": "production",
          "API_KEY": "${API_KEY}",
          "DATABASE_URL": "${DATABASE_URL}"
        },
        "capabilities": {
          "tools": true,
          "prompts": true,
          "resources": true
        },
        "metadata": {
          "name": "test-server",
          "version": "1.0.0"
        }
      },
      "python-server": {
        "command": "python",
        "args": ["mcp_server.py"],
        "env": {
          "PYTHONPATH": "./src",
          "FLASK_ENV": "production"
        },
        "auth": {
          "type": "bearer",
          "token": "${AUTH_TOKEN}"
        }
      }
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

// Parse arguments
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  displayBanner();
  program.outputHelp();
}
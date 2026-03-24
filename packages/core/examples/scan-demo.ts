#!/usr/bin/env node

/**
 * MCP-Guard Example - Scanning a Claude Desktop configuration
 */

import mcpGuard from '../src';
import { ClaudeDesktopConfig } from '../src/types';
import chalk from 'chalk';

// Example Claude Desktop configuration with vulnerabilities
const exampleConfig: ClaudeDesktopConfig = {
  mcpServers: {
    "github": {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-github"],
      env: {
        // ⚠️ VULNERABILITY: Hardcoded GitHub token
        GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_exampleDONOTUSEINPRODUCTION00000000000"
      }
    },
    "openai-server": {
      command: "node",
      args: [
        "server.js",
        // ⚠️ VULNERABILITY: API key in command line
        "--api-key", 
        "sk-example-INSECURE-DO-NOT-USE-IN-PRODUCTION-000000"
      ],
      metadata: {
        name: "OpenAI Integration Server",
        version: "1.0.0"
      }
    },
    "database-server": {
      command: "python",
      args: ["db_server.py"],
      env: {
        // ⚠️ VULNERABILITY: Database credentials exposed
        DATABASE_URL: "postgresql://admin:EXAMPLE_PASSWORD@db.example.com:5432/demo",
        // This is OK - using placeholder
        API_TOKEN: "${API_TOKEN}"
      }
    },
    "safe-server": {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-memory"],
      // This server is safe - no hardcoded secrets
      env: {
        CONFIG_PATH: "./config.json"
      }
    }
  }
};

async function runExample() {
  console.log(chalk.bold.blue('\n🔐 MCP-Guard Security Scanner Example\n'));
  console.log(chalk.gray('Scanning Claude Desktop configuration for vulnerabilities...\n'));

  // Run the scan
  const result = await mcpGuard.scan(exampleConfig.mcpServers);

  // Display results
  console.log(chalk.bold('\n📊 Scan Results\n'));
  console.log(chalk.white(`Score: ${result.summary.score}/100 (Grade: ${result.summary.grade})`));
  console.log(chalk.gray(`Servers scanned: ${result.summary.serversScanned}`));
  console.log(chalk.gray(`Duration: ${result.duration}ms\n`));

  // Display vulnerability summary
  if (result.summary.vulnerabilitiesFound > 0) {
    console.log(chalk.bold('⚠️  Vulnerabilities Found:\n'));
    
    if (result.summary.critical > 0) {
      console.log(chalk.red(`  🔴 CRITICAL: ${result.summary.critical}`));
    }
    if (result.summary.high > 0) {
      console.log(chalk.yellow(`  🟠 HIGH: ${result.summary.high}`));
    }
    if (result.summary.medium > 0) {
      console.log(chalk.blue(`  🟡 MEDIUM: ${result.summary.medium}`));
    }
    if (result.summary.low > 0) {
      console.log(chalk.gray(`  🟢 LOW: ${result.summary.low}`));
    }

    // Display detailed vulnerabilities
    console.log(chalk.bold('\n📋 Vulnerability Details:\n'));
    
    for (const vuln of result.vulnerabilities) {
      const severityColor = {
        'CRITICAL': chalk.red,
        'HIGH': chalk.yellow,
        'MEDIUM': chalk.blue,
        'LOW': chalk.gray,
        'INFO': chalk.white
      }[vuln.severity] || chalk.white;

      console.log(severityColor(`[${vuln.severity}] ${vuln.title}`));
      console.log(chalk.gray(`  Server: ${vuln.server}`));
      console.log(chalk.gray(`  Location: ${vuln.location?.path || 'Unknown'}`));
      console.log(chalk.gray(`  Evidence: ${vuln.evidence?.value || 'N/A'}`));
      console.log(chalk.cyan(`  Fix: ${vuln.remediation.description}`));
      console.log('');
    }
  } else {
    console.log(chalk.green('✅ No vulnerabilities found! Your configuration is secure.\n'));
  }

  // Display recommendations
  if (result.recommendations.length > 0) {
    console.log(chalk.bold('💡 Recommendations:\n'));
    result.recommendations.forEach(rec => {
      console.log(chalk.cyan(`  • ${rec}`));
    });
  }

  // Show how to fix
  if (result.vulnerabilities.length > 0) {
    console.log(chalk.bold('\n🔧 How to Fix:\n'));
    console.log(chalk.gray('1. Move all secrets to environment variables:'));
    console.log(chalk.green('   export GITHUB_TOKEN="your-actual-token"'));
    console.log(chalk.green('   export OPENAI_API_KEY="your-actual-key"'));
    console.log(chalk.green('   export DATABASE_URL="your-connection-string"\n'));
    
    console.log(chalk.gray('2. Update your Claude Desktop config to use placeholders:'));
    console.log(chalk.green('   "env": {'));
    console.log(chalk.green('     "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"'));
    console.log(chalk.green('   }\n'));
    
    console.log(chalk.gray('3. Never commit secrets to configuration files!'));
  }

  // Export report
  console.log(chalk.bold('\n📄 Export Options:\n'));
  console.log(chalk.gray('  • JSON report: mcp-guard scan --output=json > report.json'));
  console.log(chalk.gray('  • PDF report: mcp-guard scan --output=pdf --file=report.pdf'));
  console.log(chalk.gray('  • SARIF format: mcp-guard scan --output=sarif > report.sarif'));
  console.log(chalk.gray('  • Badge generation: mcp-guard badge --score=' + result.summary.score));
}

// Run the example
runExample().catch(console.error);

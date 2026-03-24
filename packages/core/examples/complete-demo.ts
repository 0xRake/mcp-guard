#!/usr/bin/env node

/**
 * MCP-Guard Complete Demo - Testing all implemented scanners
 */

import mcpGuard from '../src';
import { ClaudeDesktopConfig } from '../src/types';
import chalk from 'chalk';

// Example configurations with various vulnerabilities
const exampleConfigs: ClaudeDesktopConfig = {
  mcpServers: {
    // Server with API key exposure
    "openai-integration": {
      command: "node",
      args: [
        "openai-server.js",
        "--api-key", 
        "sk-example-INSECURE-DO-NOT-USE-IN-PRODUCTION-000000" // ⚠️ Intentionally insecure for demo scanning
      ],
      metadata: {
        name: "OpenAI Integration",
        version: "2.0.0"
      }
    },

    // Server with missing authentication
    "production-database": {
      command: "node",
      args: ["database-server.js", "--port", "5432"],
      env: {
        DATABASE_URL: "postgresql://admin:EXAMPLE_PASSWORD@db.example.com/demo", // ⚠️ Intentionally insecure for demo scanning
        SENSITIVE_DATA: "true"
      },
      // ⚠️ No auth configuration despite handling sensitive data
      metadata: {
        name: "Production Database Server"
      }
    },

    // Server with weak authentication
    "admin-panel": {
      command: "python",
      args: ["admin_server.py"],
      auth: {
        type: "basic",
        credentials: {
          username: "admin",
          password: "admin" // ⚠️ Default credentials
        }
      },
      metadata: {
        name: "Admin Control Panel"
      }
    },

    // Server with OAuth misconfiguration
    "api-gateway": {
      command: "node",
      args: ["gateway.js"],
      oauth: {
        authorizationServer: "http://auth.local:8080", // ⚠️ HTTP + localhost
        clientId: "gateway-client",
        scopes: ["*", "admin"], // ⚠️ Overly broad scopes
        // ⚠️ Missing PKCE
      },
      metadata: {
        name: "API Gateway"
      }
    },

    // Server with authentication bypass
    "debug-server": {
      command: "node",
      args: ["server.js", "--no-auth"], // ⚠️ Auth disabled via flag
      env: {
        DEBUG: "true", // ⚠️ Debug mode enabled
        SKIP_AUTH: "true", // ⚠️ Auth bypass enabled
        GITHUB_TOKEN: "ghp_1234567890abcdefghijklmnopqrstuvwxyz" // ⚠️ Token exposed
      },
      metadata: {
        name: "Debug Server"
      }
    },

    // Safe server (should pass all checks)
    "secure-server": {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-memory"],
      oauth: {
        authorizationServer: "https://auth.example.com",
        clientId: "secure-client",
        scopes: ["read", "write"],
        pkce: true,
        metadata: {
          issuer: "https://auth.example.com",
          authorization_endpoint: "https://auth.example.com/authorize",
          token_endpoint: "https://auth.example.com/token",
          jwks_uri: "https://auth.example.com/.well-known/jwks.json",
          grant_types_supported: ["authorization_code"]
        }
      },
      env: {
        // Using placeholders - safe
        API_TOKEN: "${API_TOKEN}",
        DATABASE_URL: "${DATABASE_URL}"
      },
      metadata: {
        name: "Secure Memory Server"
      }
    }
  }
};

async function runDemo() {
  console.log(chalk.bold.cyan('\n╔════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║     🔐 MCP-Guard Security Scanner v1.0     ║'));
  console.log(chalk.bold.cyan('╚════════════════════════════════════════════╝\n'));

  console.log(chalk.gray('Initializing security scanners...'));
  console.log(chalk.green('✓ API Key Scanner loaded'));
  console.log(chalk.green('✓ Authentication Scanner loaded\n'));

  console.log(chalk.yellow('🔍 Scanning 6 MCP server configurations...\n'));

  // Run comprehensive scan
  const startTime = Date.now();
  const result = await mcpGuard.comprehensiveScan(exampleConfigs.mcpServers);
  const scanTime = Date.now() - startTime;

  // Display scan summary
  console.log(chalk.bold.white('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(chalk.bold.white('                SCAN SUMMARY'));
  console.log(chalk.bold.white('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));

  // Score visualization
  const scoreColor = result.summary.score >= 80 ? chalk.green :
                     result.summary.score >= 60 ? chalk.yellow :
                     result.summary.score >= 40 ? chalk.red :
                     chalk.bgRed.white;

  console.log(`${chalk.bold('Security Score:')} ${scoreColor(`${result.summary.score}/100`)} ${chalk.gray(`(Grade: ${result.summary.grade})`)}`);
  console.log(`${chalk.bold('Scan Duration:')} ${chalk.cyan(`${scanTime}ms`)}`);
  console.log(`${chalk.bold('Servers Scanned:')} ${result.summary.serversScanned}`);
  console.log(`${chalk.bold('Total Vulnerabilities:')} ${result.summary.vulnerabilitiesFound}\n`);

  // Vulnerability breakdown with visual bars
  if (result.summary.vulnerabilitiesFound > 0) {
    console.log(chalk.bold('Vulnerability Breakdown:'));
    
    const maxCount = Math.max(
      result.summary.critical,
      result.summary.high,
      result.summary.medium,
      result.summary.low
    );

    const barWidth = 30;
    
    if (result.summary.critical > 0) {
      const bar = '█'.repeat(Math.ceil((result.summary.critical / maxCount) * barWidth));
      console.log(chalk.red(`  CRITICAL │ ${bar} ${result.summary.critical}`));
    }
    if (result.summary.high > 0) {
      const bar = '█'.repeat(Math.ceil((result.summary.high / maxCount) * barWidth));
      console.log(chalk.yellow(`  HIGH     │ ${bar} ${result.summary.high}`));
    }
    if (result.summary.medium > 0) {
      const bar = '█'.repeat(Math.ceil((result.summary.medium / maxCount) * barWidth));
      console.log(chalk.blue(`  MEDIUM   │ ${bar} ${result.summary.medium}`));
    }
    if (result.summary.low > 0) {
      const bar = '█'.repeat(Math.ceil((result.summary.low / maxCount) * barWidth));
      console.log(chalk.gray(`  LOW      │ ${bar} ${result.summary.low}`));
    }
  }

  // Group vulnerabilities by server
  console.log(chalk.bold.white('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(chalk.bold.white('           VULNERABILITY DETAILS'));
  console.log(chalk.bold.white('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));

  const vulnsByServer = result.vulnerabilities.reduce((acc, vuln) => {
    if (!acc[vuln.server]) acc[vuln.server] = [];
    acc[vuln.server].push(vuln);
    return acc;
  }, {} as Record<string, typeof result.vulnerabilities>);

  for (const [server, vulns] of Object.entries(vulnsByServer)) {
    const serverStatus = vulns.some(v => v.severity === 'CRITICAL') ? '🔴' :
                        vulns.some(v => v.severity === 'HIGH') ? '🟠' :
                        vulns.some(v => v.severity === 'MEDIUM') ? '🟡' : '🟢';
    
    console.log(chalk.bold(`\n${serverStatus} ${server}`));
    console.log(chalk.gray('─'.repeat(40)));

    for (const vuln of vulns) {
      const severityColor = {
        'CRITICAL': chalk.red,
        'HIGH': chalk.yellow,
        'MEDIUM': chalk.blue,
        'LOW': chalk.gray,
        'INFO': chalk.white
      }[vuln.severity] || chalk.white;

      console.log(`  ${severityColor(`[${vuln.severity}]`)} ${vuln.title}`);
      console.log(chalk.gray(`    └─ ${vuln.details?.reason || vuln.description.substring(0, 60)}...`));
      
      if (vuln.evidence?.value) {
        console.log(chalk.gray(`       Evidence: ${vuln.evidence.value}`));
      }
    }
  }

  // Check if secure server passed
  if (!vulnsByServer['Secure Memory Server']) {
    console.log(chalk.bold.green('\n✅ Secure Memory Server'));
    console.log(chalk.gray('─'.repeat(40)));
    console.log(chalk.green('  No vulnerabilities detected - properly configured!'));
  }

  // Recommendations
  if (result.recommendations.length > 0) {
    console.log(chalk.bold.white('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    console.log(chalk.bold.white('              RECOMMENDATIONS'));
    console.log(chalk.bold.white('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
    
    result.recommendations.forEach((rec, i) => {
      console.log(chalk.cyan(`${i + 1}. ${rec}`));
    });
  }

  // Quick fixes
  console.log(chalk.bold.white('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(chalk.bold.white('                QUICK FIXES'));
  console.log(chalk.bold.white('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));

  console.log(chalk.bold('For API Key Exposures:'));
  console.log(chalk.gray('  export OPENAI_API_KEY="your-actual-key"'));
  console.log(chalk.gray('  export GITHUB_TOKEN="your-actual-token"'));
  console.log(chalk.gray('  # Then use ${OPENAI_API_KEY} in config\n'));

  console.log(chalk.bold('For Missing Authentication:'));
  console.log(chalk.gray('  oauth: {'));
  console.log(chalk.gray('    authorizationServer: "https://auth.example.com",'));
  console.log(chalk.gray('    clientId: "your-client-id",'));
  console.log(chalk.gray('    pkce: true'));
  console.log(chalk.gray('  }\n'));

  console.log(chalk.bold('For Weak Authentication:'));
  console.log(chalk.gray('  - Replace basic auth with OAuth 2.1'));
  console.log(chalk.gray('  - Use strong passwords (12+ chars)'));
  console.log(chalk.gray('  - Never use default credentials'));
  console.log(chalk.gray('  - Always use HTTPS for auth endpoints'));

  // Footer
  console.log(chalk.bold.cyan('\n╔════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║   Scan complete. Stay secure with MCP-Guard! ║'));
  console.log(chalk.bold.cyan('╚════════════════════════════════════════════╝\n'));

  // CLI usage hint
  console.log(chalk.gray('To use in your project:'));
  console.log(chalk.green('  npm install @mcp-guard/core'));
  console.log(chalk.green('  mcp-guard scan claude_desktop_config.json\n'));
}

// Run the demo
runDemo().catch(error => {
  console.error(chalk.red('Error running demo:'), error);
  process.exit(1);
});

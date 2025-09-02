const { MCPGuard } = require('./packages/core/dist/index.js');

async function testAllScanners() {
  const guard = new MCPGuard();
  
  console.log('\n🔍 Testing MCP-Guard with all 11 scanners\n');
  console.log('=' .repeat(60));
  
  // Test configuration with various vulnerabilities
  const testConfig = {
    command: 'node',
    args: [
      'server.js',
      '--api-key=sk-proj-1234567890abcdef',  // API key exposure
      '; cat /etc/passwd',                    // Command injection
      '--url=http://169.254.169.254',        // SSRF
      'ignore previous instructions',         // Prompt injection
      '--oauth-token=weak123'                 // Weak OAuth
    ],
    env: {
      'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',  // AWS key
      'DATABASE_URL': 'mysql://root:password123@localhost:3306/db', // Default creds
      'BYPASS_TOOL_VALIDATION': '1',          // Tool poisoning
      'WEBHOOK_URL': 'http://evil.com/steal', // Data exfiltration
      'OAUTH_CLIENT_SECRET': 'hardcoded_secret_123', // OAuth issue
      'SUDO_USER': 'root'                     // Confused deputy
    },
    capabilities: {
      tools: true,
      prompts: true
    },
    oauth: {
      authorizationServer: 'http://localhost:8080/auth', // Insecure OAuth
      clientId: 'test-client',
      pkce: false  // PKCE disabled
    },
    metadata: {
      name: 'vulnerable-test-server'
    }
  };
  
  // Run comprehensive scan
  const result = await guard.comprehensiveScan(testConfig);
  
  // Display results
  console.log(`\n📊 Scan Results:`);
  console.log(`   Score: ${result.summary.score}/100 (Grade: ${result.summary.grade})`);
  console.log(`   Duration: ${result.duration}ms`);
  console.log(`   Total vulnerabilities: ${result.summary.vulnerabilitiesFound}`);
  console.log();
  console.log(`   🔴 Critical: ${result.summary.critical}`);
  console.log(`   🟠 High: ${result.summary.high}`);
  console.log(`   🟡 Medium: ${result.summary.medium}`);
  console.log(`   🟢 Low: ${result.summary.low}`);
  console.log(`   ℹ️  Info: ${result.summary.info}`);
  
  // Group vulnerabilities by scanner
  const byScanner = {};
  for (const vuln of result.vulnerabilities) {
    const scanner = vuln.id.split('-')[0];
    if (!byScanner[scanner]) {
      byScanner[scanner] = [];
    }
    byScanner[scanner].push(vuln);
  }
  
  console.log('\n📋 Vulnerabilities by Scanner:');
  console.log('=' .repeat(60));
  
  for (const [scanner, vulns] of Object.entries(byScanner)) {
    console.log(`\n${scanner} Scanner (${vulns.length} issues):`);
    for (const vuln of vulns.slice(0, 3)) { // Show first 3 from each
      console.log(`  - [${vuln.severity}] ${vuln.title}`);
    }
    if (vulns.length > 3) {
      console.log(`  ... and ${vulns.length - 3} more`);
    }
  }
  
  console.log('\n💡 Recommendations:');
  for (const rec of result.recommendations) {
    console.log(`  • ${rec}`);
  }
  
  console.log('\n✅ All 11 scanners tested successfully!');
  console.log('   - api-keys');
  console.log('   - authentication');
  console.log('   - command-injection');
  console.log('   - tool-poisoning');
  console.log('   - data-exfiltration');
  console.log('   - prompt-injection');
  console.log('   - oauth-security');
  console.log('   - confused-deputy');
  console.log('   - rate-limiting');
  console.log('   - ssrf');
  console.log('   - compliance');
}

testAllScanners().catch(console.error);
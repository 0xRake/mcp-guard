#!/usr/bin/env node

// Test script for MCP server tools
const { spawn } = require('child_process');

// Test configuration
const testConfig = {
  name: "test-server",
  version: "1.0.0",
  description: "Test MCP server for security scanning",
  tools: [
    {
      name: "execute_command",
      description: "Execute shell commands",
      parameters: {
        command: { type: "string" }
      }
    },
    {
      name: "read_file",
      description: "Read file contents",
      parameters: {
        path: { type: "string" }
      }
    }
  ],
  prompts: [
    {
      name: "analyze_code",
      template: "Analyze this code: {{code}}"
    }
  ],
  resources: [
    {
      uri: "file:///etc/passwd",
      sensitive: true
    }
  ]
};

// Test cases
const testCases = [
  {
    name: "scan_config",
    description: "Test basic configuration scanning",
    request: {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "scan_config",
        arguments: {
          config: testConfig,
          depth: "comprehensive"
        }
      }
    }
  },
  {
    name: "check_vulnerabilities",
    description: "Test vulnerability checking",
    request: {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "check_vulnerabilities",
        arguments: {
          config: testConfig,
          types: ["command-injection", "tool-poisoning", "data-exfiltration"]
        }
      }
    }
  },
  {
    name: "generate_report",
    description: "Test report generation",
    request: {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "generate_report",
        arguments: {
          config: testConfig,
          format: "markdown"
        }
      }
    }
  },
  {
    name: "monitor_traffic",
    description: "Test traffic monitoring",
    request: {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "monitor_traffic",
        arguments: {
          config: testConfig,
          interval: 1000,
          metrics: ["all"]
        }
      }
    }
  }
];

// Run tests
async function runTests() {
  console.log('🧪 Testing MCP Server Tools\n');
  console.log('═══════════════════════════════════════\n');

  // Start MCP server
  const server = spawn('node', ['dist/index.js'], {
    cwd: __dirname,
    stdio: ['pipe', 'pipe', 'pipe']
  });

  let buffer = '';
  
  server.stdout.on('data', (data) => {
    buffer += data.toString();
    // Try to parse complete JSON responses
    const lines = buffer.split('\n');
    for (let i = 0; i < lines.length - 1; i++) {
      const line = lines[i].trim();
      if (line) {
        try {
          const response = JSON.parse(line);
          if (response.result) {
            console.log('✅ Response received:', response.id);
            if (response.result.content) {
              console.log(response.result.content[0].text.substring(0, 200) + '...\n');
            }
          }
        } catch (e) {
          // Not JSON, probably debug output
          if (!line.includes('MCP-Guard server started')) {
            console.log('Server:', line);
          }
        }
      }
    }
    buffer = lines[lines.length - 1];
  });

  server.stderr.on('data', (data) => {
    const msg = data.toString();
    if (msg.includes('started successfully')) {
      console.log('✅ Server started successfully\n');
      runTestCases();
    } else if (!msg.includes('[')) {
      console.error('Error:', msg);
    }
  });

  // Send initialization
  setTimeout(() => {
    server.stdin.write(JSON.stringify({
      jsonrpc: "2.0",
      id: 0,
      method: "initialize",
      params: {
        protocolVersion: "0.1.0",
        capabilities: {},
        clientInfo: {
          name: "test-client",
          version: "1.0.0"
        }
      }
    }) + '\n');
  }, 500);

  // Run test cases
  function runTestCases() {
    testCases.forEach((testCase, index) => {
      setTimeout(() => {
        console.log(`\n📝 Test ${index + 1}: ${testCase.description}`);
        console.log('─'.repeat(40));
        server.stdin.write(JSON.stringify(testCase.request) + '\n');
      }, 1500 + (index * 1000));
    });

    // Cleanup
    setTimeout(() => {
      console.log('\n✨ Tests completed!\n');
      server.kill();
      process.exit(0);
    }, 6000);
  }

  server.on('error', (err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}

// Direct execution test (without stdio)
async function directTest() {
  console.log('\n🎯 Direct Tool Testing\n');
  console.log('═══════════════════════════════════════\n');

  try {
    // Import tools directly
    const { scanConfigTool } = require('./dist/tools/scan-config.js');
    const { checkVulnerabilitiesTool } = require('./dist/tools/check-vulnerabilities.js');
    const { generateReportTool } = require('./dist/tools/generate-report.js');

    // Test scan_config
    console.log('1. Testing scan_config tool...');
    const scanResult = await scanConfigTool.execute({
      config: testConfig,
      depth: 'comprehensive'
    });
    console.log('   Score:', scanResult.summary.score + '/100');
    console.log('   Vulnerabilities:', scanResult.summary.vulnerabilitiesFound);
    console.log('   ✅ scan_config working!\n');

    // Test check_vulnerabilities
    console.log('2. Testing check_vulnerabilities tool...');
    const vulns = await checkVulnerabilitiesTool.execute({
      config: testConfig,
      types: ['command-injection', 'tool-poisoning']
    });
    console.log('   Found:', vulns.length, 'vulnerabilities');
    console.log('   ✅ check_vulnerabilities working!\n');

    // Test generate_report
    console.log('3. Testing generate_report tool...');
    const report = await generateReportTool.execute({
      config: testConfig,
      format: 'markdown'
    });
    console.log('   Report length:', report.length, 'characters');
    console.log('   ✅ generate_report working!\n');

    console.log('✨ All tools tested successfully!\n');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

// Run direct test first, then server test
directTest().then(() => {
  console.log('\n🚀 Now testing via MCP server protocol...\n');
  runTests();
});
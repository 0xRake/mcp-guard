#!/usr/bin/env node

// Test MCP server transport
const { spawn } = require('child_process');

console.log('🧪 Testing MCP Server Transport\n');

// Start server
const server = spawn('node', ['dist/server.js'], {
  stdio: ['pipe', 'pipe', 'pipe']
});

let buffer = '';
let responseCount = 0;

server.stdout.on('data', (data) => {
  buffer += data.toString();
  const lines = buffer.split('\n');
  
  for (let i = 0; i < lines.length - 1; i++) {
    const line = lines[i].trim();
    if (line) {
      try {
        const msg = JSON.parse(line);
        responseCount++;
        console.log(`✅ Response ${responseCount}:`, msg.result ? 'Success' : 'Error');
        if (msg.result) {
          if (msg.result.protocolVersion) {
            console.log('   Protocol:', msg.result.protocolVersion);
            console.log('   Server:', msg.result.serverInfo.name, msg.result.serverInfo.version);
          }
          if (msg.result.tools) {
            console.log('   Tools:', msg.result.tools.length);
            msg.result.tools.forEach(t => console.log(`     - ${t.name}`));
          }
        }
      } catch (e) {
        // Not JSON
      }
    }
  }
  buffer = lines[lines.length - 1];
});

server.stderr.on('data', (data) => {
  const msg = data.toString();
  if (msg.includes('started')) {
    console.log('✅ Server started successfully\n');
    runTests();
  }
});

function runTests() {
  // Test 1: Initialize
  console.log('📝 Test 1: Initialize');
  server.stdin.write(JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
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

  // Test 2: List tools
  setTimeout(() => {
    console.log('\n📝 Test 2: List Tools');
    server.stdin.write(JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {}
    }) + '\n');
  }, 500);

  // Test 3: Call scan_config
  setTimeout(() => {
    console.log('\n📝 Test 3: Call scan_config tool');
    server.stdin.write(JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "scan_config",
        arguments: {
          config: {
            name: "test-server",
            tools: [{
              name: "exec",
              description: "Execute commands"
            }]
          },
          depth: "quick"
        }
      }
    }) + '\n');
  }, 1000);

  // Cleanup
  setTimeout(() => {
    console.log('\n✨ Transport test completed!');
    server.kill();
    process.exit(0);
  }, 2000);
}

server.on('error', (err) => {
  console.error('❌ Failed to start server:', err);
  process.exit(1);
});
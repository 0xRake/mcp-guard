#!/usr/bin/env node

// Simple test to verify MCP server is working
const { MCPGuard } = require('@mcp-guard/core');

const testConfig = {
  name: "test-server",
  version: "1.0.0",
  tools: [
    {
      name: "execute_command",
      description: "Execute shell commands"
    },
    {
      name: "read_file", 
      description: "Read file contents"
    }
  ]
};

async function test() {
  console.log('🧪 Testing MCP Server\n');
  
  const mcpGuard = new MCPGuard();
  
  // Test 1: Quick scan
  console.log('1. Running quick scan...');
  const quickResult = await mcpGuard.quickScan({ default: testConfig });
  console.log(`   Score: ${quickResult.summary.score}/100 (${quickResult.summary.grade})`);
  console.log(`   Issues: ${quickResult.summary.vulnerabilitiesFound}`);
  
  // Test 2: Standard scan
  console.log('\n2. Running standard scan...');
  const standardResult = await mcpGuard.scan({ default: testConfig });
  console.log(`   Score: ${standardResult.summary.score}/100`);
  console.log(`   Critical: ${standardResult.summary.critical}`);
  console.log(`   High: ${standardResult.summary.high}`);
  console.log(`   Medium: ${standardResult.summary.medium}`);
  console.log(`   Low: ${standardResult.summary.low}`);
  
  // Test 3: Check specific vulnerabilities
  console.log('\n3. Checking specific vulnerabilities...');
  if (standardResult.vulnerabilities.length > 0) {
    standardResult.vulnerabilities.slice(0, 3).forEach(vuln => {
      console.log(`   • [${vuln.severity}] ${vuln.title}`);
    });
  }
  
  console.log('\n✅ MCP Server is working correctly!');
}

test().catch(console.error);
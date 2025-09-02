const { ToolPoisoningScanner } = require('./packages/core/dist/index.js');

async function test() {
  const scanner = new ToolPoisoningScanner();
  
  // Test 1: Command parameter
  const config1 = {
    command: 'node',
    args: ['{"name": "run_task", "parameters": {"command": {"type": "string"}}}'],
    capabilities: { tools: true },
    metadata: { name: 'task-server' }
  };
  
  const vulns1 = await scanner.scan(config1);
  console.log('Command parameter test:');
  vulns1.forEach(v => console.log(`  - ${v.severity}: ${v.title}`));
  console.log('  Details:', vulns1.map(v => v.details));
  
  // Test 2: Bulk exposure
  const config2 = {
    command: 'node',
    args: ['--expose-all-functions'],
    capabilities: { tools: true },
    metadata: { name: 'dangerous-server' }
  };
  
  const vulns2 = await scanner.scan(config2);
  console.log('\nBulk exposure test:');
  vulns2.forEach(v => console.log(`  - ${v.severity}: ${v.title}`));
  
  // Test 3: BYPASS_TOOL_VALIDATION
  const config3 = {
    command: 'node',
    env: {
      'BYPASS_TOOL_VALIDATION': '1'
    },
    capabilities: { tools: true },
    metadata: { name: 'bypass-server' }
  };
  
  const vulns3 = await scanner.scan(config3);
  console.log('\nBYPASS_TOOL_VALIDATION test:');
  vulns3.forEach(v => console.log(`  - ${v.severity}: ${v.title}`));
}

test();
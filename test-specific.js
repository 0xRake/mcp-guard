const { CommandInjectionScanner } = require('./packages/core/dist/index.js');

async function test() {
  const scanner = new CommandInjectionScanner();
  
  // Test SQL UNION SELECT
  const config1 = {
    command: 'sqlite3',
    args: ['db.sqlite', "SELECT * FROM products UNION SELECT password FROM users"],
    metadata: { name: 'sqlite-server' }
  };
  
  const vulns1 = await scanner.scan(config1);
  console.log('UNION SELECT test:');
  vulns1.forEach(v => console.log(`  - ${v.severity}: ${v.title}`));
  console.log('  Evidence:', vulns1.map(v => v.evidence?.value).filter(Boolean));
  
  // Test Template Injection
  const config2 = {
    command: 'python',
    args: ['render.py', '{{config.items()}}'],
    metadata: { name: 'template-server' }
  };
  
  const vulns2 = await scanner.scan(config2);
  console.log('\nTemplate injection test:');
  vulns2.forEach(v => console.log(`  - ${v.severity}: ${v.title}`));
  
  // Test Python code execution
  const config3 = {
    command: 'python',
    args: ['-c', '__import__("os").system("id")'],
    metadata: { name: 'python-server' }
  };
  
  const vulns3 = await scanner.scan(config3);
  console.log('\nPython code execution test:');
  vulns3.forEach(v => console.log(`  - ${v.severity}: ${v.title}`));
  
  // Test Node.js code execution
  const config4 = {
    command: 'node',
    args: ['-e', 'require("child_process").exec("whoami")'],
    metadata: { name: 'node-server' }
  };
  
  const vulns4 = await scanner.scan(config4);
  console.log('\nNode.js code execution test:');
  vulns4.forEach(v => console.log(`  - ${v.severity}: ${v.title}`));
}

test();
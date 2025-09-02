#!/usr/bin/env node

/**
 * MCP-Guard Quick Test - No dependencies required
 * Run this to quickly validate the project structure
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

// Helper functions
const log = {
  success: (msg) => console.log(`${colors.green}✅ ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}❌ ${msg}${colors.reset}`),
  warning: (msg) => console.log(`${colors.yellow}⚠️  ${msg}${colors.reset}`),
  info: (msg) => console.log(`${colors.cyan}ℹ️  ${msg}${colors.reset}`),
  header: (msg) => console.log(`\n${colors.bright}${colors.yellow}${'='.repeat(60)}\n  ${msg}\n${'='.repeat(60)}${colors.reset}\n`)
};

// Track results
let passed = 0;
let failed = 0;

// Check if file exists
function checkFile(filePath, description) {
  const fullPath = path.join(process.cwd(), filePath);
  if (fs.existsSync(fullPath)) {
    log.success(description);
    passed++;
    return true;
  } else {
    log.error(`${description} - Missing: ${filePath}`);
    failed++;
    return false;
  }
}

// Check if directory exists
function checkDir(dirPath, description) {
  const fullPath = path.join(process.cwd(), dirPath);
  if (fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory()) {
    log.success(description);
    passed++;
    return true;
  } else {
    log.error(`${description} - Missing: ${dirPath}`);
    failed++;
    return false;
  }
}

// Count lines in file
function countLines(filePath) {
  try {
    const fullPath = path.join(process.cwd(), filePath);
    const content = fs.readFileSync(fullPath, 'utf-8');
    return content.split('\n').length;
  } catch {
    return 0;
  }
}

// Count pattern occurrences
function countPattern(filePath, pattern) {
  try {
    const fullPath = path.join(process.cwd(), filePath);
    const content = fs.readFileSync(fullPath, 'utf-8');
    const matches = content.match(new RegExp(pattern, 'g'));
    return matches ? matches.length : 0;
  } catch {
    return 0;
  }
}

// Main test function
function runTests() {
  console.log(`${colors.cyan}${colors.bright}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     🔐 MCP-Guard Quick Test (No Dependencies)             ║
║     Validating project structure and files               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
${colors.reset}`);

  // 1. ROOT FILES
  log.header('1. ROOT PROJECT FILES');
  
  checkFile('package.json', 'Root package.json');
  checkFile('pnpm-workspace.yaml', 'PNPM workspace config');
  checkFile('turbo.json', 'Turbo configuration');
  checkFile('tsconfig.json', 'TypeScript config');
  checkDir('.mcp-guard-build', 'Build memory directory');
  checkFile('.mcp-guard-build/build-memory.json', 'Build memory file');

  // 2. PACKAGE DIRECTORIES
  log.header('2. PACKAGE STRUCTURE');
  
  checkDir('packages', 'Packages directory');
  checkDir('packages/core', 'Core package');
  checkDir('packages/cli', 'CLI package');
  checkDir('packages/mcp-server', 'MCP server package');
  checkDir('packages/web', 'Web package');

  // 3. CORE PACKAGE FILES
  log.header('3. CORE PACKAGE FILES');
  
  checkFile('packages/core/package.json', 'Core package.json');
  checkFile('packages/core/tsup.config.ts', 'Build config');
  checkFile('packages/core/vitest.config.ts', 'Test config');
  checkFile('packages/core/README.md', 'Core documentation');
  checkDir('packages/core/src', 'Source directory');
  checkDir('packages/core/test', 'Test directory');
  checkDir('packages/core/examples', 'Examples directory');

  // 4. SCANNERS
  log.header('4. SECURITY SCANNERS');
  
  const scanners = [
    ['api-keys.ts', 'API Key Scanner'],
    ['authentication.ts', 'Authentication Scanner'],
    ['command-injection.ts', 'Command Injection Scanner'],
    ['tool-poisoning.ts', 'Tool Poisoning Scanner']
  ];

  let totalScannerLines = 0;
  for (const [file, name] of scanners) {
    const path = `packages/core/src/scanners/${file}`;
    if (checkFile(path, name)) {
      const lines = countLines(path);
      totalScannerLines += lines;
      log.info(`  └─ ${lines} lines of code`);
    }
  }
  log.info(`Total scanner code: ${totalScannerLines} lines`);

  // 5. TEST FILES
  log.header('5. TEST SUITES');
  
  const tests = [
    ['api-keys.test.ts', 'API Key Scanner tests'],
    ['authentication.test.ts', 'Authentication Scanner tests'],
    ['command-injection.test.ts', 'Command Injection tests'],
    ['tool-poisoning.test.ts', 'Tool Poisoning tests']
  ];

  let totalTestCases = 0;
  for (const [file, name] of tests) {
    const path = `packages/core/test/${file}`;
    if (checkFile(path, name)) {
      const testCount = countPattern(path, 'it\\(');
      totalTestCases += testCount;
      log.info(`  └─ ${testCount} test cases`);
    }
  }
  log.info(`Total test cases: ${totalTestCases}`);

  // 6. DEMO SCRIPTS
  log.header('6. DEMO SCRIPTS');
  
  checkFile('packages/core/examples/scan-demo.ts', 'Basic scanner demo');
  checkFile('packages/core/examples/complete-demo.ts', 'Complete demo');
  checkFile('packages/core/examples/all-scanners-demo.ts', 'All scanners demo');

  // 7. DOCUMENTATION
  log.header('7. DOCUMENTATION');
  
  const docs = [
    ['PROJECT_KNOWLEDGE.md', 'Project knowledge base'],
    ['CODE_ARCHIVE.md', 'Code archive'],
    ['packages/core/README.md', 'Core README']
  ];

  for (const [file, name] of docs) {
    if (checkFile(file, name)) {
      const lines = countLines(file);
      log.info(`  └─ ${lines} lines`);
    }
  }

  // 8. BUILD MEMORY ANALYSIS
  log.header('8. BUILD MEMORY ANALYSIS');
  
  try {
    const memoryPath = path.join(process.cwd(), '.mcp-guard-build/build-memory.json');
    const memory = JSON.parse(fs.readFileSync(memoryPath, 'utf-8'));
    
    log.success('Build memory valid');
    log.info(`  └─ Phase: ${memory.buildProgress.currentPhase}`);
    log.info(`  └─ Scanners: ${memory.scanners.implemented.length} implemented`);
    log.info(`  └─ Files created: ${memory.buildProgress.filesCreated.length}`);
    log.info(`  └─ Test coverage: ${memory.statistics?.testCoverage || 'Unknown'}`);
    
    // List implemented scanners
    console.log(`\n  ${colors.bright}Implemented Scanners:${colors.reset}`);
    memory.scanners.implemented.forEach(scanner => {
      console.log(`    • ${scanner.name} - ${scanner.tests} tests`);
    });
    
    passed++;
  } catch (error) {
    log.error('Could not parse build memory');
    failed++;
  }

  // 9. PACKAGE.JSON VALIDATION
  log.header('9. PACKAGE CONFIGURATION');
  
  try {
    const corePkg = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), 'packages/core/package.json'), 'utf-8')
    );
    
    log.success(`Core package: ${corePkg.name} v${corePkg.version}`);
    log.info(`  └─ Main: ${corePkg.main || 'Not set'}`);
    log.info(`  └─ Dependencies: ${Object.keys(corePkg.dependencies || {}).length}`);
    log.info(`  └─ Dev dependencies: ${Object.keys(corePkg.devDependencies || {}).length}`);
    
    // Check for critical dependencies
    const criticalDeps = ['ajv', 'chalk', 'fast-glob', 'joi', 'zod'];
    const missingDeps = criticalDeps.filter(dep => !corePkg.dependencies[dep]);
    
    if (missingDeps.length === 0) {
      log.success('All critical dependencies present');
      passed++;
    } else {
      log.warning(`Missing dependencies: ${missingDeps.join(', ')}`);
    }
  } catch (error) {
    log.error('Could not validate package.json');
    failed++;
  }

  // FINAL SUMMARY
  log.header('TEST SUMMARY');
  
  const total = passed + failed;
  const percentage = Math.round((passed / total) * 100);
  
  console.log(`\n${colors.bright}📊 Results:${colors.reset}`);
  console.log(`  ${colors.green}✅ Passed: ${passed}${colors.reset}`);
  console.log(`  ${colors.red}❌ Failed: ${failed}${colors.reset}`);
  console.log(`  ${colors.bright}📈 Success Rate: ${percentage}%${colors.reset}`);

  // Grade
  let grade;
  if (percentage >= 95) grade = `${colors.green}A - Excellent!${colors.reset}`;
  else if (percentage >= 85) grade = `${colors.green}B - Good${colors.reset}`;
  else if (percentage >= 75) grade = `${colors.yellow}C - Fair${colors.reset}`;
  else if (percentage >= 60) grade = `${colors.yellow}D - Poor${colors.reset}`;
  else grade = `${colors.red}F - Failed${colors.reset}`;

  console.log(`\n${colors.bright}🎯 Grade: ${grade}${colors.reset}`);

  // Instructions
  console.log(`\n${colors.cyan}${colors.bright}📝 Next Steps:${colors.reset}`);
  
  if (failed === 0) {
    console.log(`${colors.cyan}  1. Install dependencies: cd packages/core && pnpm install${colors.reset}`);
    console.log(`${colors.cyan}  2. Build package: pnpm build${colors.reset}`);
    console.log(`${colors.cyan}  3. Run tests: pnpm test${colors.reset}`);
    console.log(`${colors.cyan}  4. Try demo: npx tsx examples/all-scanners-demo.ts${colors.reset}`);
  } else {
    console.log(`${colors.cyan}  1. Review failed items above${colors.reset}`);
    console.log(`${colors.cyan}  2. Check if files exist in the correct locations${colors.reset}`);
    console.log(`${colors.cyan}  3. Run: ./test-everything.sh for full validation${colors.reset}`);
  }

  console.log(`\n${colors.cyan}${colors.bright}🚀 Quick Start Commands:${colors.reset}`);
  console.log(`${colors.cyan}  # Install and test everything${colors.reset}`);
  console.log(`${colors.cyan}  cd packages/core${colors.reset}`);
  console.log(`${colors.cyan}  npm install${colors.reset}`);
  console.log(`${colors.cyan}  npm run build${colors.reset}`);
  console.log(`${colors.cyan}  npm test${colors.reset}`);
  console.log(`${colors.cyan}  npx tsx examples/all-scanners-demo.ts${colors.reset}`);

  // Exit code
  process.exit(failed > 0 ? 1 : 0);
}

// Run tests
runTests();

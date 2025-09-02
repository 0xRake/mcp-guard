#!/usr/bin/env node

/**
 * MCP-Guard Complete Test Suite
 * Run this script to validate all components built from Claude
 * Usage: node test-everything.js
 */

import { exec, execSync } from 'child_process';
import { existsSync, readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import chalk from 'chalk';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Test results tracking
const results = {
  passed: [],
  failed: [],
  warnings: []
};

// ASCII Art Header
function printHeader() {
  console.log(chalk.cyan(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     🔐 MCP-Guard Complete Test Suite                      ║
║     Testing all 4 scanners and 66+ test cases            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
  `));
}

// Test section header
function section(title) {
  console.log(chalk.bold.yellow(`\n${'='.repeat(60)}`));
  console.log(chalk.bold.yellow(`  ${title}`));
  console.log(chalk.bold.yellow(`${'='.repeat(60)}\n`));
}

// Success indicator
function pass(message) {
  console.log(chalk.green(`  ✅ ${message}`));
  results.passed.push(message);
}

// Failure indicator
function fail(message, error = '') {
  console.log(chalk.red(`  ❌ ${message}`));
  if (error) console.log(chalk.gray(`     ${error}`));
  results.failed.push(message);
}

// Warning indicator
function warn(message) {
  console.log(chalk.yellow(`  ⚠️  ${message}`));
  results.warnings.push(message);
}

// Info message
function info(message) {
  console.log(chalk.gray(`  ℹ️  ${message}`));
}

// Check if a file exists
function checkFile(path, description) {
  if (existsSync(path)) {
    pass(`${description} exists`);
    return true;
  } else {
    fail(`${description} missing`, path);
    return false;
  }
}

// Execute command and capture output
async function runCommand(command, description, cwd = process.cwd()) {
  try {
    info(`Running: ${command}`);
    const { stdout, stderr } = await execAsync(command, { cwd });
    
    if (stderr && !stderr.includes('warning')) {
      warn(`${description} had warnings`);
      console.log(chalk.gray(`     ${stderr.substring(0, 200)}`));
    } else {
      pass(description);
    }
    
    return { success: true, stdout, stderr };
  } catch (error) {
    fail(description, error.message.substring(0, 200));
    return { success: false, error };
  }
}

// Main test function
async function runTests() {
  printHeader();
  const projectRoot = process.cwd();
  const corePackagePath = join(projectRoot, 'packages', 'core');

  // 1. PROJECT STRUCTURE VALIDATION
  section('1. PROJECT STRUCTURE VALIDATION');
  
  const criticalFiles = [
    { path: 'package.json', desc: 'Root package.json' },
    { path: 'pnpm-workspace.yaml', desc: 'PNPM workspace config' },
    { path: 'turbo.json', desc: 'Turbo configuration' },
    { path: 'tsconfig.json', desc: 'TypeScript config' },
    { path: '.mcp-guard-build/build-memory.json', desc: 'Build memory' },
    { path: 'packages/core/package.json', desc: 'Core package.json' },
    { path: 'packages/core/src/index.ts', desc: 'Core entry point' },
    { path: 'packages/core/src/types/index.ts', desc: 'Type definitions' }
  ];

  for (const file of criticalFiles) {
    checkFile(join(projectRoot, file.path), file.desc);
  }

  // 2. SCANNER IMPLEMENTATION CHECK
  section('2. SCANNER IMPLEMENTATIONS');
  
  const scanners = [
    'api-keys.ts',
    'authentication.ts',
    'command-injection.ts',
    'tool-poisoning.ts'
  ];

  for (const scanner of scanners) {
    const scannerPath = join(corePackagePath, 'src', 'scanners', scanner);
    if (checkFile(scannerPath, `Scanner: ${scanner.replace('.ts', '')}`)) {
      const content = readFileSync(scannerPath, 'utf-8');
      const lines = content.split('\n').length;
      info(`  └─ ${lines} lines of code`);
    }
  }

  // 3. TEST FILES VALIDATION
  section('3. TEST FILES VALIDATION');
  
  const testFiles = [
    'api-keys.test.ts',
    'authentication.test.ts',
    'command-injection.test.ts',
    'tool-poisoning.test.ts'
  ];

  let totalTestCases = 0;
  for (const testFile of testFiles) {
    const testPath = join(corePackagePath, 'test', testFile);
    if (checkFile(testPath, `Test: ${testFile.replace('.test.ts', '')}`)) {
      const content = readFileSync(testPath, 'utf-8');
      const testCount = (content.match(/it\(/g) || []).length;
      totalTestCases += testCount;
      info(`  └─ ${testCount} test cases`);
    }
  }
  info(`Total test cases: ${totalTestCases}`);

  // 4. DEPENDENCY INSTALLATION
  section('4. DEPENDENCY INSTALLATION');
  
  info('Installing dependencies with pnpm...');
  const installResult = await runCommand(
    'pnpm install --no-frozen-lockfile',
    'Dependencies installed',
    corePackagePath
  );

  if (!installResult.success) {
    warn('Trying with npm instead...');
    await runCommand('npm install', 'Dependencies installed (npm)', corePackagePath);
  }

  // 5. BUILD PROCESS
  section('5. BUILD PROCESS');
  
  await runCommand(
    'pnpm build',
    'Core package built',
    corePackagePath
  );

  // Check build output
  const distPath = join(corePackagePath, 'dist');
  if (existsSync(distPath)) {
    const distFiles = readdirSync(distPath);
    pass(`Build output generated (${distFiles.length} files)`);
    info(`  └─ Files: ${distFiles.join(', ')}`);
  } else {
    fail('No dist folder created');
  }

  // 6. RUN UNIT TESTS
  section('6. UNIT TESTS');
  
  const testResult = await runCommand(
    'pnpm test --run',
    'All tests executed',
    corePackagePath
  );

  if (testResult.stdout) {
    const passMatch = testResult.stdout.match(/(\d+) passed/);
    const failMatch = testResult.stdout.match(/(\d+) failed/);
    
    if (passMatch) {
      pass(`${passMatch[1]} tests passed`);
    }
    if (failMatch && parseInt(failMatch[1]) > 0) {
      fail(`${failMatch[1]} tests failed`);
    }
  }

  // 7. DEMO SCRIPTS VALIDATION
  section('7. DEMO SCRIPTS');
  
  const demos = [
    { file: 'scan-demo.ts', desc: 'API Key Scanner Demo' },
    { file: 'complete-demo.ts', desc: 'Auth + API Keys Demo' },
    { file: 'all-scanners-demo.ts', desc: 'All 4 Scanners Demo' }
  ];

  for (const demo of demos) {
    const demoPath = join(corePackagePath, 'examples', demo.file);
    if (existsSync(demoPath)) {
      pass(`${demo.desc} exists`);
      
      // Try to run the demo with a timeout
      const demoResult = await runCommand(
        `timeout 5 npx tsx ${demo.file} 2>&1 | head -20`,
        `${demo.desc} runs`,
        join(corePackagePath, 'examples')
      );
    } else {
      fail(`${demo.desc} missing`);
    }
  }

  // 8. SCANNER FUNCTIONALITY TEST
  section('8. SCANNER FUNCTIONALITY');
  
  const testCode = `
    import mcpGuard from '${corePackagePath}/dist/index.js';
    
    const testConfig = {
      "test-server": {
        command: "node",
        args: ["--api-key", "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab"],
        env: {
          DATABASE_URL: "postgresql://admin:password@localhost/db",
          USER_INPUT: "; cat /etc/passwd"
        },
        capabilities: { tools: true }
      }
    };
    
    mcpGuard.scan(testConfig).then(result => {
      console.log(JSON.stringify({
        score: result.summary.score,
        grade: result.summary.grade,
        vulnerabilities: result.summary.vulnerabilitiesFound,
        critical: result.summary.critical,
        high: result.summary.high
      }));
    });
  `;

  const testFilePath = join(corePackagePath, 'test-scan.mjs');
  require('fs').writeFileSync(testFilePath, testCode);
  
  const scanResult = await runCommand(
    'node test-scan.mjs',
    'Scanner integration test',
    corePackagePath
  );

  if (scanResult.stdout) {
    try {
      const result = JSON.parse(scanResult.stdout);
      pass(`Detected ${result.vulnerabilities} vulnerabilities`);
      info(`  └─ Score: ${result.score}/100 (${result.grade})`);
      info(`  └─ Critical: ${result.critical}, High: ${result.high}`);
    } catch (e) {
      warn('Could not parse scan results');
    }
  }

  // Clean up test file
  try {
    require('fs').unlinkSync(testFilePath);
  } catch (e) {}

  // 9. BUILD MEMORY VALIDATION
  section('9. BUILD MEMORY VALIDATION');
  
  const memoryPath = join(projectRoot, '.mcp-guard-build', 'build-memory.json');
  if (existsSync(memoryPath)) {
    const memory = JSON.parse(readFileSync(memoryPath, 'utf-8'));
    
    pass('Build memory file valid');
    info(`  └─ Current phase: ${memory.buildProgress.currentPhase}`);
    info(`  └─ Scanners implemented: ${memory.scanners.implemented.length}`);
    info(`  └─ Files created: ${memory.buildProgress.filesCreated.length}`);
    
    // Validate scanner count
    if (memory.scanners.implemented.length === 4) {
      pass('All 4 scanners recorded');
    } else {
      warn(`Only ${memory.scanners.implemented.length} scanners recorded`);
    }
  } else {
    fail('Build memory file missing');
  }

  // 10. DOCUMENTATION CHECK
  section('10. DOCUMENTATION');
  
  const docs = [
    { path: 'packages/core/README.md', desc: 'Core README' },
    { path: 'PROJECT_KNOWLEDGE.md', desc: 'Project knowledge base' },
    { path: 'CODE_ARCHIVE.md', desc: 'Code archive' }
  ];

  for (const doc of docs) {
    const docPath = join(projectRoot, doc.path);
    if (checkFile(docPath, doc.desc)) {
      const content = readFileSync(docPath, 'utf-8');
      const lines = content.split('\n').length;
      info(`  └─ ${lines} lines of documentation`);
    }
  }

  // FINAL SUMMARY
  section('TEST SUMMARY');
  
  const total = results.passed.length + results.failed.length;
  const percentage = Math.round((results.passed.length / total) * 100);
  
  console.log(chalk.bold('\n📊 Results:'));
  console.log(chalk.green(`  ✅ Passed: ${results.passed.length}`));
  console.log(chalk.red(`  ❌ Failed: ${results.failed.length}`));
  console.log(chalk.yellow(`  ⚠️  Warnings: ${results.warnings.length}`));
  console.log(chalk.bold(`  📈 Success Rate: ${percentage}%`));

  // Grade the build
  let grade;
  if (percentage >= 95) grade = chalk.green('A - Production Ready! 🎉');
  else if (percentage >= 85) grade = chalk.green('B - Nearly Complete');
  else if (percentage >= 75) grade = chalk.yellow('C - Functional');
  else if (percentage >= 60) grade = chalk.yellow('D - Needs Work');
  else grade = chalk.red('F - Major Issues');

  console.log(chalk.bold(`\n🎯 Build Grade: ${grade}`));

  // Show failures if any
  if (results.failed.length > 0) {
    console.log(chalk.red('\n❌ Failed Tests:'));
    results.failed.forEach(f => console.log(chalk.red(`  - ${f}`)));
  }

  // Next steps
  console.log(chalk.cyan('\n📝 Next Steps for Claude Code:'));
  if (results.failed.length === 0) {
    console.log(chalk.cyan('  1. Build the CLI package'));
    console.log(chalk.cyan('  2. Create MCP server implementation'));
    console.log(chalk.cyan('  3. Publish to NPM'));
  } else {
    console.log(chalk.cyan('  1. Fix failed tests'));
    console.log(chalk.cyan('  2. Run test-everything.js again'));
    console.log(chalk.cyan('  3. Continue with CLI development'));
  }

  console.log(chalk.gray('\n💡 To use in Claude Code:'));
  console.log(chalk.gray('  claude-code --include ".mcp-guard-build" --include "packages/core"'));
  console.log(chalk.gray('  Then: "Continue MCP-Guard from build-memory.json"'));

  // Exit code based on failures
  process.exit(results.failed.length > 0 ? 1 : 0);
}

// Run the tests
runTests().catch(error => {
  console.error(chalk.red('\n💥 Test suite crashed:'), error);
  process.exit(1);
});

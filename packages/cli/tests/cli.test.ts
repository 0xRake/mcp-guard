import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { execFileSync, ExecFileSyncOptionsWithStringEncoding } from 'child_process';
import path from 'path';
import fs from 'fs';

const distEntry = path.resolve(__dirname, '../dist/index.js');
const fixturesDir = path.resolve(__dirname, 'fixtures');
const configFixture = path.join(fixturesDir, 'test-config.json');

function ensureFixtures() {
  if (!fs.existsSync(fixturesDir)) {
    fs.mkdirSync(fixturesDir, { recursive: true });
  }
  fs.writeFileSync(configFixture, JSON.stringify({
    "test-server": {
      command: "node",
      args: ["server.js"],
      metadata: { name: "test-server" }
    }
  }, null, 2));
}

const execOpts: ExecFileSyncOptionsWithStringEncoding = {
  encoding: 'utf-8',
  timeout: 30000,
  cwd: path.resolve(__dirname, '..'),
  env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' }
};

function runCLI(args: string[]): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execFileSync('node', [distEntry, ...args], execOpts);
    return { stdout, stderr: '', exitCode: 0 };
  } catch (err: any) {
    return {
      stdout: err.stdout || '',
      stderr: err.stderr || '',
      exitCode: err.status ?? 1
    };
  }
}

describe('CLI', () => {
  beforeAll(() => {
    ensureFixtures();
    if (!fs.existsSync(distEntry)) {
      throw new Error(`CLI not built at ${distEntry} — run pnpm build first`);
    }
  });

  afterAll(() => {
    if (fs.existsSync(fixturesDir)) {
      fs.rmSync(fixturesDir, { recursive: true });
    }
  });

  describe('--help', () => {
    it('lists all commands: scan, fix, report, watch, list, init', () => {
      const { stdout, exitCode } = runCLI(['--help']);
      expect(exitCode).toBe(0);
      for (const cmd of ['scan', 'fix', 'report', 'watch', 'list', 'init']) {
        expect(stdout).toContain(cmd);
      }
    });
  });

  describe('--version', () => {
    it('outputs a semver version string', () => {
      const { stdout, exitCode } = runCLI(['--version']);
      expect(exitCode).toBe(0);
      const lastLine = stdout.trim().split('\n').pop()!;
      expect(lastLine).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });

  describe('list', () => {
    it('displays known scanner names', () => {
      const { stdout, exitCode } = runCLI(['list']);
      expect(exitCode).toBe(0);
      for (const scanner of ['api-keys', 'authentication', 'command-injection', 'ssrf']) {
        expect(stdout).toContain(scanner);
      }
    });
  });

  describe('init', () => {
    const initOutput = path.join(fixturesDir, 'init-output.json');

    afterEach(() => {
      if (fs.existsSync(initOutput)) fs.unlinkSync(initOutput);
    });

    it('writes a valid config with server entries', () => {
      const { exitCode } = runCLI(['init', '-o', initOutput]);
      expect(exitCode).toBe(0);
      expect(fs.existsSync(initOutput)).toBe(true);

      const config = JSON.parse(fs.readFileSync(initOutput, 'utf-8'));
      expect(config['test-server'].command).toBe('node');
      expect(config['python-server'].command).toBe('python');
    });
  });

  describe('scan', () => {
    it('exits non-zero when vulnerabilities are found', () => {
      const { exitCode } = runCLI(['scan', configFixture]);
      // Any real config will have findings, so exit code should be 1
      expect(exitCode).toBe(1);
    });

    it('produces valid JSON output with --output json', () => {
      const { stdout } = runCLI(['scan', configFixture, '-o', 'json']);
      const jsonStart = stdout.indexOf('{');
      expect(jsonStart).toBeGreaterThanOrEqual(0);
      // stdout should now be clean — no library noise
      const result = JSON.parse(stdout.slice(jsonStart));
      expect(typeof result.summary.score).toBe('number');
      expect(result.vulnerabilities).toBeInstanceOf(Array);
      expect(result.summary.vulnerabilitiesFound).toBe(result.vulnerabilities.length);
    });

    it('fails with a clear message for nonexistent config', () => {
      const { stdout, stderr, exitCode } = runCLI(['scan', '/no/such/file.json']);
      expect(exitCode).not.toBe(0);
      const output = stdout + stderr;
      expect(output).toContain('not found');
    });
  });
});

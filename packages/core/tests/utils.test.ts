/**
 * Tests for utility functions
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { LogLevel, noopLogger, createStderrLogger, ConfigLoader, ReportGenerator, ReportFormat } from '../src/utils';
import type { Logger } from '../src/utils';
import { ConfigValidator, InputValidator } from '../src/validators';
import type { ScanResult, MCPServerConfig } from '../src/types';

describe('Logger', () => {
  it('noopLogger silently accepts all calls', () => {
    expect(() => {
      noopLogger.debug('test');
      noopLogger.info('test');
      noopLogger.warn('test');
      noopLogger.error('test');
    }).not.toThrow();
  });

  it('createStderrLogger respects log level', () => {
    const writes: string[] = [];
    const origWrite = process.stderr.write;
    process.stderr.write = ((chunk: any) => { writes.push(String(chunk)); return true; }) as any;

    const logger = createStderrLogger(LogLevel.WARN);
    logger.debug('should not appear');
    logger.info('should not appear');
    logger.warn('should appear');
    logger.error('should appear');

    process.stderr.write = origWrite;

    expect(writes.length).toBe(2);
    expect(writes[0]).toContain('WARN');
    expect(writes[1]).toContain('ERROR');
  });

  it('createStderrLogger includes prefix', () => {
    const writes: string[] = [];
    const origWrite = process.stderr.write;
    process.stderr.write = ((chunk: any) => { writes.push(String(chunk)); return true; }) as any;

    const logger = createStderrLogger(LogLevel.INFO, '[test-prefix]');
    logger.info('hello');

    process.stderr.write = origWrite;

    expect(writes[0]).toContain('[test-prefix]');
    expect(writes[0]).toContain('hello');
  });
});

describe('ConfigValidator', () => {
  it('should validate valid configuration', () => {
    const config = {
      command: 'node',
      args: ['server.js'],
      env: { NODE_ENV: 'production' }
    };

    const validated = ConfigValidator.validate(config);
    expect(validated.command).toBe('node');
    expect(validated.args).toEqual(['server.js']);
  });

  it('should reject invalid configuration', () => {
    const config = {
      // Missing required 'command' field
      args: ['server.js']
    };

    expect(() => ConfigValidator.validate(config)).toThrow('Invalid configuration');
  });

  it('should detect security issues', () => {
    const config: MCPServerConfig = {
      command: 'node',
      env: {
        API_KEY: 'sk-1234567890abcdefgh',
        DATABASE_PASSWORD: 'admin123'
      },
      metadata: { name: 'test' }
    };

    const issues = ConfigValidator.checkSecurityIssues(config);
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.some(issue => issue.includes('secret'))).toBe(true);
  });

  it('should sanitize sensitive data', () => {
    const config: MCPServerConfig = {
      command: 'node',
      env: {
        API_KEY: 'sk-secret-key',
        NORMAL_VAR: 'normal-value'
      },
      auth: {
        type: 'basic',
        credentials: {
          username: 'admin',
          password: 'secretpass'
        }
      },
      metadata: { name: 'test' }
    };

    const sanitized = ConfigValidator.sanitize(config);
    expect(sanitized.env?.API_KEY).toBe('[REDACTED]');
    expect(sanitized.env?.NORMAL_VAR).toBe('normal-value');
    expect(sanitized.auth?.credentials?.password).toBe('[REDACTED]');
  });
});

describe('InputValidator', () => {
  it('should validate safe paths', () => {
    const safePath = '/home/user/file.txt';
    const validated = InputValidator.validatePath(safePath);
    expect(validated).toBe(safePath);
  });

  it('should reject path traversal', () => {
    const maliciousPath = '../../../etc/passwd';
    expect(() => InputValidator.validatePath(maliciousPath)).toThrow('Path traversal detected');
  });

  it('should sanitize command arguments', () => {
    const args = ['normal-arg', 'arg; rm -rf /', 'arg | cat /etc/passwd'];
    const sanitized = InputValidator.validateCommandArgs(args);
    
    expect(sanitized[0]).toBe('normal-arg');
    expect(sanitized[1]).toContain("'");  // Should be quoted
    expect(sanitized[2]).toContain("'");  // Should be quoted
  });

  it('should validate URLs', () => {
    const validUrl = 'https://example.com/api';
    const validated = InputValidator.validateUrl(validUrl);
    expect(validated).toBe(validUrl);

    const invalidUrl = 'javascript:alert(1)';
    expect(() => InputValidator.validateUrl(invalidUrl)).toThrow('Invalid protocol');
  });

  it('should detect prototype pollution in JSON', () => {
    const maliciousJson = '{"__proto__": {"isAdmin": true}}';
    expect(() => InputValidator.validateJSON(maliciousJson)).toThrow('prototype pollution');
  });

  it('should validate server names', () => {
    const validName = 'my-server_123';
    const validated = InputValidator.validateServerName(validName);
    expect(validated).toBe(validName);

    const invalidName = 'my server!@#';
    expect(() => InputValidator.validateServerName(invalidName)).toThrow('Invalid server name');
  });
});

describe('ReportGenerator', () => {
  const mockResult: ScanResult = {
    id: 'test-scan-123',
    timestamp: new Date(),
    duration: 100,
    config: { depth: 'standard' },
    summary: {
      score: 75,
      grade: 'C',
      serversScanned: 2,
      vulnerabilitiesFound: 3,
      critical: 1,
      high: 1,
      medium: 1,
      low: 0,
      info: 0
    },
    vulnerabilities: [
      {
        id: 'vuln-1',
        type: 'EXPOSED_API_KEY',
        severity: 'CRITICAL',
        score: 9.5,
        server: 'test-server',
        title: 'Exposed API Key',
        description: 'API key found in configuration',
        location: { path: 'env.API_KEY' },
        evidence: { value: 'sk-***' },
        remediation: {
          description: 'Move to secure storage',
          automated: false
        }
      }
    ],
    metadata: {
      scanner: 'mcp-guard',
      version: '1.0.0',
      signatures: 'latest',
      rules: 4
    },
    recommendations: ['Use environment variables', 'Enable authentication']
  };

  it('should generate JSON report', async () => {
    const report = await ReportGenerator.generate(mockResult, ReportFormat.JSON);
    const parsed = JSON.parse(report);
    expect(parsed.id).toBe('test-scan-123');
    expect(parsed.summary.score).toBe(75);
  });

  it('should generate Markdown report', async () => {
    const report = await ReportGenerator.generate(mockResult, ReportFormat.MARKDOWN);
    expect(report).toContain('# MCP-Guard Security Scan Report');
    expect(report).toContain('Score:** 75/100');
    expect(report).toContain('Exposed API Key');
  });

  it('should generate HTML report', async () => {
    const report = await ReportGenerator.generate(mockResult, ReportFormat.HTML);
    expect(report).toContain('<!DOCTYPE html>');
    expect(report).toContain('MCP-Guard Security Report');
    expect(report).toContain('75/100');
  });

  it('should generate SARIF report', async () => {
    const report = await ReportGenerator.generate(mockResult, ReportFormat.SARIF);
    const parsed = JSON.parse(report);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0].tool.driver.name).toBe('MCP-Guard');
  });

  it('should generate CSV report', async () => {
    const report = await ReportGenerator.generate(mockResult, ReportFormat.CSV);
    const lines = report.split('\n');
    expect(lines[0]).toContain('ID,Severity,Score');
    expect(lines[1]).toContain('vuln-1,CRITICAL,9.5');
  });

  it('should generate XML report', async () => {
    const report = await ReportGenerator.generate(mockResult, ReportFormat.XML);
    expect(report).toContain('<?xml version="1.0"');
    expect(report).toContain('<scan-result>');
    expect(report).toContain('<score>75</score>');
  });
});
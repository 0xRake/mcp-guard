import { describe, it, expect, beforeEach } from 'vitest';
import { MCPGuard } from '../src/index';
import type { MCPServerConfig, ScanResult, Scanner, Vulnerability } from '../src/types';

describe('MCPGuard', () => {
  let guard: MCPGuard;

  beforeEach(() => {
    guard = new MCPGuard();
  });

  describe('scan()', () => {
    it('returns a ScanResult with all expected fields', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        metadata: { name: 'test-server' }
      };

      const result = await guard.scan(config);

      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('timestamp');
      expect(result).toHaveProperty('duration');
      expect(result).toHaveProperty('summary');
      expect(result).toHaveProperty('vulnerabilities');
      expect(result).toHaveProperty('recommendations');
      expect(result.summary).toHaveProperty('score');
      expect(result.summary).toHaveProperty('grade');
      expect(result.summary).toHaveProperty('serversScanned');
      expect(result.summary).toHaveProperty('vulnerabilitiesFound');
      expect(typeof result.summary.score).toBe('number');
      expect(['A', 'B', 'C', 'D', 'F']).toContain(result.summary.grade);
    });

    it('detects a hardcoded API key in args', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--api-key', 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab'],
        metadata: { name: 'leaky-server' }
      };

      const result = await guard.scan(config);
      expect(result.summary.vulnerabilitiesFound).toBeGreaterThan(0);
      expect(result.vulnerabilities.some(v => v.type === 'EXPOSED_API_KEY')).toBe(true);
    });

    it('returns a numeric score between 0 and 100', async () => {
      const config: MCPServerConfig = {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-memory'],
        metadata: { name: 'safe-server' }
      };

      const result = await guard.scan(config);
      expect(result.summary.score).toBeGreaterThanOrEqual(0);
      expect(result.summary.score).toBeLessThanOrEqual(100);
    });
  });

  describe('quickScan()', () => {
    it('returns results with quick depth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js']
      };

      const result = await guard.quickScan(config);
      expect(result).toHaveProperty('summary');
      expect(result.config.depth).toBe('quick');
    });
  });

  describe('comprehensiveScan()', () => {
    it('returns results with comprehensive depth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js']
      };

      const result = await guard.comprehensiveScan(config);
      expect(result).toHaveProperty('summary');
    });
  });

  describe('multi-server config', () => {
    it('scans multiple servers', async () => {
      const config: Record<string, MCPServerConfig> = {
        'server-a': { command: 'node', args: ['a.js'], metadata: { name: 'server-a' } },
        'server-b': { command: 'python', args: ['b.py'], metadata: { name: 'server-b' } }
      };

      const result = await guard.scan(config);
      expect(result.summary.serversScanned).toBeGreaterThanOrEqual(1);
    });
  });

  describe('registerScanner()', () => {
    it('adds a custom scanner that runs during scans', async () => {
      const customScanner: Scanner = {
        name: 'custom-test',
        description: 'test scanner',
        version: '1.0.0',
        enabled: true,
        async scan() {
          return [{
            id: 'custom-1',
            type: 'MISCONFIGURATION' as any,
            severity: 'LOW' as any,
            score: 2,
            server: 'test',
            title: 'Custom finding',
            description: 'Found by custom scanner',
            remediation: { description: 'Fix it', automated: false },
            discoveredAt: new Date()
          }];
        }
      };

      guard.registerScanner(customScanner);
      const result = await guard.scan({
        command: 'node',
        args: ['server.js'],
        metadata: { name: 'test' }
      });

      expect(result.vulnerabilities.some(v => v.title === 'Custom finding')).toBe(true);
    });
  });
});

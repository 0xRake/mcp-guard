import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../src/index';
import type { FastifyInstance } from 'fastify';

describe('MCP-Guard API', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp({ logger: false });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /health', () => {
    it('returns healthy status with an ISO timestamp', async () => {
      const res = await app.inject({ method: 'GET', url: '/health' });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.status).toBe('healthy');
      expect(new Date(body.timestamp).toISOString()).toBe(body.timestamp);
    });
  });

  describe('POST /api/scan', () => {
    it('returns a scored result with vulnerabilities array', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/scan',
        payload: {
          config: {
            command: 'node',
            args: ['server.js'],
            metadata: { name: 'test-server' }
          }
        }
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.result.summary.score).toBeGreaterThanOrEqual(0);
      expect(body.result.summary.score).toBeLessThanOrEqual(100);
      expect(['A', 'B', 'C', 'D', 'F']).toContain(body.result.summary.grade);
      expect(body.result.vulnerabilities).toBeInstanceOf(Array);
      expect(body.result.summary.vulnerabilitiesFound).toBe(body.result.vulnerabilities.length);
    });

    it('detects exposed API keys in scan config', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/scan',
        payload: {
          config: {
            command: 'node',
            args: ['server.js', '--api-key', 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab'],
            metadata: { name: 'leaky-server' }
          }
        }
      });
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.result.summary.vulnerabilitiesFound).toBeGreaterThan(0);
      const hasApiKeyVuln = body.result.vulnerabilities.some(
        (v: any) => v.type === 'EXPOSED_API_KEY'
      );
      expect(hasApiKeyVuln).toBe(true);
    });

    it('respects the quick depth option', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/scan',
        payload: {
          config: { command: 'node', args: ['server.js'] },
          options: { depth: 'quick' }
        }
      });
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.result.config.depth).toBe('quick');
    });

    it('rejects requests missing the config field', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/scan',
        payload: { options: { depth: 'quick' } }
      });
      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.success).toBeUndefined();
    });
  });

  describe('GET /api/results/:id', () => {
    it('echoes back the requested id', async () => {
      const res = await app.inject({ method: 'GET', url: '/api/results/scan-abc-123' });
      expect(res.statusCode).toBe(200);
      expect(res.json().id).toBe('scan-abc-123');
    });
  });

  describe('POST /api/fix', () => {
    it('returns proposals, summary, and scanResult for a config', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/fix',
        payload: {
          config: {
            command: 'node',
            args: ['server.js'],
            metadata: { name: 'test-server' }
          }
        }
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.proposals).toBeInstanceOf(Array);
      expect(body.summary).toHaveProperty('total');
      expect(body.summary).toHaveProperty('automated');
      expect(body.summary).toHaveProperty('manual');
      expect(body.summary.total).toBe(body.proposals.length);
      expect(body.summary.automated + body.summary.manual).toBe(body.summary.total);
      expect(body.scanResult).toBeDefined();
      expect(body.scanResult.vulnerabilities).toBeInstanceOf(Array);
    });

    it('produces a secrets proposal for a config with a hardcoded API key', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/fix',
        payload: {
          config: {
            command: 'node',
            args: ['server.js', '--api-key', 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab'],
            metadata: { name: 'leaky-server' }
          }
        }
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      const secretsProposals = body.proposals.filter((p: any) => p.category === 'secrets');
      expect(secretsProposals.length).toBeGreaterThan(0);
      expect(secretsProposals[0].automated).toBe(true);
    });

    it('returns no secrets proposals for a config without hardcoded keys', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/fix',
        payload: {
          config: {
            command: 'node',
            args: ['server.js'],
            metadata: { name: 'clean-server' }
          }
        }
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      const secretsProposals = body.proposals.filter((p: any) => p.category === 'secrets');
      expect(secretsProposals.length).toBe(0);
      expect(body.summary.total).toBe(body.proposals.length);
    });

    it('rejects requests missing the config field', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/fix',
        payload: {}
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /api/stats', () => {
    it('returns numeric statistics and daily trend data', async () => {
      const res = await app.inject({ method: 'GET', url: '/api/stats' });
      const body = res.json();
      expect(typeof body.scansToday).toBe('number');
      expect(typeof body.complianceScore).toBe('number');
      expect(body.trends.daily.length).toBeGreaterThan(0);
      expect(body.trends.daily[0]).toHaveProperty('date');
      expect(body.trends.daily[0]).toHaveProperty('scans');
      expect(body.trends.daily[0]).toHaveProperty('vulnerabilities');
    });
  });

  describe('GET /api/scanners', () => {
    it('returns all scanner entries with id, name, and enabled flag', async () => {
      const res = await app.inject({ method: 'GET', url: '/api/scanners' });
      const { scanners } = res.json();
      expect(scanners.length).toBe(11);
      for (const scanner of scanners) {
        expect(typeof scanner.id).toBe('string');
        expect(typeof scanner.name).toBe('string');
        expect(typeof scanner.enabled).toBe('boolean');
      }
      const ids = scanners.map((s: any) => s.id);
      expect(ids).toContain('api-keys');
      expect(ids).toContain('ssrf');
      expect(ids).toContain('compliance');
    });
  });
});

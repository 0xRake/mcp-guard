import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';
import websocket from '@fastify/websocket';
import { MCPGuard } from '@mcp-guard/core';
import type { Logger, ScanResult, Vulnerability } from '@mcp-guard/core';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// In-memory scan store — accumulates results from POST /api/scan
// ---------------------------------------------------------------------------
interface StoredScan {
  result: ScanResult;
  serverName: string;
  storedAt: Date;
}

/** Registry of individual scanners available in @mcp-guard/core */
const SCANNER_REGISTRY: { id: string; name: string; enabled: boolean }[] = [
  { id: 'api-keys', name: 'API Keys Scanner', enabled: true },
  { id: 'authentication', name: 'Authentication Scanner', enabled: true },
  { id: 'command-injection', name: 'Command Injection Scanner', enabled: true },
  { id: 'tool-poisoning', name: 'Tool Poisoning Scanner', enabled: true },
  { id: 'data-exfiltration', name: 'Data Exfiltration Scanner', enabled: true },
  { id: 'prompt-injection', name: 'Prompt Injection Scanner', enabled: true },
  { id: 'oauth-security', name: 'OAuth Security Scanner', enabled: true },
  { id: 'confused-deputy', name: 'Confused Deputy Scanner', enabled: true },
  { id: 'rate-limiting', name: 'Rate Limiting Scanner', enabled: true },
  { id: 'ssrf', name: 'SSRF Scanner', enabled: true },
  { id: 'compliance', name: 'Compliance Scanner', enabled: true },
];

class ScanStore {
  private scans: StoredScan[] = [];

  add(result: ScanResult, serverName: string): void {
    this.scans.push({ result, serverName, storedAt: new Date() });
  }

  getById(id: string): StoredScan | undefined {
    return this.scans.find((s) => s.result.id === id);
  }

  all(): StoredScan[] {
    return this.scans;
  }

  /** Count of scans whose timestamp falls on the given date (YYYY-MM-DD). */
  countByDate(dateStr: string): number {
    return this.scans.filter((s) => s.result.timestamp.toISOString().slice(0, 10) === dateStr)
      .length;
  }

  /** Total vulnerabilities across all stored scans. */
  totalVulnerabilities(): number {
    return this.scans.reduce((sum, s) => sum + s.result.vulnerabilities.length, 0);
  }

  /** Count of CRITICAL severity findings across all stored scans. */
  totalCritical(): number {
    return this.scans.reduce(
      (sum, s) => sum + s.result.vulnerabilities.filter((v) => v.severity === 'CRITICAL').length,
      0,
    );
  }

  /** Unique server names across all stored scans. */
  uniqueServers(): number {
    const servers = new Set(this.scans.map((s) => s.serverName));
    return servers.size;
  }

  /** Average compliance score (summary.score) across all scans, or 100 if none. */
  averageScore(): number {
    if (this.scans.length === 0) return 100;
    const total = this.scans.reduce((sum, s) => sum + s.result.summary.score, 0);
    return Math.round(total / this.scans.length);
  }

  /** Returns daily scan/vulnerability counts for the last 7 days. */
  dailyTrends(): { date: string; scans: number; vulnerabilities: number }[] {
    const days: { date: string; scans: number; vulnerabilities: number }[] = [];
    const now = new Date();
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().slice(0, 10);
      const dayscans = this.scans.filter(
        (s) => s.result.timestamp.toISOString().slice(0, 10) === dateStr,
      );
      days.push({
        date: dateStr,
        scans: dayscans.length,
        vulnerabilities: dayscans.reduce((sum, s) => sum + s.result.vulnerabilities.length, 0),
      });
    }
    return days;
  }
}

const ScanRequestSchema = z.object({
  config: z.any(),
  options: z
    .object({
      depth: z.enum(['quick', 'standard', 'comprehensive']).optional(),
      excludeTypes: z.array(z.string()).optional(),
      includeCompliance: z.boolean().optional(),
    })
    .optional(),
});

const FixRequestSchema = z.object({
  config: z.any(),
  apply: z.boolean().optional(),
});

// ---- Fix proposal generation ------------------------------------------------

interface FixProposal {
  category: 'secrets' | 'permissions' | 'tools' | 'transport' | 'hygiene';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  detail: string;
  automated: boolean;
}

const TRANSPORT_VULN_TYPES = new Set(['INSECURE_TRANSMISSION', 'CORS_MISCONFIGURATION']);

function buildProposals(vulnerabilities: Vulnerability[]): FixProposal[] {
  const proposals: FixProposal[] = [];
  const handled = new Set<string>();

  for (const vuln of vulnerabilities) {
    // Exposed API keys — propose env-var extraction
    if (vuln.type === 'EXPOSED_API_KEY') {
      const locationHint = vuln.location?.path ?? vuln.server;
      proposals.push({
        category: 'secrets',
        severity: vuln.severity as FixProposal['severity'],
        description: `Replace hardcoded secret at ${locationHint}`,
        detail: 'Current value will be replaced with ${ENV_VAR} placeholder',
        automated: true,
      });
      handled.add(vuln.id);
      continue;
    }

    // Auth hardening
    if (vuln.type === 'MISSING_AUTHENTICATION' || vuln.type === 'WEAK_AUTHENTICATION') {
      proposals.push({
        category: 'tools',
        severity: vuln.severity as FixProposal['severity'],
        description: `Harden authentication for ${vuln.server}`,
        detail: vuln.remediation.description,
        automated: false,
      });
      handled.add(vuln.id);
      continue;
    }

    // Transport / SSE-related issues
    if (
      TRANSPORT_VULN_TYPES.has(vuln.type) ||
      vuln.title.toLowerCase().includes('sse') ||
      vuln.description.toLowerCase().includes('sse')
    ) {
      proposals.push({
        category: 'transport',
        severity: vuln.severity as FixProposal['severity'],
        description: `Migrate transport for ${vuln.server}`,
        detail: vuln.remediation.description,
        automated: false,
      });
      handled.add(vuln.id);
      continue;
    }
  }

  // Remaining vulnerabilities with automated remediation
  for (const vuln of vulnerabilities) {
    if (handled.has(vuln.id)) continue;
    if (!vuln.remediation.automated) continue;

    proposals.push({
      category: 'hygiene',
      severity: vuln.severity as FixProposal['severity'],
      description: vuln.title,
      detail: vuln.remediation.description,
      automated: true,
    });
  }

  return proposals;
}

export async function buildApp(opts: { logger?: boolean } = {}): Promise<FastifyInstance> {
  const fastify = Fastify({ logger: opts.logger ?? true });

  const logger: Logger = {
    debug: (msg) => fastify.log.debug(msg),
    info: (msg) => fastify.log.info(msg),
    warn: (msg) => fastify.log.warn(msg),
    error: (msg) => fastify.log.error(msg),
  };
  const mcpGuard = new MCPGuard({ logger });
  const scanStore = new ScanStore();

  await fastify.register(cors, { origin: true, credentials: true });

  await fastify.register(swagger, {
    openapi: {
      info: {
        title: 'MCP-Guard API',
        description: 'Security scanning API for MCP servers',
        version: '1.0.0',
      },
      servers: [{ url: 'http://localhost:3001', description: 'Development server' }],
    },
  });

  await fastify.register(swaggerUI, {
    routePrefix: '/docs',
    uiConfig: { docExpansion: 'list', deepLinking: false },
  });

  await fastify.register(websocket);

  // Routes
  fastify.get('/health', async () => {
    return { status: 'healthy', timestamp: new Date().toISOString() };
  });

  fastify.post(
    '/api/scan',
    {
      schema: {
        body: {
          type: 'object',
          properties: {
            config: { type: 'object' },
            options: {
              type: 'object',
              properties: {
                depth: { type: 'string', enum: ['quick', 'standard', 'comprehensive'] },
                excludeTypes: { type: 'array', items: { type: 'string' } },
                includeCompliance: { type: 'boolean' },
              },
            },
          },
          required: ['config'],
        },
      },
    },
    async (request, reply) => {
      try {
        const { config, options } = ScanRequestSchema.parse(request.body);

        const result =
          options?.depth === 'comprehensive'
            ? await mcpGuard.comprehensiveScan(config)
            : options?.depth === 'quick'
              ? await mcpGuard.quickScan(config)
              : await mcpGuard.scan(
                  config,
                  options ? ({ ...options, depth: options.depth || 'standard' } as any) : undefined,
                );

        // Store scan result for stats and history
        const serverName = (config as any)?.metadata?.name ?? (config as any)?.command ?? 'unknown';
        scanStore.add(result, serverName);

        return { success: true, result };
      } catch (error) {
        return reply.code(400).send({
          success: false,
          error: error instanceof Error ? error.message : 'Scan failed',
        });
      }
    },
  );

  fastify.get('/api/results/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const stored = scanStore.getById(id);
    if (stored) {
      return { id, status: 'completed', result: stored.result };
    }
    return { id, status: 'not_found' };
  });

  fastify.post(
    '/api/fix',
    {
      schema: {
        body: {
          type: 'object',
          properties: {
            config: { type: 'object' },
            apply: { type: 'boolean' },
          },
          required: ['config'],
        },
      },
    },
    async (request, reply) => {
      try {
        const { config } = FixRequestSchema.parse(request.body);

        if (!config) {
          return reply.code(400).send({
            success: false,
            error: 'config is required',
          });
        }

        const scanResult = await mcpGuard.scan(config);
        const proposals = buildProposals(scanResult.vulnerabilities);

        const automated = proposals.filter((p) => p.automated).length;

        return {
          success: true,
          proposals,
          summary: {
            total: proposals.length,
            automated,
            manual: proposals.length - automated,
          },
          scanResult,
        };
      } catch (error) {
        return reply.code(400).send({
          success: false,
          error: error instanceof Error ? error.message : 'Fix failed',
        });
      }
    },
  );

  fastify.get('/api/stats', async () => {
    const today = new Date().toISOString().slice(0, 10);
    return {
      scansToday: scanStore.countByDate(today),
      vulnerabilitiesFound: scanStore.totalVulnerabilities(),
      criticalIssues: scanStore.totalCritical(),
      serversMonitored: scanStore.uniqueServers(),
      complianceScore: scanStore.averageScore(),
      trends: {
        daily: scanStore.dailyTrends(),
      },
    };
  });

  fastify.get('/api/scanners', async () => {
    return { scanners: SCANNER_REGISTRY };
  });

  fastify.register(async function (fastify) {
    fastify.get('/ws', { websocket: true }, (socket, req) => {
      socket.on('message', (message: Buffer) => {
        const data = JSON.parse(message.toString());

        if (data.type === 'subscribe') {
          const interval = setInterval(() => {
            socket.send(
              JSON.stringify({
                type: 'update',
                data: {
                  timestamp: new Date().toISOString(),
                  activeScans: Math.floor(Math.random() * 5),
                  recentVulnerability: {
                    severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'][Math.floor(Math.random() * 4)],
                    scanner: 'api-keys',
                    server: 'server-' + Math.floor(Math.random() * 10),
                  },
                },
              }),
            );
          }, 5000);

          socket.on('close', () => {
            clearInterval(interval);
          });
        }
      });

      socket.send(
        JSON.stringify({
          type: 'connected',
          message: 'Connected to MCP-Guard WebSocket',
        }),
      );
    });
  });

  return fastify;
}

const start = async () => {
  try {
    const app = await buildApp();
    const port = parseInt(process.env.PORT || '3001');
    await app.listen({ port, host: '0.0.0.0' });
    console.log(`API server running at http://localhost:${port}`);
    console.log(`API documentation at http://localhost:${port}/docs`);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
};

const isMainModule =
  require.main === module ||
  process.argv[1]?.endsWith('/api/dist/index.js') ||
  process.argv[1]?.endsWith('/api/src/index.ts');

if (isMainModule) {
  start();
}

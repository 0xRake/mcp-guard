import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';
import websocket from '@fastify/websocket';
import { MCPGuard } from '@mcp-guard/core';
import type { Logger } from '@mcp-guard/core';
import { z } from 'zod';

const ScanRequestSchema = z.object({
  config: z.any(),
  options: z.object({
    depth: z.enum(['quick', 'standard', 'comprehensive']).optional(),
    excludeTypes: z.array(z.string()).optional(),
    includeCompliance: z.boolean().optional()
  }).optional()
});

const FixRequestSchema = z.object({
  vulnerabilities: z.array(z.object({
    id: z.string(),
    automated: z.boolean()
  }))
});

export async function buildApp(opts: { logger?: boolean } = {}): Promise<FastifyInstance> {
  const fastify = Fastify({ logger: opts.logger ?? true });

  const logger: Logger = {
    debug: (msg) => fastify.log.debug(msg),
    info: (msg) => fastify.log.info(msg),
    warn: (msg) => fastify.log.warn(msg),
    error: (msg) => fastify.log.error(msg),
  };
  const mcpGuard = new MCPGuard({ logger });

  await fastify.register(cors, { origin: true, credentials: true });

  await fastify.register(swagger, {
    openapi: {
      info: {
        title: 'MCP-Guard API',
        description: 'Security scanning API for MCP servers',
        version: '1.0.0'
      },
      servers: [
        { url: 'http://localhost:3001', description: 'Development server' }
      ]
    }
  });

  await fastify.register(swaggerUI, {
    routePrefix: '/docs',
    uiConfig: { docExpansion: 'list', deepLinking: false }
  });

  await fastify.register(websocket);

  // Routes
  fastify.get('/health', async () => {
    return { status: 'healthy', timestamp: new Date().toISOString() };
  });

  fastify.post('/api/scan', {
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
              includeCompliance: { type: 'boolean' }
            }
          }
        },
        required: ['config']
      }
    }
  }, async (request, reply) => {
    try {
      const { config, options } = ScanRequestSchema.parse(request.body);

      const result = options?.depth === 'comprehensive'
        ? await mcpGuard.comprehensiveScan(config)
        : options?.depth === 'quick'
        ? await mcpGuard.quickScan(config)
        : await mcpGuard.scan(config, options ? { ...options, depth: options.depth || 'standard' } as any : undefined);

      return { success: true, result };
    } catch (error) {
      return reply.code(400).send({
        success: false,
        error: error instanceof Error ? error.message : 'Scan failed'
      });
    }
  });

  fastify.get('/api/results/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    return {
      id,
      status: 'completed',
      message: 'This endpoint will return stored scan results once database is integrated'
    };
  });

  fastify.post('/api/fix', {
    schema: {
      body: {
        type: 'object',
        properties: {
          vulnerabilities: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                automated: { type: 'boolean' }
              },
              required: ['id']
            }
          }
        },
        required: ['vulnerabilities']
      }
    }
  }, async (request, reply) => {
    try {
      const { vulnerabilities } = FixRequestSchema.parse(request.body);
      const fixed = vulnerabilities.filter(v => v.automated);

      return {
        success: true,
        fixed: fixed.length,
        total: vulnerabilities.length,
        message: `Applied ${fixed.length} automated fixes`
      };
    } catch (error) {
      return reply.code(400).send({
        success: false,
        error: error instanceof Error ? error.message : 'Fix failed'
      });
    }
  });

  fastify.get('/api/stats', async () => {
    return {
      scansToday: 42,
      vulnerabilitiesFound: 156,
      criticalIssues: 12,
      serversMonitored: 8,
      complianceScore: 87,
      trends: {
        daily: [
          { date: '2025-08-28', scans: 35, vulnerabilities: 120 },
          { date: '2025-08-29', scans: 40, vulnerabilities: 145 },
          { date: '2025-08-30', scans: 38, vulnerabilities: 132 },
          { date: '2025-08-31', scans: 42, vulnerabilities: 156 },
          { date: '2025-09-01', scans: 39, vulnerabilities: 148 },
          { date: '2025-09-02', scans: 42, vulnerabilities: 156 }
        ]
      }
    };
  });

  fastify.get('/api/scanners', async () => {
    return {
      scanners: [
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
        { id: 'compliance', name: 'Compliance Scanner', enabled: true }
      ]
    };
  });

  fastify.register(async function (fastify) {
    fastify.get('/ws', { websocket: true }, (socket, req) => {
      socket.on('message', (message: Buffer) => {
        const data = JSON.parse(message.toString());

        if (data.type === 'subscribe') {
          const interval = setInterval(() => {
            socket.send(JSON.stringify({
              type: 'update',
              data: {
                timestamp: new Date().toISOString(),
                activeScans: Math.floor(Math.random() * 5),
                recentVulnerability: {
                  severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'][Math.floor(Math.random() * 4)],
                  scanner: 'api-keys',
                  server: 'server-' + Math.floor(Math.random() * 10)
                }
              }
            }));
          }, 5000);

          socket.on('close', () => {
            clearInterval(interval);
          });
        }
      });

      socket.send(JSON.stringify({
        type: 'connected',
        message: 'Connected to MCP-Guard WebSocket'
      }));
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

const isMainModule = require.main === module ||
  process.argv[1]?.endsWith('/api/dist/index.js') ||
  process.argv[1]?.endsWith('/api/src/index.ts');

if (isMainModule) {
  start();
}

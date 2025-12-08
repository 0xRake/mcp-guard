import Fastify from 'fastify';
import cors from '@fastify/cors';
import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';
import websocket from '@fastify/websocket';
import { MCPGuard } from '@mcp-guard/core';
import { z } from 'zod';

const fastify = Fastify({
  logger: true
});

// Initialize MCP-Guard
const mcpGuard = new MCPGuard();

// Register plugins
fastify.register(cors, {
  origin: true,
  credentials: true
});

fastify.register(swagger, {
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

fastify.register(swaggerUI, {
  routePrefix: '/docs',
  uiConfig: {
    docExpansion: 'list',
    deepLinking: false
  }
});

fastify.register(websocket);

// Schemas
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

// Routes
fastify.get('/health', async () => {
  return { status: 'healthy', timestamp: new Date().toISOString() };
});

// POST /api/scan - Trigger a security scan
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
    
    // Perform scan
    const result = options?.depth === 'comprehensive' 
      ? await mcpGuard.comprehensiveScan(config)
      : options?.depth === 'quick'
      ? await mcpGuard.quickScan(config)
      : await mcpGuard.scan(config, options);
    
    return {
      success: true,
      result
    };
  } catch (error) {
    return reply.code(400).send({
      success: false,
      error: error instanceof Error ? error.message : 'Scan failed'
    });
  }
});

// GET /api/results/:id - Get scan results (placeholder for future DB integration)
fastify.get('/api/results/:id', async (request, reply) => {
  const { id } = request.params as { id: string };
  
  // In a real implementation, this would fetch from a database
  return {
    id,
    status: 'completed',
    message: 'This endpoint will return stored scan results once database is integrated'
  };
});

// POST /api/fix - Apply automated fixes
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
    
    // In a real implementation, this would apply fixes
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

// GET /api/stats - Get dashboard statistics
fastify.get('/api/stats', async () => {
  // Mock statistics - in production, this would query a database
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

// GET /api/scanners - List available scanners
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

// WebSocket endpoint for real-time updates
fastify.register(async function (fastify) {
  fastify.get('/ws', { websocket: true }, (connection, req) => {
    connection.socket.on('message', (message) => {
      const data = JSON.parse(message.toString());
      
      if (data.type === 'subscribe') {
        // Send mock real-time updates
        const interval = setInterval(() => {
          connection.socket.send(JSON.stringify({
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
        
        connection.socket.on('close', () => {
          clearInterval(interval);
        });
      }
    });
    
    // Send welcome message
    connection.socket.send(JSON.stringify({
      type: 'connected',
      message: 'Connected to MCP-Guard WebSocket'
    }));
  });
});

// Start server
const start = async () => {
  try {
    const port = parseInt(process.env.PORT || '3001');
    await fastify.listen({ port, host: '0.0.0.0' });
    console.log(`🚀 API server running at http://localhost:${port}`);
    console.log(`📚 API documentation at http://localhost:${port}/docs`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
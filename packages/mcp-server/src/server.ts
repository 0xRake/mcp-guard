#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from '@modelcontextprotocol/sdk/types.js';
import { 
  createStdioTransport, 
  createWebSocketTransport,
  TransportType 
} from './transport/index.js';
import { 
  scanConfigTool,
  checkVulnerabilitiesTool,
  monitorTrafficTool,
  generateReportTool
} from './tools/index.js';
import type { MCPServerConfig } from '@mcp-guard/core';

// Parse command line arguments
const args = process.argv.slice(2);
const transportType = args.includes('--websocket') ? TransportType.WEBSOCKET : TransportType.STDIO;
const port = args.includes('--port') ? parseInt(args[args.indexOf('--port') + 1]) : 8080;

// Tool definitions with proper MCP schema
const TOOLS: Tool[] = [
  {
    name: 'scan_config',
    description: 'Scan MCP server configuration for security vulnerabilities',
    inputSchema: {
      type: 'object',
      properties: {
        config: {
          type: 'object',
          description: 'MCP server configuration to scan',
          required: true
        },
        depth: {
          type: 'string',
          enum: ['quick', 'standard', 'comprehensive', 'paranoid'],
          description: 'Scan depth level',
          default: 'standard'
        }
      },
      required: ['config']
    }
  },
  {
    name: 'check_vulnerabilities',
    description: 'Check for specific vulnerability types in configuration',
    inputSchema: {
      type: 'object',
      properties: {
        config: {
          type: 'object',
          description: 'Configuration to check',
          required: true
        },
        types: {
          type: 'array',
          items: {
            type: 'string',
            enum: [
              'api-keys',
              'authentication',
              'command-injection',
              'tool-poisoning',
              'data-exfiltration',
              'prompt-injection',
              'oauth-security',
              'confused-deputy',
              'rate-limiting',
              'ssrf',
              'compliance'
            ]
          },
          description: 'Vulnerability types to check'
        }
      },
      required: ['config']
    }
  },
  {
    name: 'monitor_traffic',
    description: 'Monitor real-time traffic and detect anomalies',
    inputSchema: {
      type: 'object',
      properties: {
        config: {
          type: 'object',
          description: 'Configuration to monitor',
          required: true
        },
        interval: {
          type: 'number',
          description: 'Monitoring interval in milliseconds',
          default: 5000
        },
        metrics: {
          type: 'array',
          items: {
            type: 'string'
          },
          description: 'Metrics to track',
          default: ['all']
        }
      },
      required: ['config']
    }
  },
  {
    name: 'generate_report',
    description: 'Generate security report for MCP configuration',
    inputSchema: {
      type: 'object',
      properties: {
        config: {
          type: 'object',
          description: 'Configuration to analyze',
          required: true
        },
        format: {
          type: 'string',
          enum: ['json', 'markdown', 'html', 'sarif', 'pdf'],
          description: 'Report format',
          default: 'json'
        },
        includeRemediation: {
          type: 'boolean',
          description: 'Include remediation steps',
          default: true
        },
        includeCompliance: {
          type: 'boolean',
          description: 'Include compliance checks',
          default: false
        }
      },
      required: ['config']
    }
  }
];

// Create and configure the MCP server
async function createMCPServer(): Promise<Server> {
  const server = new Server(
    {
      name: 'mcp-guard',
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Register tool list handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: TOOLS };
  });

  // Register tool execution handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case 'scan_config': {
          const result = await scanConfigTool.execute({
            config: args.config as MCPServerConfig,
            depth: args.depth as any
          });
          
          return {
            content: [{
              type: 'text',
              text: scanConfigTool.formatResult(result)
            }]
          };
        }

        case 'check_vulnerabilities': {
          const vulnerabilities = await checkVulnerabilitiesTool.execute({
            config: args.config as MCPServerConfig,
            types: args.types as string[]
          });
          
          return {
            content: [{
              type: 'text',
              text: checkVulnerabilitiesTool.formatResult(vulnerabilities)
            }]
          };
        }

        case 'monitor_traffic': {
          const sessionId = await monitorTrafficTool.start({
            config: args.config as MCPServerConfig,
            interval: args.interval as number,
            metrics: args.metrics as string[]
          });
          
          // Set up anomaly detection listener
          monitorTrafficTool.on('anomaly-detected', (anomaly) => {
            console.error(`[ANOMALY] ${anomaly.severity}: ${anomaly.message}`);
          });
          
          // Get initial metrics
          const metrics = monitorTrafficTool.getMetrics(sessionId);
          
          return {
            content: [{
              type: 'text',
              text: monitorTrafficTool.formatResult(sessionId, metrics)
            }]
          };
        }

        case 'generate_report': {
          const report = await generateReportTool.execute({
            config: args.config as MCPServerConfig,
            format: args.format as any,
            includeRemediation: args.includeRemediation as boolean,
            includeCompliance: args.includeCompliance as boolean
          });
          
          return {
            content: [{
              type: 'text',
              text: report
            }]
          };
        }

        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Error: ${error instanceof Error ? error.message : String(error)}`
        }],
        isError: true
      };
    }
  });

  return server;
}

// Main entry point
async function main() {
  try {
    console.error('Starting MCP-Guard Security Server...');
    console.error(`Transport: ${transportType}`);
    
    const server = await createMCPServer();
    
    // Start appropriate transport
    if (transportType === TransportType.WEBSOCKET) {
      const wsTransport = createWebSocketTransport(server, port);
      await wsTransport.start();
    } else {
      const stdioTransport = createStdioTransport(server);
      await stdioTransport.start();
    }
    
    // Handle shutdown gracefully
    process.on('SIGINT', async () => {
      console.error('\nShutting down MCP-Guard server...');
      await server.close();
      process.exit(0);
    });
    
    process.on('SIGTERM', async () => {
      console.error('\nShutting down MCP-Guard server...');
      await server.close();
      process.exit(0);
    });
    
  } catch (error) {
    console.error('Fatal error:', error);
    process.exit(1);
  }
}

// Run the server
if (require.main === module) {
  main();
}

export { createMCPServer, TOOLS };
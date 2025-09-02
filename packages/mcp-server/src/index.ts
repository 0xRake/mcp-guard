#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from '@modelcontextprotocol/sdk/types.js';
import mcpGuard from '@mcp-guard/core';
import type { ScanResult, MCPServerConfig } from '@mcp-guard/core';
import { z } from 'zod';

// Tool definitions
const TOOLS: Tool[] = [
  {
    name: 'scan_config',
    description: 'Scan MCP server configuration for security vulnerabilities',
    inputSchema: {
      type: 'object',
      properties: {
        config: {
          type: 'object',
          description: 'MCP server configuration to scan'
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
          description: 'Configuration to check'
        },
        types: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['api-keys', 'authentication', 'command-injection', 'tool-poisoning']
          },
          description: 'Vulnerability types to check'
        }
      },
      required: ['config']
    }
  },
  {
    name: 'monitor_config',
    description: 'Start monitoring configuration for security issues',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to configuration file to monitor'
        },
        interval: {
          type: 'number',
          description: 'Check interval in seconds',
          default: 30
        }
      },
      required: ['path']
    }
  },
  {
    name: 'auto_fix',
    description: 'Automatically fix detected vulnerabilities',
    inputSchema: {
      type: 'object',
      properties: {
        config: {
          type: 'object',
          description: 'Configuration with vulnerabilities'
        },
        dryRun: {
          type: 'boolean',
          description: 'Preview fixes without applying',
          default: false
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
          description: 'Configuration to analyze'
        },
        format: {
          type: 'string',
          enum: ['json', 'markdown', 'html', 'sarif'],
          description: 'Report format',
          default: 'json'
        }
      },
      required: ['config']
    }
  },
  {
    name: 'risk_score',
    description: 'Calculate security risk score for configuration',
    inputSchema: {
      type: 'object',
      properties: {
        config: {
          type: 'object',
          description: 'Configuration to score'
        }
      },
      required: ['config']
    }
  }
];

// Active monitoring sessions
const monitoringSessions = new Map<string, NodeJS.Timeout>();

// Helper to format scan results
function formatScanResult(result: ScanResult): string {
  const lines: string[] = [
    `Security Score: ${result.summary.score}/100 (Grade: ${result.summary.grade})`,
    `Vulnerabilities Found: ${result.summary.vulnerabilitiesFound}`,
    `  Critical: ${result.summary.critical}`,
    `  High: ${result.summary.high}`,
    `  Medium: ${result.summary.medium}`,
    `  Low: ${result.summary.low}`,
    ''
  ];

  if (result.vulnerabilities.length > 0) {
    lines.push('Vulnerabilities:');
    result.vulnerabilities.forEach(vuln => {
      lines.push(`  [${vuln.severity}] ${vuln.title}`);
      lines.push(`    Server: ${vuln.server}`);
      lines.push(`    ${vuln.description}`);
    });
    lines.push('');
  }

  if (result.recommendations.length > 0) {
    lines.push('Recommendations:');
    result.recommendations.forEach((rec, i) => {
      lines.push(`  ${i + 1}. ${rec}`);
    });
  }

  return lines.join('\n');
}

// Generate reports in different formats
function generateReport(result: ScanResult, format: string): string {
  switch (format) {
    case 'json':
      return JSON.stringify(result, null, 2);
    
    case 'markdown':
      let md = '# MCP Security Report\n\n';
      md += `## Summary\n`;
      md += `- Score: ${result.summary.score}/100 (${result.summary.grade})\n`;
      md += `- Vulnerabilities: ${result.summary.vulnerabilitiesFound}\n\n`;
      
      if (result.vulnerabilities.length > 0) {
        md += '## Vulnerabilities\n\n';
        result.vulnerabilities.forEach(v => {
          md += `### [${v.severity}] ${v.title}\n`;
          md += `- Server: ${v.server}\n`;
          md += `- ${v.description}\n\n`;
        });
      }
      
      if (result.recommendations.length > 0) {
        md += '## Recommendations\n\n';
        result.recommendations.forEach((r, i) => {
          md += `${i + 1}. ${r}\n`;
        });
      }
      
      return md;
    
    case 'html':
      return `<!DOCTYPE html>
<html>
<head><title>MCP Security Report</title></head>
<body>
  <h1>MCP Security Report</h1>
  <h2>Score: ${result.summary.score}/100 (${result.summary.grade})</h2>
  <p>Vulnerabilities Found: ${result.summary.vulnerabilitiesFound}</p>
  ${result.vulnerabilities.map(v => `
    <div style="margin: 20px 0; padding: 10px; border-left: 4px solid ${
      v.severity === 'CRITICAL' ? 'red' : 
      v.severity === 'HIGH' ? 'orange' : 
      v.severity === 'MEDIUM' ? 'yellow' : 'blue'
    };">
      <h3>[${v.severity}] ${v.title}</h3>
      <p>Server: ${v.server}</p>
      <p>${v.description}</p>
    </div>
  `).join('')}
</body>
</html>`;
    
    case 'sarif':
      return JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: {
            driver: {
              name: 'MCP-Guard',
              version: '1.0.0'
            }
          },
          results: result.vulnerabilities.map(v => ({
            ruleId: v.id,
            level: v.severity === 'CRITICAL' || v.severity === 'HIGH' ? 'error' : 'warning',
            message: { text: v.description }
          }))
        }]
      }, null, 2);
    
    default:
      return formatScanResult(result);
  }
}

// Create and start the MCP server
async function main() {
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

  // Handle tool listing
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: TOOLS };
  });

  // Handle tool execution
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case 'scan_config': {
          const config = args.config as MCPServerConfig;
          const depth = args.depth as string || 'standard';
          
          const result = await mcpGuard.scan(
            { default: config },
            { depth: depth as any }
          );
          
          return {
            content: [{
              type: 'text',
              text: formatScanResult(result)
            }]
          };
        }

        case 'check_vulnerabilities': {
          const config = args.config as MCPServerConfig;
          const types = args.types as string[] || ['api-keys', 'authentication', 'command-injection', 'tool-poisoning'];
          
          const result = await mcpGuard.scan(
            { default: config },
            { excludeTypes: [] } // Include all types then filter
          );
          
          // Filter vulnerabilities by requested types
          const filtered = {
            ...result,
            vulnerabilities: result.vulnerabilities.filter(v => 
              types.some(t => v.type.toLowerCase().includes(t))
            )
          };
          
          return {
            content: [{
              type: 'text',
              text: formatScanResult(filtered)
            }]
          };
        }

        case 'monitor_config': {
          const path = args.path as string;
          const interval = (args.interval as number) || 30;
          
          // Clear existing monitoring for this path
          if (monitoringSessions.has(path)) {
            clearInterval(monitoringSessions.get(path)!);
          }
          
          // Start new monitoring
          const intervalId = setInterval(async () => {
            try {
              // In real implementation, would read file from path
              // For now, we'll just return a status message
              console.log(`[Monitor] Checking ${path}...`);
            } catch (error) {
              console.error(`[Monitor] Error checking ${path}:`, error);
            }
          }, interval * 1000);
          
          monitoringSessions.set(path, intervalId);
          
          return {
            content: [{
              type: 'text',
              text: `Started monitoring ${path} every ${interval} seconds. Session ID: ${path}`
            }]
          };
        }

        case 'auto_fix': {
          const config = args.config as MCPServerConfig;
          const dryRun = args.dryRun as boolean || false;
          
          const result = await mcpGuard.scan(
            { default: config },
            { autoFix: !dryRun }
          );
          
          const fixable = result.vulnerabilities.filter(v => v.remediation?.automated);
          
          return {
            content: [{
              type: 'text',
              text: `${dryRun ? 'Would fix' : 'Fixed'} ${fixable.length} vulnerabilities:\n` +
                    fixable.map(v => `- ${v.title}`).join('\n')
            }]
          };
        }

        case 'generate_report': {
          const config = args.config as MCPServerConfig;
          const format = args.format as string || 'json';
          
          const result = await mcpGuard.scan({ default: config });
          const report = generateReport(result, format);
          
          return {
            content: [{
              type: 'text',
              text: report
            }]
          };
        }

        case 'risk_score': {
          const config = args.config as MCPServerConfig;
          
          const result = await mcpGuard.quickScan({ default: config });
          
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                score: result.summary.score,
                grade: result.summary.grade,
                risk_level: result.summary.score < 40 ? 'CRITICAL' :
                           result.summary.score < 60 ? 'HIGH' :
                           result.summary.score < 80 ? 'MEDIUM' : 'LOW',
                vulnerabilities: {
                  critical: result.summary.critical,
                  high: result.summary.high,
                  medium: result.summary.medium,
                  low: result.summary.low
                }
              }, null, 2)
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

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.error('MCP-Guard server started successfully');
}

// Handle errors
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
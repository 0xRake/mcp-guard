import { MCPGuard, createStderrLogger, LogLevel } from '@mcp-guard/core';
import type { MCPServerConfig, ScanResult } from '@mcp-guard/core';

export interface ScanConfigArgs {
  config: MCPServerConfig;
  depth?: 'quick' | 'standard' | 'comprehensive' | 'paranoid';
}

export class ScanConfigTool {
  private mcpGuard: MCPGuard;

  constructor() {
    const logger = createStderrLogger(LogLevel.INFO);
    this.mcpGuard = new MCPGuard({ logger });
  }

  async execute(args: ScanConfigArgs): Promise<ScanResult> {
    const { config, depth = 'standard' } = args;
    
    // Validate config structure
    if (!config || typeof config !== 'object') {
      throw new Error('Invalid configuration object');
    }

    // Perform the scan based on depth
    let result: ScanResult;
    
    switch (depth) {
      case 'quick':
        result = await this.mcpGuard.quickScan({ default: config });
        break;
      case 'comprehensive':
        result = await this.mcpGuard.comprehensiveScan({ default: config });
        break;
      case 'paranoid':
        // Run comprehensive scan with all checks enabled
        result = await this.mcpGuard.scan(
          { default: config },
          { 
            depth: 'comprehensive',
            includeCompliance: true,
            excludeTypes: []
          }
        );
        break;
      default:
        result = await this.mcpGuard.scan({ default: config });
    }

    return result;
  }

  formatResult(result: ScanResult): string {
    const lines: string[] = [
      `🛡️ Security Scan Results`,
      `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
      `Score: ${result.summary.score}/100 (${result.summary.grade})`,
      `Total Issues: ${result.summary.vulnerabilitiesFound}`,
      `  • Critical: ${result.summary.critical}`,
      `  • High: ${result.summary.high}`,
      `  • Medium: ${result.summary.medium}`,
      `  • Low: ${result.summary.low}`,
      ''
    ];

    if (result.vulnerabilities.length > 0) {
      lines.push('Vulnerabilities Found:');
      lines.push('─────────────────────');
      
      result.vulnerabilities.forEach((vuln, index) => {
        lines.push(`${index + 1}. [${vuln.severity}] ${vuln.title}`);
        lines.push(`   Location: ${vuln.server}`);
        lines.push(`   ${vuln.description}`);
        if (vuln.remediation) {
          lines.push(`   Fix: ${vuln.remediation.description}`);
        }
        lines.push('');
      });
    }

    if (result.recommendations.length > 0) {
      lines.push('Recommendations:');
      lines.push('───────────────');
      result.recommendations.forEach((rec, index) => {
        lines.push(`${index + 1}. ${rec}`);
      });
    }

    return lines.join('\n');
  }
}

export const scanConfigTool = new ScanConfigTool();
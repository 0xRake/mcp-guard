import { MCPGuard } from '@mcp-guard/core';
import type { MCPServerConfig, ScanResult, Vulnerability } from '@mcp-guard/core';

export interface CheckVulnerabilitiesArgs {
  config: MCPServerConfig;
  types?: string[];
}

export class CheckVulnerabilitiesChuiTool {
  private mcpGuard: MCPGuard;
  
  private validTypes = [
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
  ];

  constructor() {
    this.mcpGuard = new MCPGuard();
  }

  async execute(args: CheckVulnerabilitiesArgs): Promise<Vulnerability[]> {
    const { config, types = this.validTypes } = args;
    
    // Validate config
    if (!config || typeof config !== 'object') {
      throw new Error('Invalid configuration object');
    }

    // Validate types
    const invalidTypes = types.filter(t => !this.validTypes.includes(t));
    if (invalidTypes.length > 0) {
      throw new Error(`Invalid vulnerability types: ${invalidTypes.join(', ')}`);
    }

    // Run targeted scan
    const result = await this.mcpGuard.scan(
      { default: config },
      { 
        excludeTypes: this.validTypes.filter(t => !types.includes(t))
      }
    );

    // Filter vulnerabilities by requested types
    return result.vulnerabilities.filter(vuln => {
      const vulnType = vuln.type.toLowerCase().replace(/_/g, '-');
      return types.some(type => vulnType.includes(type));
    });
  }

  formatResult(vulnerabilities: Vulnerability[]): string {
    if (vulnerabilities.length === 0) {
      return '✅ No vulnerabilities found for the specified types';
    }

    const lines: string[] = [
      `🔍 Vulnerability Check Results`,
      `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
      `Found ${vulnerabilities.length} vulnerabilities`,
      ''
    ];

    // Group by type
    const byType = vulnerabilities.reduce((acc, vuln) => {
      const type = vuln.type;
      if (!acc[type]) acc[type] = [];
      acc[type].push(vuln);
      return acc;
    }, {} as Record<string, Vulnerability[]>);

    Object.entries(byType).forEach(([type, vulns]) => {
      lines.push(`${type} (${vulns.length} issues):`);
      lines.push('─'.repeat(30));
      
      vulns.forEach(vuln => {
        lines.push(`  [${vuln.severity}] ${vuln.title}`);
        lines.push(`    ${vuln.description}`);
        if (vuln.remediation?.automated) {
          lines.push(`    ✓ Automated fix available`);
        }
      });
      lines.push('');
    });

    return lines.join('\n');
  }
}

export const checkVulnerabilitiesTool = new CheckVulnerabilitiesChuiTool();
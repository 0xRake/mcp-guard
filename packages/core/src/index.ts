/**
 * MCP-Guard Core - Security scanning engine for MCP servers
 */

// Export all types
export * from './types';

// Export scanners
export { APIKeyScanner } from './scanners/api-keys';
export { AuthenticationScanner } from './scanners/authentication';
export { CommandInjectionScanner } from './scanners/command-injection';
export { ToolPoisoningScanner } from './scanners/tool-poisoning';

// Scanner registry
import { APIKeyScanner } from './scanners/api-keys';
import { AuthenticationScanner } from './scanners/authentication';
import { CommandInjectionScanner } from './scanners/command-injection';
import { ToolPoisoningScanner } from './scanners/tool-poisoning';
import type { Scanner, MCPServerConfig, ScanConfig, ScanResult, Vulnerability } from './types';

export class MCPGuard {
  private scanners: Scanner[] = [];
  
  constructor() {
    // Register default scanners
    this.registerScanner(new APIKeyScanner());
    this.registerScanner(new AuthenticationScanner());
    this.registerScanner(new CommandInjectionScanner());
    this.registerScanner(new ToolPoisoningScanner());
  }

  /**
   * Register a new scanner
   */
  registerScanner(scanner: Scanner): void {
    if (scanner.enabled) {
      this.scanners.push(scanner);
      console.log(`✓ Registered scanner: ${scanner.name} v${scanner.version}`);
    }
  }

  /**
   * Scan MCP server configuration for vulnerabilities
   */
  async scan(config: MCPServerConfig | Record<string, MCPServerConfig>, options?: ScanConfig): Promise<ScanResult> {
    const startTime = Date.now();
    const scanId = this.generateScanId();
    const allVulnerabilities: Vulnerability[] = [];
    
    // Handle both single server and multiple servers
    const configs = this.isMultiServerConfig(config) 
      ? Object.entries(config as Record<string, MCPServerConfig>)
      : [['default', config as MCPServerConfig]];

    console.log(`🔍 Starting security scan on ${configs.length} server(s)...`);

    // Run all scanners on each configuration
    for (const [serverName, serverConfig] of configs) {
      // Add server name to metadata if not present
      if (typeof serverConfig === 'object' && serverConfig !== null) {
        if (!serverConfig.metadata) {
          serverConfig.metadata = {};
        }
        if (!serverConfig.metadata.name && typeof serverName === 'string') {
          serverConfig.metadata.name = serverName;
        }

        for (const scanner of this.scanners) {
          if (!options?.excludeTypes?.includes(scanner.name as any)) {
            try {
              const vulnerabilities = await scanner.scan(serverConfig, options);
              allVulnerabilities.push(...vulnerabilities);
            } catch (error) {
              console.error(`❌ Scanner ${scanner.name} failed:`, error);
            }
          }
        }
      }
    }

    const duration = Date.now() - startTime;
    const summary = this.calculateSummary(allVulnerabilities, configs.length);
    
    return {
      id: scanId,
      timestamp: new Date(),
      duration,
      config: options || { depth: 'standard' },
      summary,
      vulnerabilities: allVulnerabilities,
      metadata: {
        scanner: 'mcp-guard',
        version: '1.0.0',
        signatures: new Date().toISOString(),
        rules: this.scanners.length
      },
      recommendations: this.generateRecommendations(allVulnerabilities)
    };
  }

  /**
   * Quick scan with minimal configuration
   */
  async quickScan(config: MCPServerConfig | Record<string, MCPServerConfig>): Promise<ScanResult> {
    return this.scan(config, { depth: 'quick' });
  }

  /**
   * Comprehensive scan with all checks
   */
  async comprehensiveScan(config: MCPServerConfig | Record<string, MCPServerConfig>): Promise<ScanResult> {
    return this.scan(config, { 
      depth: 'comprehensive',
      includeCompliance: true 
    });
  }

  private isMultiServerConfig(config: any): boolean {
    // Check if it's a multi-server config (like Claude Desktop format)
    return config.mcpServers || (!config.command && Object.values(config).some((v: any) => v.command));
  }

  private generateScanId(): string {
    return `scan-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  }

  private calculateSummary(vulnerabilities: Vulnerability[], serversScanned: number) {
    const critical = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const high = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const medium = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const low = vulnerabilities.filter(v => v.severity === 'LOW').length;
    const info = vulnerabilities.filter(v => v.severity === 'INFO').length;

    // Calculate score (0-100, where 100 is perfect)
    let score = 100;
    score -= critical * 20;
    score -= high * 10;
    score -= medium * 5;
    score -= low * 2;
    score = Math.max(0, score);

    // Calculate grade
    let grade: 'A' | 'B' | 'C' | 'D' | 'F';
    if (score >= 90) grade = 'A';
    else if (score >= 80) grade = 'B';
    else if (score >= 70) grade = 'C';
    else if (score >= 60) grade = 'D';
    else grade = 'F';

    return {
      score,
      grade,
      serversScanned,
      vulnerabilitiesFound: vulnerabilities.length,
      critical,
      high,
      medium,
      low,
      info
    };
  }

  private generateRecommendations(vulnerabilities: Vulnerability[]): string[] {
    const recommendations: string[] = [];
    
    if (vulnerabilities.some(v => v.type === 'EXPOSED_API_KEY')) {
      recommendations.push('Move all API keys and secrets to environment variables or a secure vault');
    }
    
    if (vulnerabilities.some(v => v.severity === 'CRITICAL')) {
      recommendations.push('Address all CRITICAL vulnerabilities immediately before deployment');
    }

    if (vulnerabilities.length === 0) {
      recommendations.push('Great job! No vulnerabilities detected. Continue monitoring regularly.');
    }

    return recommendations;
  }
}

// Export default instance
const mcpGuard = new MCPGuard();
export default mcpGuard;

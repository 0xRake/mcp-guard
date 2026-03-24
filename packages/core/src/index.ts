/**
 * MCP-Guard Core - Security scanning engine for MCP servers
 */

// Export all types
export * from './types';

// Export new consolidated domains
export { DataProtectionDomain } from './domains/data-protection';
export { ExecutionControlDomain } from './domains/execution-control';
export { IdentityAccessControlDomain } from './domains/identity-access-control';
export { ConfigurationAssuranceDomain } from './domains/configuration-assurance';
export { ComplianceGovernanceDomain } from './domains/compliance-governance';

// Export distributed scanning components
export { DistributedScanningManager } from './distributed/distributed-scanner';
export { ScannerWorker } from './distributed/worker/scanner-worker';
export { ConfigurationPartitioner } from './distributed/utils/configuration-partitioner';
export { ResultAggregator } from './distributed/utils/result-aggregator';
export { FaultToleranceManager } from './distributed/utils/fault-tolerance';

// Export distributed interfaces
export * from './distributed/interfaces/distributed-interfaces';

// Export utilities
export * from './utils';

// Export validators
export * from './validators';

// Scanner registry using new consolidated domains
import { DataProtectionDomain } from './domains/data-protection';
import { ExecutionControlDomain } from './domains/execution-control';
import { IdentityAccessControlDomain } from './domains/identity-access-control';
import { ConfigurationAssuranceDomain } from './domains/configuration-assurance';
import { ComplianceGovernanceDomain } from './domains/compliance-governance';
import { DistributedScanningManager } from './distributed/distributed-scanner';
import { createHash } from 'crypto';
import type { Scanner, MCPServerConfig, ScanConfig, ScanResult, Vulnerability } from './types';
import type { Logger } from './utils/logger';
import { noopLogger } from './utils/logger';
import type { DistributedConfig } from './distributed/interfaces/distributed-interfaces';

export interface MCPGuardOptions {
  logger?: Logger;
}

export class MCPGuard {
  private scanners: Scanner[] = [];
  private distributedScanner?: DistributedScanningManager;
  private isDistributed: boolean = false;
  private enterpriseConfig?: DistributedConfig;
  private logger: Logger;

  constructor(options?: MCPGuardOptions) {
    this.logger = options?.logger ?? noopLogger;

    this.registerScanner(new DataProtectionDomain());
    this.registerScanner(new ExecutionControlDomain());
    this.registerScanner(new IdentityAccessControlDomain());
    this.registerScanner(new ConfigurationAssuranceDomain());
    this.registerScanner(new ComplianceGovernanceDomain());

    this.logger.debug(`Initialized with ${this.scanners.length} scanners`);
  }

  /**
   * Register a new scanner
   */
  registerScanner(scanner: Scanner): void {
    if (scanner.enabled) {
      this.scanners.push(scanner);
      this.logger.debug(`Registered scanner: ${scanner.name} v${scanner.version}`);
    }
  }

  /**
   * Initialize distributed scanning for enterprise deployments
   */
  initializeDistributed(config?: Partial<DistributedConfig>): void {
    if (this.isDistributed) {
      return;
    }

    this.distributedScanner = new DistributedScanningManager(config);
    this.isDistributed = true;
    this.enterpriseConfig = config as DistributedConfig;
    
  }

  /**
   * Scan using distributed workers (enterprise mode)
   */
  async distributedScan(
    config: MCPServerConfig | Record<string, MCPServerConfig>, 
    options?: ScanConfig
  ): Promise<ScanResult> {
    if (!this.isDistributed || !this.distributedScanner) {
      throw new Error('Distributed scanning not initialized. Call initializeDistributed() first.');
    }

    // Convert single config to multi-server format
    const serverConfigs = this.isMultiServerConfig(config)
      ? config as Record<string, MCPServerConfig>
      : { 'default': config as MCPServerConfig };

    const startTime = Date.now();
    const scanId = this.generateScanId();


    try {
      // Create distributed scan request
      const distributedResults = await this.distributedScanner.distributeScan({
        id: scanId,
        scanId,
        configurations: Object.entries(serverConfigs).map(([serverName, serverConfig]) => ({
          id: `${serverName}-${Date.now()}`,
          serverName,
          config: serverConfig,
          priority: 'high' as const,
          domains: ['all'],
          partitionKey: serverName,
          fingerprint: `fp-${serverName}`,
          estimatedSize: JSON.stringify(serverConfig).length
        })),
        options: {
          depth: 'comprehensive',
          parallel: true,
          timeout: 60000
        },
        distributedConfig: this.enterpriseConfig!,
        fingerprint: {
          hash: `scan-${createHash('sha256').update(JSON.stringify(serverConfigs)).digest('hex').substring(0, 16)}`,
          timestamp: new Date(),
          serverName: 'distributed',
          configSize: JSON.stringify(serverConfigs).length,
          domains: ['all'],
          checksum: `checksum-${createHash('sha256').update(JSON.stringify(serverConfigs)).digest('hex').substring(0, 16)}`,
          version: '2.0.0'
        },
        priority: 'high',
        createdAt: new Date()
      });

      // Aggregate results
      const allVulnerabilities = distributedResults.flatMap(result => 
        result.vulnerabilities.map(vuln => ({
          ...vuln,
          server: result.serverName
        }))
      );

      const duration = Date.now() - startTime;
      const summary = this.calculateSummary(allVulnerabilities, Object.keys(serverConfigs).length);

      return {
        id: scanId,
        timestamp: new Date(),
        duration,
        config: options || { depth: 'standard' },
        summary,
        vulnerabilities: allVulnerabilities,
        metadata: {
          scanner: 'mcp-guard-distributed',
          version: '2.0.0',
          signatures: new Date().toISOString(),
          rules: this.scanners.length,
          distributed: true,
          workersUsed: distributedResults.length
        } as any,
        recommendations: this.generateRecommendations(allVulnerabilities)
      };
    } catch (error) {
      this.logger.error('Distributed scan failed:', error);
      throw error;
    }
  }

  /**
   * Get distributed scanning status
   */
  getDistributedStatus() {
    if (!this.distributedScanner) {
      return { initialized: false };
    }

    return {
      initialized: true,
      ...this.distributedScanner.getStatus()
    };
  }

  /**
   * Shutdown distributed scanning
   */
  async shutdownDistributed(): Promise<void> {
    if (this.distributedScanner) {
      this.distributedScanner.shutdown();
      this.distributedScanner = undefined;
      this.isDistributed = false;
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

    this.logger.info(`Scan ${scanId}: ${configs.length} server(s), depth=${options?.depth ?? 'standard'}`);

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
              this.logger.error(`Scanner ${scanner.name} failed:`, error);
            }
          }
        }
      }
    }

    const duration = Date.now() - startTime;
    const summary = this.calculateSummary(allVulnerabilities, configs.length);

    this.logger.info(`Scan ${scanId}: completed in ${duration}ms, ${allVulnerabilities.length} findings, score=${summary.score}`);

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

// Export pre-configured instance
export const mcpGuard = new MCPGuard();

/**
 * Scanner Worker Implementation
 * Handles parallel processing of distributed security scans
 */

import { parentPort, workerData, threadId } from 'worker_threads';
import * as crypto from 'crypto';
import { 
  DistributedScanRequest, 
  DistributedScanResult, 
  DistributedConfiguration,
  DistributedVulnerability,
  WorkerMessage,
  WorkerMessageType,
  WorkerResponse,
  WorkerStatus,
  WorkerPerformance,
  FaultToleranceConfig,
  RetryPolicy,
  CheckpointData,
  ScanPerformanceMetrics,
  WorkerMetrics,
  ScanPhase
} from '../interfaces/distributed-interfaces';
import type { 
  ScanConfig, 
  Vulnerability,
  Severity,
  MCPServerConfig
} from '../../types';
import { VulnerabilityType } from '../../types';

export class ScannerWorker {
  private workerId: number;
  private status: WorkerStatus = WorkerStatus.IDLE;
  private currentRequest?: DistributedScanRequest;
  private currentPartition?: string;
  private performance: WorkerPerformance;
  private checkpointData: Map<string, CheckpointData> = new Map();
  private faultTolerance: FaultToleranceConfig;
  private lastHeartbeat: Date = new Date();
  private heartbeatInterval?: NodeJS.Timeout;
  private scanHistory: Date[] = [];
  private processedCount: number = 0;
  private errorCount: number = 0;

  constructor(workerId: number) {
    this.workerId = workerId;
    this.performance = {
      partitionsProcessed: 0,
      averageProcessingTime: 0,
      successRate: 100,
      lastActivity: new Date(),
      errorCount: 0
    };
    
    this.faultTolerance = this.getDefaultFaultToleranceConfig();
    this.initializeMessageHandling();
    this.startHeartbeat();
  }

  private initializeMessageHandling(): void {
    if (!parentPort) {
      throw new Error('Parent port not available');
    }

    parentPort.on('message', async (message: WorkerMessage) => {
      try {
        await this.handleMessage(message);
      } catch (error) {
        await this.handleError(error as Error, message);
      }
    });

    parentPort.on('error', (error) => {
      this.handleFatalError(error);
    });
  }

  private startHeartbeat(): void {

    this.heartbeatInterval = setInterval(() => {
      this.sendHeartbeat();
    }, 30000);
  }

  private sendHeartbeat(): void {
    const metrics = this.getMetrics();
    this.sendMessage(WorkerMessageType.HEARTBEAT, {
      workerId: this.workerId,
      status: this.status,
      metrics,
      lastActivity: this.performance.lastActivity,
      uptime: Date.now() - (this.scanHistory[0] ? new Date(this.scanHistory[0]).getTime() : Date.now())
    });
  }

  private async handleMessage(message: WorkerMessage): Promise<void> {
    this.updateLastActivity();

    switch (message.type) {
      case WorkerMessageType.INITIALIZE:
        await this.handleInitialize(message);
        break;
      
      case WorkerMessageType.SCAN_REQUEST:
        await this.handleScanRequest(message);
        break;
      
      case WorkerMessageType.CHECKPOINT:
        await this.handleCheckpoint(message);
        break;
      
      case WorkerMessageType.RECOVER:
        await this.handleRecovery(message);
        break;
      
      case WorkerMessageType.TERMINATE:
        await this.handleTerminate();
        break;
      
      case WorkerMessageType.STATUS:
        await this.handleStatus(message);
        break;
      
      default:
        throw new Error(`Unknown message type: ${message.type}`);
    }
  }

  private async handleInitialize(message: WorkerMessage): Promise<void> {
    this.status = WorkerStatus.IDLE;
    await this.sendResponse(message.requestId!, true, {
      workerId: this.workerId,
      status: this.status,
      metrics: this.getMetrics(),
      initializedAt: new Date()
    });
  }

  private async handleScanRequest(message: WorkerMessage): Promise<void> {
    if (!message.data) {
      throw new Error('Scan request data is required');
    }

    this.currentRequest = message.data as DistributedScanRequest;
    this.status = WorkerStatus.PROCESSING;
    this.currentPartition = this.currentRequest.id;

    try {
      const startTime = Date.now();
      const results = await this.processPartition(this.currentRequest);
      const executionTime = Date.now() - startTime;

      const scanResult: DistributedScanResult = {
        id: this.generateResultId(),
        requestId: message.requestId!,
        workerId: this.workerId,
        partitionId: this.currentPartition!,
        serverName: results.serverName,
        vulnerabilities: results.vulnerabilities,
        summary: results.summary,
        executionTime,
        timestamp: new Date(),
        fingerprint: this.generateFingerprint(this.currentRequest),
        performance: this.calculatePerformance(executionTime)
      };

      this.updatePerformance(executionTime, true);
      this.processedCount++;

      await this.sendResponse(message.requestId!, true, scanResult);
      this.status = WorkerStatus.IDLE;
      this.currentPartition = undefined;

    } catch (error) {
      this.updatePerformance(0, false);
      this.errorCount++;
      
      if (this.errorCount < this.faultTolerance.maxWorkerRestarts) {
        this.status = WorkerStatus.RECOVERING;
        await this.sendResponse(message.requestId!, false, null, error as Error);
      } else {
        this.status = WorkerStatus.FAILED;
        await this.handleFatalError(error as Error);
      }
    }
  }

  private async processPartition(request: DistributedScanRequest): Promise<{
    serverName: string;
    vulnerabilities: DistributedVulnerability[];
    summary: any;
  }> {
    const results: DistributedVulnerability[] = [];
    let totalScore = 100;
    let critical = 0, high = 0, medium = 0, low = 0, info = 0;

    for (const config of request.configurations) {
      try {
        const scanResult = await this.scanConfiguration(config, request.options);
        
        const distributedVulns = scanResult.map(vuln => ({
          ...vuln,
          partitionId: request.id,
          workerId: this.workerId,
          correlationId: this.generateCorrelationId(vuln),
          duplicates: []
        }));

        results.push(...distributedVulns);

        distributedVulns.forEach(vuln => {
          totalScore -= this.getSeverityScore(vuln.severity);
          switch (vuln.severity) {
            case 'CRITICAL': critical++; break;
            case 'HIGH': high++; break;
            case 'MEDIUM': medium++; break;
            case 'LOW': low++; break;
            default: info++;
          }
        });

      } catch (error) {
        console.error(`Failed to scan ${config.serverName}:`, error);
        this.errorCount++;
      }
    }

    totalScore = Math.max(0, totalScore);

    return {
      serverName: request.configurations[0]?.serverName || 'unknown',
      vulnerabilities: results,
      summary: {
        score: totalScore,
        grade: this.calculateGrade(totalScore),
        critical,
        high,
        medium,
        low,
        info,
        serversScanned: request.configurations.length,
        partitionsProcessed: 1,
        executionTime: 0,
        workerId: this.workerId
      }
    };
  }

  private async scanConfiguration(
    config: DistributedConfiguration, 
    options: ScanConfig
  ): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    if (options.targets?.length) {
      for (const target of options.targets) {
        const vulns = await this.scanTarget(config.config, target, options);
        vulnerabilities.push(...vulns);
      }
    } else {
      const vulns = await this.scanAllTargets(config.config, options);
      vulnerabilities.push(...vulns);
    }

    return vulnerabilities;
  }

  private async scanTarget(
    config: MCPServerConfig, 
    target: string, 
    options: ScanConfig
  ): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    switch (target) {
      case 'authentication':
        vulnerabilities.push(...await this.scanAuthentication(config));
        break;
      case 'command-injection':
        vulnerabilities.push(...await this.scanCommandInjection(config));
        break;
      case 'data-exfiltration':
        vulnerabilities.push(...await this.scanDataExfiltration(config));
        break;
      default:
        vulnerabilities.push(...await this.scanAllTargets(config, options));
    }

    return vulnerabilities;
  }

  private async scanAllTargets(config: MCPServerConfig, options: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    vulnerabilities.push(...await this.scanAuthentication(config));
    vulnerabilities.push(...await this.scanCommandInjection(config));
    vulnerabilities.push(...await this.scanDataExfiltration(config));
    vulnerabilities.push(...await this.scanConfigurationIssues(config));
    vulnerabilities.push(...await this.scanOauthSecurity(config));

    return vulnerabilities;
  }

  private async scanAuthentication(config: MCPServerConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    if (!config.auth && !config.oauth) {
        vulnerabilities.push({
          id: this.generateVulnId(),
          type: VulnerabilityType.MISSING_AUTHENTICATION,
        severity: 'HIGH' as Severity,
        score: 8.5,
        server: config.metadata?.name || 'unknown',
        title: 'Missing Authentication Configuration',
        description: 'No authentication mechanism configured',
        remediation: {
          description: 'Configure OAuth 2.1 or API key authentication',
          automated: false
        },
        discoveredAt: new Date()
      });
    }

    if (config.auth?.type === 'basic' && !config.oauth) {
        vulnerabilities.push({
          id: this.generateVulnId(),
          type: VulnerabilityType.WEAK_AUTHENTICATION,
        severity: 'MEDIUM' as Severity,
        score: 6.0,
        server: config.metadata?.name || 'unknown',
        title: 'Basic Authentication Detected',
        description: 'Basic authentication is less secure than OAuth 2.1',
        remediation: {
          description: 'Migrate to OAuth 2.1 with PKCE',
          automated: false
        },
        discoveredAt: new Date()
      });
    }

    return vulnerabilities;
  }

  private async scanCommandInjection(config: MCPServerConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    if (config.command && this.hasShellInjectionRisk(config.command)) {
      vulnerabilities.push({
        id: this.generateVulnId(),
          type: VulnerabilityType.COMMAND_INJECTION,
        severity: 'CRITICAL' as Severity,
        score: 9.2,
        server: config.metadata?.name || 'unknown',
        title: 'Potential Command Injection Risk',
        description: `Command "${config.command}" may be vulnerable to injection attacks`,
        remediation: {
          description: 'Use parameterized commands and input validation',
          automated: false
        },
        discoveredAt: new Date()
      });
    }

    return vulnerabilities;
  }

  private async scanDataExfiltration(config: MCPServerConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    if (config.args?.some(arg => this.hasDataExfiltrationRisk(arg))) {
      vulnerabilities.push({
        id: this.generateVulnId(),
          type: VulnerabilityType.DATA_EXFILTRATION,
        severity: 'HIGH' as Severity,
        score: 7.8,
        server: config.metadata?.name || 'unknown',
        title: 'Potential Data Exfiltration Risk',
        description: 'Command arguments may allow unauthorized data access',
        remediation: {
          description: 'Restrict data access and implement proper authorization',
          automated: false
        },
        discoveredAt: new Date()
      });
    }

    return vulnerabilities;
  }

  private async scanConfigurationIssues(config: MCPServerConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    if (config.env) {
      const envVars = Object.keys(config.env);
      const secretKeys = envVars.filter(key => 
        /secret|key|token|password|credential/i.test(key)
      );

      if (secretKeys.length > 0) {
        vulnerabilities.push({
          id: this.generateVulnId(),
          type: VulnerabilityType.EXPOSED_API_KEY,
          severity: 'HIGH' as Severity,
          score: 8.0,
          server: config.metadata?.name || 'unknown',
          title: 'Potential Secret Exposure in Environment Variables',
          description: `Environment variables may contain secrets: ${secretKeys.join(', ')}`,
          remediation: {
            description: 'Move secrets to secure vault or encrypted storage',
            automated: false
          },
          discoveredAt: new Date()
        });
      }
    }

    return vulnerabilities;
  }

  private async scanOauthSecurity(config: MCPServerConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    if (config.oauth) {
      if (!config.oauth.pkce) {
        vulnerabilities.push({
          id: this.generateVulnId(),
          type: VulnerabilityType.OAUTH_TOKEN_LEAKAGE,
          severity: 'MEDIUM' as Severity,
          score: 6.5,
          server: config.metadata?.name || 'unknown',
          title: 'Missing PKCE in OAuth Configuration',
          description: 'OAuth 2.1 requires PKCE for public clients',
          remediation: {
            description: 'Enable PKCE for enhanced security',
            automated: true
          },
          discoveredAt: new Date()
        });
      }
    }

    return vulnerabilities;
  }

  private hasShellInjectionRisk(command: string): boolean {
    const riskyPatterns = [
      /\|\s*nc\s+/i,
      /\|\s*netcat\s+/i,
      /\|\s*curl\s+/i,
      /\|\s*wget\s+/i,
      />\s*\//,
      /\|\s*sh\s+/i,
      /\|\s*bash\s+/i,
      /\$?\(/,
      /`[^`]*`/,
      /\$+\{/,
      /&&/,              // Command chaining
      /\|\|/,            // Conditional chaining
      /;\s*/,            // Command separator
      /\\n/,             // Newline injection
      /<</,              // Heredoc injection
      /\$[A-Z_]{2,}/    // Environment variable reference in commands
    ];

    return riskyPatterns.some(pattern => pattern.test(command));
  }

  private hasDataExfiltrationRisk(arg: string): boolean {
    const riskyPatterns = [
      /--output\s+/i,
      />\s+\//,
      /tee\s+/i,
      /\|\s*cat\s+/i,
      /\|\s*base64\s+/i
    ];

    return riskyPatterns.some(pattern => pattern.test(arg));
  }

  private getSeverityScore(severity: Severity): number {
    switch (severity) {
      case 'CRITICAL': return 20;
      case 'HIGH': return 10;
      case 'MEDIUM': return 5;
      case 'LOW': return 2;
      default: return 0;
    }
  }

  private calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  private generateCorrelationId(vuln: Vulnerability): string {
    return crypto
      .createHash('sha256')
      .update(`${vuln.type}-${vuln.title}-${vuln.server}`)
      .digest('hex')
      .substring(0, 16);
  }

  private generateFingerprint(request: DistributedScanRequest): string {
    return crypto
      .createHash('sha256')
      .update(JSON.stringify(request.configurations.map(c => ({
        serverName: c.serverName,
        fingerprint: c.fingerprint
      }))))
      .digest('hex');
  }

  private generateResultId(): string {
    return `result-${this.workerId}-${Date.now()}-${Math.random().toString(36).substring(2)}`;
  }

  private generateVulnId(): string {
    return `vuln-${Date.now()}-${Math.random().toString(36).substring(2)}`;
  }

  private calculatePerformance(executionTime: number): ScanPerformanceMetrics {
    return {
      throughput: this.processedCount / (Date.now() - this.performance.lastActivity.getTime()),
      memoryUsage: process.memoryUsage().heapUsed / 1024 / 1024,
      cpuUsage: process.cpuUsage().user / 1000,
      networkLatency: 0,
      partitionsPerSecond: 1000 / executionTime,
      averageLatency: executionTime
    };
  }

  private updatePerformance(executionTime: number, success: boolean): void {
    this.performance.partitionsProcessed++;
    this.performance.averageProcessingTime = 
      (this.performance.averageProcessingTime + executionTime) / 2;
    
    if (success) {
      this.performance.errorCount = Math.max(0, this.performance.errorCount - 1);
    } else {
      this.performance.errorCount++;
    }

    this.performance.successRate = 
      (this.performance.partitionsProcessed - this.performance.errorCount) / 
      this.performance.partitionsProcessed * 100;
    
    this.performance.lastActivity = new Date();
  }

  private updateLastActivity(): void {
    this.performance.lastActivity = new Date();
  }

  private getMetrics(): WorkerMetrics {
    return {
      workerId: this.workerId,
      uptime: this.scanHistory.length > 0 ? 
        Date.now() - this.scanHistory[0]!.getTime() : 
        Date.now(),
      partitionsProcessed: this.performance.partitionsProcessed,
      averageProcessingTime: this.performance.averageProcessingTime,
      errorRate: this.performance.errorCount / Math.max(1, this.processedCount),
      memoryUsage: process.memoryUsage().heapUsed / 1024 / 1024,
      cpuUsage: process.cpuUsage().user / 1000,
      lastActivity: this.performance.lastActivity,
      status: this.status
    };
  }

  private async sendResponse(
    requestId: string, 
    success: boolean, 
    data?: any, 
    error?: Error
  ): Promise<void> {
    const response: WorkerResponse = {
      success,
      requestId,
      workerId: this.workerId,
      data,
      error: error ? {
        code: error.name,
        message: error.message,
        details: error.stack
      } : undefined,
      timestamp: new Date(),
      executionTime: Date.now() - (this.scanHistory[this.scanHistory.length - 1]?.getTime() || Date.now())
    };

    if (parentPort) {
      parentPort.postMessage(response);
    }
  }

  private sendMessage(type: WorkerMessageType, data: any): void {
    if (parentPort) {
      parentPort.postMessage({
        type,
        workerId: this.workerId,
        data,
        timestamp: new Date()
      });
    }
  }

  private async handleCheckpoint(message: WorkerMessage): Promise<void> {
    if (this.currentRequest) {
      const checkpoint: CheckpointData = {
        scanId: this.currentRequest.id,
        completedPartitions: [this.currentPartition!],
        failedPartitions: [],
        workerStates: new Map([[this.workerId, {
          workerId: this.workerId,
          status: this.status,
          currentPartition: this.currentPartition,
          lastHeartbeat: this.lastHeartbeat,
          processedPartitions: [this.currentPartition!],
          failedPartitions: [],
          retryCount: 0,
          performance: this.performance
        }]]),
        progress: {
          totalConfigurations: this.currentRequest.configurations.length,
          processedConfigurations: 1,
          completedPartitions: 1,
          totalPartitions: 1,
          currentPhase: ScanPhase.PROCESSING,
          throughput: this.processedCount / ((Date.now() - this.performance.lastActivity.getTime()) / 1000)
        },
        timestamp: new Date(),
        nextPartitionIndex: 1,
        totalPartitions: 1
      };

      this.checkpointData.set(this.currentRequest.id, checkpoint);
      await this.sendResponse(message.requestId!, true, checkpoint);
    }
  }

  private async handleRecovery(message: WorkerMessage): Promise<void> {
    this.status = WorkerStatus.RECOVERING;
    this.lastHeartbeat = new Date();
    
    await this.sendResponse(message.requestId!, true, {
      workerId: this.workerId,
      status: this.status,
      recoveryTime: Date.now(),
      checkpoints: Array.from(this.checkpointData.entries())
    });
  }

  private async handleTerminate(): Promise<void> {
    this.status = WorkerStatus.TERMINATED;
    
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    if (parentPort) {
      parentPort.removeAllListeners();
      parentPort.postMessage({
        type: 'terminated',
        workerId: this.workerId,
        timestamp: new Date(),
        finalMetrics: this.getMetrics()
      });
    }
  }

  private async handleStatus(message: WorkerMessage): Promise<void> {
    await this.sendResponse(message.requestId!, true, {
      workerId: this.workerId,
      status: this.status,
      metrics: this.getMetrics(),
      currentPartition: this.currentPartition,
      performance: this.performance
    });
  }

  private async handleError(error: Error, message: WorkerMessage): Promise<void> {
    console.error(`Worker ${this.workerId} error handling message:`, error);
    
    await this.sendResponse(message.requestId!, false, null, error);
    
    if (this.errorCount >= this.faultTolerance.maxWorkerRestarts) {
      await this.handleFatalError(error);
    }
  }

  private async handleFatalError(error: Error): Promise<void> {
    this.status = WorkerStatus.FAILED;
    
    if (parentPort) {
      parentPort.postMessage({
        type: 'fatal_error',
        workerId: this.workerId,
        error: {
          message: error.message,
          stack: error.stack
        },
        timestamp: new Date(),
        finalMetrics: this.getMetrics()
      });
    }

    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
  }

  private getDefaultFaultToleranceConfig(): FaultToleranceConfig {
    return {
      maxWorkerRestarts: 3,
      restartDelay: 5000,
      circuitBreakerThreshold: 5,
      circuitBreakerTimeout: 30000,
      gracefulShutdownTimeout: 10000,
      checkpointEnabled: true,
      autoRecovery: true,
      alertOnFailure: true,
      retryPolicy: {
        maxAttempts: 3,
        baseDelay: 1000,
        maxDelay: 10000,
        backoffMultiplier: 2,
        jitter: true,
        retryableErrors: ['timeout', 'network', 'memory']
      }
    };
  }
}

if (parentPort && workerData) {
  new ScannerWorker(workerData.workerId || 0);
}

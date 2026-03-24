import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ConfigurationPartitioner } from '../src/distributed/utils/configuration-partitioner';
import { ResultAggregator } from '../src/distributed/utils/result-aggregator';
import { FaultToleranceManager } from '../src/distributed/utils/fault-tolerance';
import {
  PartitionStrategy,
  AggregationStrategy,
  WorkerStatus,
} from '../src/distributed/interfaces/distributed-interfaces';
import type {
  DistributedConfig,
  DistributedScanResult,
  DistributedVulnerability,
  FaultToleranceConfig,
  WorkerMetrics,
  ConfigurationFingerprint,
} from '../src/distributed/interfaces/distributed-interfaces';
import type { MCPServerConfig, ScanConfig } from '../src/types';
import { Severity, VulnerabilityType } from '../src/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDistributedConfig(
  overrides: Partial<DistributedConfig> = {}
): DistributedConfig {
  return {
    workerPoolSize: 4,
    maxRetries: 3,
    retryDelay: 100,
    checkpointInterval: 5000,
    batchSize: 2,
    enableFaultTolerance: true,
    enableIncrementalScans: false,
    resultRetentionPeriod: 3600000,
    workerTimeout: 30000,
    heartbeatInterval: 5000,
    partitionStrategy: PartitionStrategy.PRIORITY_BASED,
    aggregationStrategy: AggregationStrategy.BATCHED,
    ...overrides,
  };
}

function makeScanConfig(): ScanConfig {
  return { depth: 'standard' };
}

function makeServerConfig(overrides: Partial<MCPServerConfig> = {}): MCPServerConfig {
  return {
    command: 'node',
    args: ['server.js'],
    ...overrides,
  };
}

function makeVulnerability(
  overrides: Partial<DistributedVulnerability> = {}
): DistributedVulnerability {
  return {
    id: `vuln-${Math.random().toString(36).slice(2, 8)}`,
    type: VulnerabilityType.MISCONFIGURATION,
    severity: Severity.MEDIUM,
    score: 5.0,
    server: 'test-server',
    title: 'Test vulnerability',
    description: 'A test vulnerability for unit testing',
    remediation: { description: 'Fix it', automated: false },
    discoveredAt: new Date(),
    partitionId: 'partition-0',
    workerId: 0,
    duplicates: [],
    ...overrides,
  };
}

function makeScanResult(
  overrides: Partial<DistributedScanResult> = {}
): DistributedScanResult {
  return {
    id: 'result-1',
    requestId: 'req-1',
    workerId: 0,
    partitionId: 'partition-0',
    serverName: 'test-server',
    vulnerabilities: [],
    summary: {
      score: 100,
      grade: 'A',
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      serversScanned: 1,
      partitionsProcessed: 1,
      executionTime: 100,
      workerId: 0,
    },
    executionTime: 100,
    timestamp: new Date(),
    fingerprint: 'abc123',
    performance: {
      throughput: 10,
      memoryUsage: 0,
      cpuUsage: 0,
      networkLatency: 0,
      partitionsPerSecond: 10,
      averageLatency: 100,
    },
    ...overrides,
  };
}

function makeFaultToleranceConfig(
  overrides: Partial<FaultToleranceConfig> = {}
): FaultToleranceConfig {
  return {
    maxWorkerRestarts: 3,
    restartDelay: 10,
    circuitBreakerThreshold: 3,
    circuitBreakerTimeout: 500,
    gracefulShutdownTimeout: 5000,
    checkpointEnabled: true,
    autoRecovery: true,
    alertOnFailure: false,
    retryPolicy: {
      maxAttempts: 3,
      baseDelay: 10,
      maxDelay: 100,
      backoffMultiplier: 2,
      jitter: false,
      retryableErrors: ['timeout', 'network', 'temporary'],
    },
    ...overrides,
  };
}

function makeWorkerMetrics(
  overrides: Partial<WorkerMetrics> = {}
): WorkerMetrics {
  return {
    workerId: 0,
    uptime: 1000,
    partitionsProcessed: 5,
    averageProcessingTime: 200,
    errorRate: 0.0,
    memoryUsage: 50,
    cpuUsage: 30,
    lastActivity: new Date(),
    status: WorkerStatus.PROCESSING,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// ConfigurationPartitioner
// ---------------------------------------------------------------------------

describe('ConfigurationPartitioner', () => {
  let partitioner: ConfigurationPartitioner;

  beforeEach(() => {
    partitioner = new ConfigurationPartitioner(makeDistributedConfig());
  });

  describe('createPartitionPlan()', () => {
    it('partitions multiple servers into batches', () => {
      const servers: Record<string, MCPServerConfig> = {
        'server-a': makeServerConfig({ command: 'node' }),
        'server-b': makeServerConfig({ command: 'python' }),
        'server-c': makeServerConfig({ command: 'ruby' }),
        'server-d': makeServerConfig({ command: 'go' }),
      };

      const plan = partitioner.createPartitionPlan(servers, makeScanConfig());

      expect(plan.partitions.length).toBeGreaterThan(0);
      expect(plan.totalSize).toBeGreaterThan(0);
      expect(plan.strategy).toBe(PartitionStrategy.PRIORITY_BASED);
      expect(plan.loadBalanceScore).toBeGreaterThanOrEqual(0);
      expect(plan.loadBalanceScore).toBeLessThanOrEqual(100);

      const totalConfigs = plan.partitions.reduce(
        (sum, p) => sum + p.configurations.length,
        0
      );
      expect(totalConfigs).toBe(4);
    });

    it('handles a single server', () => {
      const servers: Record<string, MCPServerConfig> = {
        'only-server': makeServerConfig(),
      };

      const plan = partitioner.createPartitionPlan(servers, makeScanConfig());

      expect(plan.partitions.length).toBe(1);
      expect(plan.partitions[0]!.configurations.length).toBe(1);
    });

    it('handles empty server config', () => {
      const plan = partitioner.createPartitionPlan({}, makeScanConfig());

      expect(plan.partitions.length).toBe(0);
      expect(plan.totalSize).toBe(0);
    });

    it('handles more workers than servers (no empty partitions in priority mode)', () => {
      const config = makeDistributedConfig({ workerPoolSize: 10, batchSize: 2 });
      const p = new ConfigurationPartitioner(config);

      const servers: Record<string, MCPServerConfig> = {
        'a': makeServerConfig(),
        'b': makeServerConfig(),
      };

      const plan = p.createPartitionPlan(servers, makeScanConfig());

      expect(plan.partitions.length).toBe(1);
      expect(plan.partitions[0]!.configurations.length).toBe(2);
    });

    it('uses hash-based strategy when configured', () => {
      const config = makeDistributedConfig({
        partitionStrategy: PartitionStrategy.HASH_BASED,
      });
      const p = new ConfigurationPartitioner(config);

      const servers: Record<string, MCPServerConfig> = {
        's1': makeServerConfig({ command: 'node' }),
        's2': makeServerConfig({ command: 'python' }),
        's3': makeServerConfig({ command: 'ruby' }),
      };

      const plan = p.createPartitionPlan(servers, makeScanConfig());

      expect(plan.strategy).toBe(PartitionStrategy.HASH_BASED);
      expect(plan.partitions.length).toBeGreaterThan(0);
    });

    it('uses size-based strategy when configured', () => {
      const config = makeDistributedConfig({
        partitionStrategy: PartitionStrategy.SIZE_BASED,
      });
      const p = new ConfigurationPartitioner(config);

      const servers: Record<string, MCPServerConfig> = {
        's1': makeServerConfig({ command: 'node', env: { A: 'x'.repeat(500) } }),
        's2': makeServerConfig({ command: 'python' }),
      };

      const plan = p.createPartitionPlan(servers, makeScanConfig());
      expect(plan.strategy).toBe(PartitionStrategy.SIZE_BASED);
    });

    it('uses domain-based strategy when configured', () => {
      const config = makeDistributedConfig({
        partitionStrategy: PartitionStrategy.DOMAIN_BASED,
      });
      const p = new ConfigurationPartitioner(config);

      const servers: Record<string, MCPServerConfig> = {
        's1': makeServerConfig({ auth: { type: 'basic' } }),
        's2': makeServerConfig({ oauth: { authorizationServer: 'https://auth.example.com', pkce: false } }),
      };

      const plan = p.createPartitionPlan(servers, makeScanConfig());
      expect(plan.strategy).toBe(PartitionStrategy.DOMAIN_BASED);
      expect(plan.partitions.length).toBeGreaterThan(0);
    });

    it('assigns higher priority to configs with security risks', () => {
      const config = makeDistributedConfig({
        partitionStrategy: PartitionStrategy.PRIORITY_BASED,
        batchSize: 1,
      });
      const p = new ConfigurationPartitioner(config);

      const servers: Record<string, MCPServerConfig> = {
        'safe': makeServerConfig({ command: 'node' }),
        'risky': makeServerConfig({
          command: 'curl',
          env: { SECRET_KEY: 'leaked' },
          oauth: { authorizationServer: 'https://auth.example.com', pkce: false },
        }),
      };

      const plan = p.createPartitionPlan(servers, makeScanConfig());

      // The first partition should contain the higher-priority config
      const firstPartition = plan.partitions[0]!;
      const priorityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      const lastPartition = plan.partitions[plan.partitions.length - 1]!;
      expect(priorityOrder[firstPartition.priority]).toBeGreaterThanOrEqual(
        priorityOrder[lastPartition.priority]
      );
    });
  });

  describe('generateConfigurationFingerprint()', () => {
    it('produces a deterministic fingerprint for the same input', () => {
      const config = makeServerConfig({ command: 'node', args: ['app.js'] });

      const fp1 = partitioner.generateConfigurationFingerprint(config, 'my-server');
      const fp2 = partitioner.generateConfigurationFingerprint(config, 'my-server');

      expect(fp1.hash).toBe(fp2.hash);
      expect(fp1.checksum).toBe(fp2.checksum);
      expect(fp1.serverName).toBe('my-server');
      expect(fp1.version).toBe('1.0.0');
    });

    it('produces different fingerprints for different configs', () => {
      const fp1 = partitioner.generateConfigurationFingerprint(
        makeServerConfig({ command: 'node' }),
        'server-a'
      );
      const fp2 = partitioner.generateConfigurationFingerprint(
        makeServerConfig({ command: 'python' }),
        'server-b'
      );

      expect(fp1.hash).not.toBe(fp2.hash);
    });

    it('includes correct config size', () => {
      const config = makeServerConfig({ command: 'node' });
      const fp = partitioner.generateConfigurationFingerprint(config, 'srv');

      expect(fp.configSize).toBe(JSON.stringify(config).length);
    });
  });

  describe('compareFingerprints()', () => {
    it('reports no changes for identical fingerprints', () => {
      const fp = partitioner.generateConfigurationFingerprint(
        makeServerConfig(),
        'srv'
      );
      const result = partitioner.compareFingerprints(fp, fp);

      expect(result.changed).toBe(false);
      expect(result.changes).toHaveLength(0);
      expect(result.severity).toBe('none');
    });

    it('detects content changes', () => {
      const fp1 = partitioner.generateConfigurationFingerprint(
        makeServerConfig({ command: 'node' }),
        'srv'
      );
      const fp2 = partitioner.generateConfigurationFingerprint(
        makeServerConfig({ command: 'python' }),
        'srv'
      );

      const result = partitioner.compareFingerprints(fp1, fp2);

      expect(result.changed).toBe(true);
      expect(result.changes.length).toBeGreaterThan(0);
    });

    it('detects domain changes', () => {
      const fp1: ConfigurationFingerprint = {
        hash: 'aaa',
        timestamp: new Date(),
        serverName: 'srv',
        configSize: 100,
        domains: ['basic'],
        checksum: 'ccc',
        version: '1.0.0',
      };
      const fp2: ConfigurationFingerprint = {
        ...fp1,
        hash: 'aaa', // same hash
        domains: ['basic', 'authentication'],
      };

      const result = partitioner.compareFingerprints(fp1, fp2);
      expect(result.changed).toBe(true);
      expect(result.changes.some(c => c.includes('Added domains'))).toBe(true);
    });

    it('reports major severity for significant size changes', () => {
      const fp1: ConfigurationFingerprint = {
        hash: 'aaa',
        timestamp: new Date(),
        serverName: 'srv',
        configSize: 100,
        domains: ['basic'],
        checksum: 'c1',
        version: '1.0.0',
      };
      const fp2: ConfigurationFingerprint = {
        ...fp1,
        hash: 'bbb',
        configSize: 5000,
        checksum: 'c2',
      };

      const result = partitioner.compareFingerprints(fp1, fp2);
      expect(result.severity).toBe('major');
    });
  });
});

// ---------------------------------------------------------------------------
// ResultAggregator
// ---------------------------------------------------------------------------

describe('ResultAggregator', () => {
  let aggregator: ResultAggregator;

  beforeEach(() => {
    aggregator = new ResultAggregator();
  });

  describe('aggregateAndDeduplicate()', () => {
    it('aggregates multiple results into one', () => {
      const results: DistributedScanResult[] = [
        makeScanResult({
          id: 'r1',
          vulnerabilities: [makeVulnerability({ id: 'v1', server: 'srv-a' })],
          executionTime: 100,
        }),
        makeScanResult({
          id: 'r2',
          vulnerabilities: [makeVulnerability({ id: 'v2', server: 'srv-b' })],
          executionTime: 200,
        }),
      ];

      const { aggregatedResult, deduplication } = aggregator.aggregateAndDeduplicate(results);

      expect(aggregatedResult.vulnerabilities.length).toBe(2);
      expect(deduplication.duplicatesFound).toBe(0);
    });

    it('deduplicates identical vulnerabilities', () => {
      const sharedProps = {
        type: VulnerabilityType.EXPOSED_API_KEY,
        title: 'Exposed API Key',
        description: 'An API key is exposed in the configuration',
        server: 'srv-a',
        severity: Severity.HIGH,
      };

      const results: DistributedScanResult[] = [
        makeScanResult({
          vulnerabilities: [makeVulnerability({ id: 'v1', ...sharedProps })],
          executionTime: 100,
        }),
        makeScanResult({
          vulnerabilities: [makeVulnerability({ id: 'v2', ...sharedProps })],
          executionTime: 100,
        }),
      ];

      // Use IMMEDIATE strategy for straightforward single-pass deduplication
      const { aggregatedResult, deduplication } = aggregator.aggregateAndDeduplicate(
        results,
        AggregationStrategy.IMMEDIATE
      );

      expect(aggregatedResult.vulnerabilities.length).toBe(1);
      expect(deduplication.duplicatesFound).toBeGreaterThan(0);
    });

    it('handles empty results array', () => {
      const results: DistributedScanResult[] = [
        makeScanResult({ vulnerabilities: [], executionTime: 50 }),
      ];

      const { aggregatedResult } = aggregator.aggregateAndDeduplicate(results);

      expect(aggregatedResult.vulnerabilities.length).toBe(0);
      expect(aggregatedResult.summary.score).toBe(100);
      expect(aggregatedResult.summary.grade).toBe('A');
    });

    it('correctly scores and grades based on severity counts', () => {
      const vulns = [
        makeVulnerability({ severity: Severity.CRITICAL, title: 'Critical vuln 1', description: 'crit1' }),
        makeVulnerability({ severity: Severity.HIGH, title: 'High vuln 1', description: 'high1' }),
        makeVulnerability({ severity: Severity.MEDIUM, title: 'Medium vuln 1', description: 'med1' }),
      ];

      const results: DistributedScanResult[] = [
        makeScanResult({ vulnerabilities: vulns, executionTime: 100 }),
      ];

      const { aggregatedResult } = aggregator.aggregateAndDeduplicate(results);

      // score = 100 - 20 (critical) - 10 (high) - 5 (medium) = 65
      expect(aggregatedResult.summary.score).toBe(65);
      expect(aggregatedResult.summary.grade).toBe('D');
      expect(aggregatedResult.summary.critical).toBe(1);
      expect(aggregatedResult.summary.high).toBe(1);
      expect(aggregatedResult.summary.medium).toBe(1);
    });

    it('clamps score at 0 for many critical vulnerabilities', () => {
      const vulns = Array.from({ length: 6 }, (_, i) =>
        makeVulnerability({
          severity: Severity.CRITICAL,
          title: `Critical ${i}`,
          description: `Critical vulnerability ${i}`,
        })
      );

      const results: DistributedScanResult[] = [
        makeScanResult({ vulnerabilities: vulns, executionTime: 100 }),
      ];

      const { aggregatedResult } = aggregator.aggregateAndDeduplicate(results);

      expect(aggregatedResult.summary.score).toBe(0);
      expect(aggregatedResult.summary.grade).toBe('F');
    });

    it('supports IMMEDIATE aggregation strategy', () => {
      const results: DistributedScanResult[] = [
        makeScanResult({
          vulnerabilities: [makeVulnerability({ title: 'Vuln A', description: 'desc a' })],
          executionTime: 100,
        }),
      ];

      const { aggregatedResult } = aggregator.aggregateAndDeduplicate(
        results,
        AggregationStrategy.IMMEDIATE
      );

      expect(aggregatedResult.partitionId).toBe('aggregated');
      expect(aggregatedResult.vulnerabilities.length).toBe(1);
    });

    it('supports PRIORITY aggregation strategy', () => {
      const results: DistributedScanResult[] = [
        makeScanResult({
          vulnerabilities: [
            makeVulnerability({ severity: Severity.LOW, title: 'Low vuln', description: 'low' }),
          ],
          executionTime: 50,
        }),
        makeScanResult({
          vulnerabilities: [
            makeVulnerability({ severity: Severity.CRITICAL, title: 'Crit vuln', description: 'crit' }),
          ],
          executionTime: 50,
        }),
      ];

      const { aggregatedResult } = aggregator.aggregateAndDeduplicate(
        results,
        AggregationStrategy.PRIORITY
      );

      expect(aggregatedResult.vulnerabilities.length).toBe(2);
    });

    it('supports CORRELATED aggregation strategy', () => {
      const results: DistributedScanResult[] = [
        makeScanResult({
          vulnerabilities: [
            makeVulnerability({
              id: 'v1',
              title: 'Authentication bypass',
              description: 'Authentication bypass vulnerability found',
              type: VulnerabilityType.MISSING_AUTHENTICATION,
            }),
          ],
          executionTime: 100,
        }),
      ];

      const { aggregatedResult } = aggregator.aggregateAndDeduplicate(
        results,
        AggregationStrategy.CORRELATED
      );

      expect(aggregatedResult.partitionId).toBe('correlated-aggregated');
    });

    it('counts servers scanned from unique server names', () => {
      const results: DistributedScanResult[] = [
        makeScanResult({
          vulnerabilities: [
            makeVulnerability({ server: 'srv-a', title: 'V1', description: 'd1' }),
            makeVulnerability({ server: 'srv-b', title: 'V2', description: 'd2' }),
          ],
          executionTime: 100,
        }),
        makeScanResult({
          vulnerabilities: [
            makeVulnerability({ server: 'srv-a', title: 'V3', description: 'd3' }),
          ],
          executionTime: 100,
        }),
      ];

      const { aggregatedResult } = aggregator.aggregateAndDeduplicate(results);

      expect(aggregatedResult.summary.serversScanned).toBe(2);
    });
  });
});

// ---------------------------------------------------------------------------
// FaultToleranceManager
// ---------------------------------------------------------------------------

describe('FaultToleranceManager', () => {
  let manager: FaultToleranceManager;

  beforeEach(() => {
    manager = new FaultToleranceManager(makeFaultToleranceConfig());
  });

  describe('circuit breaker', () => {
    it('starts in CLOSED state', async () => {
      const status = await manager.monitorWorkerHealth(0, makeWorkerMetrics());
      expect(status.circuitBreakerState).toBe('CLOSED');
    });

    it('opens after threshold failures', async () => {
      const config = makeFaultToleranceConfig({
        circuitBreakerThreshold: 2,
        alertOnFailure: false,
      });
      const mgr = new FaultToleranceManager(config);

      await mgr.handleWorkerFailure(0, new Error('fail 1'));
      await mgr.handleWorkerFailure(0, new Error('fail 2'));

      const status = await mgr.monitorWorkerHealth(
        0,
        makeWorkerMetrics({ errorRate: 0.0 })
      );
      expect(status.circuitBreakerState).toBe('OPEN');
    });

    it('transitions from OPEN to HALF_OPEN after timeout', async () => {
      const config = makeFaultToleranceConfig({
        circuitBreakerThreshold: 1,
        circuitBreakerTimeout: 50,
        restartDelay: 1,
      });
      const mgr = new FaultToleranceManager(config);

      await mgr.handleWorkerFailure(0, new Error('fail'));

      // Verify it is OPEN
      let status = await mgr.monitorWorkerHealth(
        0,
        makeWorkerMetrics({ errorRate: 0.0 })
      );
      expect(status.circuitBreakerState).toBe('OPEN');

      // Wait longer than the timeout
      await new Promise(r => setTimeout(r, 60));

      status = await mgr.monitorWorkerHealth(
        0,
        makeWorkerMetrics({ errorRate: 0.0 })
      );
      expect(status.circuitBreakerState).toBe('HALF_OPEN');
    });

    it('closes from HALF_OPEN when error rate is low', async () => {
      const config = makeFaultToleranceConfig({
        circuitBreakerThreshold: 1,
        circuitBreakerTimeout: 10,
        restartDelay: 1,
      });
      const mgr = new FaultToleranceManager(config);

      await mgr.handleWorkerFailure(0, new Error('fail'));
      await new Promise(r => setTimeout(r, 20));

      // Transition to HALF_OPEN
      await mgr.monitorWorkerHealth(0, makeWorkerMetrics({ errorRate: 0.0 }));

      // Now with low error rate it should close
      const status = await mgr.monitorWorkerHealth(
        0,
        makeWorkerMetrics({ errorRate: 0.01 })
      );
      expect(status.circuitBreakerState).toBe('CLOSED');
    });
  });

  describe('handleWorkerFailure()', () => {
    it('returns a failure handling result', async () => {
      const result = await manager.handleWorkerFailure(0, new Error('timeout error'));

      expect(result.handled).toBe(true);
      expect(result.workerId).toBe(0);
      expect(typeof result.strategy).toBe('string');
    });

    it('selects TIMEOUT_RETRY strategy for timeout errors', async () => {
      const result = await manager.handleWorkerFailure(0, new Error('timeout'));
      expect(result.strategy).toBe('TIMEOUT_RETRY');
    });

    it('selects MEMORY_CLEANUP strategy for memory errors', async () => {
      const result = await manager.handleWorkerFailure(0, new Error('memory'));
      expect(result.strategy).toBe('MEMORY_CLEANUP');
    });

    it('does not restart on fatal errors', async () => {
      const result = await manager.handleWorkerFailure(0, new Error('fatal crash'));
      expect(result.shouldRestart).toBe(false);
    });
  });

  describe('executeWithRetry()', () => {
    it('returns result on first success', async () => {
      const op = vi.fn().mockResolvedValue('ok');
      const result = await manager.executeWithRetry(op, {
        operationId: 'worker-0-op',
        timeout: 5000,
      });

      expect(result).toBe('ok');
      expect(op).toHaveBeenCalledTimes(1);
    });

    it('retries on retryable errors and eventually succeeds', async () => {
      let attempt = 0;
      const op = vi.fn().mockImplementation(async () => {
        attempt++;
        if (attempt < 3) throw new Error('timeout');
        return 'recovered';
      });

      const result = await manager.executeWithRetry(op, {
        operationId: 'worker-0-op',
        timeout: 5000,
      });

      expect(result).toBe('recovered');
      expect(op).toHaveBeenCalledTimes(3);
    });

    it('throws after exhausting max attempts', async () => {
      const op = vi.fn().mockRejectedValue(new Error('timeout'));

      await expect(
        manager.executeWithRetry(op, {
          operationId: 'worker-0-op',
          timeout: 5000,
        })
      ).rejects.toThrow(/failed after 3 attempts/);

      expect(op).toHaveBeenCalledTimes(3);
    });

    it('throws immediately on non-retryable errors', async () => {
      const op = vi.fn().mockRejectedValue(new Error('fatal crash'));

      await expect(
        manager.executeWithRetry(op, {
          operationId: 'worker-0-op',
          timeout: 5000,
        })
      ).rejects.toThrow('fatal crash');

      expect(op).toHaveBeenCalledTimes(1);
    });
  });

  describe('checkpoint and recovery', () => {
    it('creates and retrieves checkpoints', async () => {
      const checkpoint = await manager.createCheckpoint('scan-1', 'part-0', {});

      expect(checkpoint.scanId).toBe('scan-1');
      expect(checkpoint.completedPartitions).toContain('part-0');
    });

    it('accumulates partitions across multiple checkpoints', async () => {
      await manager.createCheckpoint('scan-1', 'part-0', {});
      const cp = await manager.createCheckpoint('scan-1', 'part-1', {});

      expect(cp.completedPartitions).toContain('part-0');
      expect(cp.completedPartitions).toContain('part-1');
      expect(cp.progress.completedPartitions).toBe(2);
    });

    it('does not duplicate partition IDs', async () => {
      await manager.createCheckpoint('scan-1', 'part-0', {});
      const cp = await manager.createCheckpoint('scan-1', 'part-0', {});

      expect(cp.completedPartitions.filter(p => p === 'part-0').length).toBe(1);
    });

    it('recovers from checkpoint', async () => {
      await manager.createCheckpoint('scan-1', 'part-0', {});
      const plan = await manager.recoverFromCheckpoint('scan-1');

      expect(plan.scanId).toBe('scan-1');
      expect(plan.strategy).toBeDefined();
    });

    it('throws when recovering from nonexistent checkpoint', async () => {
      await expect(
        manager.recoverFromCheckpoint('nonexistent')
      ).rejects.toThrow(/No checkpoint found/);
    });
  });

  describe('getOverallHealth()', () => {
    it('returns 100% health when no workers are tracked', () => {
      const report = manager.getOverallHealth();
      expect(report.overallHealth).toBe(100);
      expect(report.totalWorkers).toBe(0);
    });

    it('reflects worker status after monitoring', async () => {
      // Healthy worker: low error rate => PROCESSING status
      await manager.monitorWorkerHealth(0, makeWorkerMetrics({ errorRate: 0.0 }));
      // Moderately unhealthy worker: errorRate between 0.2 and 0.5 => RECOVERING status
      await manager.monitorWorkerHealth(1, makeWorkerMetrics({ workerId: 1, errorRate: 0.3 }));

      const report = manager.getOverallHealth();
      expect(report.totalWorkers).toBe(2);
      // PROCESSING counts as healthy; RECOVERING does not
      expect(report.healthyWorkers).toBe(1);
    });

    it('tracks failed workers correctly', async () => {
      // Use handleWorkerFailure to put a worker into FAILED state directly
      // First register the worker via monitoring
      await manager.monitorWorkerHealth(0, makeWorkerMetrics({ errorRate: 0.0 }));

      // handleWorkerFailure sets status to FAILED
      await manager.handleWorkerFailure(0, new Error('crash'));

      const report = manager.getOverallHealth();
      expect(report.totalWorkers).toBe(1);
      expect(report.failedWorkers).toBe(1);
      expect(report.healthyWorkers).toBe(0);
    });
  });
});

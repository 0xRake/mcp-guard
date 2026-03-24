/**
 * Distributed Scanning Interfaces
 * Enterprise-grade interfaces for distributed MCP-Guard security scanning
 */

import type { 
  MCPServerConfig, 
  ScanConfig, 
  Vulnerability, 
  ScanResult,
  Severity,
  VulnerabilityType 
} from '../../types';

export interface DistributedConfig {
  workerPoolSize: number;
  maxRetries: number;
  retryDelay: number;
  checkpointInterval: number;
  batchSize: number;
  enableFaultTolerance: boolean;
  enableIncrementalScans: boolean;
  resultRetentionPeriod: number;
  workerTimeout: number;
  heartbeatInterval: number;
  partitionStrategy: PartitionStrategy;
  aggregationStrategy: AggregationStrategy;
}

export enum PartitionStrategy {
  PRIORITY_BASED = 'priority-based',
  DOMAIN_BASED = 'domain-based',
  SIZE_BASED = 'size-based',
  HASH_BASED = 'hash-based',
  ADAPTIVE = 'adaptive'
}

export enum AggregationStrategy {
  IMMEDIATE = 'immediate',
  BATCHED = 'batched',
  PRIORITY = 'priority',
  CORRELATED = 'correlated'
}

export interface ConfigurationFingerprint {
  hash: string;
  timestamp: Date;
  serverName: string;
  configPath?: string;
  configSize: number;
  domains: string[];
  checksum: string;
  version: string;
}

export interface CheckpointData {
  scanId: string;
  completedPartitions: string[];
  failedPartitions: string[];
  workerStates: Map<number, WorkerState>;
  progress: ScanProgress;
  timestamp: Date;
  nextPartitionIndex: number;
  totalPartitions: number;
}

export interface WorkerState {
  workerId: number;
  status: WorkerStatus;
  currentPartition?: string;
  lastHeartbeat: Date;
  processedPartitions: string[];
  failedPartitions: string[];
  retryCount: number;
  performance: WorkerPerformance;
}

export enum WorkerStatus {
  IDLE = 'idle',
  PROCESSING = 'processing',
  FAILED = 'failed',
  TERMINATED = 'terminated',
  RECOVERING = 'recovering'
}

export interface WorkerPerformance {
  partitionsProcessed: number;
  averageProcessingTime: number;
  successRate: number;
  lastActivity: Date;
  errorCount: number;
}

export interface ScanProgress {
  totalConfigurations: number;
  processedConfigurations: number;
  completedPartitions: number;
  totalPartitions: number;
  currentPhase: ScanPhase;
  estimatedTimeRemaining?: number;
  throughput: number;
}

export enum ScanPhase {
  INITIALIZING = 'initializing',
  PARTITIONING = 'partitioning',
  DISTRIBUTING = 'distributing',
  PROCESSING = 'processing',
  AGGREGATING = 'aggregating',
  FINALIZING = 'finalizing',
  COMPLETED = 'completed',
  FAILED = 'failed'
}

export interface DistributedScanRequest {
  id: string;
  scanId: string;
  configurations: DistributedConfiguration[];
  options: ScanConfig;
  distributedConfig: DistributedConfig;
  fingerprint: ConfigurationFingerprint;
  dependencies?: string[];
  priority: 'critical' | 'high' | 'medium' | 'low';
  createdAt: Date;
}

export interface DistributedConfiguration {
  id: string;
  serverName: string;
  config: MCPServerConfig;
  priority: 'critical' | 'high' | 'medium' | 'low';
  domains: string[];
  dependencies?: string[];
  partitionKey: string;
  fingerprint: string;
  estimatedSize: number;
}

export interface DistributedScanResult {
  id: string;
  requestId: string;
  workerId: number;
  partitionId: string;
  serverName: string;
  vulnerabilities: DistributedVulnerability[];
  summary: DistributedSummary;
  executionTime: number;
  timestamp: Date;
  fingerprint: string;
  performance: ScanPerformanceMetrics;
}

export interface DistributedVulnerability extends Vulnerability {
  partitionId: string;
  workerId: number;
  correlationId?: string;
  duplicates: string[];
  deduplicationKey?: string;
}

export interface DistributedSummary {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  serversScanned: number;
  partitionsProcessed: number;
  executionTime: number;
  workerId: number;
}

export interface ScanPerformanceMetrics {
  throughput: number;
  memoryUsage: number;
  cpuUsage: number;
  networkLatency: number;
  partitionsPerSecond: number;
  averageLatency: number;
}

export interface PartitionPlan {
  partitions: Partition[];
  totalSize: number;
  estimatedTime: number;
  strategy: PartitionStrategy;
  loadBalanceScore: number;
}

export interface Partition {
  id: string;
  configurations: DistributedConfiguration[];
  priority: 'critical' | 'high' | 'medium' | 'low';
  estimatedSize: number;
  estimatedTime: number;
  dependencies: string[];
  workerAffinity?: number;
  retryCount: number;
  maxRetries: number;
}

export interface WorkerMessage {
  type: WorkerMessageType;
  requestId?: string;
  workerId: number;
  data?: any;
  timestamp: Date;
  metadata?: Record<string, any>;
}

export enum WorkerMessageType {
  INITIALIZE = 'initialize',
  SCAN_REQUEST = 'scan_request',
  SCAN_RESULT = 'scan_result',
  SCAN_ERROR = 'scan_error',
  HEARTBEAT = 'heartbeat',
  CHECKPOINT = 'checkpoint',
  RECOVER = 'recover',
  TERMINATE = 'terminate',
  STATUS = 'status'
}

export interface WorkerResponse {
  success: boolean;
  requestId: string;
  workerId: number;
  data?: any;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  timestamp: Date;
  executionTime: number;
}

export interface FaultToleranceConfig {
  maxWorkerRestarts: number;
  restartDelay: number;
  circuitBreakerThreshold: number;
  circuitBreakerTimeout: number;
  gracefulShutdownTimeout: number;
  checkpointEnabled: boolean;
  autoRecovery: boolean;
  alertOnFailure: boolean;
  retryPolicy: RetryPolicy;
}

export interface RetryPolicy {
  maxAttempts: number;
  baseDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
  jitter: boolean;
  retryableErrors: string[];
}

export interface ResultCorrelation {
  correlationId: string;
  relatedResults: string[];
  confidence: number;
  reason: string;
  algorithm: CorrelationAlgorithm;
}

export enum CorrelationAlgorithm {
  EXACT_MATCH = 'exact_match',
  FUZZY_MATCH = 'fuzzy_match',
  SEMANTIC_SIMILARITY = 'semantic_similarity',
  PATTERN_BASED = 'pattern_based'
}

export interface DeduplicationResult {
  duplicatesFound: number;
  duplicatesRemoved: DistributedVulnerability[];
  uniqueResults: DistributedVulnerability[];
  correlationGroups: ResultCorrelation[];
  statistics: DeduplicationStats;
}

export interface DeduplicationStats {
  totalResults: number;
  uniqueResults: number;
  duplicateRate: number;
  correlationAccuracy: number;
  processingTime: number;
}

export interface WorkerMetrics {
  workerId: number;
  uptime: number;
  partitionsProcessed: number;
  averageProcessingTime: number;
  errorRate: number;
  memoryUsage: number;
  cpuUsage: number;
  lastActivity: Date;
  status: WorkerStatus;
}

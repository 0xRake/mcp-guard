/**
 * Fault Tolerance Module
 * Enterprise-grade fault tolerance and recovery for distributed scanning
 */

import { EventEmitter } from 'events';
import {
  FaultToleranceConfig,
  RetryPolicy,
  WorkerStatus,
  WorkerMetrics,
  CheckpointData,
  ScanPhase,
  WorkerState
} from '../interfaces/distributed-interfaces';

export class FaultToleranceManager extends EventEmitter {
  private config: FaultToleranceConfig;
  private workerStates: Map<number, WorkerState> = new Map();
  private circuitBreakerStates: Map<number, CircuitBreakerState> = new Map();
  private checkpoints: Map<string, CheckpointData> = new Map();
  private recoveryAttempts: Map<string, number> = new Map();
  private alertQueue: Alert[] = [];

  constructor(config: FaultToleranceConfig) {
    super();
    this.config = config;
    this.initializeCircuitBreakers();
  }

  /**
   * Initialize circuit breakers for all workers
   */
  private initializeCircuitBreakers(): void {
    for (let i = 0; i < 16; i++) {
      this.circuitBreakerStates.set(i, {
        workerId: i,
        state: 'CLOSED',
        failureCount: 0,
        lastFailureTime: null,
        nextAttemptTime: null,
        totalRequests: 0,
        successfulRequests: 0,
        recoveryThreshold: 5
      });
    }
  }

  /**
   * Monitor worker health and trigger recovery if needed
   */
  async monitorWorkerHealth(workerId: number, metrics: WorkerMetrics): Promise<HealthStatus> {
    const circuitBreaker = this.circuitBreakerStates.get(workerId);
    if (!circuitBreaker) {
      throw new Error(`Circuit breaker not found for worker ${workerId}`);
    }

    // Update circuit breaker state
    this.updateCircuitBreaker(circuitBreaker, metrics);

    // Update worker state
    this.updateWorkerState(workerId, metrics);

    // Check if recovery is needed
    const needsRecovery = this.assessRecoveryNeed(workerId, metrics);
    
    if (needsRecovery) {
      await this.triggerRecovery(workerId);
    }

    return {
      healthy: this.isWorkerHealthy(workerId, metrics),
      needsRecovery,
      circuitBreakerState: circuitBreaker.state,
      errorRate: metrics.errorRate,
      lastHeartbeat: metrics.lastActivity
    };
  }

  /**
   * Create checkpoint for recovery
   */
  async createCheckpoint(scanId: string, partitionId: string, data: any): Promise<CheckpointData> {
    const checkpoint: CheckpointData = {
      scanId,
      completedPartitions: [],
      failedPartitions: [],
      workerStates: new Map(),
      progress: {
        totalConfigurations: 0,
        processedConfigurations: 0,
        completedPartitions: 0,
        totalPartitions: 0,
        currentPhase: ScanPhase.PROCESSING,
        throughput: 0
      },
      timestamp: new Date(),
      nextPartitionIndex: 0,
      totalPartitions: 0
    };

    // Merge with existing checkpoint if available
    const existing = this.checkpoints.get(scanId);
    if (existing) {
      checkpoint.completedPartitions = [...existing.completedPartitions];
      checkpoint.failedPartitions = [...existing.failedPartitions];
      checkpoint.workerStates = new Map(existing.workerStates);
      checkpoint.progress = { ...existing.progress };
      checkpoint.nextPartitionIndex = existing.nextPartitionIndex;
      checkpoint.totalPartitions = existing.totalPartitions;
    }

    // Add current partition
    if (!checkpoint.completedPartitions.includes(partitionId)) {
      checkpoint.completedPartitions.push(partitionId);
      checkpoint.progress.completedPartitions++;
    }

    this.checkpoints.set(scanId, checkpoint);
    this.emit('checkpointCreated', checkpoint);

    return checkpoint;
  }

  /**
   * Recover from checkpoint
   */
  async recoverFromCheckpoint(scanId: string): Promise<RecoveryPlan> {
    const checkpoint = this.checkpoints.get(scanId);
    if (!checkpoint) {
      throw new Error(`No checkpoint found for scan ${scanId}`);
    }

    const recoveryAttempts = this.recoveryAttempts.get(scanId) || 0;
    
    if (recoveryAttempts >= this.config.maxWorkerRestarts) {
      throw new Error(`Maximum recovery attempts reached for scan ${scanId}`);
    }

    this.recoveryAttempts.set(scanId, recoveryAttempts + 1);

    // Analyze recovery requirements
    const failedWorkers = this.identifyFailedWorkers(checkpoint);
    const availableWorkers = this.identifyAvailableWorkers();
    const requiredWorkers = this.determineRequiredWorkers(checkpoint);

    const recoveryPlan: RecoveryPlan = {
      scanId,
      checkpoint,
      failedWorkers,
      availableWorkers,
      requiredWorkers,
      estimatedRecoveryTime: this.estimateRecoveryTime(checkpoint),
      strategy: this.selectRecoveryStrategy(checkpoint, failedWorkers.length),
      canProceed: failedWorkers.length < requiredWorkers
    };

    this.emit('recoveryInitiated', recoveryPlan);
    return recoveryPlan;
  }

  /**
   * Execute retry logic with exponential backoff
   */
  async executeWithRetry<T>(
    operation: () => Promise<T>,
    context: RetryContext
  ): Promise<T> {
    let lastError: Error | undefined;
    
    for (let attempt = 1; attempt <= this.config.retryPolicy.maxAttempts; attempt++) {
      try {
        const result = await this.executeWithTimeout(operation, context);
        this.onRetrySuccess(context.operationId);
        return result;
      } catch (error) {
        lastError = error as Error;
        
        if (!this.isRetryableError(error as Error, context)) {
          throw error;
        }

        if (attempt === this.config.retryPolicy.maxAttempts) {
          break;
        }

        const delay = this.calculateRetryDelay(attempt);
        await this.delay(delay);
        
        this.emit('retryScheduled', {
          context,
          attempt,
          nextAttempt: attempt + 1,
          delay,
          error: error
        });
      }
    }

    this.onRetryFailure(context.operationId);
    throw new Error(`Operation failed after ${this.config.retryPolicy.maxAttempts} attempts: ${lastError?.message}`);
  }

  /**
   * Handle worker failure with graceful degradation
   */
  async handleWorkerFailure(workerId: number, error: Error): Promise<FailureHandlingResult> {
    const circuitBreaker = this.circuitBreakerStates.get(workerId);
    if (circuitBreaker) {
      circuitBreaker.failureCount++;
      circuitBreaker.lastFailureTime = new Date();
      circuitBreaker.state = this.determineCircuitBreakerState(circuitBreaker);
    }

    // Update worker state
    const workerState = this.workerStates.get(workerId);
    if (workerState) {
      workerState.status = WorkerStatus.FAILED;
      workerState.retryCount++;
    }

    // Determine handling strategy
    const strategy = this.selectFailureHandlingStrategy(workerId, error);
    
    const result: FailureHandlingResult = {
      workerId,
      handled: true,
      strategy,
      shouldRestart: this.shouldRestartWorker(workerId, error),
      shouldRedistribute: this.shouldRedistributeWork(workerId),
      estimatedRecoveryTime: this.estimateWorkerRecoveryTime(workerId),
      alternativeWorkers: this.findAlternativeWorkers(workerId)
    };

    this.emit('workerFailed', { workerId, error, result });

    if (this.config.alertOnFailure) {
      await this.sendAlert({
        type: 'WORKER_FAILURE',
        severity: 'HIGH',
        workerId,
        error: error.message,
        timestamp: new Date(),
        metadata: { strategy }
      });
    }

    return result;
  }

  /**
   * Graceful shutdown with health checks
   */
  async gracefulShutdown(timeoutMs: number = 30000): Promise<ShutdownResult> {
    const startTime = Date.now();
    const workers = Array.from(this.workerStates.keys());
    const shutdownPromises = workers.map(workerId => 
      this.shutdownWorker(workerId, timeoutMs)
    );

    const results = await Promise.allSettled(shutdownPromises);
    
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    const result: ShutdownResult = {
      successfulShutdowns: successful,
      failedShutdowns: failed,
      totalWorkers: workers.length,
      duration: Date.now() - startTime,
      results: results.map((r, i) => ({
        workerId: workers[i]!,
        success: r.status === 'fulfilled',
        error: r.status === 'rejected' ? (r.reason as Error).message : undefined
      }))
    };

    this.emit('gracefulShutdown', result);
    return result;
  }

  /**
   * Health check aggregation
   */
  getOverallHealth(): HealthReport {
    const workerStates = Array.from(this.workerStates.values());
    const healthyWorkers = workerStates.filter(ws => ws.status === WorkerStatus.IDLE || ws.status === WorkerStatus.PROCESSING);
    const failedWorkers = workerStates.filter(ws => ws.status === WorkerStatus.FAILED);
    
    const healthPercentage = workerStates.length > 0 
      ? (healthyWorkers.length / workerStates.length) * 100 
      : 100;

    const circuitBreakerStats = this.getCircuitBreakerStatistics();

    return {
      overallHealth: healthPercentage,
      healthyWorkers: healthyWorkers.length,
      failedWorkers: failedWorkers.length,
      totalWorkers: workerStates.length,
      circuitBreakerStats,
      recentAlerts: this.alertQueue.slice(-10),
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      activeCheckpoints: this.checkpoints.size
    };
  }

  private updateCircuitBreaker(circuitBreaker: CircuitBreakerState, metrics: WorkerMetrics): void {
    circuitBreaker.totalRequests++;

    if (metrics.errorRate < 0.1) {
      circuitBreaker.successfulRequests++;
    }

    if (circuitBreaker.state === 'OPEN' && circuitBreaker.lastFailureTime) {
      const timeSinceFailure = Date.now() - circuitBreaker.lastFailureTime.getTime();
      if (timeSinceFailure > this.config.circuitBreakerTimeout) {
        circuitBreaker.state = 'HALF_OPEN';
      }
    } else if (circuitBreaker.state === 'HALF_OPEN') {
      if (metrics.errorRate < 0.05) {
        circuitBreaker.state = 'CLOSED';
        circuitBreaker.failureCount = 0;
      } else {
        circuitBreaker.state = 'OPEN';
        circuitBreaker.lastFailureTime = new Date();
      }
    }
  }

  private updateWorkerState(workerId: number, metrics: WorkerMetrics): void {
    const existingState = this.workerStates.get(workerId) || {
      workerId,
      status: WorkerStatus.IDLE,
      lastHeartbeat: new Date(),
      processedPartitions: [],
      failedPartitions: [],
      retryCount: 0,
      performance: {
        partitionsProcessed: 0,
        averageProcessingTime: 0,
        successRate: 100,
        lastActivity: new Date(),
        errorCount: 0
      }
    };

    existingState.lastHeartbeat = metrics.lastActivity;
    existingState.performance = metrics as any;
    
    if (metrics.errorRate > 0.5) {
      existingState.status = WorkerStatus.FAILED;
    } else if (metrics.errorRate > 0.2) {
      existingState.status = WorkerStatus.RECOVERING;
    } else {
      existingState.status = WorkerStatus.PROCESSING;
    }

    this.workerStates.set(workerId, existingState);
  }

  private assessRecoveryNeed(workerId: number, metrics: WorkerMetrics): boolean {
    const workerState = this.workerStates.get(workerId);
    const circuitBreaker = this.circuitBreakerStates.get(workerId);

    if (!workerState || !circuitBreaker) return false;

    return (
      workerState.status === WorkerStatus.FAILED ||
      circuitBreaker.state === 'OPEN' ||
      metrics.errorRate > 0.8 ||
      (Date.now() - metrics.lastActivity.getTime()) > 60000
    );
  }

  private isWorkerHealthy(workerId: number, metrics: WorkerMetrics): boolean {
    const circuitBreaker = this.circuitBreakerStates.get(workerId);
    
    return (
      circuitBreaker?.state !== 'OPEN' &&
      metrics.errorRate < 0.5 &&
      (Date.now() - metrics.lastActivity.getTime()) < 30000
    );
  }

  private async triggerRecovery(workerId: number): Promise<void> {
    const workerState = this.workerStates.get(workerId);
    if (!workerState) return;

    workerState.status = WorkerStatus.RECOVERING;
    
    await this.delay(this.config.restartDelay);
    
    if (this.config.autoRecovery) {
      workerState.status = WorkerStatus.IDLE;
      this.emit('workerRecovered', workerId);
    }
  }

  private determineCircuitBreakerState(circuitBreaker: CircuitBreakerState): CircuitBreakerState['state'] {
    if (circuitBreaker.failureCount >= this.config.circuitBreakerThreshold) {
      return 'OPEN';
    }
    return 'CLOSED';
  }

  private selectFailureHandlingStrategy(workerId: number, error: Error): FailureHandlingStrategy {
    const circuitBreaker = this.circuitBreakerStates.get(workerId);
    
    if (circuitBreaker?.state === 'OPEN') {
      return 'CIRCUIT_BREAKER';
    }

    if (error.message.includes('timeout')) {
      return 'TIMEOUT_RETRY';
    }

    if (error.message.includes('memory')) {
      return 'MEMORY_CLEANUP';
    }

    return 'RESTART_WORKER';
  }

  private shouldRestartWorker(workerId: number, error: Error): boolean {
    const circuitBreaker = this.circuitBreakerStates.get(workerId);
    
    if (circuitBreaker?.state === 'OPEN') {
      return false;
    }

    if (error.message.includes('fatal')) {
      return false;
    }

    return true;
  }

  private shouldRedistributeWork(workerId: number): boolean {
    const workerState = this.workerStates.get(workerId);
    return workerState?.status === WorkerStatus.FAILED;
  }

  private estimateWorkerRecoveryTime(workerId: number): number {
    const circuitBreaker = this.circuitBreakerStates.get(workerId);
    
    if (circuitBreaker?.state === 'OPEN') {
      return this.config.circuitBreakerTimeout;
    }

    return this.config.restartDelay;
  }

  private findAlternativeWorkers(workerId: number): number[] {
    const alternatives: number[] = [];
    
    for (const [id, state] of this.workerStates) {
      if (id !== workerId && state.status === WorkerStatus.IDLE) {
        alternatives.push(id);
      }
    }

    return alternatives;
  }

  private async shutdownWorker(workerId: number, timeoutMs: number): Promise<void> {
    const workerState = this.workerStates.get(workerId);
    if (workerState?.status === WorkerStatus.PROCESSING) {
      await this.delay(timeoutMs);
    }
  }

  private isRetryableError(error: Error, context: RetryContext): boolean {
    const retryableErrors = this.config.retryPolicy.retryableErrors;
    const errorMessage = error.message.toLowerCase();
    
    return retryableErrors.some(retryable => 
      errorMessage.includes(retryable.toLowerCase())
    );
  }

  private calculateRetryDelay(attempt: number): number {
    const baseDelay = this.config.retryPolicy.baseDelay;
    const maxDelay = this.config.retryPolicy.maxDelay;
    const backoffMultiplier = this.config.retryPolicy.backoffMultiplier;
    
    let delay = baseDelay * Math.pow(backoffMultiplier, attempt - 1);
    
    if (this.config.retryPolicy.jitter) {
      delay *= (0.5 + Math.random() * 0.5);
    }
    
    return Math.min(delay, maxDelay);
  }

  private async executeWithTimeout<T>(operation: () => Promise<T>, context: RetryContext): Promise<T> {
    const timeout = setTimeout(() => {
      throw new Error(`Operation timed out after ${context.timeout}ms`);
    }, context.timeout);

    try {
      const result = await operation();
      clearTimeout(timeout);
      return result;
    } catch (error) {
      clearTimeout(timeout);
      throw error;
    }
  }

  private onRetrySuccess(operationId: string): void {
    const parts = operationId.split('-');
    const workerId = parseInt(parts[1] || '0');
    const state = this.workerStates.get(workerId);
    if (state) {
      state.retryCount = 0;
    }
  }

  private onRetryFailure(operationId: string): void {
    const parts = operationId.split('-');
    const workerId = parseInt(parts[1] || '0');
    const state = this.workerStates.get(workerId);
    if (state) {
      state.retryCount++;
    }
  }

  private async delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private async sendAlert(alert: Alert): Promise<void> {
    this.alertQueue.push(alert);
    this.emit('alert', alert);
  }

  private getCircuitBreakerStatistics(): CircuitBreakerStats {
    const states = Array.from(this.circuitBreakerStates.values());
    
    return {
      total: states.length,
      closed: states.filter(s => s.state === 'CLOSED').length,
      open: states.filter(s => s.state === 'OPEN').length,
      halfOpen: states.filter(s => s.state === 'HALF_OPEN').length,
      totalFailures: states.reduce((sum, s) => sum + s.failureCount, 0),
      totalRequests: states.reduce((sum, s) => sum + s.totalRequests, 0),
      successRate: states.length > 0 
        ? states.reduce((sum, s) => sum + (s.successfulRequests / s.totalRequests), 0) / states.length * 100
        : 100
    };
  }

  private identifyFailedWorkers(checkpoint: CheckpointData): number[] {
    const failedWorkers: number[] = [];
    
    for (const [workerId, state] of checkpoint.workerStates) {
      if (state.status === WorkerStatus.FAILED) {
        failedWorkers.push(workerId);
      }
    }
    
    return failedWorkers;
  }

  private identifyAvailableWorkers(): number[] {
    const available: number[] = [];
    
    for (const [workerId, state] of this.workerStates) {
      if (state.status === WorkerStatus.IDLE) {
        available.push(workerId);
      }
    }
    
    return available;
  }

  private determineRequiredWorkers(checkpoint: CheckpointData): number {
    const totalPartitions = checkpoint.totalPartitions;
    const availableWorkers = this.identifyAvailableWorkers().length;
    
    return Math.min(availableWorkers, Math.max(2, Math.ceil(totalPartitions / 2)));
  }

  private estimateRecoveryTime(checkpoint: CheckpointData): number {
    const failedWorkers = this.identifyFailedWorkers(checkpoint);
    const baseTime = 5000;
    
    return baseTime * (failedWorkers.length + 1);
  }

  private selectRecoveryStrategy(checkpoint: CheckpointData, failedWorkerCount: number): RecoveryStrategy {
    if (failedWorkerCount === 0) {
      return 'NO_RECOVERY_NEEDED';
    }
    
    if (failedWorkerCount <= 2) {
      return 'PARTIAL_RESTART';
    }
    
    if (failedWorkerCount <= checkpoint.totalPartitions / 2) {
      return 'GRADUAL_RECOVERY';
    }
    
    return 'FULL_RESTART';
  }
}

// Supporting interfaces and types
interface CircuitBreakerState {
  workerId: number;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  failureCount: number;
  lastFailureTime: Date | null;
  nextAttemptTime: Date | null;
  totalRequests: number;
  successfulRequests: number;
  recoveryThreshold: number;
}

interface HealthStatus {
  healthy: boolean;
  needsRecovery: boolean;
  circuitBreakerState: string;
  errorRate: number;
  lastHeartbeat: Date;
}

interface RecoveryPlan {
  scanId: string;
  checkpoint: CheckpointData;
  failedWorkers: number[];
  availableWorkers: number[];
  requiredWorkers: number;
  estimatedRecoveryTime: number;
  strategy: RecoveryStrategy;
  canProceed: boolean;
}

interface FailureHandlingResult {
  workerId: number;
  handled: boolean;
  strategy: FailureHandlingStrategy;
  shouldRestart: boolean;
  shouldRedistribute: boolean;
  estimatedRecoveryTime: number;
  alternativeWorkers: number[];
}

interface ShutdownResult {
  successfulShutdowns: number;
  failedShutdowns: number;
  totalWorkers: number;
  duration: number;
  results: Array<{
    workerId: number;
    success: boolean;
    error?: string;
  }>;
}

interface HealthReport {
  overallHealth: number;
  healthyWorkers: number;
  failedWorkers: number;
  totalWorkers: number;
  circuitBreakerStats: CircuitBreakerStats;
  recentAlerts: Alert[];
  uptime: number;
  memoryUsage: NodeJS.MemoryUsage;
  activeCheckpoints: number;
}

interface CircuitBreakerStats {
  total: number;
  closed: number;
  open: number;
  halfOpen: number;
  totalFailures: number;
  totalRequests: number;
  successRate: number;
}

interface Alert {
  type: 'WORKER_FAILURE' | 'CIRCUIT_BREAKER_OPEN' | 'RECOVERY_FAILED';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  workerId?: number;
  error?: string;
  timestamp: Date;
  metadata?: Record<string, any>;
}

interface RetryContext {
  operationId: string;
  timeout: number;
  maxRetries?: number;
}

type FailureHandlingStrategy = 
  | 'CIRCUIT_BREAKER'
  | 'TIMEOUT_RETRY'
  | 'MEMORY_CLEANUP'
  | 'RESTART_WORKER'
  | 'REDISTRIBUTE_WORK';

type RecoveryStrategy = 
  | 'NO_RECOVERY_NEEDED'
  | 'PARTIAL_RESTART'
  | 'GRADUAL_RECOVERY'
  | 'FULL_RESTART';
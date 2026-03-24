/**
 * Distributed Scanning Manager
 * Handles horizontal scaling for enterprise MCP server security scanning
 */

import { Worker } from 'worker_threads';
import * as path from 'path';
import * as os from 'os';
import { EventEmitter } from 'events';
import {
  DistributedScanRequest,
  DistributedScanResult,
  DistributedConfig,
  WorkerMessage,
  WorkerMessageType,
  WorkerResponse,
  PartitionPlan,
  AggregationStrategy,
  FaultToleranceConfig,
  PartitionStrategy
} from './interfaces/distributed-interfaces';
import { ConfigurationPartitioner } from './utils/configuration-partitioner';
import { ResultAggregator } from './utils/result-aggregator';
import { FaultToleranceManager } from './utils/fault-tolerance';
import type { MCPServerConfig, ScanConfig, ScanResult } from '../types';

export class DistributedScanningManager extends EventEmitter {
  private workers: Worker[] = [];
  private workerPoolSize: number;
  private scanQueue: DistributedScanRequest[] = [];
  private activeScans: Map<string, DistributedScanResult[]> = new Map();
  private isProcessing: boolean = false;
  private partitioner: ConfigurationPartitioner;
  private aggregator: ResultAggregator;
  private faultTolerance: FaultToleranceManager;
  private config: DistributedConfig;

  constructor(config?: Partial<DistributedConfig>) {
    super();
    
    this.config = this.createDefaultConfig(config);
    this.workerPoolSize = this.config.workerPoolSize;
    
    this.partitioner = new ConfigurationPartitioner(this.config);
    this.aggregator = new ResultAggregator();
    this.faultTolerance = new FaultToleranceManager(this.getDefaultFaultToleranceConfig());
    
    this.initializeWorkerPool();
    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.faultTolerance.on('workerFailed', (data) => {
      this.emit('workerFailed', data);
    });

    this.faultTolerance.on('workerRecovered', (workerId) => {
      this.emit('workerRecovered', workerId);
    });

    this.faultTolerance.on('checkpointCreated', (checkpoint) => {
      this.emit('checkpointCreated', checkpoint);
    });
  }

  private createDefaultConfig(overrides?: Partial<DistributedConfig>): DistributedConfig {
    return {
      workerPoolSize: Math.max(2, Math.min(os.cpus().length, 8)),
      maxRetries: 3,
      retryDelay: 1000,
      checkpointInterval: 30000,
      batchSize: 10,
      enableFaultTolerance: true,
      enableIncrementalScans: true,
      resultRetentionPeriod: 3600000,
      workerTimeout: 60000,
      heartbeatInterval: 30000,
      partitionStrategy: PartitionStrategy.ADAPTIVE,
      aggregationStrategy: AggregationStrategy.CORRELATED,
      ...overrides
    };
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

  private initializeWorkerPool(): void {
    for (let i = 0; i < this.workerPoolSize; i++) {
      const worker = new Worker(
        path.join(__dirname, '../workers/scanner-worker.js'),
        {
          workerData: { workerId: i }
        }
      );

      worker.on('message', (result: DistributedScanResult) => {
        this.handleWorkerResult(result);
      });

      worker.on('error', (error) => {
        console.error(`Worker ${i} error:`, error);
        this.handleWorkerError(i, error);
      });

      worker.on('exit', (code) => {
        if (code !== 0) {
          console.error(`Worker ${i} exited with code ${code}`);
          this.restartWorker(i);
        }
      });

      this.workers.push(worker);
    }
  }

  async distributeScan(request: DistributedScanRequest): Promise<DistributedScanResult[]> {
    return new Promise((resolve, reject) => {
      this.scanQueue.push(request);
      this.activeScans.set(request.id, []);

      this.processScanQueue()
        .then(() => {
          const results = this.activeScans.get(request.id) || [];
          this.activeScans.delete(request.id);
          resolve(results);
        })
        .catch(reject);
    });
  }

  private async processScanQueue(): Promise<void> {
    if (this.isProcessing) return;
    
    this.isProcessing = true;

    while (this.scanQueue.length > 0) {
      const request = this.scanQueue.shift()!;
      
      // Distribute configurations across available workers
      const configurationsByPriority = this.sortByPriority(request.configurations);
      const batches = this.createBatches(configurationsByPriority, this.workerPoolSize);

      const batchPromises = batches.map((batch, batchIndex) => 
        this.processBatch(request, batch, batchIndex)
      );

      await Promise.all(batchPromises);
    }

    this.isProcessing = false;
  }

  private sortByPriority(configurations: DistributedScanRequest['configurations']) {
    return configurations.sort((a, b) => {
      const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });
  }

  private createBatches(configurations: any[], workerCount: number): any[][] {
    const batches: any[][] = [];
    
    for (let i = 0; i < workerCount; i++) {
      batches.push([]);
    }

    configurations.forEach((config, index) => {
      const batchIndex = index % workerCount;
      if (batches[batchIndex]) {
        batches[batchIndex].push(config);
      }
    });

    return batches;
  }

  private async processBatch(request: DistributedScanRequest, batch: any[], batchIndex: number): Promise<void> {
    const workerPromises = batch.map((config, configIndex) => {
      const workerIndex = (batchIndex * this.workerPoolSize + configIndex) % this.workers.length;
      return this.processWithWorker(workerIndex, request, config);
    });

    await Promise.all(workerPromises);
  }

  private async processWithWorker(workerIndex: number, request: DistributedScanRequest, config: any): Promise<void> {
    return new Promise((resolve, reject) => {
      const worker = this.workers[workerIndex];
      
      if (!worker) {
        reject(new Error(`Worker ${workerIndex} not available`));
        return;
      }
      
      const timeout = setTimeout(() => {
        reject(new Error(`Scan timeout for ${config.serverName}`));
      }, request.options.timeout || 30000);

      const messageHandler = (result: DistributedScanResult) => {
        if (result.serverName === config.serverName) {
          clearTimeout(timeout);
          worker.removeListener('message', messageHandler);
          
          const currentResults = this.activeScans.get(request.id) || [];
          currentResults.push(result);
          this.activeScans.set(request.id, currentResults);
          
          this.emit('scanComplete', result);
          resolve();
        }
      };

      worker.addListener('message', messageHandler);
      worker.postMessage({
        type: 'SCAN_REQUEST',
        request: {
          ...request,
          config,
          workerId: workerIndex
        }
      });
    });
  }

  private handleWorkerResult(result: DistributedScanResult): void {
    this.emit('workerResult', result);
  }

  private handleWorkerError(workerId: number, error: Error): void {
    this.emit('workerError', { workerId, error });
    this.restartWorker(workerId);
  }

  private restartWorker(workerId: number): void {
    const oldWorker = this.workers[workerId];
    if (oldWorker) {
      oldWorker.terminate();
    }

    const newWorker = new Worker(
      path.join(__dirname, '../workers/scanner-worker.js'),
      {
        workerData: { workerId }
      }
    );

    // Setup event handlers for new worker
    newWorker.on('message', (result: DistributedScanResult) => {
      this.handleWorkerResult(result);
    });

    newWorker.on('error', (error) => {
      this.handleWorkerError(workerId, error);
    });

    this.workers[workerId] = newWorker;
  }

  public getStatus() {
    return {
      workerPoolSize: this.workerPoolSize,
      activeWorkers: this.workers.length,
      queuedScans: this.scanQueue.length,
      activeScans: this.activeScans.size
    };
  }

  public shutdown(): void {
    this.workers.forEach(worker => {
      worker.terminate();
    });
    this.workers = [];
  }
}
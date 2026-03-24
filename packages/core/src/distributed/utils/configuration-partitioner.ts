/**
 * Configuration Partitioner
 * Handles intelligent configuration partitioning for distributed scanning
 */

import * as crypto from 'crypto';
import {
  DistributedConfiguration,
  PartitionStrategy,
  PartitionPlan,
  Partition,
  ConfigurationFingerprint,
  DistributedConfig
} from '../interfaces/distributed-interfaces';
import type { MCPServerConfig, ScanConfig } from '../../types';

export class ConfigurationPartitioner {
  private config: DistributedConfig;

  constructor(config: DistributedConfig) {
    this.config = config;
  }

  /**
   * Create a partition plan for distributed scanning
   */
  createPartitionPlan(
    configurations: Record<string, MCPServerConfig>,
    scanConfig: ScanConfig
  ): PartitionPlan {
    const distributedConfigs = this.createDistributedConfigurations(configurations, scanConfig);
    
    switch (this.config.partitionStrategy) {
      case PartitionStrategy.PRIORITY_BASED:
        return this.createPriorityBasedPartition(distributedConfigs);
      
      case PartitionStrategy.DOMAIN_BASED:
        return this.createDomainBasedPartition(distributedConfigs);
      
      case PartitionStrategy.SIZE_BASED:
        return this.createSizeBasedPartition(distributedConfigs);
      
      case PartitionStrategy.HASH_BASED:
        return this.createHashBasedPartition(distributedConfigs);
      
      case PartitionStrategy.ADAPTIVE:
        return this.createAdaptivePartition(distributedConfigs);
      
      default:
        return this.createPriorityBasedPartition(distributedConfigs);
    }
  }

  /**
   * Create distributed configurations from server configs
   */
  private createDistributedConfigurations(
    serverConfigs: Record<string, MCPServerConfig>,
    scanConfig: ScanConfig
  ): DistributedConfiguration[] {
    return Object.entries(serverConfigs).map(([serverName, config], index) => {
      const fingerprint = this.generateConfigurationFingerprint(config, serverName);
      const domains = this.identifySecurityDomains(config);
      
      return {
        id: `config-${index}`,
        serverName,
        config,
        priority: this.determinePriority(config),
        domains,
        partitionKey: this.generatePartitionKey(config, domains),
        fingerprint: fingerprint.hash,
        estimatedSize: this.estimateConfigurationSize(config)
      };
    });
  }

  /**
   * Generate configuration fingerprint for incremental scanning
   */
  generateConfigurationFingerprint(
    config: MCPServerConfig,
    serverName: string
  ): ConfigurationFingerprint {
    const configString = JSON.stringify(config);
    const checksum = crypto
      .createHash('sha256')
      .update(configString)
      .digest('hex');
    
    const hash = crypto
      .createHash('sha256')
      .update(`${serverName}:${checksum}`)
      .digest('hex');

    return {
      hash,
      timestamp: new Date(),
      serverName,
      configSize: configString.length,
      domains: this.identifySecurityDomains(config),
      checksum,
      version: '1.0.0'
    };
  }

  /**
   * Create priority-based partition plan
   */
  private createPriorityBasedPartition(configs: DistributedConfiguration[]): PartitionPlan {
    const sortedConfigs = [...configs].sort((a, b) => {
      const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });

    const partitions: Partition[] = [];
    const partitionCount = Math.min(this.config.workerPoolSize, Math.ceil(sortedConfigs.length / this.config.batchSize));
    
    for (let i = 0; i < partitionCount; i++) {
      const batch = sortedConfigs.slice(i * this.config.batchSize, (i + 1) * this.config.batchSize);
      
      if (batch.length > 0) {
        const priority = batch[0]!.priority;
        partitions.push({
          id: `priority-partition-${i}`,
          configurations: batch,
          priority,
          estimatedSize: batch.reduce((sum, c) => sum + c.estimatedSize, 0),
          estimatedTime: this.estimateProcessingTime(batch),
          dependencies: [],
          retryCount: 0,
          maxRetries: this.config.maxRetries
        });
      }
    }

    return {
      partitions,
      totalSize: sortedConfigs.reduce((sum, c) => sum + c.estimatedSize, 0),
      estimatedTime: this.estimateProcessingTime(sortedConfigs),
      strategy: this.config.partitionStrategy,
      loadBalanceScore: this.calculateLoadBalanceScore(partitions)
    };
  }

  /**
   * Create domain-based partition plan
   */
  private createDomainBasedPartition(configs: DistributedConfiguration[]): PartitionPlan {
    const domainGroups = new Map<string, DistributedConfiguration[]>();
    
    configs.forEach(config => {
      config.domains.forEach(domain => {
        if (!domainGroups.has(domain)) {
          domainGroups.set(domain, []);
        }
        domainGroups.get(domain)!.push(config);
      });
    });

    const partitions: Partition[] = [];
    let partitionIndex = 0;

    for (const [domain, domainConfigs] of domainGroups) {
      const batchedConfigs = this.createBatches(domainConfigs, this.config.batchSize);
      
    batchedConfigs.forEach(batch => {
      if (batch.length > 0) {
        const priority = batch[0]!.priority;
        partitions.push({
          id: `domain-${domain}-partition-${partitionIndex++}`,
          configurations: batch,
          priority,
          estimatedSize: batch.reduce((sum, c) => sum + c.estimatedSize, 0),
          estimatedTime: this.estimateProcessingTime(batch),
          dependencies: [],
          retryCount: 0,
          maxRetries: this.config.maxRetries
        });
      }
    });
    }

    return {
      partitions,
      totalSize: configs.reduce((sum, c) => sum + c.estimatedSize, 0),
      estimatedTime: this.estimateProcessingTime(configs),
      strategy: this.config.partitionStrategy,
      loadBalanceScore: this.calculateLoadBalanceScore(partitions)
    };
  }

  /**
   * Create size-based partition plan
   */
  private createSizeBasedPartition(configs: DistributedConfiguration[]): PartitionPlan {
    const sortedBySize = [...configs].sort((a, b) => b.estimatedSize - a.estimatedSize);
    const partitions: Partition[] = [];
    
    let currentPartition: DistributedConfiguration[] = [];
    let currentSize = 0;
    const targetSize = this.calculateTargetPartitionSize(sortedBySize);
    let partitionIndex = 0;

    for (const config of sortedBySize) {
      if (currentSize + config.estimatedSize > targetSize && currentPartition.length > 0) {
        partitions.push(this.createPartitionFromBatch(currentPartition, partitionIndex++));
        currentPartition = [];
        currentSize = 0;
      }
      
      currentPartition.push(config);
      currentSize += config.estimatedSize;
    }

    if (currentPartition.length > 0) {
      partitions.push(this.createPartitionFromBatch(currentPartition, partitionIndex++));
    }

    return {
      partitions,
      totalSize: configs.reduce((sum, c) => sum + c.estimatedSize, 0),
      estimatedTime: this.estimateProcessingTime(configs),
      strategy: this.config.partitionStrategy,
      loadBalanceScore: this.calculateLoadBalanceScore(partitions)
    };
  }

  /**
   * Create hash-based partition plan
   */
  private createHashBasedPartition(configs: DistributedConfiguration[]): PartitionPlan {
    const partitions: Partition[] = [];
    const partitionCount = Math.min(this.config.workerPoolSize, Math.ceil(configs.length / this.config.batchSize));
    
    for (let i = 0; i < partitionCount; i++) {
      partitions.push({
        id: `hash-partition-${i}`,
        configurations: [],
        priority: 'medium',
        estimatedSize: 0,
        estimatedTime: 0,
        dependencies: [],
        retryCount: 0,
        maxRetries: this.config.maxRetries
      });
    }

    configs.forEach((config, index) => {
      const partitionIndex = this.hashToPartition(config.partitionKey, partitionCount);
      const partition = partitions[partitionIndex];
      if (partition) {
        partition.configurations.push(config);
      }
    });

    partitions.forEach((partition, index) => {
      partition.estimatedSize = partition.configurations.reduce((sum, c) => sum + c.estimatedSize, 0);
      partition.estimatedTime = this.estimateProcessingTime(partition.configurations);
      partition.priority = partition.configurations[0]?.priority || 'medium';
    });

    return {
      partitions,
      totalSize: configs.reduce((sum, c) => sum + c.estimatedSize, 0),
      estimatedTime: this.estimateProcessingTime(configs),
      strategy: this.config.partitionStrategy,
      loadBalanceScore: this.calculateLoadBalanceScore(partitions)
    };
  }

  /**
   * Create adaptive partition plan based on runtime metrics
   */
  private createAdaptivePartition(configs: DistributedConfiguration[]): PartitionPlan {
    const historicalMetrics = this.getHistoricalMetrics();
    const adaptiveStrategy = this.determineAdaptiveStrategy(configs, historicalMetrics);
    
    switch (adaptiveStrategy) {
      case 'priority':
        return this.createPriorityBasedPartition(configs);
      case 'domain':
        return this.createDomainBasedPartition(configs);
      case 'size':
        return this.createSizeBasedPartition(configs);
      case 'hash':
        return this.createHashBasedPartition(configs);
      default:
        return this.createPriorityBasedPartition(configs);
    }
  }

  /**
   * Identify security domains for a configuration
   */
  private identifySecurityDomains(config: MCPServerConfig): string[] {
    const domains: string[] = ['basic'];

    if (config.auth) {
      domains.push('authentication');
      if (config.auth.type === 'basic') {
        domains.push('weak-authentication');
      }
    }

    if (config.oauth) {
      domains.push('oauth');
      if (config.oauth.pkce === false) {
        domains.push('oauth-security');
      }
    }

    if (config.command) {
      domains.push('command-execution');
      if (config.args && config.args.length > 0) {
        domains.push('command-args');
      }
    }

    if (config.env) {
      domains.push('environment');
      const hasSecrets = Object.keys(config.env).some(key => 
        /secret|key|token|password/i.test(key)
      );
      if (hasSecrets) {
        domains.push('secret-management');
      }
    }

    if (config.capabilities) {
      if (config.capabilities.tools) domains.push('tool-capabilities');
      if (config.capabilities.resources) domains.push('resource-capabilities');
      if (config.capabilities.prompts) domains.push('prompt-capabilities');
    }

    return domains;
  }

  /**
   * Determine priority for a configuration
   */
  private determinePriority(config: MCPServerConfig): 'critical' | 'high' | 'medium' | 'low' {
    let score = 0;

    if (config.oauth?.pkce === false) score += 3;
    if (config.auth?.type === 'basic') score += 2;
    if (config.command && /curl|wget|nc|netcat/i.test(config.command)) score += 4;
    if (config.env) {
      const hasSecrets = Object.keys(config.env).some(key => 
        /secret|key|token|password/i.test(key)
      );
      if (hasSecrets) score += 3;
    }

    if (score >= 7) return 'critical';
    if (score >= 5) return 'high';
    if (score >= 3) return 'medium';
    return 'low';
  }

  /**
   * Generate partition key for hash-based distribution
   */
  private generatePartitionKey(config: MCPServerConfig, domains: string[]): string {
    const keyData = {
      command: config.command,
      auth: config.auth?.type,
      oauth: !!config.oauth,
      domains: domains.sort()
    };

    return crypto
      .createHash('sha256')
      .update(JSON.stringify(keyData))
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Estimate configuration size for load balancing
   */
  private estimateConfigurationSize(config: MCPServerConfig): number {
    let size = 0;

    size += config.command?.length || 0;
    size += (config.args || []).join(' ').length;
    size += JSON.stringify(config.env || {}).length;
    size += JSON.stringify(config.oauth || {}).length;
    size += JSON.stringify(config.capabilities || {}).length;

    return Math.max(size, 1024);
  }

  /**
   * Estimate processing time for a batch
   */
  private estimateProcessingTime(configs: DistributedConfiguration[]): number {
    const baseTime = 100;
    const complexityMultiplier = configs.reduce((sum, config) => {
      let complexity = 1;
      complexity += config.domains.length * 0.1;
      complexity += config.estimatedSize / 10240;
      return sum + complexity;
    }, 0);

    return baseTime * complexityMultiplier;
  }

  /**
   * Calculate target partition size for size-based partitioning
   */
  private calculateTargetPartitionSize(configs: DistributedConfiguration[]): number {
    const totalSize = configs.reduce((sum, c) => sum + c.estimatedSize, 0);
    const partitionCount = Math.min(this.config.workerPoolSize, Math.ceil(configs.length / this.config.batchSize));
    return totalSize / partitionCount;
  }

  /**
   * Create batches from configurations
   */
  private createBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  /**
   * Create partition from batch
   */
  private createPartitionFromBatch(
    configs: DistributedConfiguration[], 
    index: number
  ): Partition {
    return {
      id: `size-partition-${index}`,
      configurations: configs,
      priority: configs[0]?.priority || 'medium',
      estimatedSize: configs.reduce((sum, c) => sum + c.estimatedSize, 0),
      estimatedTime: this.estimateProcessingTime(configs),
      dependencies: [],
      retryCount: 0,
      maxRetries: this.config.maxRetries
    };
  }

  /**
   * Hash configuration to partition
   */
  private hashToPartition(partitionKey: string, partitionCount: number): number {
    const hash = parseInt(partitionKey.substring(0, 8), 16);
    return hash % partitionCount;
  }

  /**
   * Calculate load balance score
   */
  private calculateLoadBalanceScore(partitions: Partition[]): number {
    if (partitions.length === 0) return 100;

    const sizes = partitions.map(p => p.estimatedSize);
    const avgSize = sizes.reduce((sum, size) => sum + size, 0) / sizes.length;
    
    const variance = sizes.reduce((sum, size) => sum + Math.pow(size - avgSize, 2), 0) / sizes.length;
    const standardDeviation = Math.sqrt(variance);
    
    return Math.max(0, 100 - (standardDeviation / avgSize * 100));
  }

  /**
   * Get historical metrics for adaptive partitioning
   */
  private getHistoricalMetrics(): Record<string, any> {
    return {
      averageProcessingTime: 150,
      throughput: 50,
      errorRate: 0.05,
      loadBalanceEfficiency: 0.85
    };
  }

  /**
   * Determine adaptive strategy based on current conditions
   */
  private determineAdaptiveStrategy(configs: DistributedConfiguration[], metrics: Record<string, any>): string {
    const priorityVariance = this.calculatePriorityVariance(configs);
    const sizeVariance = this.calculateSizeVariance(configs);
    const domainCount = new Set(configs.flatMap(c => c.domains)).size;

    if (priorityVariance > 0.5) return 'priority';
    if (sizeVariance > 0.7) return 'size';
    if (domainCount > 5) return 'domain';
    return 'hash';
  }

  /**
   * Calculate priority variance
   */
  private calculatePriorityVariance(configs: DistributedConfiguration[]): number {
    const priorities = configs.map(c => {
      const order = { critical: 4, high: 3, medium: 2, low: 1 };
      return order[c.priority];
    });

    const avg = priorities.reduce((sum, p) => sum + p, 0) / priorities.length;
    const variance = priorities.reduce((sum, p) => sum + Math.pow(p - avg, 2), 0) / priorities.length;
    return Math.sqrt(variance) / avg;
  }

  /**
   * Calculate size variance
   */
  private calculateSizeVariance(configs: DistributedConfiguration[]): number {
    const sizes = configs.map(c => c.estimatedSize);
    const avg = sizes.reduce((sum, s) => sum + s, 0) / sizes.length;
    const variance = sizes.reduce((sum, s) => sum + Math.pow(s - avg, 2), 0) / sizes.length;
    return Math.sqrt(variance) / avg;
  }

  /**
   * Compare fingerprints for incremental scanning
   */
  compareFingerprints(
    oldFingerprint: ConfigurationFingerprint,
    newFingerprint: ConfigurationFingerprint
  ): {
    changed: boolean;
    changes: string[];
    severity: 'none' | 'minor' | 'major' | 'critical';
  } {
    const changes: string[] = [];
    let severity: 'none' | 'minor' | 'major' | 'critical' = 'none';

    if (oldFingerprint.hash !== newFingerprint.hash) {
      changes.push('Configuration content changed');
      severity = 'minor';
    }

    const oldDomains = new Set(oldFingerprint.domains);
    const newDomains = new Set(newFingerprint.domains);

    const addedDomains = [...newDomains].filter(d => !oldDomains.has(d));
    const removedDomains = [...oldDomains].filter(d => !newDomains.has(d));

    if (addedDomains.length > 0) {
      changes.push(`Added domains: ${addedDomains.join(', ')}`);
      severity = severity === 'none' ? 'minor' : severity;
    }

    if (removedDomains.length > 0) {
      changes.push(`Removed domains: ${removedDomains.join(', ')}`);
      severity = severity === 'none' ? 'minor' : severity;
    }

    if (Math.abs(oldFingerprint.configSize - newFingerprint.configSize) > 1000) {
      changes.push('Significant size change detected');
      severity = severity === 'minor' ? 'major' : severity;
    }

    return {
      changed: changes.length > 0,
      changes,
      severity
    };
  }
}

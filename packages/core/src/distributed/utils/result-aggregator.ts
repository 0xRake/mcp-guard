/**
 * Result Aggregator
 * Handles deduplication, correlation, and aggregation of distributed scan results
 */

import * as crypto from 'crypto';
import {
  DistributedScanResult,
  DistributedVulnerability,
  DeduplicationResult,
  DeduplicationStats,
  ResultCorrelation,
  CorrelationAlgorithm,
  AggregationStrategy,
  DistributedSummary
} from '../interfaces/distributed-interfaces';
import type { ScanResult, Vulnerability, Severity } from '../../types';

export class ResultAggregator {
  private correlationThreshold: number = 0.85;
  private deduplicationWindow: number = 60000;

  constructor(correlationThreshold: number = 0.85) {
    this.correlationThreshold = correlationThreshold;
  }

  /**
   * Aggregate and deduplicate distributed scan results
   */
  aggregateAndDeduplicate(
    results: DistributedScanResult[],
    strategy: AggregationStrategy = AggregationStrategy.BATCHED
  ): {
    aggregatedResult: DistributedScanResult;
    deduplication: DeduplicationResult;
  } {
    const startTime = Date.now();

    switch (strategy) {
      case AggregationStrategy.IMMEDIATE:
        return this.immediateAggregation(results);
      
      case AggregationStrategy.BATCHED:
        return this.batchedAggregation(results);
      
      case AggregationStrategy.PRIORITY:
        return this.priorityAggregation(results);
      
      case AggregationStrategy.CORRELATED:
        return this.correlatedAggregation(results);
      
      default:
        return this.batchedAggregation(results);
    }
  }

  /**
   * Immediate aggregation - process results as they arrive
   */
  private immediateAggregation(results: DistributedScanResult[]): {
    aggregatedResult: DistributedScanResult;
    deduplication: DeduplicationResult;
  } {
    const allVulnerabilities: DistributedVulnerability[] = [];
    let totalExecutionTime = 0;
    let workerCount = 0;

    for (const result of results) {
      allVulnerabilities.push(...result.vulnerabilities);
      totalExecutionTime += result.executionTime;
      workerCount++;
    }

    const deduplicationResult = this.deduplicateVulnerabilities(allVulnerabilities);
    
    const summary = this.calculateAggregatedSummary(deduplicationResult.uniqueResults, workerCount, totalExecutionTime);

    const aggregatedResult: DistributedScanResult = {
      id: this.generateAggregatedId(results[0]?.requestId || 'unknown'),
      requestId: results[0]?.requestId || 'unknown',
      workerId: 0,
      partitionId: 'aggregated',
      serverName: 'multiple',
      vulnerabilities: deduplicationResult.uniqueResults,
      summary,
      executionTime: totalExecutionTime,
      timestamp: new Date(),
      fingerprint: this.generateAggregatedFingerprint(results),
      performance: {
        throughput: results.length / (totalExecutionTime / 1000),
        memoryUsage: 0,
        cpuUsage: 0,
        networkLatency: 0,
        partitionsPerSecond: results.length / (totalExecutionTime / 1000),
        averageLatency: totalExecutionTime / results.length
      }
    };

    return {
      aggregatedResult,
      deduplication: {
        ...deduplicationResult,
        statistics: {
          ...deduplicationResult.statistics,
          processingTime: Date.now() - this.getEarliestTimestamp(results)
        }
      }
    };
  }

  /**
   * Batched aggregation - collect and process in batches
   */
  private batchedAggregation(results: DistributedScanResult[]): {
    aggregatedResult: DistributedScanResult;
    deduplication: DeduplicationResult;
  } {
    const batchSize = Math.ceil(results.length / Math.sqrt(results.length));
    const batches: DistributedScanResult[][] = [];
    
    for (let i = 0; i < results.length; i += batchSize) {
      batches.push(results.slice(i, i + batchSize));
    }

    const batchResults: DistributedVulnerability[] = [];
    let totalExecutionTime = 0;

    for (const batch of batches) {
      const batchVulnerabilities = batch.flatMap((result: DistributedScanResult) => result.vulnerabilities);
      const batchDeduplicated = this.deduplicateVulnerabilities(batchVulnerabilities);
      batchResults.push(...batchDeduplicated.uniqueResults);
      
      const batchMaxTime = Math.max(...batch.map(b => b.executionTime));
      if (batchMaxTime > 0) {
        totalExecutionTime += batchMaxTime;
      }
    }

    const finalDeduplication = this.deduplicateVulnerabilities(batchResults);
    const summary = this.calculateAggregatedSummary(finalDeduplication.uniqueResults, results.length, totalExecutionTime);

    const aggregatedResult: DistributedScanResult = {
      id: this.generateAggregatedId(results[0]?.requestId || 'unknown'),
      requestId: results[0]?.requestId || 'unknown',
      workerId: 0,
      partitionId: 'batched-aggregated',
      serverName: 'multiple',
      vulnerabilities: finalDeduplication.uniqueResults,
      summary,
      executionTime: totalExecutionTime,
      timestamp: new Date(),
      fingerprint: this.generateAggregatedFingerprint(results),
      performance: {
        throughput: results.length / (totalExecutionTime / 1000),
        memoryUsage: 0,
        cpuUsage: 0,
        networkLatency: 0,
        partitionsPerSecond: results.length / (totalExecutionTime / 1000),
        averageLatency: totalExecutionTime / results.length
      }
    };

    return {
      aggregatedResult,
      deduplication: {
        ...finalDeduplication,
        statistics: {
          ...finalDeduplication.statistics,
          processingTime: Date.now() - this.getEarliestTimestamp(results)
        }
      }
    };
  }

  /**
   * Priority aggregation - process high-priority results first
   */
  private priorityAggregation(results: DistributedScanResult[]): {
    aggregatedResult: DistributedScanResult;
    deduplication: DeduplicationResult;
  } {
    const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    
    const sortedResults = [...results].sort((a, b) => {
      const aPriority = this.extractMaxPriority(a.vulnerabilities);
      const bPriority = this.extractMaxPriority(b.vulnerabilities);
      return (priorityOrder[bPriority as keyof typeof priorityOrder] || 1) - 
             (priorityOrder[aPriority as keyof typeof priorityOrder] || 1);
    });

    return this.immediateAggregation(sortedResults);
  }

  /**
   * Correlated aggregation - group related results together
   */
  private correlatedAggregation(results: DistributedScanResult[]): {
    aggregatedResult: DistributedScanResult;
    deduplication: DeduplicationResult;
  } {
    const allVulnerabilities = results.flatMap(result => result.vulnerabilities);
    const correlations = this.correlateVulnerabilities(allVulnerabilities);
    
    const correlatedGroups = this.groupByCorrelation(allVulnerabilities, correlations);
    const aggregatedVulnerabilities = correlatedGroups.map(group => 
      this.mergeCorrelatedVulnerabilities(group)
    );

    const deduplicationResult = this.deduplicateVulnerabilities(aggregatedVulnerabilities);
    const summary = this.calculateAggregatedSummary(
      deduplicationResult.uniqueResults, 
      results.length, 
      Math.max(...results.map(r => r.executionTime))
    );

    const aggregatedResult: DistributedScanResult = {
      id: this.generateAggregatedId(results[0]?.requestId || 'unknown'),
      requestId: results[0]?.requestId || 'unknown',
      workerId: 0,
      partitionId: 'correlated-aggregated',
      serverName: 'multiple',
      vulnerabilities: deduplicationResult.uniqueResults,
      summary,
      executionTime: Math.max(...results.map(r => r.executionTime)),
      timestamp: new Date(),
      fingerprint: this.generateAggregatedFingerprint(results),
      performance: {
        throughput: results.length / (Math.max(...results.map(r => r.executionTime)) / 1000),
        memoryUsage: 0,
        cpuUsage: 0,
        networkLatency: 0,
        partitionsPerSecond: results.length / (Math.max(...results.map(r => r.executionTime)) / 1000),
        averageLatency: Math.max(...results.map(r => r.executionTime)) / results.length
      }
    };

    return {
      aggregatedResult,
      deduplication: {
        ...deduplicationResult,
        correlationGroups: correlations,
        statistics: {
          ...deduplicationResult.statistics,
          correlationAccuracy: this.calculateCorrelationAccuracy(correlations),
          processingTime: Date.now() - this.getEarliestTimestamp(results)
        }
      }
    };
  }

  /**
   * Deduplicate vulnerabilities using multiple strategies
   */
  private deduplicateVulnerabilities(
    vulnerabilities: DistributedVulnerability[]
  ): DeduplicationResult {
    const uniqueVulnerabilities: DistributedVulnerability[] = [];
    const duplicates: DistributedVulnerability[] = [];
    const duplicatesFound = new Set<string>();

    for (const vuln of vulnerabilities) {
      const duplicateKey = this.generateDeduplicationKey(vuln);
      
      if (!duplicatesFound.has(duplicateKey)) {
        duplicatesFound.add(duplicateKey);
        uniqueVulnerabilities.push(vuln);
      } else {
        duplicates.push(vuln);
        const existingVuln = uniqueVulnerabilities.find(u => 
          this.generateDeduplicationKey(u) === duplicateKey
        );
        if (existingVuln) {
          existingVuln.duplicates = existingVuln.duplicates || [];
          existingVuln.duplicates.push(vuln.id);
        }
      }
    }

    const correlationGroups = this.correlateVulnerabilities(uniqueVulnerabilities);

    return {
      duplicatesFound: duplicates.length,
      duplicatesRemoved: duplicates,
      uniqueResults: uniqueVulnerabilities,
      correlationGroups,
      statistics: {
        totalResults: vulnerabilities.length,
        uniqueResults: uniqueVulnerabilities.length,
        duplicateRate: vulnerabilities.length > 0 ? duplicates.length / vulnerabilities.length : 0,
        correlationAccuracy: this.calculateCorrelationAccuracy(correlationGroups),
        processingTime: 0
      }
    };
  }

  /**
   * Generate deduplication key for vulnerability
   */
  private generateDeduplicationKey(vuln: DistributedVulnerability): string {
    const keyData = {
      type: vuln.type,
      title: vuln.title.toLowerCase().replace(/[^a-z0-9]/g, ''),
      server: vuln.server,
      severity: vuln.severity,
      description: vuln.description.substring(0, 100).toLowerCase()
    };

    return crypto
      .createHash('sha256')
      .update(JSON.stringify(keyData))
      .digest('hex');
  }

  /**
   * Correlate vulnerabilities using similarity algorithms
   */
  private correlateVulnerabilities(
    vulnerabilities: DistributedVulnerability[]
  ): ResultCorrelation[] {
    const correlations: ResultCorrelation[] = [];

    for (let i = 0; i < vulnerabilities.length; i++) {
      for (let j = i + 1; j < vulnerabilities.length; j++) {
        const vuln1 = vulnerabilities[i]!;
        const vuln2 = vulnerabilities[j]!;

        const correlation = this.calculateSimilarity(vuln1, vuln2);
        
        if (correlation.confidence >= this.correlationThreshold) {
          correlations.push({
            correlationId: crypto
              .createHash('sha256')
              .update(`${vuln1.id}-${vuln2.id}`)
              .digest('hex')
              .substring(0, 16),
            relatedResults: [vuln1.id, vuln2.id],
            confidence: correlation.confidence,
            reason: correlation.reason,
            algorithm: correlation.algorithm
          });
        }
      }
    }

    return correlations;
  }

  /**
   * Calculate similarity between two vulnerabilities
   */
  private calculateSimilarity(
    vuln1: DistributedVulnerability,
    vuln2: DistributedVulnerability
  ): {
    confidence: number;
    reason: string;
    algorithm: CorrelationAlgorithm;
  } {
    let confidence = 0;
    let reason = '';
    let algorithm: CorrelationAlgorithm = CorrelationAlgorithm.EXACT_MATCH;

    if (vuln1.type === vuln2.type) {
      confidence += 0.3;
      reason = 'Same vulnerability type';
    }

    if (vuln1.title.toLowerCase() === vuln2.title.toLowerCase()) {
      confidence += 0.4;
      reason = reason ? `${reason}, identical title` : 'Identical title';
    }

    if (vuln1.server === vuln2.server) {
      confidence += 0.2;
      reason = reason ? `${reason}, same server` : 'Same server';
    }

    const titleSimilarity = this.calculateStringSimilarity(vuln1.title, vuln2.title);
    if (titleSimilarity > 0.8) {
      confidence += 0.3;
      algorithm = CorrelationAlgorithm.FUZZY_MATCH;
      reason = reason ? `${reason}, similar titles (${titleSimilarity.toFixed(2)})` : `Similar titles (${titleSimilarity.toFixed(2)})`;
    }

    const descSimilarity = this.calculateStringSimilarity(vuln1.description, vuln2.description);
    if (descSimilarity > 0.7) {
      confidence += 0.2;
      algorithm = CorrelationAlgorithm.SEMANTIC_SIMILARITY;
      reason = reason ? `${reason}, similar descriptions` : 'Similar descriptions';
    }

    const patternMatch = this.detectPatternMatch(vuln1, vuln2);
    if (patternMatch) {
      confidence += 0.4;
      algorithm = CorrelationAlgorithm.PATTERN_BASED;
      reason = reason ? `${reason}, matching patterns` : 'Matching patterns';
    }

    return {
      confidence: Math.min(confidence, 1.0),
      reason: reason || 'Low similarity',
      algorithm
    };
  }

  /**
   * Calculate string similarity using Levenshtein distance
   */
  private calculateStringSimilarity(str1: string, str2: string): number {
    const len1 = str1.length;
    const len2 = str2.length;
    
    if (len1 === 0) return len2 === 0 ? 1 : 0;
    if (len2 === 0) return 0;

    const matrix: number[][] = [];
    
    for (let i = 0; i <= len1; i++) {
      matrix[i] = [i];
    }
    
    for (let j = 0; j <= len2; j++) {
      matrix[0]![j] = j;
    }
    
    for (let i = 1; i <= len1; i++) {
      for (let j = 1; j <= len2; j++) {
        if (str1[i - 1] === str2[j - 1]) {
          matrix[i]![j] = matrix[i - 1]![j - 1]!;
        } else {
          matrix[i]![j] = Math.min(
            matrix[i - 1]![j - 1]! + 1,
            matrix[i]![j - 1]! + 1,
            matrix[i - 1]![j]! + 1
          );
        }
      }
    }

    const distance = matrix[len1]![len2]!;
    return 1 - distance / Math.max(len1, len2);
  }

  /**
   * Detect pattern match between vulnerabilities
   */
  private detectPatternMatch(vuln1: DistributedVulnerability, vuln2: DistributedVulnerability): boolean {
    const patterns = [
      /authentication/i,
      /authorization/i,
      /injection/i,
      /exposure/i,
      /misconfiguration/i,
      /weak.*password/i,
      /missing.*encryption/i,
      /insecure.*transmission/i
    ];

    const text1 = `${vuln1.title} ${vuln1.description}`.toLowerCase();
    const text2 = `${vuln2.title} ${vuln2.description}`.toLowerCase();

    return patterns.some(pattern => 
      pattern.test(text1) && pattern.test(text2)
    );
  }

  /**
   * Group vulnerabilities by correlation
   */
  private groupByCorrelation(
    vulnerabilities: DistributedVulnerability[],
    correlations: ResultCorrelation[]
  ): DistributedVulnerability[][] {
    const groups: DistributedVulnerability[][] = [];
    const processed = new Set<string>();

    for (const vuln of vulnerabilities) {
      if (processed.has(vuln.id)) continue;

      const relatedVulns = [vuln];
      processed.add(vuln.id);

      for (const correlation of correlations) {
        if (correlation.relatedResults.includes(vuln.id)) {
          for (const vulnId of correlation.relatedResults) {
            if (!processed.has(vulnId)) {
              const relatedVuln = vulnerabilities.find(v => v.id === vulnId);
              if (relatedVuln) {
                relatedVulns.push(relatedVuln);
                processed.add(vulnId);
              }
            }
          }
        }
      }

      groups.push(relatedVulns);
    }

    for (const vuln of vulnerabilities) {
      if (!processed.has(vuln.id)) {
        groups.push([vuln]);
        processed.add(vuln.id);
      }
    }

    return groups;
  }

  /**
   * Merge correlated vulnerabilities into a single representative vulnerability
   */
  private mergeCorrelatedVulnerabilities(
    group: DistributedVulnerability[]
  ): DistributedVulnerability {
    if (group.length === 1) {
      return group[0]!;
    }

    const representative: DistributedVulnerability = { ...group[0]! };

    representative.id = `merged-${group.map(v => v.id).join('-')}`;
    representative.correlationId = this.generateCorrelationId(group[0]!);
    representative.duplicates = group.slice(1).map(v => v.id);

    const severities = group.map(v => v.severity);
    representative.severity = this.getHighestSeverity(severities);

    const scores = group.map(v => v.score);
    representative.score = Math.max(...scores);

    return representative;
  }

  /**
   * Calculate aggregated summary from distributed results
   */
  private calculateAggregatedSummary(
    vulnerabilities: DistributedVulnerability[],
    workerCount: number,
    totalExecutionTime: number
  ): DistributedSummary {
    const critical = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const high = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const medium = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const low = vulnerabilities.filter(v => v.severity === 'LOW').length;
    const info = vulnerabilities.filter(v => v.severity === 'INFO').length;

    let score = 100;
    score -= critical * 20;
    score -= high * 10;
    score -= medium * 5;
    score -= low * 2;
    score = Math.max(0, score);

    return {
      score,
      grade: this.calculateGrade(score),
      critical,
      high,
      medium,
      low,
      info,
      serversScanned: new Set(vulnerabilities.map(v => v.server)).size,
      partitionsProcessed: workerCount,
      executionTime: totalExecutionTime,
      workerId: 0
    };
  }

  /**
   * Extract maximum priority from vulnerabilities
   */
  private extractMaxPriority(vulnerabilities: DistributedVulnerability[]): 'critical' | 'high' | 'medium' | 'low' {
    const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    let maxPriority: 'critical' | 'high' | 'medium' | 'low' = 'low';

    for (const vuln of vulnerabilities) {
      if (priorityOrder[vuln.severity.toLowerCase() as keyof typeof priorityOrder] > 
          priorityOrder[maxPriority]) {
        maxPriority = vuln.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low';
      }
    }

    return maxPriority;
  }

  /**
   * Get highest severity from list
   */
  private getHighestSeverity(severities: Severity[]): Severity {
    const severityOrder: Record<Severity, number> = {
      'CRITICAL': 4,
      'HIGH': 3,
      'MEDIUM': 2,
      'LOW': 1,
      'INFO': 0
    };

    return severities.reduce((max, current) =>
      severityOrder[current] > severityOrder[max] ? current : max
    );
  }

  /**
   * Calculate grade from score
   */
  private calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * Generate correlation ID
   */
  private generateCorrelationId(vuln: DistributedVulnerability): string {
    return crypto
      .createHash('sha256')
      .update(`${vuln.type}-${vuln.title}-${vuln.server}`)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Generate aggregated ID
   */
  private generateAggregatedId(requestId: string): string {
    return `aggregated-${requestId}-${Date.now()}`;
  }

  /**
   * Generate aggregated fingerprint
   */
  private generateAggregatedFingerprint(results: DistributedScanResult[]): string {
    const fingerprintData = results.map(r => ({
      partitionId: r.partitionId,
      serverName: r.serverName,
      vulnCount: r.vulnerabilities.length
    }));

    return crypto
      .createHash('sha256')
      .update(JSON.stringify(fingerprintData))
      .digest('hex');
  }

  /**
   * Get earliest timestamp from results
   */
  private getEarliestTimestamp(results: DistributedScanResult[]): number {
    return Math.min(...results.map(r => r.timestamp.getTime()));
  }

  /**
   * Calculate correlation accuracy
   */
  private calculateCorrelationAccuracy(correlations: ResultCorrelation[]): number {
    if (correlations.length === 0) return 1.0;

    const totalConfidence = correlations.reduce((sum, c) => sum + c.confidence, 0);
    return totalConfidence / correlations.length;
  }
}

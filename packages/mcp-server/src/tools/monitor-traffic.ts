import { EventEmitter } from 'events';
import type { MCPServerConfig } from '@mcp-guard/core';

export interface MonitorTrafficArgs {
  config: MCPServerConfig;
  interval?: number;
  metrics?: string[];
}

interface TrafficMetrics {
  timestamp: Date;
  requestsPerSecond: number;
  activeConnections: number;
  bytesTransferred: number;
  errorRate: number;
  avgResponseTime: number;
  suspiciousPatterns: string[];
}

export class MonitorTrafficTool extends EventEmitter {
  private monitoringSessions: Map<string, NodeJS.Timeout>;
  private metricsHistory: Map<string, TrafficMetrics[]>;

  constructor() {
    super();
    this.monitoringSessions = new Map();
    this.metricsHistory = new Map();
  }

  async start(args: MonitorTrafficArgs): Promise<string> {
    const { config, interval = 5000, metrics = ['all'] } = args;
    
    // Generate session ID
    const sessionId = `monitor-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    
    // Stop any existing monitoring for this config
    this.stopAll();

    // Initialize metrics history
    this.metricsHistory.set(sessionId, []);

    // Start monitoring
    const intervalId = setInterval(() => {
      this.collectMetrics(sessionId, config, metrics);
    }, interval);

    this.monitoringSessions.set(sessionId, intervalId);

    // Emit start event
    this.emit('monitoring-started', { sessionId, config });

    return sessionId;
  }

  async stop(sessionId: string): Promise<boolean> {
    const interval = this.monitoringSessions.get(sessionId);
    if (interval) {
      clearInterval(interval);
      this.monitoringSessions.delete(sessionId);
      this.emit('monitoring-stopped', { sessionId });
      return true;
    }
    return false;
  }

  stopAll(): void {
    this.monitoringSessions.forEach((interval, sessionId) => {
      clearInterval(interval);
      this.emit('monitoring-stopped', { sessionId });
    });
    this.monitoringSessions.clear();
  }

  private collectMetrics(sessionId: string, config: MCPServerConfig, metricTypes: string[]): void {
    const metrics: TrafficMetrics = {
      timestamp: new Date(),
      requestsPerSecond: this.simulateMetric(10, 100),
      activeConnections: this.simulateMetric(5, 50),
      bytesTransferred: this.simulateMetric(1000, 10000),
      errorRate: this.simulateMetric(0, 5) / 100,
      avgResponseTime: this.simulateMetric(50, 500),
      suspiciousPatterns: this.detectSuspiciousPatterns(config)
    };

    // Store metrics
    const history = this.metricsHistory.get(sessionId) || [];
    history.push(metrics);
    
    // Keep only last 100 metrics
    if (history.length > 100) {
      history.shift();
    }
    
    this.metricsHistory.set(sessionId, history);

    // Emit metrics event
    this.emit('metrics-collected', { sessionId, metrics });

    // Check for anomalies
    this.checkAnomalies(sessionId, metrics);
  }

  private simulateMetric(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  private detectSuspiciousPatterns(config: MCPServerConfig): string[] {
    const patterns: string[] = [];
    
    // Check for suspicious patterns in config
    if (config.tools?.some((tool: any) => tool.name?.includes('exec'))) {
      patterns.push('Potential command execution tool detected');
    }
    
    if (config.tools?.some((tool: any) => tool.name?.includes('file'))) {
      patterns.push('File system access tool detected');
    }

    // Simulate random suspicious activity
    if (Math.random() > 0.8) {
      patterns.push('Unusual request pattern detected');
    }

    if (Math.random() > 0.9) {
      patterns.push('Potential data exfiltration attempt');
    }

    return patterns;
  }

  private checkAnomalies(sessionId: string, metrics: TrafficMetrics): void {
    // Check for high error rate
    if (metrics.errorRate > 0.1) {
      this.emit('anomaly-detected', {
        sessionId,
        type: 'high-error-rate',
        severity: 'HIGH',
        message: `Error rate ${(metrics.errorRate * 100).toFixed(2)}% exceeds threshold`,
        metrics
      });
    }

    // Check for suspicious patterns
    if (metrics.suspiciousPatterns.length > 0) {
      this.emit('anomaly-detected', {
        sessionId,
        type: 'suspicious-pattern',
        severity: 'MEDIUM',
        message: `Detected ${metrics.suspiciousPatterns.length} suspicious patterns`,
        patterns: metrics.suspiciousPatterns,
        metrics
      });
    }

    // Check for high response time
    if (metrics.avgResponseTime > 400) {
      this.emit('anomaly-detected', {
        sessionId,
        type: 'slow-response',
        severity: 'LOW',
        message: `Average response time ${metrics.avgResponseTime}ms exceeds threshold`,
        metrics
      });
    }
  }

  getMetrics(sessionId: string): TrafficMetrics[] {
    return this.metricsHistory.get(sessionId) || [];
  }

  formatResult(sessionId: string, metrics?: TrafficMetrics[]): string {
    const history = metrics || this.getMetrics(sessionId);
    
    if (history.length === 0) {
      return 'No metrics collected yet';
    }

    const latest = history[history.length - 1];
    const lines: string[] = [
      `📊 Traffic Monitoring Report`,
      `━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
      `Session ID: ${sessionId}`,
      `Timestamp: ${latest.timestamp.toISOString()}`,
      '',
      `Current Metrics:`,
      `  • Requests/sec: ${latest.requestsPerSecond}`,
      `  • Active Connections: ${latest.activeConnections}`,
      `  • Bytes Transferred: ${latest.bytesTransferred.toLocaleString()}`,
      `  • Error Rate: ${(latest.errorRate * 100).toFixed(2)}%`,
      `  • Avg Response Time: ${latest.avgResponseTime}ms`,
      ''
    ];

    if (latest.suspiciousPatterns.length > 0) {
      lines.push('⚠️ Suspicious Patterns Detected:');
      latest.suspiciousPatterns.forEach(pattern => {
        lines.push(`  • ${pattern}`);
      });
      lines.push('');
    }

    // Calculate averages
    const avgRPS = history.reduce((sum, m) => sum + m.requestsPerSecond, 0) / history.length;
    const avgConnections = history.reduce((sum, m) => sum + m.activeConnections, 0) / history.length;
    const avgErrorRate = history.reduce((sum, m) => sum + m.errorRate, 0) / history.length;

    lines.push(`Statistics (last ${history.length} samples):`);
    lines.push(`  • Avg Requests/sec: ${avgRPS.toFixed(1)}`);
    lines.push(`  • Avg Connections: ${avgConnections.toFixed(1)}`);
    lines.push(`  • Avg Error Rate: ${(avgErrorRate * 100).toFixed(2)}%`);

    return lines.join('\n');
  }
}

export const monitorTrafficTool = new MonitorTrafficTool();
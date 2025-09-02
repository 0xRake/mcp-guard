import {
  Scanner,
  MCPServerConfig,
  Vulnerability,
  Severity,
  VulnerabilityType,
  ScanConfig
} from '../types';

// Services that require rate limiting
const SERVICES_REQUIRING_LIMITS = [
  'api',
  'llm',
  'openai',
  'anthropic',
  'gpt',
  'claude',
  'database',
  'auth',
  'login',
  'webhook',
  'email',
  'sms'
];

// Dangerous operations that need rate limiting
const DANGEROUS_OPERATIONS = [
  'execute',
  'eval',
  'spawn',
  'write',
  'delete',
  'create',
  'modify',
  'send',
  'post',
  'upload'
];

export class RateLimitingScanner implements Scanner {
  public readonly name = 'rate-limiting';
  public readonly version = '1.0.0';
  public readonly description = 'Detects missing or inadequate rate limiting configurations';
  public readonly enabled = true;

  async scan(config: MCPServerConfig, scanConfig?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Check for rate limiting configuration
    vulnerabilities.push(...this.checkRateLimitingConfig(config, serverId));

    // Check for services that need rate limiting
    vulnerabilities.push(...this.checkServicesNeedingLimits(config, serverId));

    // Check for dangerous operations without limits
    vulnerabilities.push(...this.checkDangerousOperations(config, serverId));

    // Check for DDoS vulnerabilities
    vulnerabilities.push(...this.checkDDoSVulnerabilities(config, serverId));

    return vulnerabilities;
  }

  private checkRateLimitingConfig(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check if rate limiting is configured at all
    const hasRateLimiting = configText.includes('rate') && 
      (configText.includes('limit') || configText.includes('throttle'));

    if (!hasRateLimiting) {
      // Check if this service needs rate limiting
      const needsRateLimiting = SERVICES_REQUIRING_LIMITS.some(service => 
        configText.includes(service)
      );

      if (needsRateLimiting) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'no-rate-limiting',
          'No rate limiting configured for service that handles requests',
          Severity.HIGH,
          'config',
          'Missing rate limiting'
        ));
      }
    } else {
      // Check rate limit values
      const rateLimitMatch = configText.match(/(?:rate|limit|throttle)[^\d]*(\d+)/);
      if (rateLimitMatch) {
        const limit = parseInt(rateLimitMatch[1]);
        
        // Check if limit is too high
        if (limit > 1000) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'excessive-rate-limit',
            `Rate limit too high: ${limit} requests`,
            Severity.MEDIUM,
            'config',
            `Limit: ${limit}`
          ));
        }

        // Check if window is specified
        if (!configText.includes('window') && !configText.includes('interval') && 
            !configText.includes('period')) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'no-time-window',
            'Rate limit without time window specification',
            Severity.MEDIUM,
            'config',
            'No time window'
          ));
        }
      }
    }

    // Check for per-user vs global limits
    if (hasRateLimiting && !configText.includes('per') && !configText.includes('user') && 
        !configText.includes('client') && !configText.includes('ip')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'global-rate-limit',
        'Rate limiting appears to be global rather than per-user',
        Severity.MEDIUM,
        'config',
        'Global limit'
      ));
    }

    // Check for bypass mechanisms
    if (configText.includes('bypass') || configText.includes('skip') || 
        configText.includes('exempt')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'rate-limit-bypass',
        'Rate limiting bypass mechanism detected',
        Severity.HIGH,
        'config',
        'Bypass mechanism'
      ));
    }

    return vulnerabilities;
  }

  private checkServicesNeedingLimits(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for LLM/AI services without limits
    if ((configText.includes('openai') || configText.includes('anthropic') || 
         configText.includes('gpt') || configText.includes('claude')) &&
        !configText.includes('limit') && !configText.includes('throttle')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'unlimited-llm-access',
        'LLM/AI service access without rate limiting - cost and abuse risk',
        Severity.CRITICAL,
        'config',
        'Unlimited LLM access'
      ));
    }

    // Check for authentication endpoints without limits
    if ((configText.includes('login') || configText.includes('auth') || 
         configText.includes('signin') || configText.includes('password')) &&
        !configText.includes('attempt') && !configText.includes('limit')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'unlimited-auth-attempts',
        'Authentication endpoint without attempt limiting - brute force risk',
        Severity.CRITICAL,
        'config',
        'Unlimited auth attempts'
      ));
    }

    // Check for API endpoints without limits
    if (configText.includes('/api') || configText.includes('endpoint') || 
        configText.includes('route')) {
      if (!configText.includes('quota') && !configText.includes('limit')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unlimited-api-access',
          'API endpoints without rate limiting',
          Severity.HIGH,
          'config',
          'Unlimited API access'
        ));
      }
    }

    // Check for webhook endpoints without limits
    if (configText.includes('webhook') && !configText.includes('limit')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'unlimited-webhooks',
        'Webhook endpoint without rate limiting - spam risk',
        Severity.MEDIUM,
        'config',
        'Unlimited webhooks'
      ));
    }

    return vulnerabilities;
  }

  private checkDangerousOperations(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    for (const operation of DANGEROUS_OPERATIONS) {
      if (configText.includes(operation)) {
        // Check if this operation has specific limits
        const context = this.getContext(configText, operation, 100);
        if (!context.includes('limit') && !context.includes('throttle') && 
            !context.includes('restrict')) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'unlimited-dangerous-operation',
            `Dangerous operation '${operation}' without rate limiting`,
            Severity.HIGH,
            'config',
            operation
          ));
        }
      }
    }

    // Check for bulk operations without limits
    if ((configText.includes('bulk') || configText.includes('batch') || 
         configText.includes('mass')) && !configText.includes('limit')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'unlimited-bulk-operations',
        'Bulk operations without rate limiting',
        Severity.HIGH,
        'config',
        'Bulk operations'
      ));
    }

    // Check for file operations without limits
    if ((configText.includes('upload') || configText.includes('download')) && 
        !configText.includes('size') && !configText.includes('limit')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'unlimited-file-operations',
        'File operations without size or rate limits',
        Severity.MEDIUM,
        'config',
        'File operations'
      ));
    }

    return vulnerabilities;
  }

  private checkDDoSVulnerabilities(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for resource-intensive operations
    if (configText.includes('compute') || configText.includes('process') || 
        configText.includes('analyze')) {
      if (!configText.includes('timeout') && !configText.includes('limit')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'resource-exhaustion',
          'Resource-intensive operations without limits - DoS risk',
          Severity.HIGH,
          'config',
          'Resource exhaustion'
        ));
      }
    }

    // Check for infinite loops or recursion
    if (configText.includes('recursive') || configText.includes('loop') || 
        configText.includes('repeat')) {
      if (!configText.includes('max') && !configText.includes('limit')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'infinite-loop-risk',
          'Potential infinite loop without iteration limits',
          Severity.HIGH,
          'config',
          'Infinite loop risk'
        ));
      }
    }

    // Check for connection limits
    if ((configText.includes('connect') || configText.includes('socket')) && 
        !configText.includes('max_connection') && !configText.includes('connection_limit')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'unlimited-connections',
        'No connection limits - connection exhaustion risk',
        Severity.MEDIUM,
        'config',
        'Unlimited connections'
      ));
    }

    // Check for memory limits
    if (!configText.includes('memory_limit') && !configText.includes('max_memory') && 
        (configText.includes('buffer') || configText.includes('cache'))) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'no-memory-limits',
        'No memory limits configured - memory exhaustion risk',
        Severity.MEDIUM,
        'config',
        'No memory limits'
      ));
    }

    // Check for request size limits
    if (!configText.includes('max_size') && !configText.includes('size_limit') && 
        !configText.includes('payload_limit')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'no-size-limits',
        'No request size limits - large payload DoS risk',
        Severity.MEDIUM,
        'config',
        'No size limits'
      ));
    }

    return vulnerabilities;
  }

  private getContext(text: string, term: string, radius: number): string {
    const index = text.indexOf(term);
    if (index === -1) return '';
    
    const start = Math.max(0, index - radius);
    const end = Math.min(text.length, index + term.length + radius);
    return text.substring(start, end);
  }

  private createVulnerability(
    serverId: string,
    vulnerabilityType: string,
    title: string,
    severity: Severity,
    location: string,
    evidence: string
  ): Vulnerability {
    return {
      id: `RATE-${this.generateId()}`,
      type: VulnerabilityType.MISCONFIGURATION,
      severity,
      score: this.calculateScore(severity),
      server: serverId,
      title: `Rate Limiting: ${title}`,
      description: `${title}. This could lead to denial of service, resource exhaustion, cost overruns, or brute force attacks.`,
      details: {
        vulnerabilityType,
        description: title,
        location
      },
      location: {
        path: location
      },
      evidence: {
        value: evidence
      },
      remediation: {
        description: 'Implement comprehensive rate limiting with per-user limits, time windows, gradual backoff, and monitoring.',
        automated: false,
        commands: [
          '# Basic rate limiting configuration:',
          'rateLimit: {',
          '  windowMs: 60000, // 1 minute',
          '  max: 100, // 100 requests per window',
          '  standardHeaders: true,',
          '  legacyHeaders: false,',
          '  handler: (req, res) => {',
          '    res.status(429).json({ error: "Too many requests" });',
          '  }',
          '}',
          '',
          '# Per-user rate limiting:',
          'rateLimit: {',
          '  keyGenerator: (req) => req.user?.id || req.ip,',
          '  max: 100,',
          '  windowMs: 60000',
          '}',
          '',
          '# Different limits for different operations:',
          'limits: {',
          '  login: { max: 5, windowMs: 900000 }, // 5 attempts per 15 min',
          '  api: { max: 100, windowMs: 60000 },   // 100 per minute',
          '  upload: { max: 10, windowMs: 3600000 } // 10 per hour',
          '}',
          '',
          '# Resource limits:',
          'limits: {',
          '  maxPayloadSize: "10mb",',
          '  maxConnections: 100,',
          '  timeout: 30000',
          '}'
        ],
        documentation: 'https://owasp.org/www-community/controls/Rate_Limiting'
      },
      references: [
        'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/',
        'https://cwe.mitre.org/data/definitions/770.html'
      ],
      cwe: ['CWE-770', 'CWE-400', 'CWE-799'],
      compliance: {
        gdpr: false,
        soc2: true,
        hipaa: false,
        iso27001: true
      },
      discoveredAt: new Date().toISOString()
    };
  }

  private calculateScore(severity: Severity): number {
    const scores = {
      [Severity.CRITICAL]: 8.6,
      [Severity.HIGH]: 7.1,
      [Severity.MEDIUM]: 4.8,
      [Severity.LOW]: 2.3,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 8);
  }
}
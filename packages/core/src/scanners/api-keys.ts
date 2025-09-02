/**
 * API Key Scanner - Detects exposed API keys and secrets in MCP configurations
 * Priority: CRITICAL
 * CVSS Score: 9.0-10.0
 */

import * as crypto from 'crypto';
import {
  Scanner,
  Vulnerability,
  VulnerabilityType,
  Severity,
  MCPServerConfig,
  ScanConfig
} from '../types';

// Common API key patterns
const API_KEY_PATTERNS = [
  // OpenAI
  { pattern: /sk-[a-zA-Z0-9]{48}/g, name: 'OpenAI API Key', severity: Severity.CRITICAL },
  { pattern: /sk-proj-[a-zA-Z0-9]{48}/g, name: 'OpenAI Project Key', severity: Severity.CRITICAL },
  
  // Anthropic
  { pattern: /sk-ant-[a-zA-Z0-9]{100,}/g, name: 'Anthropic API Key', severity: Severity.CRITICAL },
  
  // AWS
  { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key', severity: Severity.CRITICAL },
  { pattern: /aws_secret_access_key\s*=\s*[a-zA-Z0-9/+=]{40}/gi, name: 'AWS Secret Key', severity: Severity.CRITICAL },
  
  // Google Cloud
  { pattern: /AIza[0-9A-Za-z\-_]{35}/g, name: 'Google API Key', severity: Severity.HIGH },
  
  // GitHub
  { pattern: /ghp_[a-zA-Z0-9]{36}/g, name: 'GitHub Personal Access Token', severity: Severity.HIGH },
  { pattern: /gho_[a-zA-Z0-9]{36}/g, name: 'GitHub OAuth Token', severity: Severity.HIGH },
  { pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g, name: 'GitHub Fine-grained PAT', severity: Severity.HIGH },
  
  // Stripe
  { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, name: 'Stripe Live Secret Key', severity: Severity.CRITICAL },
  { pattern: /sk_test_[a-zA-Z0-9]{24,}/g, name: 'Stripe Test Secret Key', severity: Severity.MEDIUM },
  
  // Generic patterns
  { pattern: /api[_\-]?key\s*[:=]\s*["']?[a-zA-Z0-9\-_]{32,}["']?/gi, name: 'Generic API Key', severity: Severity.HIGH },
  { pattern: /secret[_\-]?key\s*[:=]\s*["']?[a-zA-Z0-9\-_]{32,}["']?/gi, name: 'Generic Secret Key', severity: Severity.HIGH },
  { pattern: /bearer\s+[a-zA-Z0-9\-_\.]{20,}/gi, name: 'Bearer Token', severity: Severity.HIGH },
  { pattern: /token\s*[:=]\s*["']?[a-zA-Z0-9\-_]{32,}["']?/gi, name: 'Generic Token', severity: Severity.MEDIUM },
  { pattern: /password\s*[:=]\s*["']?[^\s"']{8,}["']?/gi, name: 'Hardcoded Password', severity: Severity.HIGH },
  
  // Database URLs
  { pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s]+/gi, name: 'MongoDB Connection String', severity: Severity.CRITICAL },
  { pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\s]+/gi, name: 'PostgreSQL Connection String', severity: Severity.CRITICAL },
  { pattern: /mysql:\/\/[^:]+:[^@]+@[^\s]+/gi, name: 'MySQL Connection String', severity: Severity.CRITICAL },
  
  // OAuth Secrets
  { pattern: /client_secret\s*[:=]\s*["']?[a-zA-Z0-9\-_]{32,}["']?/gi, name: 'OAuth Client Secret', severity: Severity.HIGH },
  
  // Private Keys (simplified patterns)
  { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g, name: 'Private Key', severity: Severity.CRITICAL },
  { pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/g, name: 'SSH Private Key', severity: Severity.CRITICAL }
];

// Environment variable names that commonly contain secrets
const SENSITIVE_ENV_VARS = [
  'API_KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'PRIVATE_KEY',
  'CLIENT_SECRET', 'ACCESS_KEY', 'SECRET_KEY', 'CREDENTIALS',
  'AUTH_TOKEN', 'BEARER_TOKEN', 'JWT_SECRET', 'ENCRYPTION_KEY',
  'DATABASE_URL', 'CONNECTION_STRING', 'MONGO_URI', 'REDIS_URL'
];

export class APIKeyScanner implements Scanner {
  name = 'api-keys';
  description = 'Detects exposed API keys, tokens, and secrets in MCP server configurations';
  version = '1.0.0';
  enabled = true;
  canAutoFix = true;

  async scan(config: MCPServerConfig, options?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Scan command and arguments
    vulnerabilities.push(...this.scanCommandLine(config, serverId));

    // Scan environment variables
    if (config.env) {
      vulnerabilities.push(...this.scanEnvironment(config.env, serverId));
    }

    // Scan authentication configuration
    if (config.auth) {
      vulnerabilities.push(...this.scanAuthConfig(config.auth, serverId));
    }

    // Scan OAuth configuration
    if (config.oauth) {
      vulnerabilities.push(...this.scanOAuthConfig(config.oauth, serverId));
    }

    return vulnerabilities;
  }

  private scanCommandLine(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const commandLine = [config.command, ...(config.args || [])].join(' ');

    for (const { pattern, name, severity } of API_KEY_PATTERNS) {
      const matches = commandLine.match(pattern);
      if (matches) {
        matches.forEach((match, index) => {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            name,
            severity,
            'command line arguments',
            this.redactSecret(match),
            match
          ));
        });
      }
    }

    return vulnerabilities;
  }

  private scanEnvironment(env: Record<string, string>, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for sensitive variable names with actual values
    for (const [key, value] of Object.entries(env)) {
      const upperKey = key.toUpperCase();
      
      // Check if variable name suggests it contains secrets
      const isSensitive = SENSITIVE_ENV_VARS.some(sensitive => 
        upperKey.includes(sensitive)
      );

      if (isSensitive && value && !this.isPlaceholder(value)) {
        // Scan the value for known patterns
        for (const { pattern, name, severity } of API_KEY_PATTERNS) {
          const matches = value.match(pattern);
          if (matches) {
            vulnerabilities.push(this.createVulnerability(
              serverId,
              name,
              severity,
              `environment variable: ${key}`,
              this.redactSecret(value),
              value
            ));
          }
        }

        // Even if no pattern matches, flag hardcoded secrets in sensitive vars
        if (!vulnerabilities.some(v => v.location?.path === `env.${key}`)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'Hardcoded Secret',
            Severity.HIGH,
            `environment variable: ${key}`,
            this.redactSecret(value),
            value
          ));
        }
      }
    }

    return vulnerabilities;
  }

  private scanAuthConfig(auth: any, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    if (auth.token && !this.isPlaceholder(auth.token)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'Hardcoded Auth Token',
        Severity.HIGH,
        'auth.token',
        this.redactSecret(auth.token),
        auth.token
      ));
    }

    if (auth.credentials) {
      if (auth.credentials.password && !this.isPlaceholder(auth.credentials.password)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'Hardcoded Password',
          Severity.HIGH,
          'auth.credentials.password',
          this.redactSecret(auth.credentials.password),
          auth.credentials.password
        ));
      }
    }

    return vulnerabilities;
  }

  private scanOAuthConfig(oauth: any, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for client secrets in OAuth config
    if (oauth.clientSecret && !this.isPlaceholder(oauth.clientSecret)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'OAuth Client Secret',
        Severity.HIGH,
        'oauth.clientSecret',
        this.redactSecret(oauth.clientSecret),
        oauth.clientSecret
      ));
    }

    return vulnerabilities;
  }

  private createVulnerability(
    serverId: string,
    keyType: string,
    severity: Severity,
    location: string,
    redactedValue: string,
    originalValue: string
  ): Vulnerability {
    const id = crypto
      .createHash('sha256')
      .update(`${serverId}-${keyType}-${location}-${originalValue}`)
      .digest('hex')
      .substring(0, 8);

    const score = this.calculateCVSSScore(severity);

    return {
      id: `APIK-${id}`,
      type: VulnerabilityType.EXPOSED_API_KEY,
      severity,
      score,
      server: serverId,
      title: `Exposed ${keyType}`,
      description: `A ${keyType} is exposed in ${location}. This could allow unauthorized access to external services.`,
      details: {
        keyType,
        location,
        pattern: redactedValue,
        length: originalValue.length
      },
      location: {
        path: location
      },
      evidence: {
        value: redactedValue,
        pattern: keyType
      },
      remediation: {
        description: `Move the ${keyType} to a secure environment variable or secrets management system. Never commit secrets to configuration files.`,
        automated: true,
        commands: [
          `# Store in environment variable instead:`,
          `export ${this.suggestEnvVarName(keyType)}="<your-secret>"`,
          `# Then reference it in config as:`,
          `env: { "${this.suggestEnvVarName(keyType)}": process.env.${this.suggestEnvVarName(keyType)} }`
        ],
        documentation: 'https://docs.mcp-guard.dev/remediation/api-keys'
      },
      references: [
        'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
        'https://cwe.mitre.org/data/definitions/798.html'
      ],
      cwe: ['CWE-798', 'CWE-200'],
      compliance: {
        gdpr: true,
        soc2: true,
        hipaa: true,
        iso27001: true
      },
      discoveredAt: new Date()
    };
  }

  private redactSecret(value: string): string {
    if (value.length <= 8) {
      return '*'.repeat(value.length);
    }
    
    const visibleChars = 4;
    const prefix = value.substring(0, visibleChars);
    const suffix = value.substring(value.length - visibleChars);
    const redactedMiddle = '*'.repeat(Math.min(value.length - (visibleChars * 2), 20));
    
    return `${prefix}${redactedMiddle}${suffix}`;
  }

  private isPlaceholder(value: string): boolean {
    const placeholders = [
      /^\$\{.*\}$/,          // ${VARIABLE}
      /^<.*>$/,              // <placeholder>
      /^\[.*\]$/,            // [placeholder]
      /^process\.env\./,     // process.env.VARIABLE
      /^env:/,               // env:VARIABLE
      /^\{\{.*\}\}$/,        // {{variable}}
      /^your-/i,             // your-api-key
      /^my-/i,               // my-secret
      /^example/i,           // example-key
      /^placeholder/i,       // placeholder
      /^xxx/i,               // xxx
      /^\*+$/                // ***
    ];

    return placeholders.some(pattern => pattern.test(value));
  }

  private suggestEnvVarName(keyType: string): string {
    return keyType
      .replace(/\s+/g, '_')
      .replace(/[^A-Z0-9_]/gi, '')
      .toUpperCase();
  }

  private calculateCVSSScore(severity: Severity): number {
    const scores = {
      [Severity.CRITICAL]: 9.8,
      [Severity.HIGH]: 8.2,
      [Severity.MEDIUM]: 5.5,
      [Severity.LOW]: 2.8,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  async autoFix(vulnerability: Vulnerability): Promise<boolean> {
    // Auto-fix implementation would:
    // 1. Move secret to .env file
    // 2. Update config to reference environment variable
    // 3. Add .env to .gitignore
    // This is a placeholder for the actual implementation
    console.log(`Auto-fixing vulnerability: ${vulnerability.id}`);
    return false; // Return false for now as actual fix needs file system access
  }
}

// Export singleton instance
export default new APIKeyScanner();

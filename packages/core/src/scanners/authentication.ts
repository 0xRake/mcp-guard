/**
 * Authentication Scanner - Detects missing or weak authentication in MCP configurations
 * Priority: HIGH
 * CVSS Score: 7.0-8.9
 */

import * as crypto from 'crypto';
import {
  Scanner,
  Vulnerability,
  VulnerabilityType,
  Severity,
  MCPServerConfig,
  ScanConfig,
  AuthConfig,
  OAuthConfig
} from '../types';

interface AuthenticationIssue {
  type: 'missing' | 'weak' | 'misconfigured' | 'deprecated';
  reason: string;
  severity: Severity;
}

export class AuthenticationScanner implements Scanner {
  name = 'authentication';
  description = 'Detects missing, weak, or misconfigured authentication in MCP servers';
  version = '1.0.0';
  enabled = true;
  canAutoFix = true;

  // Known secure MCP servers that don't require auth (for false positive reduction)
  private readonly SECURE_PUBLIC_SERVERS = [
    '@modelcontextprotocol/server-memory',
    '@modelcontextprotocol/server-filesystem',
    '@modelcontextprotocol/server-stdio',
    'mcp-server-sqlite'
  ];

  // Servers that MUST have authentication
  private readonly REQUIRES_AUTH = [
    'database',
    'api',
    'admin',
    'production',
    'banking',
    'payment',
    'medical',
    'sensitive',
    'private'
  ];

  // Weak authentication patterns
  private readonly WEAK_PASSWORDS = [
    'password', 'admin', '123456', 'password123', 'admin123',
    'qwerty', 'letmein', 'welcome', 'monkey', 'dragon',
    'master', 'abc123', '111111', 'iloveyou', 'sunshine',
    'princess', 'football', 'shadow', 'michael', 'jennifer'
  ];

  async scan(config: MCPServerConfig, options?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Skip known secure public servers
    if (this.isSecurePublicServer(config)) {
      return vulnerabilities;
    }

    // Check if server requires authentication based on name/type
    const requiresAuth = this.serverRequiresAuth(config);

    // Check for missing authentication
    const missingAuth = this.checkMissingAuth(config, requiresAuth);
    if (missingAuth) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        missingAuth.type,
        missingAuth.reason,
        missingAuth.severity
      ));
    }

    // Check authentication configuration if present
    if (config.auth) {
      const authIssues = this.checkAuthConfig(config.auth, serverId);
      authIssues.forEach(issue => {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          issue.type,
          issue.reason,
          issue.severity
        ));
      });
    }

    // Check OAuth configuration if present
    if (config.oauth) {
      const oauthIssues = await this.checkOAuthConfig(config.oauth, serverId);
      oauthIssues.forEach(issue => {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          issue.type,
          issue.reason,
          issue.severity
        ));
      });
    }

    // Check for authentication bypass patterns in environment
    if (config.env) {
      const bypassIssues = this.checkAuthBypass(config.env, serverId);
      bypassIssues.forEach(issue => {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          issue.type,
          issue.reason,
          issue.severity
        ));
      });
    }

    // Check for insecure authentication methods in command args
    const insecureAuth = this.checkInsecureAuthMethods(config);
    insecureAuth.forEach(issue => {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        issue.type,
        issue.reason,
        issue.severity
      ));
    });

    return vulnerabilities;
  }

  private isSecurePublicServer(config: MCPServerConfig): boolean {
    // Return false if no command is defined
    if (!config.command) return false;
    
    const command = config.command.toLowerCase();
    const args = config.args?.join(' ').toLowerCase() || '';
    const fullCommand = `${command} ${args}`;

    return this.SECURE_PUBLIC_SERVERS.some(server => 
      fullCommand.includes(server.toLowerCase())
    );
  }

  private serverRequiresAuth(config: MCPServerConfig): boolean {
    const serverName = config.metadata?.name?.toLowerCase() || '';
    const command = config.command?.toLowerCase() || '';
    const args = config.args?.join(' ').toLowerCase() || '';
    
    // Check if server name/command contains sensitive keywords
    return this.REQUIRES_AUTH.some(keyword => 
      serverName.includes(keyword) || 
      command.includes(keyword) || 
      args.includes(keyword)
    );
  }

  private checkMissingAuth(config: MCPServerConfig, requiresAuth: boolean): AuthenticationIssue | null {
    // No auth configured at all
    if (!config.auth && !config.oauth) {
      // Check for auth in environment variables
      const hasEnvAuth = config.env && (
        config.env['AUTH_TOKEN'] ||
        config.env['API_KEY'] ||
        config.env['ACCESS_TOKEN'] ||
        config.env['BEARER_TOKEN']
      );

      if (!hasEnvAuth) {
        if (requiresAuth) {
          return {
            type: 'missing',
            reason: 'No authentication configured for sensitive server',
            severity: Severity.CRITICAL
          };
        }

        // Check if server handles sensitive data based on env vars
        const handlesSensitiveData = config.env && (
          Object.keys(config.env).some(key => 
            key.includes('DATABASE') ||
            key.includes('API') ||
            key.includes('SECRET') ||
            key.includes('PRIVATE')
          )
        );

        if (handlesSensitiveData) {
          return {
            type: 'missing',
            reason: 'Server handles sensitive data but has no authentication',
            severity: Severity.HIGH
          };
        }
      }
    }

    return null;
  }

  private checkAuthConfig(auth: AuthConfig, serverId: string): AuthenticationIssue[] {
    const issues: AuthenticationIssue[] = [];

    // Check for basic auth (less secure than bearer tokens)
    if (auth.type === 'basic') {
      issues.push({
        type: 'weak',
        reason: 'Basic authentication is less secure than bearer tokens',
        severity: Severity.MEDIUM
      });

      // Check for weak passwords in basic auth
      if (auth.credentials) {
        const password = auth.credentials.password?.toLowerCase();
        if (password && this.WEAK_PASSWORDS.includes(password)) {
          issues.push({
            type: 'weak',
            reason: 'Weak password detected in basic authentication',
            severity: Severity.HIGH
          });
        }

        // Check for default credentials
        if (auth.credentials.username === 'admin' && 
            (auth.credentials.password === 'admin' || auth.credentials.password === 'password')) {
          issues.push({
            type: 'weak',
            reason: 'Default credentials detected (admin/admin or admin/password)',
            severity: Severity.CRITICAL
          });
        }
      }
    }

    // Check for custom auth without proper implementation details
    if (auth.type === 'custom' && !auth.token) {
      issues.push({
        type: 'misconfigured',
        reason: 'Custom authentication type specified but no token provided',
        severity: Severity.HIGH
      });
    }

    // Check for empty tokens
    if (auth.token === '' || auth.token === null || auth.token === undefined) {
      issues.push({
        type: 'misconfigured',
        reason: 'Empty authentication token',
        severity: Severity.CRITICAL
      });
    }

    return issues;
  }

  private async checkOAuthConfig(oauth: OAuthConfig, serverId: string): Promise<AuthenticationIssue[]> {
    const issues: AuthenticationIssue[] = [];

    // Check for missing PKCE in OAuth flow
    if (!oauth.pkce) {
      issues.push({
        type: 'weak',
        reason: 'OAuth configuration missing PKCE (Proof Key for Code Exchange)',
        severity: Severity.HIGH
      });
    }

    // Check for insecure authorization server
    if (oauth.authorizationServer) {
      const authServer = oauth.authorizationServer.toLowerCase();
      
      // Check for HTTP instead of HTTPS
      if (authServer.startsWith('http://') && !authServer.includes('localhost')) {
        issues.push({
          type: 'misconfigured',
          reason: 'OAuth authorization server using insecure HTTP protocol',
          severity: Severity.CRITICAL
        });
      }

      // Check for localhost in production
      if (authServer.includes('localhost') || authServer.includes('127.0.0.1')) {
        issues.push({
          type: 'misconfigured',
          reason: 'OAuth authorization server pointing to localhost',
          severity: Severity.HIGH
        });
      }
    }

    // Check for overly broad scopes
    if (oauth.scopes) {
      const dangerousScopes = ['*', 'admin', 'write:all', 'delete:all', 'root'];
      const hasDangerousScope = oauth.scopes.some(scope => 
        dangerousScopes.includes(scope.toLowerCase())
      );

      if (hasDangerousScope) {
        issues.push({
          type: 'misconfigured',
          reason: 'OAuth configuration requests overly broad or dangerous scopes',
          severity: Severity.HIGH
        });
      }
    }

    // Check OAuth metadata for security issues
    if (oauth.metadata) {
      // Check for missing JWKS URI (needed for token validation)
      if (!oauth.metadata.jwks_uri) {
        issues.push({
          type: 'weak',
          reason: 'OAuth metadata missing JWKS URI for token validation',
          severity: Severity.MEDIUM
        });
      }

      // Check for deprecated grant types
      if (oauth.metadata.grant_types_supported?.includes('implicit')) {
        issues.push({
          type: 'deprecated',
          reason: 'OAuth configuration supports deprecated implicit grant type',
          severity: Severity.HIGH
        });
      }

      if (oauth.metadata.grant_types_supported?.includes('password')) {
        issues.push({
          type: 'deprecated',
          reason: 'OAuth configuration supports deprecated password grant type',
          severity: Severity.HIGH
        });
      }
    }

    return issues;
  }

  private checkAuthBypass(env: Record<string, string>, serverId: string): AuthenticationIssue[] {
    const issues: AuthenticationIssue[] = [];

    // Check for authentication bypass flags
    const bypassFlags = ['SKIP_AUTH', 'NO_AUTH', 'BYPASS_AUTH', 'DISABLE_AUTH', 'AUTH_DISABLED'];
    
    for (const [key, value] of Object.entries(env)) {
      const upperKey = key.toUpperCase();
      
      if (bypassFlags.includes(upperKey)) {
        if (value === 'true' || value === '1' || value === 'yes') {
          issues.push({
            type: 'misconfigured',
            reason: `Authentication bypass enabled via ${key} environment variable`,
            severity: Severity.CRITICAL
          });
        }
      }

      // Check for debug mode that might bypass auth
      if (upperKey === 'DEBUG' || upperKey === 'DEBUG_MODE') {
        if (value === 'true' || value === '1') {
          issues.push({
            type: 'weak',
            reason: 'Debug mode enabled which may bypass authentication',
            severity: Severity.MEDIUM
          });
        }
      }
    }

    return issues;
  }

  private checkInsecureAuthMethods(config: MCPServerConfig): AuthenticationIssue[] {
    const issues: AuthenticationIssue[] = [];
    const commandLine = [config.command, ...(config.args || [])].join(' ').toLowerCase();

    // Check for authentication in URL parameters (insecure)
    if (commandLine.includes('?token=') || commandLine.includes('&token=')) {
      issues.push({
        type: 'weak',
        reason: 'Authentication token passed in URL parameters (vulnerable to logging)',
        severity: Severity.HIGH
      });
    }

    // Check for --no-auth or --skip-auth flags
    if (commandLine.includes('--no-auth') || 
        commandLine.includes('--skip-auth') ||
        commandLine.includes('--disable-auth')) {
      issues.push({
        type: 'misconfigured',
        reason: 'Authentication explicitly disabled via command line flag',
        severity: Severity.CRITICAL
      });
    }

    // Check for insecure protocols
    if (commandLine.includes('telnet://') || commandLine.includes('ftp://')) {
      issues.push({
        type: 'weak',
        reason: 'Using insecure protocol that transmits credentials in plaintext',
        severity: Severity.CRITICAL
      });
    }

    return issues;
  }

  private createVulnerability(
    serverId: string,
    issueType: string,
    reason: string,
    severity: Severity
  ): Vulnerability {
    const id = crypto
      .createHash('sha256')
      .update(`${serverId}-auth-${issueType}-${reason}`)
      .digest('hex')
      .substring(0, 8);

    const typeMap = {
      'missing': VulnerabilityType.MISSING_AUTHENTICATION,
      'weak': VulnerabilityType.WEAK_AUTHENTICATION,
      'misconfigured': VulnerabilityType.MISCONFIGURATION,
      'deprecated': VulnerabilityType.WEAK_AUTHENTICATION
    };

    const vulnerabilityType = typeMap[issueType as keyof typeof typeMap] || VulnerabilityType.MISCONFIGURATION;

    return {
      id: `AUTH-${id}`,
      type: vulnerabilityType,
      severity,
      score: this.calculateCVSSScore(severity),
      server: serverId,
      title: this.generateTitle(issueType, reason),
      description: this.generateDescription(issueType, reason),
      details: {
        issueType,
        reason
      },
      location: {
        path: issueType === 'missing' ? 'config.auth' : 'config.auth/oauth'
      },
      evidence: {
        value: reason
      },
      remediation: this.generateRemediation(issueType, reason),
      references: [
        'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication',
        'https://modelcontextprotocol.io/specification/basic/security#authentication',
        'https://cwe.mitre.org/data/definitions/287.html'
      ],
      cwe: ['CWE-287', 'CWE-306', 'CWE-798'],
      compliance: {
        gdpr: severity === Severity.CRITICAL || severity === Severity.HIGH,
        soc2: true,
        hipaa: severity === Severity.CRITICAL || severity === Severity.HIGH,
        iso27001: true
      },
      discoveredAt: new Date()
    };
  }

  private generateTitle(issueType: string, reason: string): string {
    const titles = {
      'missing': 'Missing Authentication',
      'weak': 'Weak Authentication Method',
      'misconfigured': 'Authentication Misconfiguration',
      'deprecated': 'Deprecated Authentication Method'
    };
    return titles[issueType as keyof typeof titles] || 'Authentication Issue';
  }

  private generateDescription(issueType: string, reason: string): string {
    return `${reason}. This could allow unauthorized access to the MCP server and its resources.`;
  }

  private generateRemediation(issueType: string, reason: string): any {
    const remediations: Record<string, any> = {
      'missing': {
        description: 'Implement OAuth 2.1 or bearer token authentication for the MCP server',
        automated: true,
        commands: [
          '# Add OAuth configuration:',
          'oauth: {',
          '  authorizationServer: "https://auth.example.com",',
          '  clientId: "your-client-id",',
          '  scopes: ["read", "write"],',
          '  pkce: true',
          '}',
          '',
          '# Or add bearer token:',
          'auth: {',
          '  type: "bearer",',
          '  token: process.env.MCP_AUTH_TOKEN',
          '}'
        ],
        documentation: 'https://modelcontextprotocol.io/specification/basic/authorization'
      },
      'weak': {
        description: 'Upgrade to a more secure authentication method such as OAuth 2.1 with PKCE',
        automated: true,
        commands: [
          '# Replace basic auth with bearer token:',
          'auth: {',
          '  type: "bearer",',
          '  token: process.env.SECURE_TOKEN',
          '}',
          '',
          '# Use strong passwords (min 12 chars, mixed case, numbers, symbols)',
          '# Enable MFA where possible'
        ],
        documentation: 'https://oauth.net/2.1/'
      },
      'misconfigured': {
        description: 'Fix the authentication configuration to ensure proper security',
        automated: false,
        commands: [
          '# Review and fix configuration:',
          '- Enable PKCE for OAuth flows',
          '- Use HTTPS for all auth endpoints',
          '- Validate tokens with JWKS',
          '- Remove debug/bypass flags',
          '- Use secure token storage'
        ],
        documentation: 'https://modelcontextprotocol.io/specification/basic/security'
      },
      'deprecated': {
        description: 'Migrate from deprecated authentication methods to OAuth 2.1',
        automated: false,
        commands: [
          '# Remove deprecated grant types:',
          '- Remove implicit grant',
          '- Remove password grant',
          '- Use authorization_code with PKCE',
          '- Implement refresh token rotation'
        ],
        documentation: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13'
      }
    };

    return remediations[issueType] || remediations['missing'];
  }

  private calculateCVSSScore(severity: Severity): number {
    const scores = {
      [Severity.CRITICAL]: 9.1,
      [Severity.HIGH]: 7.5,
      [Severity.MEDIUM]: 5.3,
      [Severity.LOW]: 3.1,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  async autoFix(vulnerability: Vulnerability): Promise<boolean> {
    // Auto-fix would implement OAuth configuration or add bearer token setup
    console.log(`Auto-fixing vulnerability: ${vulnerability.id}`);
    
    // In a real implementation, this would:
    // 1. Generate secure token
    // 2. Add to .env file
    // 3. Update config to use environment variable
    // 4. Add OAuth configuration with PKCE
    
    return false; // Placeholder
  }
}

// Export singleton instance
export default new AuthenticationScanner();

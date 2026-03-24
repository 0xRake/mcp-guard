import {
  Scanner,
  MCPServerConfig,
  Vulnerability,
  Severity,
  VulnerabilityType,
  ScanConfig
} from '../types';

// Patterns indicating privilege escalation risks
const PRIVILEGE_ESCALATION_PATTERNS = [
  /sudo/i,
  /run[_\s]?as/i,
  /elevat(e|ed|ion)/i,
  /privilege/i,
  /impersonat/i,
  /switch[_\s]?user/i,
  /become[_\s]?user/i,
  /setuid/i,
  /setgid/i,
  /su\s+-/
];

// Cross-service request patterns
const CROSS_SERVICE_PATTERNS = [
  /forward/i,
  /proxy/i,
  /relay/i,
  /redirect/i,
  /delegate/i,
  /behalf/i,
  /represent/i,
  /act[_\s]?as/i,
  /on[_\s]?behalf[_\s]?of/i
];

// Resource access patterns that might indicate confused deputy
const RESOURCE_ACCESS_PATTERNS = [
  /s3:\/\//i,
  /arn:aws/i,
  /gs:\/\//i,
  /azure:\/\//i,
  /file:\/\//i,
  /internal\//i,
  /private\//i,
  /admin\//i,
  /service\//i
];

// Unsafe delegation patterns
const UNSAFE_DELEGATION = [
  'allow_all',
  'trust_all',
  'bypass_auth',
  'skip_validation',
  'no_check',
  'force',
  'override'
];

export class ConfusedDeputyScanner implements Scanner {
  public readonly name = 'confused-deputy';
  public readonly version = '1.0.0';
  public readonly description = 'Detects confused deputy vulnerabilities where servers act on behalf of others';
  public readonly enabled = true;

  async scan(config: MCPServerConfig, scanConfig?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Check for privilege escalation patterns
    vulnerabilities.push(...this.scanForPrivilegeEscalation(config, serverId));

    // Check for cross-service request vulnerabilities
    vulnerabilities.push(...this.scanForCrossServiceRequests(config, serverId));

    // Check for unsafe resource access
    vulnerabilities.push(...this.scanForUnsafeResourceAccess(config, serverId));

    // Check for delegation issues
    vulnerabilities.push(...this.scanForDelegationIssues(config, serverId));

    // Check for ambient authority issues
    vulnerabilities.push(...this.scanForAmbientAuthority(config, serverId));

    return vulnerabilities;
  }

  private scanForPrivilegeEscalation(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check command for privilege escalation
    if (config.command) {
      for (const pattern of PRIVILEGE_ESCALATION_PATTERNS) {
        if (pattern.test(config.command)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'privilege-escalation-command',
            `Command may allow privilege escalation: ${config.command}`,
            Severity.CRITICAL,
            'command',
            config.command
          ));
        }
      }
    }

    // Check args for privilege escalation
    if (config.args) {
      const argsText = config.args.join(' ');
      for (const pattern of PRIVILEGE_ESCALATION_PATTERNS) {
        if (pattern.test(argsText)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'privilege-escalation-args',
            'Arguments contain privilege escalation patterns',
            Severity.HIGH,
            'args',
            argsText.match(pattern)?.[0] || 'unknown'
          ));
        }
      }

      // Check for UID/GID manipulation
      if (/--uid[=\s]\d+|--gid[=\s]\d+/i.test(argsText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'uid-gid-manipulation',
          'Direct UID/GID manipulation detected',
          Severity.CRITICAL,
          'args',
          'UID/GID setting'
        ));
      }
    }

    // Check environment for privilege indicators
    if (config.env) {
      const dangerousEnvVars = ['USER', 'USERNAME', 'UID', 'GID', 'SUDO_USER', 'SUDO_UID'];
      for (const envVar of dangerousEnvVars) {
        if (config.env[envVar]) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'privilege-env-override',
            `Potentially dangerous environment override: ${envVar}`,
            Severity.MEDIUM,
            `env.${envVar}`,
            config.env[envVar]
          ));
        }
      }
    }

    return vulnerabilities;
  }

  private scanForCrossServiceRequests(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config);

    // Check for cross-service patterns
    for (const pattern of CROSS_SERVICE_PATTERNS) {
      if (pattern.test(configText)) {
        const match = configText.match(pattern);
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'cross-service-request',
          `Cross-service request pattern detected: ${match?.[0]}`,
          Severity.MEDIUM,
          'config',
          match?.[0] || 'unknown'
        ));
      }
    }

    // Check for service impersonation
    if (/service[_\s]?account|service[_\s]?principal/i.test(configText)) {
      if (!configText.includes('validate') && !configText.includes('verify')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unvalidated-service-account',
          'Service account usage without validation',
          Severity.HIGH,
          'config',
          'Service account'
        ));
      }
    }

    // Check for request forwarding without validation
    if (configText.includes('forward') || configText.includes('proxy')) {
      if (!configText.includes('whitelist') && !configText.includes('allowlist')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unrestricted-forwarding',
          'Request forwarding without destination restrictions',
          Severity.HIGH,
          'config',
          'Unrestricted forwarding'
        ));
      }
    }

    return vulnerabilities;
  }

  private scanForUnsafeResourceAccess(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config);

    // Check for resource access patterns
    for (const pattern of RESOURCE_ACCESS_PATTERNS) {
      const match = configText.match(pattern);
      if (match) {
        // Check if there's proper authorization
        const context = configText.substring(
          Math.max(0, configText.indexOf(match[0]) - 50),
          Math.min(configText.length, configText.indexOf(match[0]) + 100)
        );
        
        if (!context.includes('auth') && !context.includes('token') && !context.includes('key')) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'unauthorized-resource-access',
            `Resource access without apparent authorization: ${match[0]}`,
            Severity.HIGH,
            'config',
            match[0]
          ));
        }
      }
    }

    // Check for file:// protocol abuse
    if (/file:\/\/\//i.test(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'file-protocol-abuse',
        'Direct file:// protocol access - potential for local file access',
        Severity.CRITICAL,
        'config',
        'file:// protocol'
      ));
    }

    // Check for internal network access
    if (/10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+/.test(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'internal-network-access',
        'Access to internal network addresses detected',
        Severity.MEDIUM,
        'config',
        'Internal IP'
      ));
    }

    return vulnerabilities;
  }

  private scanForDelegationIssues(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for unsafe delegation patterns
    for (const pattern of UNSAFE_DELEGATION) {
      if (configText.includes(pattern)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unsafe-delegation',
          `Unsafe delegation pattern: ${pattern}`,
          Severity.HIGH,
          'config',
          pattern
        ));
      }
    }

    // Check for wildcard permissions
    if (configText.includes('*') && (configText.includes('permission') || 
        configText.includes('grant') || configText.includes('allow'))) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'wildcard-permissions',
        'Wildcard permissions detected - overly broad access',
        Severity.HIGH,
        'config',
        'Wildcard permissions'
      ));
    }

    // Check for missing origin validation
    if ((configText.includes('accept') || configText.includes('receive')) && 
        !configText.includes('origin') && !configText.includes('source')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'missing-origin-validation',
        'Accepting requests without origin validation',
        Severity.MEDIUM,
        'config',
        'No origin validation'
      ));
    }

    // Check for token relay without validation
    if ((configText.includes('token') || configText.includes('bearer')) && 
        (configText.includes('forward') || configText.includes('pass'))) {
      if (!configText.includes('validate') && !configText.includes('verify')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unvalidated-token-relay',
          'Token relay without validation - confused deputy risk',
          Severity.CRITICAL,
          'config',
          'Token relay'
        ));
      }
    }

    return vulnerabilities;
  }

  private scanForAmbientAuthority(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for ambient credentials in environment
    if (config.env) {
      const ambientCredentials = [
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'GOOGLE_APPLICATION_CREDENTIALS',
        'AZURE_CLIENT_ID',
        'AZURE_CLIENT_SECRET'
      ];

      for (const cred of ambientCredentials) {
        if (config.env[cred]) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'ambient-credentials',
            `Ambient credentials in environment: ${cred}`,
            Severity.HIGH,
            `env.${cred}`,
            'Ambient authority'
          ));
        }
      }
    }

    // Check for default service accounts
    const configText = JSON.stringify(config);
    if (/default[_\-]?service[_\-]?account/i.test(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'default-service-account',
        'Using default service account - may have excessive permissions',
        Severity.MEDIUM,
        'config',
        'Default service account'
      ));
    }

    // Check for capability-based access without proper checks
    if (config.capabilities) {
      const caps = JSON.stringify(config.capabilities);
      if (caps.includes('true') && !config.auth && !config.oauth) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unrestricted-capabilities',
          'Capabilities enabled without authentication',
          Severity.CRITICAL,
          'capabilities',
          'Unrestricted capabilities'
        ));
      }
    }

    // Check for missing request context validation
    if (!configText.includes('context') && !configText.includes('caller') && 
        !configText.includes('principal')) {
      if (config.capabilities?.tools || config.capabilities?.prompts) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'missing-context-validation',
          'No request context validation - confused deputy risk',
          Severity.HIGH,
          'config',
          'No context validation'
        ));
      }
    }

    return vulnerabilities;
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
      id: `DEPUTY-${this.generateId()}`,
      type: VulnerabilityType.CONFUSED_DEPUTY,
      severity,
      score: this.calculateScore(severity),
      server: serverId,
      title: `Confused Deputy: ${title}`,
      description: `${title}. This vulnerability occurs when a server with elevated privileges is tricked into misusing its authority on behalf of another party.`,
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
        description: 'Implement proper authorization checks, validate all requests, use capability-based security, implement the principle of least privilege, and audit all privileged operations.',
        automated: false,
        commands: [
          '# Validate request origin:',
          'function validateRequestOrigin(request) {',
          '  const caller = request.headers["x-caller-identity"];',
          '  if (!isAuthorized(caller, request.resource)) {',
          '    throw new Error("Unauthorized");',
          '  }',
          '}',
          '',
          '# Use explicit capability checks:',
          'capabilities: {',
          '  checkPermission: (action, resource, caller) => {',
          '    return hasExplicitGrant(caller, action, resource);',
          '  }',
          '}',
          '',
          '# Implement request signing:',
          'const signature = crypto.sign(request, callerPrivateKey);',
          'request.headers["x-signature"] = signature;',
          '',
          '# Use scoped credentials:',
          'const scopedToken = generateScopedToken(caller, resource, ["read"]);',
          '',
          '# Audit all privileged operations:',
          'audit.log({ caller, action, resource, timestamp })'
        ],
        documentation: 'https://owasp.org/www-community/attacks/Session_fixation'
      },
      references: [
        'https://cwe.mitre.org/data/definitions/441.html',
        'https://en.wikipedia.org/wiki/Confused_deputy_problem'
      ],
      cwe: ['CWE-441', 'CWE-863', 'CWE-284'],
      compliance: {
        gdpr: true,
        soc2: true,
        hipaa: true,
        iso27001: true
      },
      discoveredAt: new Date()
    };
  }

  private calculateScore(severity: Severity): number {
    const scores = {
      [Severity.CRITICAL]: 9.1,
      [Severity.HIGH]: 7.4,
      [Severity.MEDIUM]: 5.3,
      [Severity.LOW]: 3.1,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 8);
  }
}
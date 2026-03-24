import {
  Scanner,
  MCPServerConfig,
  Vulnerability,
  Severity,
  VulnerabilityType,
  ScanConfig
} from '../types';

// Internal/Private IP ranges
const INTERNAL_IP_PATTERNS = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,  // Link-local
  /^fc00:/,       // IPv6 private
  /^fe80:/,       // IPv6 link-local
  /^::1$/,        // IPv6 loopback
  /^0\.0\.0\.0/   // All interfaces
];

// Cloud metadata endpoints
const METADATA_ENDPOINTS = [
  '169.254.169.254',           // AWS/GCP/Azure
  'metadata.google.internal',   // GCP
  'metadata.azure.com',         // Azure
  '100.100.100.200'            // Alibaba Cloud
];

// Dangerous protocols
const DANGEROUS_PROTOCOLS = [
  'file://',
  'gopher://',
  'dict://',
  'ftp://',
  'jar://',
  'ldap://',
  'sftp://',
  'tftp://'
];

// URL parameter patterns that might indicate SSRF
const URL_PARAM_PATTERNS = [
  /url=/i,
  /uri=/i,
  /path=/i,
  /dest=/i,
  /redirect=/i,
  /out=/i,
  /callback=/i,
  /fetch=/i,
  /proxy=/i,
  /load=/i,
  /source=/i,
  /src=/i,
  /href=/i,
  /link=/i
];

export class SSRFScanner implements Scanner {
  public readonly name = 'ssrf';
  public readonly version = '1.0.0';
  public readonly description = 'Detects Server-Side Request Forgery vulnerabilities';
  public readonly enabled = true;

  async scan(config: MCPServerConfig, scanConfig?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Check for SSRF in arguments
    if (config.args) {
      vulnerabilities.push(...this.scanArguments(config.args, serverId));
    }

    // Check for SSRF in environment variables
    if (config.env) {
      vulnerabilities.push(...this.scanEnvironment(config.env, serverId));
    }

    // Check for URL handling patterns
    vulnerabilities.push(...this.scanForURLHandling(config, serverId));

    // Check for request forwarding
    vulnerabilities.push(...this.scanForRequestForwarding(config, serverId));

    // Check for webhook configurations
    vulnerabilities.push(...this.scanForWebhooks(config, serverId));

    return vulnerabilities;
  }

  private scanArguments(args: string[], serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const argsText = args.join(' ');

    // Check for internal IPs
    for (const pattern of INTERNAL_IP_PATTERNS) {
      const match = argsText.match(new RegExp(pattern.source + '\\d+\\.\\d+', 'g'));
      if (match) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'internal-ip-access',
          `Access to internal IP address: ${match[0]}`,
          Severity.HIGH,
          'args',
          match[0]
        ));
      }
    }

    // Check for metadata endpoints
    for (const endpoint of METADATA_ENDPOINTS) {
      if (argsText.includes(endpoint)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'metadata-endpoint-access',
          `Access to cloud metadata endpoint: ${endpoint}`,
          Severity.CRITICAL,
          'args',
          endpoint
        ));
      }
    }

    // Check for dangerous protocols
    for (const protocol of DANGEROUS_PROTOCOLS) {
      if (argsText.includes(protocol)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'dangerous-protocol',
          `Dangerous protocol in use: ${protocol}`,
          Severity.HIGH,
          'args',
          protocol
        ));
      }
    }

    // Check for URL parameters
    for (const pattern of URL_PARAM_PATTERNS) {
      if (pattern.test(argsText)) {
        const match = argsText.match(pattern);
        // Check if the URL parameter contains user input placeholder
        if (argsText.includes('${') || argsText.includes('{{') || argsText.includes('%s')) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'user-controlled-url',
            `User-controlled URL parameter: ${match?.[0]}`,
            Severity.CRITICAL,
            'args',
            match?.[0] || 'URL parameter'
          ));
        }
      }
    }

    // Check for localhost references
    if (/localhost|127\.0\.0\.1|::1|0\.0\.0\.0/.test(argsText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'localhost-access',
        'Access to localhost detected - potential SSRF',
        Severity.MEDIUM,
        'args',
        'localhost'
      ));
    }

    // Check for port scanning patterns
    if (/:\d{1,5}/.test(argsText) && /\{|\$|%/.test(argsText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'port-scanning',
        'Dynamic port access detected - potential port scanning',
        Severity.HIGH,
        'args',
        'Dynamic port'
      ));
    }

    return vulnerabilities;
  }

  private scanEnvironment(env: Record<string, string>, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const [key, value] of Object.entries(env)) {
      // Check for URLs in environment variables
      if (/URL|URI|ENDPOINT|HOST/i.test(key)) {
        // Check for internal IPs
        for (const pattern of INTERNAL_IP_PATTERNS) {
          if (pattern.test(value)) {
            vulnerabilities.push(this.createVulnerability(
              serverId,
              'internal-ip-in-env',
              `Internal IP in environment variable ${key}`,
              Severity.HIGH,
              `env.${key}`,
              value
            ));
          }
        }

        // Check for metadata endpoints
        for (const endpoint of METADATA_ENDPOINTS) {
          if (value.includes(endpoint)) {
            vulnerabilities.push(this.createVulnerability(
              serverId,
              'metadata-endpoint-in-env',
              `Metadata endpoint in environment variable ${key}`,
              Severity.CRITICAL,
              `env.${key}`,
              endpoint
            ));
          }
        }

        // Check for dangerous protocols
        for (const protocol of DANGEROUS_PROTOCOLS) {
          if (value.includes(protocol)) {
            vulnerabilities.push(this.createVulnerability(
              serverId,
              'dangerous-protocol-in-env',
              `Dangerous protocol in environment variable ${key}`,
              Severity.HIGH,
              `env.${key}`,
              protocol
            ));
          }
        }
      }

      // Check for proxy configurations
      if (/PROXY/i.test(key) && value) {
        if (/localhost|127\.0\.0\.1/.test(value)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'localhost-proxy',
            `Proxy pointing to localhost in ${key}`,
            Severity.MEDIUM,
            `env.${key}`,
            value
          ));
        }
      }
    }

    return vulnerabilities;
  }

  private scanForURLHandling(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for fetch/request functions
    if (configText.includes('fetch') || configText.includes('request') || 
        configText.includes('axios') || configText.includes('curl')) {
      
      // Check if URL validation is present
      if (!configText.includes('validate') && !configText.includes('whitelist') && 
          !configText.includes('allowlist')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unvalidated-url-fetch',
          'URL fetching without validation - SSRF risk',
          Severity.HIGH,
          'config',
          'Unvalidated URL fetch'
        ));
      }

      // Check for redirect following
      if (configText.includes('follow') && configText.includes('redirect')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'redirect-following',
          'Automatic redirect following enabled - SSRF amplification',
          Severity.MEDIUM,
          'config',
          'Redirect following'
        ));
      }
    }

    // Check for image/media loading
    if (configText.includes('image') || configText.includes('img') || 
        configText.includes('media') || configText.includes('avatar')) {
      if (configText.includes('src') || configText.includes('url')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'media-ssrf',
          'Media loading from URLs - potential SSRF vector',
          Severity.MEDIUM,
          'config',
          'Media URL loading'
        ));
      }
    }

    // Check for PDF generation
    if (configText.includes('pdf') || configText.includes('puppeteer') || 
        configText.includes('wkhtmltopdf')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'pdf-ssrf',
        'PDF generation detected - common SSRF vector',
        Severity.HIGH,
        'config',
        'PDF generation'
      ));
    }

    // Check for XML external entity processing
    if (configText.includes('xml') && !configText.includes('disable.*external.*entit')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'xxe-ssrf',
        'XML processing without XXE protection - SSRF via XXE',
        Severity.HIGH,
        'config',
        'XML without XXE protection'
      ));
    }

    return vulnerabilities;
  }

  private scanForRequestForwarding(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for proxy/forward patterns
    if (configText.includes('proxy') || configText.includes('forward')) {
      // Check if there's destination validation
      if (!configText.includes('allowed') && !configText.includes('whitelist')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'open-proxy',
          'Open proxy configuration - can be used for SSRF',
          Severity.CRITICAL,
          'config',
          'Open proxy'
        ));
      }

      // Check for proxy authentication bypass
      if (configText.includes('proxy') && configText.includes('bypass')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'proxy-bypass',
          'Proxy bypass mechanism - potential SSRF vector',
          Severity.HIGH,
          'config',
          'Proxy bypass'
        ));
      }
    }

    // Check for service mesh/API gateway patterns
    if (configText.includes('gateway') || configText.includes('mesh') || 
        configText.includes('sidecar')) {
      if (!configText.includes('auth') && !configText.includes('verify')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unauthenticated-gateway',
          'Service gateway without authentication - SSRF risk',
          Severity.HIGH,
          'config',
          'Unauthenticated gateway'
        ));
      }
    }

    return vulnerabilities;
  }

  private scanForWebhooks(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config);

    // Check for webhook configurations
    if (configText.toLowerCase().includes('webhook')) {
      // Check if webhook URLs are validated
      if (!configText.includes('validate') && !configText.includes('verify')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unvalidated-webhook',
          'Webhook URLs not validated - SSRF risk',
          Severity.HIGH,
          'config',
          'Unvalidated webhooks'
        ));
      }

      // Check for webhook to internal networks
      for (const pattern of INTERNAL_IP_PATTERNS) {
        const regex = new RegExp(pattern.source + '\\d+\\.\\d+', 'g');
        if (regex.test(configText)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'internal-webhook',
            'Webhook pointing to internal network',
            Severity.CRITICAL,
            'config',
            'Internal webhook'
          ));
        }
      }
    }

    // Check for callback URLs
    if (configText.includes('callback')) {
      if (!configText.includes('whitelist') && !configText.includes('allowlist')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'open-callback',
          'Open callback URL configuration - SSRF risk',
          Severity.HIGH,
          'config',
          'Open callback'
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
      id: `SSRF-${this.generateId()}`,
      type: VulnerabilityType.MISCONFIGURATION,
      severity,
      score: this.calculateScore(severity),
      server: serverId,
      title: `SSRF: ${title}`,
      description: `${title}. Server-Side Request Forgery allows attackers to make requests from the server to internal resources or external sites.`,
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
        description: 'Implement URL validation, use allowlists, disable unnecessary protocols, implement network segmentation, and validate all user-supplied URLs.',
        automated: false,
        commands: [
          '# URL validation with allowlist:',
          'const allowedHosts = ["api.example.com", "cdn.example.com"];',
          'function validateURL(url) {',
          '  const parsed = new URL(url);',
          '  if (!allowedHosts.includes(parsed.hostname)) {',
          '    throw new Error("Host not allowed");',
          '  }',
          '  if (parsed.protocol !== "https:") {',
          '    throw new Error("Only HTTPS allowed");',
          '  }',
          '  // Block internal IPs',
          '  if (isInternalIP(parsed.hostname)) {',
          '    throw new Error("Internal IPs not allowed");',
          '  }',
          '}',
          '',
          '# Disable dangerous protocols:',
          'const allowedProtocols = ["http:", "https:"];',
          'if (!allowedProtocols.includes(url.protocol)) {',
          '  throw new Error("Protocol not allowed");',
          '}',
          '',
          '# Use DNS resolution validation:',
          'const resolved = await dns.resolve4(hostname);',
          'if (isPrivateIP(resolved[0])) {',
          '  throw new Error("Resolved to private IP");',
          '}'
        ],
        documentation: 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'
      },
      references: [
        'https://portswigger.net/web-security/ssrf',
        'https://cwe.mitre.org/data/definitions/918.html'
      ],
      cwe: ['CWE-918', 'CWE-441', 'CWE-610'],
      compliance: {
        gdpr: false,
        soc2: true,
        hipaa: false,
        iso27001: true
      },
      discoveredAt: new Date()
    };
  }

  private calculateScore(severity: Severity): number {
    const scores = {
      [Severity.CRITICAL]: 9.3,
      [Severity.HIGH]: 7.7,
      [Severity.MEDIUM]: 5.4,
      [Severity.LOW]: 3.2,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 8);
  }
}
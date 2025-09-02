import {
  Scanner,
  MCPServerConfig,
  Vulnerability,
  Severity,
  VulnerabilityType,
  ScanConfig
} from '../types';

// OAuth 2.1 required parameters
const OAUTH21_REQUIREMENTS = {
  requiredFields: ['authorizationServer', 'clientId'],
  recommendedFields: ['scopes', 'pkce'],
  secureFields: ['clientSecret', 'refreshToken', 'accessToken']
};

// Insecure OAuth flows
const INSECURE_FLOWS = [
  'implicit',
  'password',
  'client_credentials' // Without proper constraints
];

// Known vulnerable OAuth endpoints
const VULNERABLE_ENDPOINTS = [
  /localhost/i,
  /127\.0\.0\.1/,
  /0\.0\.0\.0/,
  /http:\/\//i, // Non-HTTPS
  /\.ngrok\.io/i,
  /\.localtunnel\.me/i
];

// Weak token patterns
const WEAK_TOKEN_PATTERNS = [
  /^[a-z]+$/i,           // Only letters
  /^[0-9]+$/,            // Only numbers
  /^.{1,16}$/,           // Too short
  /password/i,           // Contains 'password'
  /secret/i,             // Contains 'secret'
  /test/i,               // Test tokens
  /demo/i,               // Demo tokens
  /example/i             // Example tokens
];

export class OAuthSecurityScanner implements Scanner {
  public readonly name = 'oauth-security';
  public readonly version = '1.0.0';
  public readonly description = 'Scans for OAuth 2.0/2.1 security vulnerabilities';
  public readonly enabled = true;

  async scan(config: MCPServerConfig, scanConfig?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Check OAuth configuration if present
    if (config.oauth) {
      vulnerabilities.push(...this.scanOAuthConfig(config.oauth, serverId));
    }

    // Check for OAuth in environment variables
    if (config.env) {
      vulnerabilities.push(...this.scanOAuthInEnvironment(config.env, serverId));
    }

    // Check for OAuth-related patterns in args
    if (config.args) {
      vulnerabilities.push(...this.scanOAuthInArgs(config.args, serverId));
    }

    // Check for missing OAuth when it should be present
    vulnerabilities.push(...this.checkOAuthRequirements(config, serverId));

    return vulnerabilities;
  }

  private scanOAuthConfig(oauth: any, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for missing required fields (OAuth 2.1)
    for (const field of OAUTH21_REQUIREMENTS.requiredFields) {
      if (!oauth[field]) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'missing-required-field',
          `Missing required OAuth 2.1 field: ${field}`,
          Severity.HIGH,
          'oauth',
          field
        ));
      }
    }

    // Check for missing recommended fields
    for (const field of OAUTH21_REQUIREMENTS.recommendedFields) {
      if (!oauth[field]) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'missing-recommended-field',
          `Missing recommended OAuth 2.1 field: ${field}`,
          Severity.MEDIUM,
          'oauth',
          field
        ));
      }
    }

    // Check PKCE implementation
    if (oauth.pkce === false) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'pkce-disabled',
        'PKCE is explicitly disabled - vulnerable to authorization code interception',
        Severity.CRITICAL,
        'oauth.pkce',
        'false'
      ));
    }

    // Check authorization server URL
    if (oauth.authorizationServer) {
      // Check for insecure endpoints
      for (const pattern of VULNERABLE_ENDPOINTS) {
        if (pattern.test(oauth.authorizationServer)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'insecure-auth-server',
            `Insecure authorization server URL: ${oauth.authorizationServer}`,
            Severity.CRITICAL,
            'oauth.authorizationServer',
            oauth.authorizationServer
          ));
        }
      }

      // Check for HTTP instead of HTTPS
      if (oauth.authorizationServer.startsWith('http://')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'non-https-oauth',
          'OAuth using non-HTTPS connection - tokens can be intercepted',
          Severity.CRITICAL,
          'oauth.authorizationServer',
          oauth.authorizationServer
        ));
      }
    }

    // Check for hardcoded secrets
    for (const field of OAUTH21_REQUIREMENTS.secureFields) {
      if (oauth[field] && typeof oauth[field] === 'string') {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'hardcoded-secret',
          `Hardcoded OAuth secret in configuration: ${field}`,
          Severity.CRITICAL,
          `oauth.${field}`,
          'REDACTED'
        ));
      }
    }

    // Check redirect URI security
    if (oauth.redirectUri) {
      // Check for wildcard redirects
      if (oauth.redirectUri.includes('*')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'wildcard-redirect',
          'Wildcard in redirect URI - open redirect vulnerability',
          Severity.CRITICAL,
          'oauth.redirectUri',
          oauth.redirectUri
        ));
      }

      // Check for localhost redirects in production
      if (/localhost|127\.0\.0\.1/.test(oauth.redirectUri)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'localhost-redirect',
          'Localhost redirect URI - not suitable for production',
          Severity.HIGH,
          'oauth.redirectUri',
          oauth.redirectUri
        ));
      }
    }

    // Check scopes
    if (oauth.scopes) {
      // Check for overly broad scopes
      const dangerousScopes = ['admin', 'write:all', 'delete:all', '*', 'full_access'];
      for (const scope of oauth.scopes) {
        if (dangerousScopes.includes(scope.toLowerCase())) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'overly-broad-scope',
            `Overly broad OAuth scope: ${scope}`,
            Severity.HIGH,
            'oauth.scopes',
            scope
          ));
        }
      }

      // Check for empty scopes
      if (oauth.scopes.length === 0) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'empty-scopes',
          'Empty OAuth scopes - may default to full access',
          Severity.MEDIUM,
          'oauth.scopes',
          '[]'
        ));
      }
    }

    // Check token storage
    if (oauth.tokenStorage) {
      if (oauth.tokenStorage === 'localStorage') {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'insecure-token-storage',
          'Tokens stored in localStorage - vulnerable to XSS',
          Severity.HIGH,
          'oauth.tokenStorage',
          'localStorage'
        ));
      }
    }

    // Check token expiry
    if (oauth.tokenExpiry) {
      const expiry = parseInt(oauth.tokenExpiry);
      if (expiry > 3600) { // More than 1 hour
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'long-token-expiry',
          `Token expiry too long: ${expiry} seconds`,
          Severity.MEDIUM,
          'oauth.tokenExpiry',
          oauth.tokenExpiry
        ));
      }
    }

    // Check for insecure grant types
    if (oauth.grantType) {
      if (INSECURE_FLOWS.includes(oauth.grantType.toLowerCase())) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'insecure-grant-type',
          `Insecure OAuth grant type: ${oauth.grantType}`,
          Severity.HIGH,
          'oauth.grantType',
          oauth.grantType
        ));
      }
    }

    return vulnerabilities;
  }

  private scanOAuthInEnvironment(env: Record<string, string>, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    const oauthEnvPatterns = [
      /OAUTH_.*SECRET/i,
      /CLIENT_SECRET/i,
      /ACCESS_TOKEN/i,
      /REFRESH_TOKEN/i,
      /BEARER_TOKEN/i,
      /API_TOKEN/i,
      /AUTH_TOKEN/i
    ];

    for (const [key, value] of Object.entries(env)) {
      // Check for OAuth secrets in environment
      for (const pattern of oauthEnvPatterns) {
        if (pattern.test(key)) {
          // Check if it's a weak token
          for (const weakPattern of WEAK_TOKEN_PATTERNS) {
            if (weakPattern.test(value)) {
              vulnerabilities.push(this.createVulnerability(
                serverId,
                'weak-oauth-token',
                `Weak OAuth token in environment: ${key}`,
                Severity.HIGH,
                `env.${key}`,
                'Weak token pattern'
              ));
            }
          }

          // Check if it's hardcoded (not a placeholder)
          if (!value.includes('${') && !value.includes('$') && !value.includes('<') && value.length > 5) {
            vulnerabilities.push(this.createVulnerability(
              serverId,
              'hardcoded-oauth-token',
              `Hardcoded OAuth token in environment: ${key}`,
              Severity.CRITICAL,
              `env.${key}`,
              'REDACTED'
            ));
          }
        }
      }

      // Check for OAuth URLs
      if (/OAUTH.*URL|AUTH.*ENDPOINT/i.test(key)) {
        for (const pattern of VULNERABLE_ENDPOINTS) {
          if (pattern.test(value)) {
            vulnerabilities.push(this.createVulnerability(
              serverId,
              'insecure-oauth-url',
              `Insecure OAuth URL in environment: ${key}`,
              Severity.HIGH,
              `env.${key}`,
              value
            ));
          }
        }
      }
    }

    return vulnerabilities;
  }

  private scanOAuthInArgs(args: string[], serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const argsText = args.join(' ');

    // Check for OAuth tokens in command line args
    const tokenPatterns = [
      /Bearer\s+[A-Za-z0-9\-._~+/]+=*/,
      /token[=:]\s*[A-Za-z0-9\-._~+/]+/i,
      /client_secret[=:]\s*[A-Za-z0-9\-._~+/]+/i
    ];

    for (const pattern of tokenPatterns) {
      const match = argsText.match(pattern);
      if (match) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'token-in-args',
          'OAuth token exposed in command line arguments',
          Severity.CRITICAL,
          'args',
          'Token in args'
        ));
      }
    }

    // Check for OAuth configuration in args
    if (argsText.includes('--oauth') || argsText.includes('--auth')) {
      // Check for insecure configurations
      if (argsText.includes('--no-verify') || argsText.includes('--insecure')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'oauth-no-verify',
          'OAuth configured with certificate verification disabled',
          Severity.CRITICAL,
          'args',
          '--no-verify/--insecure'
        ));
      }
    }

    return vulnerabilities;
  }

  private checkOAuthRequirements(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check if API access is implied but OAuth is missing
    if ((configText.includes('api') || configText.includes('http') || 
         configText.includes('rest') || configText.includes('graphql')) && 
        !config.oauth && !config.auth) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'missing-oauth',
        'API access detected without OAuth configuration',
        Severity.HIGH,
        'config',
        'No OAuth/auth configuration'
      ));
    }

    // Check for JWT without proper validation
    if (configText.includes('jwt') || configText.includes('jsonwebtoken')) {
      if (!configText.includes('verify') && !configText.includes('validate')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unverified-jwt',
          'JWT tokens used without verification',
          Severity.CRITICAL,
          'config',
          'No JWT verification'
        ));
      }

      // Check for weak JWT secrets
      const jwtSecretMatch = configText.match(/jwt.*secret['":\s]*([^'",\s]+)/);
      if (jwtSecretMatch && jwtSecretMatch[1].length < 32) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'weak-jwt-secret',
          'JWT secret is too short (should be at least 32 characters)',
          Severity.HIGH,
          'config',
          'Weak JWT secret'
        ));
      }
    }

    // Check for session management issues
    if (configText.includes('session')) {
      if (!configText.includes('secure') || !configText.includes('httponly')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'insecure-session',
          'Session cookies may not be secure (missing secure/httpOnly flags)',
          Severity.MEDIUM,
          'config',
          'Insecure session config'
        ));
      }
    }

    // Check for CORS issues with OAuth
    if (config.oauth && configText.includes('cors')) {
      if (configText.includes('*') || configText.includes('allow.*origin.*\\*')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'oauth-cors-wildcard',
          'OAuth with wildcard CORS - allows token theft from any origin',
          Severity.CRITICAL,
          'config',
          'CORS wildcard with OAuth'
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
      id: `OAUTH-${this.generateId()}`,
      type: VulnerabilityType.OAUTH_TOKEN_LEAKAGE,
      severity,
      score: this.calculateScore(severity),
      server: serverId,
      title: `OAuth Security: ${title}`,
      description: `${title}. This could lead to unauthorized access, token theft, or authentication bypass.`,
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
        description: 'Follow OAuth 2.1 specifications, use PKCE, implement proper token storage, validate all tokens, use HTTPS, and implement token rotation.',
        automated: false,
        commands: [
          '# OAuth 2.1 compliant configuration:',
          'oauth: {',
          '  authorizationServer: "https://auth.example.com",',
          '  clientId: process.env.OAUTH_CLIENT_ID,',
          '  clientSecret: process.env.OAUTH_CLIENT_SECRET, // Never hardcode',
          '  pkce: true, // Always use PKCE',
          '  scopes: ["read:user", "read:data"], // Minimal required scopes',
          '  redirectUri: "https://app.example.com/callback",',
          '  tokenStorage: "memory", // Or secure httpOnly cookies',
          '  tokenExpiry: 900, // 15 minutes',
          '}',
          '',
          '# Validate JWT tokens:',
          'jwt.verify(token, secret, { algorithms: ["HS256"] })',
          '',
          '# Secure session configuration:',
          'session: {',
          '  cookie: { secure: true, httpOnly: true, sameSite: "strict" }',
          '}'
        ],
        documentation: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07'
      },
      references: [
        'https://oauth.net/2.1/',
        'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication'
      ],
      cwe: ['CWE-287', 'CWE-522', 'CWE-798'],
      compliance: {
        gdpr: true,
        soc2: true,
        hipaa: true,
        iso27001: true
      },
      discoveredAt: new Date().toISOString()
    };
  }

  private calculateScore(severity: Severity): number {
    const scores = {
      [Severity.CRITICAL]: 9.8,
      [Severity.HIGH]: 7.5,
      [Severity.MEDIUM]: 5.0,
      [Severity.LOW]: 2.5,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 8);
  }
}
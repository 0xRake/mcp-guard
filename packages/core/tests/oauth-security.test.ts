import { describe, it, expect, beforeEach } from 'vitest';
import { OAuthSecurityScanner } from '../src/scanners/oauth-security';
import { MCPServerConfig, Severity, VulnerabilityType } from '../src/types';

describe('OAuthSecurityScanner', () => {
  let scanner: OAuthSecurityScanner;

  beforeEach(() => {
    scanner = new OAuthSecurityScanner();
  });

  describe('OAuth 2.1 Requirements', () => {
    it('should detect missing required fields', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          scopes: ['read']
          // Missing authorizationServer and clientId
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const missingAuth = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'missing-required-field' &&
        v.evidence?.value === 'authorizationServer'
      );
      const missingClient = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'missing-required-field' &&
        v.evidence?.value === 'clientId'
      );

      expect(missingAuth).toBeDefined();
      expect(missingClient).toBeDefined();
      expect(missingAuth?.severity).toBe(Severity.HIGH);
    });

    it('should detect missing recommended fields', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123'
          // Missing scopes and pkce
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const missingScopes = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'missing-recommended-field' &&
        v.evidence?.value === 'scopes'
      );
      const missingPkce = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'missing-recommended-field' &&
        v.evidence?.value === 'pkce'
      );

      expect(missingScopes).toBeDefined();
      expect(missingPkce).toBeDefined();
      expect(missingScopes?.severity).toBe(Severity.MEDIUM);
    });

    it('should detect explicitly disabled PKCE', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          pkce: false
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const pkceDisabled = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'pkce-disabled'
      );

      expect(pkceDisabled).toBeDefined();
      expect(pkceDisabled?.severity).toBe(Severity.CRITICAL);
      expect(pkceDisabled?.title).toContain('PKCE is explicitly disabled');
    });
  });

  describe('Insecure Authorization Servers', () => {
    it('should detect HTTP authorization server', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'http://auth.example.com',
          clientId: 'client123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const nonHttps = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'non-https-oauth'
      );

      expect(nonHttps).toBeDefined();
      expect(nonHttps?.severity).toBe(Severity.CRITICAL);
      expect(nonHttps?.title).toContain('non-HTTPS');
    });

    it('should detect localhost authorization server', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://localhost:8080',
          clientId: 'client123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecure = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-auth-server'
      );

      expect(insecure).toBeDefined();
      expect(insecure?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect 127.0.0.1 authorization server', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://127.0.0.1:8080',
          clientId: 'client123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecure = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-auth-server'
      );

      expect(insecure).toBeDefined();
    });

    it('should detect ngrok tunnels', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://abc123.ngrok.io',
          clientId: 'client123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecure = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-auth-server'
      );

      expect(insecure).toBeDefined();
    });

    it('should detect localtunnel endpoints', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://test.localtunnel.me',
          clientId: 'client123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecure = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-auth-server'
      );

      expect(insecure).toBeDefined();
    });
  });

  describe('Hardcoded Secrets', () => {
    it('should detect hardcoded client secret', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          clientSecret: 'secret-abc-123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const hardcoded = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'hardcoded-secret'
      );

      expect(hardcoded).toBeDefined();
      expect(hardcoded?.severity).toBe(Severity.CRITICAL);
      expect(hardcoded?.evidence?.value).toBe('REDACTED');
    });

    it('should detect hardcoded refresh token', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          refreshToken: 'refresh_token_12345'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const hardcoded = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'hardcoded-secret'
      );

      expect(hardcoded).toBeDefined();
    });

    it('should detect hardcoded access token', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          accessToken: 'ya29.a0AfH6SMBx...'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const hardcoded = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'hardcoded-secret'
      );

      expect(hardcoded).toBeDefined();
      expect(hardcoded?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Redirect URI Security', () => {
    it('should detect wildcard redirect URIs', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          redirectUri: 'https://*.example.com/callback'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const wildcard = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'wildcard-redirect'
      );

      expect(wildcard).toBeDefined();
      expect(wildcard?.severity).toBe(Severity.CRITICAL);
      expect(wildcard?.title).toContain('Wildcard');
    });

    it('should detect localhost redirect URI', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          redirectUri: 'http://localhost:3000/callback'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const localhost = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'localhost-redirect'
      );

      expect(localhost).toBeDefined();
      expect(localhost?.severity).toBe(Severity.HIGH);
    });

    it('should detect 127.0.0.1 redirect URI', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          redirectUri: 'http://127.0.0.1:3000/callback'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const localhost = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'localhost-redirect'
      );

      expect(localhost).toBeDefined();
    });
  });

  describe('OAuth Scopes', () => {
    it('should detect overly broad scopes', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          scopes: ['admin', 'write:all', 'delete:all']
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const broadScopes = vulnerabilities.filter(v =>
        v.details?.vulnerabilityType === 'overly-broad-scope'
      );

      expect(broadScopes.length).toBeGreaterThan(0);
      expect(broadScopes[0].severity).toBe(Severity.HIGH);
    });

    it('should detect wildcard scope', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          scopes: ['*']
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const wildcard = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'overly-broad-scope'
      );

      expect(wildcard).toBeDefined();
    });

    it('should detect full_access scope', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          scopes: ['full_access']
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const fullAccess = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'overly-broad-scope'
      );

      expect(fullAccess).toBeDefined();
    });

    it('should detect empty scopes array', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          scopes: []
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const emptyScopes = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'empty-scopes'
      );

      expect(emptyScopes).toBeDefined();
      expect(emptyScopes?.severity).toBe(Severity.MEDIUM);
    });
  });

  describe('Token Storage', () => {
    it('should detect localStorage token storage', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          tokenStorage: 'localStorage'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecureStorage = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-token-storage'
      );

      expect(insecureStorage).toBeDefined();
      expect(insecureStorage?.severity).toBe(Severity.HIGH);
      expect(insecureStorage?.title).toContain('localStorage');
    });
  });

  describe('Token Expiry', () => {
    it('should detect excessive token expiry', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          tokenExpiry: '7200' // 2 hours
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const longExpiry = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'long-token-expiry'
      );

      expect(longExpiry).toBeDefined();
      expect(longExpiry?.severity).toBe(Severity.MEDIUM);
    });

    it('should not flag reasonable token expiry', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          tokenExpiry: '900' // 15 minutes
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const longExpiry = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'long-token-expiry'
      );

      expect(longExpiry).toBeUndefined();
    });
  });

  describe('Insecure Grant Types', () => {
    it('should detect implicit grant type', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          grantType: 'implicit'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecureGrant = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-grant-type'
      );

      expect(insecureGrant).toBeDefined();
      expect(insecureGrant?.severity).toBe(Severity.HIGH);
    });

    it('should detect password grant type', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          grantType: 'password'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecureGrant = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-grant-type'
      );

      expect(insecureGrant).toBeDefined();
    });

    it('should detect client_credentials without constraints', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          grantType: 'client_credentials'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecureGrant = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-grant-type'
      );

      expect(insecureGrant).toBeDefined();
    });
  });

  describe('Environment Variable Security', () => {
    it('should detect OAuth secrets in environment', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'OAUTH_CLIENT_SECRET': 'my-secret-123',
          'API_KEY': 'key123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const hardcoded = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'hardcoded-oauth-token'
      );

      expect(hardcoded).toBeDefined();
      expect(hardcoded?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect weak OAuth tokens', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'ACCESS_TOKEN': 'password', // Weak token
          'API_KEY': 'key123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const weak = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'weak-oauth-token'
      );

      expect(weak).toBeDefined();
      expect(weak?.severity).toBe(Severity.HIGH);
    });

    it('should detect short tokens', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'BEARER_TOKEN': '12345', // Too short
          'API_KEY': 'key123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const weak = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'weak-oauth-token'
      );

      expect(weak).toBeDefined();
    });

    it('should detect test tokens', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'AUTH_TOKEN': 'test_token_123',
          'API_KEY': 'key123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const weak = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'weak-oauth-token'
      );

      expect(weak).toBeDefined();
    });

    it('should not flag environment variable placeholders', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'CLIENT_SECRET': '${CLIENT_SECRET}',
          'API_KEY': '$API_KEY'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const hardcoded = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'hardcoded-oauth-token'
      );

      expect(hardcoded).toBeUndefined();
    });

    it('should detect insecure OAuth URLs in environment', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'OAUTH_AUTH_URL': 'http://localhost:8080/auth',
          'API_KEY': 'key123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecureUrl = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-oauth-url'
      );

      expect(insecureUrl).toBeDefined();
      expect(insecureUrl?.severity).toBe(Severity.HIGH);
    });
  });

  describe('Command Line Arguments', () => {
    it('should detect Bearer tokens in args', async () => {
      const config: MCPServerConfig = {
        command: 'curl',
        args: ['-H', 'Authorization: Bearer abc123def456'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const tokenInArgs = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'token-in-args'
      );

      expect(tokenInArgs).toBeDefined();
      expect(tokenInArgs?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect token= in args', async () => {
      const config: MCPServerConfig = {
        command: 'curl',
        args: ['https://api.example.com', '--data', 'token=secret123'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const tokenInArgs = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'token-in-args'
      );

      expect(tokenInArgs).toBeDefined();
    });

    it('should detect client_secret in args', async () => {
      const config: MCPServerConfig = {
        command: 'curl',
        args: ['--data', 'client_secret=abc123'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const tokenInArgs = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'token-in-args'
      );

      expect(tokenInArgs).toBeDefined();
    });

    it('should detect disabled certificate verification', async () => {
      const config: MCPServerConfig = {
        command: 'curl',
        args: ['--oauth', '--no-verify', 'https://api.example.com'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const noVerify = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'oauth-no-verify'
      );

      expect(noVerify).toBeDefined();
      expect(noVerify?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect --insecure flag', async () => {
      const config: MCPServerConfig = {
        command: 'curl',
        args: ['--auth', '--insecure', 'https://api.example.com'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecure = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'oauth-no-verify'
      );

      expect(insecure).toBeDefined();
    });
  });

  describe('Missing OAuth Detection', () => {
    it('should detect API access without OAuth', async () => {
      const config: MCPServerConfig = {
        command: 'curl',
        args: ['https://api.example.com/users'],
        metadata: { name: 'api-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const missingOAuth = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'missing-oauth'
      );

      expect(missingOAuth).toBeDefined();
      expect(missingOAuth?.severity).toBe(Severity.HIGH);
    });

    it('should detect REST API without auth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['rest-server.js'],
        metadata: { name: 'rest-api' }
      };

      const vulnerabilities = await scanner.scan(config);

      const missingOAuth = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'missing-oauth'
      );

      expect(missingOAuth).toBeDefined();
    });

    it('should detect GraphQL API without auth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['graphql-server.js'],
        metadata: { name: 'graphql-api' }
      };

      const vulnerabilities = await scanner.scan(config);

      const missingOAuth = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'missing-oauth'
      );

      expect(missingOAuth).toBeDefined();
    });
  });

  describe('JWT Security', () => {
    it('should detect unverified JWT tokens', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'JWT_ENABLED': 'true',
          'API_KEY': 'key123'
        },
        metadata: { name: 'jwt-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const unverified = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'unverified-jwt'
      );

      expect(unverified).toBeDefined();
      expect(unverified?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect weak JWT secrets', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'JWT_SECRET': 'short',
          'API_KEY': 'key123'
        },
        metadata: { name: 'jwt-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const weakSecret = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'weak-jwt-secret'
      );

      expect(weakSecret).toBeDefined();
      expect(weakSecret?.severity).toBe(Severity.HIGH);
    });
  });

  describe('Session Management', () => {
    it('should detect insecure session configuration', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'SESSION_ENABLED': 'true',
          'API_KEY': 'key123'
        },
        metadata: { name: 'session-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const insecureSession = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'insecure-session'
      );

      expect(insecureSession).toBeDefined();
      expect(insecureSession?.severity).toBe(Severity.MEDIUM);
    });
  });

  describe('CORS with OAuth', () => {
    it('should detect wildcard CORS with OAuth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123'
        },
        env: {
          'CORS_ORIGIN': '*'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const corsWildcard = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'oauth-cors-wildcard'
      );

      expect(corsWildcard).toBeDefined();
      expect(corsWildcard?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Safe OAuth Configurations', () => {
    it('should not flag secure OAuth 2.1 configuration', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          pkce: true,
          scopes: ['read:user', 'read:data'],
          redirectUri: 'https://app.example.com/callback',
          tokenStorage: 'memory'
        },
        env: {
          'OAUTH_CLIENT_SECRET': '${OAUTH_CLIENT_SECRET}' // Placeholder
        },
        metadata: { name: 'secure-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const critical = vulnerabilities.filter(v => v.severity === Severity.CRITICAL);
      expect(critical.length).toBe(0);
    });

    it('should not flag environment variable references', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'CLIENT_ID': '${CLIENT_ID}',
          'CLIENT_SECRET': '${CLIENT_SECRET}'
        },
        metadata: { name: 'env-ref-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const hardcoded = vulnerabilities.find(v =>
        v.details?.vulnerabilityType === 'hardcoded-oauth-token'
      );

      expect(hardcoded).toBeUndefined();
    });
  });

  describe('Remediation', () => {
    it('should provide appropriate remediation for OAuth vulnerabilities', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'http://auth.example.com',
          clientId: 'client123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities[0].remediation).toBeDefined();
      expect(vulnerabilities[0].remediation.description).toContain('OAuth 2.1');
      expect(vulnerabilities[0].remediation.commands).toBeDefined();
      expect(vulnerabilities[0].remediation.documentation).toContain('oauth');
    });
  });

  describe('Compliance', () => {
    it('should flag compliance issues for OAuth vulnerabilities', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'http://auth.example.com',
          clientId: 'client123',
          clientSecret: 'hardcoded-secret'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities[0].compliance).toBeDefined();
      expect(vulnerabilities[0].compliance?.gdpr).toBe(true);
      expect(vulnerabilities[0].compliance?.soc2).toBe(true);
      expect(vulnerabilities[0].compliance?.hipaa).toBe(true);
    });
  });

  describe('CWE References', () => {
    it('should include CWE references for OAuth vulnerabilities', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          clientSecret: 'hardcoded'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities[0].cwe).toBeDefined();
      expect(vulnerabilities[0].cwe).toContain('CWE-287');
    });
  });

  describe('Vulnerability Type', () => {
    it('should use correct vulnerability type for OAuth issues', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          clientSecret: 'secret123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities[0].type).toBe(VulnerabilityType.OAUTH_TOKEN_LEAKAGE);
    });
  });
});

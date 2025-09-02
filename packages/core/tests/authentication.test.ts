import { describe, it, expect, beforeEach } from 'vitest';
import { AuthenticationScanner } from '../src/scanners/authentication';
import { MCPServerConfig, Severity, VulnerabilityType } from '../src/types';

describe('AuthenticationScanner', () => {
  let scanner: AuthenticationScanner;

  beforeEach(() => {
    scanner = new AuthenticationScanner();
  });

  describe('Missing Authentication', () => {
    it('should detect missing authentication for sensitive servers', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['database-server.js'],
        metadata: { name: 'production-database' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.MISSING_AUTHENTICATION);
      expect(vulnerabilities[0].severity).toBe(Severity.CRITICAL);
      expect(vulnerabilities[0].title).toContain('Missing Authentication');
    });

    it('should detect missing auth for servers with sensitive env vars', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'DATABASE_URL': 'postgresql://localhost/db',
          'API_ENDPOINT': 'https://api.example.com'
        },
        metadata: { name: 'api-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      const missingAuth = vulnerabilities.find(v => v.type === VulnerabilityType.MISSING_AUTHENTICATION);
      expect(missingAuth).toBeDefined();
    });

    it('should not flag secure public servers', async () => {
      const config: MCPServerConfig = {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-memory'],
        metadata: { name: 'memory-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('Weak Authentication', () => {
    it('should detect basic authentication as less secure', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        auth: {
          type: 'basic',
          credentials: {
            username: 'user',
            password: 'SecurePass123!'
          }
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const weakAuth = vulnerabilities.find(v => 
        v.details?.reason === 'Basic authentication is less secure than bearer tokens'
      );
      expect(weakAuth).toBeDefined();
      expect(weakAuth?.severity).toBe(Severity.MEDIUM);
    });

    it('should detect weak passwords', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        auth: {
          type: 'basic',
          credentials: {
            username: 'admin',
            password: 'password123'
          }
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const weakPassword = vulnerabilities.find(v => 
        v.details?.reason === 'Weak password detected in basic authentication'
      );
      expect(weakPassword).toBeDefined();
      expect(weakPassword?.severity).toBe(Severity.HIGH);
    });

    it('should detect default credentials', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        auth: {
          type: 'basic',
          credentials: {
            username: 'admin',
            password: 'admin'
          }
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const defaultCreds = vulnerabilities.find(v => 
        v.details?.reason?.includes('Default credentials detected')
      );
      expect(defaultCreds).toBeDefined();
      expect(defaultCreds?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('OAuth Security', () => {
    it('should detect missing PKCE in OAuth configuration', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          scopes: ['read', 'write']
          // pkce is missing
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const missingPKCE = vulnerabilities.find(v => 
        v.details?.reason?.includes('PKCE')
      );
      expect(missingPKCE).toBeDefined();
      expect(missingPKCE?.severity).toBe(Severity.HIGH);
    });

    it('should detect insecure HTTP authorization server', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'http://auth.example.com', // HTTP instead of HTTPS
          clientId: 'client123',
          pkce: true
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const insecureHttp = vulnerabilities.find(v => 
        v.details?.reason?.includes('insecure HTTP protocol')
      );
      expect(insecureHttp).toBeDefined();
      expect(insecureHttp?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect localhost authorization server', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://localhost:8080',
          clientId: 'client123',
          pkce: true
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const localhost = vulnerabilities.find(v => 
        v.details?.reason?.includes('localhost')
      );
      expect(localhost).toBeDefined();
      expect(localhost?.severity).toBe(Severity.HIGH);
    });

    it('should detect overly broad OAuth scopes', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          scopes: ['*', 'admin', 'write:all'],
          pkce: true
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const broadScopes = vulnerabilities.find(v => 
        v.details?.reason?.includes('broad or dangerous scopes')
      );
      expect(broadScopes).toBeDefined();
      expect(broadScopes?.severity).toBe(Severity.HIGH);
    });

    it('should detect deprecated OAuth grant types', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          pkce: true,
          metadata: {
            issuer: 'https://auth.example.com',
            authorization_endpoint: 'https://auth.example.com/authorize',
            token_endpoint: 'https://auth.example.com/token',
            grant_types_supported: ['implicit', 'password'] // Deprecated grant types
          }
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const implicitGrant = vulnerabilities.find(v => 
        v.details?.reason?.includes('implicit grant')
      );
      const passwordGrant = vulnerabilities.find(v => 
        v.details?.reason?.includes('password grant')
      );
      
      expect(implicitGrant).toBeDefined();
      expect(passwordGrant).toBeDefined();
      expect(implicitGrant?.severity).toBe(Severity.HIGH);
    });
  });

  describe('Authentication Bypass', () => {
    it('should detect authentication bypass environment variables', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'SKIP_AUTH': 'true',
          'API_KEY': 'some-key'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const authBypass = vulnerabilities.find(v => 
        v.details?.reason?.includes('Authentication bypass enabled')
      );
      expect(authBypass).toBeDefined();
      expect(authBypass?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect debug mode that may bypass auth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'DEBUG': 'true',
          'DEBUG_MODE': '1'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const debugMode = vulnerabilities.find(v => 
        v.details?.reason?.includes('Debug mode enabled')
      );
      expect(debugMode).toBeDefined();
      expect(debugMode?.severity).toBe(Severity.MEDIUM);
    });
  });

  describe('Insecure Authentication Methods', () => {
    it('should detect auth tokens in URL parameters', async () => {
      const config: MCPServerConfig = {
        command: 'curl',
        args: ['https://api.example.com?token=secret123'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const urlToken = vulnerabilities.find(v => 
        v.details?.reason?.includes('URL parameters')
      );
      expect(urlToken).toBeDefined();
      expect(urlToken?.severity).toBe(Severity.HIGH);
    });

    it('should detect --no-auth command line flags', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--no-auth', '--port', '3000'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const noAuthFlag = vulnerabilities.find(v => 
        v.details?.reason?.includes('explicitly disabled via command line')
      );
      expect(noAuthFlag).toBeDefined();
      expect(noAuthFlag?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect insecure protocols', async () => {
      const config: MCPServerConfig = {
        command: 'telnet',
        args: ['telnet://server.example.com'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const insecureProtocol = vulnerabilities.find(v => 
        v.details?.reason?.includes('insecure protocol')
      );
      expect(insecureProtocol).toBeDefined();
      expect(insecureProtocol?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Remediation', () => {
    it('should provide appropriate remediation for missing auth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['database-server.js'],
        metadata: { name: 'production-database' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities[0].remediation).toBeDefined();
      expect(vulnerabilities[0].remediation.description).toContain('OAuth 2.1');
      expect(vulnerabilities[0].remediation.commands).toBeDefined();
      expect(vulnerabilities[0].remediation.documentation).toContain('modelcontextprotocol.io');
    });
  });

  describe('Compliance', () => {
    it('should flag compliance issues for missing authentication', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['medical-records-server.js'],
        metadata: { name: 'medical-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities[0].compliance).toBeDefined();
      expect(vulnerabilities[0].compliance?.gdpr).toBe(true);
      expect(vulnerabilities[0].compliance?.hipaa).toBe(true);
      expect(vulnerabilities[0].compliance?.soc2).toBe(true);
    });
  });
});

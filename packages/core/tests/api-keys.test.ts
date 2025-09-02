import { describe, it, expect, beforeEach } from 'vitest';
import { APIKeyScanner } from '../src/scanners/api-keys';
import { MCPServerConfig, Severity, VulnerabilityType } from '../src/types';

describe('APIKeyScanner', () => {
  let scanner: APIKeyScanner;

  beforeEach(() => {
    scanner = new APIKeyScanner();
  });

  describe('OpenAI Keys', () => {
    it('should detect OpenAI API keys in command arguments', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--api-key', 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.EXPOSED_API_KEY);
      expect(vulnerabilities[0].severity).toBe(Severity.CRITICAL);
      expect(vulnerabilities[0].title).toContain('OpenAI API Key');
    });

    it('should detect OpenAI project keys', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['--key=sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].title).toContain('OpenAI Project Key');
    });
  });

  describe('Environment Variables', () => {
    it('should detect secrets in environment variables', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'OPENAI_API_KEY': 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab',
          'DATABASE_PASSWORD': 'super-secret-password-123'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      const apiKeyVuln = vulnerabilities.find(v => v.details?.keyType === 'OpenAI API Key');
      expect(apiKeyVuln).toBeDefined();
      expect(apiKeyVuln?.location?.path).toContain('OPENAI_API_KEY');
    });

    it('should ignore placeholder values', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'API_KEY': '${API_KEY}',
          'SECRET': '<your-secret-here>',
          'TOKEN': 'process.env.TOKEN',
          'PASSWORD': '***********'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('AWS Credentials', () => {
    it('should detect AWS access keys', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0].title).toContain('AWS Access Key');
      expect(vulnerabilities[0].severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Database Connection Strings', () => {
    it('should detect MongoDB connection strings with credentials', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'MONGO_URI': 'mongodb://username:password@localhost:27017/database'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      const mongoVuln = vulnerabilities.find(v => v.details?.keyType === 'MongoDB Connection String');
      expect(mongoVuln).toBeDefined();
      expect(mongoVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect PostgreSQL connection strings', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['--db', 'postgresql://user:pass@localhost/db'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0].title).toContain('PostgreSQL Connection String');
    });
  });

  describe('OAuth Configuration', () => {
    it('should detect hardcoded OAuth client secrets', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123',
          clientSecret: 'super-secret-client-secret-123456789'
        } as any,
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      const oauthVuln = vulnerabilities.find(v => v.details?.keyType === 'OAuth Client Secret');
      expect(oauthVuln).toBeDefined();
      expect(oauthVuln?.severity).toBe(Severity.HIGH);
    });
  });

  describe('GitHub Tokens', () => {
    it('should detect GitHub personal access tokens', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'GITHUB_TOKEN': 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0].title).toContain('GitHub Personal Access Token');
      expect(vulnerabilities[0].severity).toBe(Severity.HIGH);
    });
  });

  describe('Redaction', () => {
    it('should properly redact secrets in evidence', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'SECRET_KEY': 'this-is-a-very-long-secret-key-that-should-be-redacted'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      const evidence = vulnerabilities[0].evidence?.value;
      expect(evidence).toContain('this');
      expect(evidence).toContain('cted');
      expect(evidence).toContain('*');
      expect(evidence).not.toContain('very-long-secret');
    });
  });

  describe('Remediation', () => {
    it('should provide remediation instructions', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'API_KEY': 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities[0].remediation).toBeDefined();
      expect(vulnerabilities[0].remediation.description).toContain('environment variable');
      expect(vulnerabilities[0].remediation.automated).toBe(true);
      expect(vulnerabilities[0].remediation.commands).toBeDefined();
      expect(vulnerabilities[0].remediation.commands?.length).toBeGreaterThan(0);
    });
  });

  describe('Compliance', () => {
    it('should flag compliance issues for exposed secrets', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'DATABASE_PASSWORD': 'production-password-123'
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
});

import { describe, it, expect, beforeEach } from 'vitest';
import { RateLimitingScanner } from '../src/scanners/rate-limiting';
import { MCPServerConfig, Severity } from '../src/types';

describe('RateLimitingScanner', () => {
  let scanner: RateLimitingScanner;

  beforeEach(() => {
    scanner = new RateLimitingScanner();
  });

  it('should have correct metadata', () => {
    expect(scanner.name).toBe('rate-limiting');
    expect(scanner.enabled).toBe(true);
    expect(scanner.version).toBe('1.0.0');
  });

  describe('Missing Rate Limiting', () => {
    it('should detect missing rate limiting for API services', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['api-server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const apiVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'no-rate-limiting');
      expect(apiVuln).toBeDefined();
    });

    it('should detect missing rate limiting for LLM services', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'OPENAI_API_KEY': 'sk-test'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const llmVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unlimited-llm-access');
      expect(llmVuln).toBeDefined();
      expect(llmVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect missing rate limiting for Claude services', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['claude-server.js'],
        env: {
          'ANTHROPIC_API_KEY': 'sk-ant-test'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe('Authentication Rate Limiting', () => {
    it('should detect unlimited login attempts', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--enable-login'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const authVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unlimited-auth-attempts');
      expect(authVuln).toBeDefined();
      expect(authVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect unlimited password endpoints', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'PASSWORD_RESET_ENABLED': 'true'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe('Rate Limit Configuration', () => {
    it('should detect excessive rate limits', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'RATE_LIMIT': '10000',
          'API_RATE_LIMIT': '5000'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const excessiveVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'excessive-rate-limit');
      expect(excessiveVuln).toBeDefined();
      expect(excessiveVuln?.severity).toBe(Severity.MEDIUM);
    });

    it('should detect missing time window', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'RATE_LIMIT': '100'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const windowVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'no-time-window');
      expect(windowVuln).toBeDefined();
    });

    it('should detect global rate limiting without per-user limits', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'RATE_LIMIT': '100',
          'RATE_LIMIT_WINDOW': '60000'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const globalVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'global-rate-limit');
      expect(globalVuln).toBeDefined();
    });

    it('should detect rate limit bypass mechanisms', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'RATE_LIMIT_BYPASS': 'admin-key'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const bypassVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'rate-limit-bypass');
      expect(bypassVuln).toBeDefined();
      expect(bypassVuln?.severity).toBe(Severity.HIGH);
    });
  });

  describe('Dangerous Operations', () => {
    it('should detect unlimited execute operations', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--enable-execute'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const execVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unlimited-dangerous-operation');
      expect(execVuln).toBeDefined();
    });

    it('should detect unlimited spawn operations', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'SPAWN_ENABLED': 'true'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
    });

    it('should detect unlimited bulk operations', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--bulk-mode'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const bulkVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unlimited-bulk-operations');
      expect(bulkVuln).toBeDefined();
    });

    it('should detect unlimited file operations', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--enable-upload'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const fileVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unlimited-file-operations');
      expect(fileVuln).toBeDefined();
    });
  });

  describe('DDoS Vulnerabilities', () => {
    it('should detect resource exhaustion risks', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--compute-mode'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const resourceVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'resource-exhaustion');
      expect(resourceVuln).toBeDefined();
    });

    it('should detect infinite loop risks', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--recursive-mode'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const loopVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'infinite-loop-risk');
      expect(loopVuln).toBeDefined();
    });

    it('should detect missing connection limits', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--socket-mode'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const connVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unlimited-connections');
      expect(connVuln).toBeDefined();
    });

    it('should detect missing memory limits', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--buffer-enabled'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const memVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'no-memory-limits');
      expect(memVuln).toBeDefined();
    });

    it('should detect missing size limits', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const sizeVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'no-size-limits');
      expect(sizeVuln).toBeDefined();
    });
  });

  describe('Webhook Rate Limiting', () => {
    it('should detect unlimited webhook endpoints', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--webhook-enabled'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const webhookVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unlimited-webhooks');
      expect(webhookVuln).toBeDefined();
    });
  });

  describe('API Rate Limiting', () => {
    it('should detect unlimited API access', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'API_ENDPOINT': '/api/v1'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const apiVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unlimited-api-access');
      expect(apiVuln).toBeDefined();
    });
  });

  describe('Clean Configurations', () => {
    it('should accept properly rate-limited config', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'RATE_LIMIT_PER_USER': '100',
          'RATE_LIMIT_WINDOW': '60000',
          'MAX_SIZE': '10mb',
          'TIMEOUT': '30000'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      // Should have fewer vulnerabilities with proper rate limiting
      const criticalVulns = vulnerabilities.filter(v => v.severity === Severity.CRITICAL);
      expect(criticalVulns).toHaveLength(0);
    });
  });

  describe('Compliance', () => {
    it('should flag SOC2 compliance for rate limiting issues', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['api-server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities[0].compliance).toBeDefined();
      expect(vulnerabilities[0].compliance?.soc2).toBe(true);
    });
  });

  describe('Remediation', () => {
    it('should provide remediation instructions', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['api-server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities[0].remediation).toBeDefined();
      expect(vulnerabilities[0].remediation.description).toContain('rate limiting');
      expect(vulnerabilities[0].remediation.commands?.length).toBeGreaterThan(0);
    });
  });
});

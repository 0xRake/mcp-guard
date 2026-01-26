import { describe, it, expect, beforeEach } from 'vitest';
import { ConfusedDeputyScanner } from '../src/scanners/confused-deputy';
import { MCPServerConfig, Severity, VulnerabilityType } from '../src/types';

describe('ConfusedDeputyScanner', () => {
  let scanner: ConfusedDeputyScanner;

  beforeEach(() => {
    scanner = new ConfusedDeputyScanner();
  });

  it('should have correct metadata', () => {
    expect(scanner.name).toBe('confused-deputy');
    expect(scanner.enabled).toBe(true);
    expect(scanner.version).toBe('1.0.0');
  });

  describe('Privilege Escalation', () => {
    it('should detect sudo in command', async () => {
      const config: MCPServerConfig = {
        command: 'sudo',
        args: ['node', 'server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
      const sudoVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'privilege-escalation-command');
      expect(sudoVuln).toBeDefined();
      expect(sudoVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect setuid in arguments', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--setuid=0'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
      const vuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'privilege-escalation-args');
      expect(vuln).toBeDefined();
    });

    it('should detect UID/GID manipulation', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--uid=0', '--gid=0'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const uidVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'uid-gid-manipulation');
      expect(uidVuln).toBeDefined();
      expect(uidVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect dangerous environment overrides', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'SUDO_USER': 'root',
          'UID': '0'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const envVulns = vulnerabilities.filter(v => v.details?.vulnerabilityType === 'privilege-env-override');
      expect(envVulns.length).toBeGreaterThan(0);
    });
  });

  describe('Cross-Service Requests', () => {
    it('should detect forward patterns', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--forward-requests'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const forwardVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'cross-service-request');
      expect(forwardVuln).toBeDefined();
    });

    it('should detect proxy patterns', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['proxy-server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
    });

    it('should detect unrestricted forwarding', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['forward-server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const unrestrictedVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unrestricted-forwarding');
      expect(unrestrictedVuln).toBeDefined();
    });

    it('should detect unvalidated service accounts', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'SERVICE_ACCOUNT': 'admin-service'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const serviceVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unvalidated-service-account');
      expect(serviceVuln).toBeDefined();
    });
  });

  describe('Unsafe Resource Access', () => {
    it('should detect S3 access without authorization', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--bucket=s3://my-bucket'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const s3Vuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unauthorized-resource-access');
      expect(s3Vuln).toBeDefined();
    });

    it('should detect file:// protocol abuse', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--config=file:///etc/passwd'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const fileVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'file-protocol-abuse');
      expect(fileVuln).toBeDefined();
      expect(fileVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect internal network access', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--api=http://192.168.1.100:8080'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const internalVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'internal-network-access');
      expect(internalVuln).toBeDefined();
    });

    it('should detect ARN patterns without auth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--resource=arn:aws:s3:::bucket'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const arnVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unauthorized-resource-access');
      expect(arnVuln).toBeDefined();
    });
  });

  describe('Delegation Issues', () => {
    it('should detect unsafe delegation patterns', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--allow_all'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const delegationVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unsafe-delegation');
      expect(delegationVuln).toBeDefined();
    });

    it('should detect bypass_auth patterns', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'BYPASS_AUTH': 'true'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const bypassVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unsafe-delegation');
      expect(bypassVuln).toBeDefined();
    });

    it('should detect wildcard permissions', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'PERMISSION_GRANT': '*'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const wildcardVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'wildcard-permissions');
      expect(wildcardVuln).toBeDefined();
    });

    it('should detect unvalidated token relay', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'TOKEN_FORWARD': 'enabled',
          'BEARER_PASS_THROUGH': 'true'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const tokenVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unvalidated-token-relay');
      expect(tokenVuln).toBeDefined();
      expect(tokenVuln?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Ambient Authority', () => {
    it('should detect AWS credentials in environment', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
          'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const ambientVulns = vulnerabilities.filter(v => v.details?.vulnerabilityType === 'ambient-credentials');
      expect(ambientVulns.length).toBeGreaterThanOrEqual(2);
    });

    it('should detect Google credentials in environment', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'GOOGLE_APPLICATION_CREDENTIALS': '/path/to/service-account.json'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const gcpVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'ambient-credentials');
      expect(gcpVuln).toBeDefined();
    });

    it('should detect Azure credentials in environment', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'AZURE_CLIENT_ID': 'client-id',
          'AZURE_CLIENT_SECRET': 'client-secret'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const azureVulns = vulnerabilities.filter(v => v.details?.vulnerabilityType === 'ambient-credentials');
      expect(azureVulns.length).toBeGreaterThanOrEqual(2);
    });

    it('should detect default service account usage', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--use-default-service-account'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const defaultVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'default-service-account');
      expect(defaultVuln).toBeDefined();
    });

    it('should detect unrestricted capabilities without auth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        capabilities: {
          tools: true,
          resources: true,
          prompts: true
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const capVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unrestricted-capabilities');
      expect(capVuln).toBeDefined();
      expect(capVuln?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Clean Configurations', () => {
    it('should pass clean config with proper auth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        auth: {
          type: 'bearer',
          token: '${AUTH_TOKEN}'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      // May still have some low-severity findings but no critical ones
      const criticalVulns = vulnerabilities.filter(v => v.severity === Severity.CRITICAL);
      expect(criticalVulns).toHaveLength(0);
    });
  });

  describe('Compliance', () => {
    it('should flag compliance issues for confused deputy vulnerabilities', async () => {
      const config: MCPServerConfig = {
        command: 'sudo',
        args: ['node', 'server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
      const vuln = vulnerabilities[0]!;
      expect(vuln.compliance).toBeDefined();
      expect(vuln.compliance?.soc2).toBe(true);
      expect(vuln.compliance?.iso27001).toBe(true);
    });
  });

  describe('Remediation', () => {
    it('should provide remediation instructions', async () => {
      const config: MCPServerConfig = {
        command: 'sudo',
        args: ['node', 'server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
      const vuln = vulnerabilities[0]!;
      expect(vuln.remediation).toBeDefined();
      expect(vuln.remediation.description).toBeDefined();
      expect(vuln.remediation.commands).toBeDefined();
      expect(vuln.remediation.commands?.length).toBeGreaterThan(0);
    });
  });
});

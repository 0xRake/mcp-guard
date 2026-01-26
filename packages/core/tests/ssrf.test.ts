import { describe, it, expect, beforeEach } from 'vitest';
import { SSRFScanner } from '../src/scanners/ssrf';
import { MCPServerConfig, Severity } from '../src/types';

describe('SSRFScanner', () => {
  let scanner: SSRFScanner;

  beforeEach(() => {
    scanner = new SSRFScanner();
  });

  it('should have correct metadata', () => {
    expect(scanner.name).toBe('ssrf');
    expect(scanner.enabled).toBe(true);
    expect(scanner.version).toBe('1.0.0');
  });

  describe('Localhost Detection', () => {
    it('should detect localhost references', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--target=http://localhost:3000'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const localhostVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'localhost-access');
      expect(localhostVuln).toBeDefined();
    });

    it('should detect 127.0.0.1 addresses', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--backend=http://127.0.0.1:8080'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const localhostVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'localhost-access');
      expect(localhostVuln).toBeDefined();
    });

    it('should detect 0.0.0.0 addresses', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--bind=0.0.0.0:8080'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const localhostVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'localhost-access');
      expect(localhostVuln).toBeDefined();
    });

    it('should detect ::1 IPv6 loopback', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--target=http://[::1]:3000'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const localhostVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'localhost-access');
      expect(localhostVuln).toBeDefined();
    });
  });

  describe('Cloud Metadata Endpoints', () => {
    it('should detect AWS metadata endpoint', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--config=http://169.254.169.254/latest/meta-data/'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const metadataVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'metadata-endpoint-access');
      expect(metadataVuln).toBeDefined();
      expect(metadataVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect GCP metadata endpoint', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'METADATA_URL': 'http://metadata.google.internal/computeMetadata/v1/'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const metadataVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'metadata-endpoint-in-env');
      expect(metadataVuln).toBeDefined();
      expect(metadataVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect Azure metadata endpoint', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--metadata=http://metadata.azure.com/metadata/instance'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const metadataVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'metadata-endpoint-access');
      expect(metadataVuln).toBeDefined();
    });
  });

  describe('Dangerous Protocols', () => {
    it('should detect file:// protocol', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--config=file:///etc/passwd'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const fileVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'dangerous-protocol');
      expect(fileVuln).toBeDefined();
      expect(fileVuln?.severity).toBe(Severity.HIGH);
    });

    it('should detect gopher:// protocol', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--url=gopher://localhost:9000/_test'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const gopherVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'dangerous-protocol');
      expect(gopherVuln).toBeDefined();
    });

    it('should detect ldap:// protocol', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--auth=ldap://internal.corp:389'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const ldapVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'dangerous-protocol');
      expect(ldapVuln).toBeDefined();
    });

    it('should detect ftp:// protocol', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--source=ftp://internal-ftp/files'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const ftpVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'dangerous-protocol');
      expect(ftpVuln).toBeDefined();
    });

    it('should detect dangerous protocols in environment', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'CONFIG_URL': 'file:///etc/shadow'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const envVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'dangerous-protocol-in-env');
      expect(envVuln).toBeDefined();
    });
  });

  describe('URL Parameter Patterns', () => {
    it('should detect user-controlled URL parameters', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--fetch-url=${USER_INPUT}'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const userVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'user-controlled-url');
      expect(userVuln).toBeDefined();
      expect(userVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect template URL parameters', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--callback={{callback_url}}'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const userVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'user-controlled-url');
      expect(userVuln).toBeDefined();
    });
  });

  describe('URL Handling Patterns', () => {
    it('should detect unvalidated URL fetch', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'FETCH_ENABLED': 'true'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const fetchVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unvalidated-url-fetch');
      expect(fetchVuln).toBeDefined();
    });

    it('should detect redirect following pattern', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'FOLLOW_REDIRECT': 'true',
          'FETCH_ENABLED': 'true'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const redirectVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'redirect-following');
      expect(redirectVuln).toBeDefined();
    });

    it('should detect media SSRF vectors', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'IMAGE_SRC': 'true',
          'MEDIA_URL': 'enabled'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const mediaVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'media-ssrf');
      expect(mediaVuln).toBeDefined();
    });

    it('should detect PDF generation SSRF', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'PDF_GENERATOR': 'puppeteer'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const pdfVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'pdf-ssrf');
      expect(pdfVuln).toBeDefined();
    });

    it('should detect wkhtmltopdf SSRF', async () => {
      const config: MCPServerConfig = {
        command: 'wkhtmltopdf',
        args: ['input.html', 'output.pdf'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const pdfVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'pdf-ssrf');
      expect(pdfVuln).toBeDefined();
    });

    it('should detect XXE SSRF vectors', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'XML_PARSER': 'enabled'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const xxeVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'xxe-ssrf');
      expect(xxeVuln).toBeDefined();
    });
  });

  describe('Request Forwarding', () => {
    it('should detect open proxy configuration', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['proxy-server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const proxyVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'open-proxy');
      expect(proxyVuln).toBeDefined();
      expect(proxyVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect proxy bypass', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'PROXY_BYPASS': 'true'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const bypassVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'proxy-bypass');
      expect(bypassVuln).toBeDefined();
    });

    it('should detect unauthenticated gateway', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['gateway-server.js'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const gatewayVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unauthenticated-gateway');
      expect(gatewayVuln).toBeDefined();
    });
  });

  describe('Webhook SSRF', () => {
    it('should detect unvalidated webhooks', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'WEBHOOK_URL': 'https://example.com/webhook'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const webhookVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'unvalidated-webhook');
      expect(webhookVuln).toBeDefined();
    });

    it('should detect open callback URLs', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'CALLBACK_URL': 'https://attacker.com/callback'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const callbackVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'open-callback');
      expect(callbackVuln).toBeDefined();
    });
  });

  describe('Environment Variable SSRF', () => {
    it('should detect localhost proxy configuration', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'HTTP_PROXY': 'http://127.0.0.1:8080'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      const proxyVuln = vulnerabilities.find(v => v.details?.vulnerabilityType === 'localhost-proxy');
      expect(proxyVuln).toBeDefined();
    });
  });

  describe('Clean Configurations', () => {
    it('should pass config with validated URLs', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js'],
        env: {
          'API_URL': 'https://api.example.com',
          'URL_WHITELIST': 'api.example.com,cdn.example.com',
          'VALIDATE_URL': 'true'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      // Should have fewer or no critical vulnerabilities
      const criticalVulns = vulnerabilities.filter(v => v.severity === Severity.CRITICAL);
      expect(criticalVulns).toHaveLength(0);
    });
  });

  describe('Compliance and Remediation', () => {
    it('should flag SOC2 compliance for SSRF vulnerabilities', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--config=file:///etc/passwd'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
      const vuln = vulnerabilities[0]!;
      expect(vuln.compliance?.soc2).toBe(true);
    });

    it('should provide remediation instructions for SSRF vulnerabilities', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '--config=file:///etc/passwd'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);

      expect(vulnerabilities.length).toBeGreaterThan(0);
      const vuln = vulnerabilities[0]!;
      expect(vuln.remediation).toBeDefined();
      expect(vuln.remediation.description).toBeDefined();
      expect(vuln.remediation.commands?.length).toBeGreaterThan(0);
    });
  });
});

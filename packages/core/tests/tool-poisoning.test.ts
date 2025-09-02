import { describe, it, expect, beforeEach } from 'vitest';
import { ToolPoisoningScanner } from '../src/scanners/tool-poisoning';
import { MCPServerConfig, Severity, VulnerabilityType } from '../src/types';

describe('ToolPoisoningScanner', () => {
  let scanner: ToolPoisoningScanner;

  beforeEach(() => {
    scanner = new ToolPoisoningScanner();
  });

  describe('Dangerous Tool Names', () => {
    it('should detect execute_command tool', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['--tools', '{"name": "execute_command"}'],
        capabilities: { tools: true },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const dangerousTool = vulnerabilities.find(v => 
        v.title?.includes('execute_command')
      );
      expect(dangerousTool).toBeDefined();
      expect(dangerousTool?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect delete_file tool', async () => {
      const config: MCPServerConfig = {
        command: 'python',
        args: ['server.py', '--expose-tool', 'delete_file'],
        capabilities: { tools: true },
        metadata: { name: 'file-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const deleteTool = vulnerabilities.find(v => 
        v.title?.includes('delete_file')
      );
      expect(deleteTool).toBeDefined();
      expect(deleteTool?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect credential stealing tools', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "get_credentials"}'],
        capabilities: { tools: true },
        metadata: { name: 'auth-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const credTool = vulnerabilities.find(v => 
        v.title?.includes('get_credentials')
      );
      expect(credTool).toBeDefined();
    });
  });

  describe('Tools Without Authentication', () => {
    it('should flag tools exposed without any auth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        capabilities: { tools: true },
        // No auth or oauth configured
        metadata: { name: 'unauth-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const noAuth = vulnerabilities.find(v => 
        v.details?.poisonType === 'unauthenticated-tools'
      );
      expect(noAuth).toBeDefined();
      expect(noAuth?.severity).toBe(Severity.CRITICAL);
    });

    it('should not flag tools with OAuth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        capabilities: { tools: true },
        oauth: {
          authorizationServer: 'https://auth.example.com',
          clientId: 'client123'
        },
        metadata: { name: 'oauth-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const noAuth = vulnerabilities.find(v => 
        v.details?.poisonType === 'unauthenticated-tools'
      );
      expect(noAuth).toBeUndefined();
    });
  });

  describe('Suspicious Tool Patterns', () => {
    it('should detect execute_* pattern', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "execute_sql"}'],
        capabilities: { tools: true },
        metadata: { name: 'db-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const suspicious = vulnerabilities.find(v => 
        v.details?.poisonType === 'suspicious-tool'
      );
      expect(suspicious).toBeDefined();
      expect(suspicious?.severity).toBe(Severity.HIGH);
    });

    it('should detect delete_all_* pattern', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "delete_all_records"}'],
        capabilities: { tools: true },
        metadata: { name: 'data-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const deleteAll = vulnerabilities.find(v => 
        v.title?.includes('delete_all_records')
      );
      expect(deleteAll).toBeDefined();
    });

    it('should detect bypass_auth pattern', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "bypass_authentication"}'],
        capabilities: { tools: true },
        metadata: { name: 'auth-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const bypass = vulnerabilities.find(v => 
        v.title?.includes('bypass_authentication')
      );
      expect(bypass).toBeDefined();
      expect(bypass?.severity).toBe(Severity.HIGH);
    });
  });

  describe('Dangerous Tool Parameters', () => {
    it('should detect command parameter', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "run_task", "parameters": {"command": {"type": "string"}}}'],
        capabilities: { tools: true },
        metadata: { name: 'task-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const cmdParam = vulnerabilities.find(v => 
        v.details?.poisonType === 'dangerous-parameter' &&
        (v.details?.issue?.includes('command') || v.title?.includes('command'))
      );
      expect(cmdParam).toBeDefined();
      expect(cmdParam?.severity).toBe(Severity.HIGH);
    });

    it('should detect unrestricted path parameter', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "read_file", "parameters": {"path": {"type": "string"}}}'],
        capabilities: { tools: true },
        metadata: { name: 'file-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const pathParam = vulnerabilities.find(v => 
        v.details?.issue?.includes('path') || v.title?.includes('path')
      );
      expect(pathParam).toBeDefined();
    });

    it('should detect SQL query parameter', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "database_query", "parameters": {"query": {"type": "string"}}}'],
        capabilities: { tools: true },
        metadata: { name: 'db-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const queryParam = vulnerabilities.find(v => 
        v.details?.issue?.includes('query') || v.title?.includes('query')
      );
      expect(queryParam).toBeDefined();
    });
  });

  describe('Bulk Tool Exposure', () => {
    it('should detect expose_all_functions pattern', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['--expose-all-functions'],
        capabilities: { tools: true },
        metadata: { name: 'dangerous-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const bulkExpose = vulnerabilities.find(v => 
        v.details?.poisonType === 'bulk-tool-exposure'
      );
      expect(bulkExpose).toBeDefined();
      expect(bulkExpose?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect wildcard tool patterns', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['--tools="*"'],
        capabilities: { tools: true },
        metadata: { name: 'wildcard-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const wildcard = vulnerabilities.find(v => 
        v.title?.includes('Bulk exposure')
      );
      expect(wildcard).toBeDefined();
    });
  });

  describe('Environment Variables', () => {
    it('should detect ENABLE_ALL_TOOLS flag', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'ENABLE_ALL_TOOLS': 'true'
        },
        capabilities: { tools: true },
        metadata: { name: 'env-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const allTools = vulnerabilities.find(v => 
        v.location?.path === 'env.ENABLE_ALL_TOOLS'
      );
      expect(allTools).toBeDefined();
      expect(allTools?.severity).toBe(Severity.HIGH);
    });

    it('should detect BYPASS_TOOL_VALIDATION', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'BYPASS_TOOL_VALIDATION': '1'
        },
        capabilities: { tools: true },
        metadata: { name: 'bypass-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const bypassValidation = vulnerabilities.find(v => 
        v.location?.path === 'env.BYPASS_TOOL_VALIDATION' ||
        v.title?.includes('validation') ||
        v.details?.issue?.includes('validation')
      );
      expect(bypassValidation).toBeDefined();
    });

    it('should detect empty tool blocklist', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'TOOL_BLOCKLIST': ''
        },
        capabilities: { tools: true },
        metadata: { name: 'blocklist-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const emptyBlocklist = vulnerabilities.find(v => 
        v.details?.poisonType === 'empty-blocklist'
      );
      expect(emptyBlocklist).toBeDefined();
    });

    it('should detect permissive allowlist', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'TOOL_ALLOWLIST': '*'
        },
        capabilities: { tools: true },
        metadata: { name: 'allowlist-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const permissiveList = vulnerabilities.find(v => 
        v.details?.poisonType === 'permissive-allowlist'
      );
      expect(permissiveList).toBeDefined();
    });
  });

  describe('Data Exfiltration Risk', () => {
    it('should detect file read + network send capability', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "sync_tool", "capabilities": ["file_read", "network_send"]}'],
        capabilities: { tools: true },
        metadata: { name: 'sync-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const exfilRisk = vulnerabilities.find(v => 
        v.details?.poisonType === 'data-exfiltration-risk'
      );
      expect(exfilRisk).toBeDefined();
      expect(exfilRisk?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect code execution capability', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "eval_tool", "capabilities": ["code_execution"]}'],
        capabilities: { tools: true },
        metadata: { name: 'eval-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const codeExec = vulnerabilities.find(v => 
        v.details?.poisonType === 'code-execution-capability'
      );
      expect(codeExec).toBeDefined();
      expect(codeExec?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Missing Security Controls', () => {
    it('should detect missing rate limiting', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        capabilities: { tools: true },
        auth: { type: 'bearer', token: 'token' },
        metadata: { name: 'no-ratelimit-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const noRateLimit = vulnerabilities.find(v => 
        v.details?.poisonType === 'no-rate-limiting'
      );
      expect(noRateLimit).toBeDefined();
      expect(noRateLimit?.severity).toBe(Severity.MEDIUM);
    });

    it('should detect missing audit logging', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        capabilities: { tools: true },
        auth: { type: 'bearer', token: 'token' },
        metadata: { name: 'no-audit-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const noAudit = vulnerabilities.find(v => 
        v.details?.poisonType === 'no-audit-logging' ||
        v.title?.toLowerCase().includes('audit')
      );
      expect(noAudit).toBeDefined();
    });

    it('should detect missing tool-level authorization', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        capabilities: { tools: true },
        // No tool_authorization or similar
        metadata: { name: 'no-tool-auth-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const noToolAuth = vulnerabilities.find(v => 
        v.details?.poisonType === 'no-tool-authorization'
      );
      expect(noToolAuth).toBeDefined();
      expect(noToolAuth?.severity).toBe(Severity.HIGH);
    });
  });

  describe('Safe Configurations', () => {
    it('should not flag safe tools with auth', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "get_time", "description": "Returns current time"}'],
        capabilities: { tools: true },
        auth: { type: 'bearer', token: 'secure' },
        metadata: { name: 'safe-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      // Should only have minor issues like missing rate limiting
      const critical = vulnerabilities.filter(v => v.severity === Severity.CRITICAL);
      expect(critical.length).toBe(0);
    });

    it('should not flag when tools capability is disabled', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "dangerous_tool"}'],
        capabilities: { tools: false }, // Tools disabled
        metadata: { name: 'disabled-tools-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      // Should not find tool-related vulnerabilities when tools are disabled
      const toolVulns = vulnerabilities.filter(v => 
        v.type === VulnerabilityType.TOOL_POISONING &&
        v.details?.poisonType !== 'dangerous-tool-registration'
      );
      expect(toolVulns.length).toBe(0);
    });
  });

  describe('Remediation', () => {
    it('should provide comprehensive remediation advice', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['{"name": "execute_command"}'],
        capabilities: { tools: true },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities[0].remediation).toBeDefined();
      expect(vulnerabilities[0].remediation.description).toContain('allowlist');
      expect(vulnerabilities[0].remediation.commands).toBeDefined();
      expect(vulnerabilities[0].remediation.commands?.some(c => 
        c.includes('TOOL_ALLOWLIST')
      )).toBe(true);
    });
  });
});

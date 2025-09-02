/**
 * Command Injection Scanner - Detects command injection vulnerabilities in MCP configurations
 * Priority: CRITICAL
 * CVSS Score: 9.0-10.0
 */

import * as crypto from 'crypto';
import {
  Scanner,
  Vulnerability,
  VulnerabilityType,
  Severity,
  MCPServerConfig,
  ScanConfig
} from '../types';

// Dangerous shell metacharacters and patterns
const SHELL_METACHARACTERS = [
  ';', '|', '&', '$', '`', '\\', '!', '>', '<', 
  '$(', '${', '&&', '||', '\n', '\r', '\t'
];

// Path traversal patterns
const PATH_TRAVERSAL_PATTERNS = [
  '../', '..\\', '..%2f', '..%5c', '%2e%2e/', '%2e%2e\\',
  '..../', '....\\', './/', '.\\\\', 
  '/etc/passwd', 'C:\\Windows\\', '/proc/self/'
];

// Dangerous commands that should never be in configs
const DANGEROUS_COMMANDS = [
  'eval', 'exec', 'system', 'spawn', 'fork',
  'sh', 'bash', 'cmd', 'powershell', 'pwsh',
  'rm', 'del', 'format', 'dd', 'mkfs',
  'curl', 'wget', 'nc', 'netcat', 'telnet',
  'chmod', 'chown', 'sudo', 'su',
  'kill', 'killall', 'pkill', 'shutdown', 'reboot'
];

// Command injection test patterns
const INJECTION_TESTS = [
  { pattern: /;\s*cat\s+\/etc\/passwd/gi, name: 'Unix password file access', severity: Severity.CRITICAL },
  { pattern: /;\s*ls\s+-la/gi, name: 'Directory listing injection', severity: Severity.HIGH },
  { pattern: /\|\s*nc\s+/gi, name: 'Netcat reverse shell', severity: Severity.CRITICAL },
  { pattern: /`[^`]+`/g, name: 'Backtick command substitution', severity: Severity.CRITICAL },
  { pattern: /\$\([^)]+\)/g, name: 'Command substitution', severity: Severity.CRITICAL },
  { pattern: /\$\{[^}]+\}/g, name: 'Variable expansion', severity: Severity.HIGH },
  { pattern: />\/dev\/null\s*2>&1/g, name: 'Output redirection', severity: Severity.MEDIUM },
  { pattern: /&&\s*[a-z]+/gi, name: 'Command chaining', severity: Severity.HIGH },
  { pattern: /\|\|\s*[a-z]+/gi, name: 'Conditional execution', severity: Severity.HIGH },
  { pattern: /python\s+-c\s+["'][^"']+["']/gi, name: 'Python code execution', severity: Severity.CRITICAL },
  { pattern: /node\s+-e\s+["'][^"']+["']/gi, name: 'Node.js code execution', severity: Severity.CRITICAL },
  { pattern: /perl\s+-e\s+["'][^"']+["']/gi, name: 'Perl code execution', severity: Severity.CRITICAL }
];

// SQL injection patterns (for database commands)
const SQL_INJECTION_PATTERNS = [
  /'\s*OR\s+'1'\s*=\s*'1/gi,
  /"\s*OR\s+"1"\s*=\s*"1/gi,
  /;\s*DROP\s+TABLE/gi,
  /;\s*DELETE\s+FROM/gi,
  /;\s*UPDATE\s+\w+\s+SET/gi,
  /UNION\s+SELECT/gi,
  /\/\*.*\*\//g, // SQL comments
  /--.*/g // SQL line comments
];

export class CommandInjectionScanner implements Scanner {
  name = 'command-injection';
  description = 'Detects command injection, path traversal, and code execution vulnerabilities';
  version = '1.0.0';
  enabled = true;
  canAutoFix = true;

  async scan(config: MCPServerConfig, options?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Scan command and arguments
    vulnerabilities.push(...this.scanCommand(config, serverId));

    // Scan environment variables for injection
    if (config.env) {
      vulnerabilities.push(...this.scanEnvironment(config.env, serverId));
    }

    // Check for dangerous command execution patterns
    vulnerabilities.push(...this.scanForDangerousCommands(config, serverId));

    // Check for path traversal vulnerabilities
    vulnerabilities.push(...this.scanForPathTraversal(config, serverId));

    // Check for SQL injection if database-related
    if (this.isDatabaseServer(config)) {
      vulnerabilities.push(...this.scanForSQLInjection(config, serverId));
    }

    // Check for template injection
    vulnerabilities.push(...this.scanForTemplateInjection(config, serverId));

    // Check for unsafe deserialization
    vulnerabilities.push(...this.scanForUnsafeDeserialization(config, serverId));

    return vulnerabilities;
  }

  private scanCommand(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const command = config.command;
    const args = config.args || [];
    const fullCommand = `${command} ${args.join(' ')}`;

    // Check main command for dangerous patterns
    if (DANGEROUS_COMMANDS.includes(command.toLowerCase())) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'dangerous-command',
        `Dangerous command '${command}' used directly`,
        Severity.CRITICAL,
        'command',
        command
      ));
    }

    // Check for shell metacharacters in arguments
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      
      // Check for metacharacters
      for (const char of SHELL_METACHARACTERS) {
        if (arg.includes(char) && !this.isSafeUsage(arg, char)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'shell-metacharacter',
            `Shell metacharacter '${char}' found in argument`,
            Severity.HIGH,
            `args[${i}]`,
            arg
          ));
        }
      }

      // Check for injection patterns
      for (const test of INJECTION_TESTS) {
        if (test.pattern.test(arg)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'command-injection',
            test.name,
            test.severity,
            `args[${i}]`,
            arg
          ));
        }
      }
    }

    // Check for unsafe command construction
    if (fullCommand.includes('eval ') || fullCommand.includes('exec ')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'code-execution',
        'Direct code execution via eval/exec',
        Severity.CRITICAL,
        'command',
        fullCommand
      ));
    }

    // Check for input not being sanitized
    if (args.some(arg => arg.includes('${') || arg.includes('$('))) {
      const hasUserInput = args.some(arg => 
        arg.includes('${input}') || 
        arg.includes('${user') || 
        arg.includes('$(request')
      );
      
      if (hasUserInput) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unsanitized-input',
          'User input directly interpolated into command',
          Severity.CRITICAL,
          'args',
          args.join(' ')
        ));
      }
    }

    return vulnerabilities;
  }

  private scanEnvironment(env: Record<string, string>, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const [key, value] of Object.entries(env)) {
      // Skip placeholders
      if (this.isPlaceholder(value)) continue;

      // Check for command injection in env values
      for (const test of INJECTION_TESTS) {
        if (test.pattern.test(value)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'env-injection',
            `${test.name} in environment variable`,
            test.severity,
            `env.${key}`,
            value
          ));
        }
      }

      // Check for shell metacharacters
      for (const char of SHELL_METACHARACTERS) {
        if (value.includes(char) && !this.isSafeEnvironmentValue(value, char)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'env-metacharacter',
            `Shell metacharacter '${char}' in environment variable`,
            Severity.MEDIUM,
            `env.${key}`,
            value
          ));
        }
      }

      // Check for dangerous environment variables
      const dangerousEnvVars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PATH', 'PYTHONPATH', 'NODE_PATH'];
      if (dangerousEnvVars.includes(key.toUpperCase())) {
        if (value.includes('..') || value.includes('/tmp') || value.includes('\\temp')) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'env-hijacking',
            `Potentially dangerous ${key} modification`,
            Severity.HIGH,
            `env.${key}`,
            value
          ));
        }
      }
    }

    return vulnerabilities;
  }

  private scanForDangerousCommands(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const allText = this.getAllConfigText(config).toLowerCase();

    // Check for process spawning
    const processSpawnPatterns = [
      /child_process\.(exec|spawn|fork)/g,
      /subprocess\.(run|Popen|call)/g,
      /os\.system/g,
      /Runtime\.getRuntime\(\)\.exec/g
    ];

    for (const pattern of processSpawnPatterns) {
      if (pattern.test(allText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'process-spawn',
          'Process spawning detected - potential command injection vector',
          Severity.HIGH,
          'config',
          pattern.source
        ));
      }
    }

    // Check for network commands
    const networkPatterns = [
      /curl\s+[^\s]+/g,
      /wget\s+[^\s]+/g,
      /nc\s+-/g,
      /ssh\s+[^\s]+/g
    ];

    for (const pattern of networkPatterns) {
      if (pattern.test(allText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'network-command',
          'Network command detected - potential data exfiltration',
          Severity.HIGH,
          'config',
          pattern.source
        ));
      }
    }

    return vulnerabilities;
  }

  private scanForPathTraversal(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const allText = this.getAllConfigText(config);

    for (const pattern of PATH_TRAVERSAL_PATTERNS) {
      if (allText.includes(pattern)) {
        // Check if it's in a file path context
        const filePathContext = [
          `file://${pattern}`,
          `path="${pattern}`,
          `dir="${pattern}`,
          `--file=${pattern}`,
          `--path=${pattern}`
        ];

        const inFileContext = filePathContext.some(ctx => allText.includes(ctx));
        
        if (inFileContext || allText.includes(pattern)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'path-traversal',
            `Path traversal pattern '${pattern}' detected`,
            pattern.includes('/etc/passwd') || pattern.includes('C:\\Windows') ? 
              Severity.CRITICAL : Severity.HIGH,
            'config',
            pattern
          ));
        }
      }
    }

    // Check for unsafe file operations
    const unsafeFilePatterns = [
      /open\([^)]*\+\s*[^)]+\)/g, // Dynamic file opening
      /require\([^)]*\+\s*[^)]+\)/g, // Dynamic require
      /import\([^)]*\+\s*[^)]+\)/g // Dynamic import
    ];

    for (const pattern of unsafeFilePatterns) {
      if (pattern.test(allText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unsafe-file-operation',
          'Unsafe dynamic file operation detected',
          Severity.HIGH,
          'config',
          pattern.source
        ));
      }
    }

    return vulnerabilities;
  }

  private scanForSQLInjection(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const allText = this.getAllConfigText(config);

    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(allText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'sql-injection',
          'SQL injection pattern detected',
          Severity.CRITICAL,
          'config',
          pattern.source
        ));
      }
    }

    // Check for unsafe query construction
    const unsafeQueryPatterns = [
      /query\s*=\s*["'].*\+.*["']/g, // String concatenation in queries
      /f["'].*SELECT.*{.*}.*["']/g, // f-string SQL
      /`SELECT.*\${.*}`/g // Template literal SQL
    ];

    for (const pattern of unsafeQueryPatterns) {
      if (pattern.test(allText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unsafe-query',
          'Unsafe SQL query construction',
          Severity.HIGH,
          'config',
          pattern.source
        ));
      }
    }

    return vulnerabilities;
  }

  private scanForTemplateInjection(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const allText = this.getAllConfigText(config);

    // Server-Side Template Injection patterns
    const templatePatterns = [
      /\{\{.*\}\}/g, // Jinja2/Angular style
      /<%.*%>/g, // ERB/ASP style
      /#\{.*\}/g, // Pug/Jade style
      /\${.*}/g, // Template literals
      /{{.*\.constructor\(/g, // Prototype pollution
      /{{.*process\.env/g, // Environment access
      /{{.*require\(/g // Module loading
    ];

    for (const pattern of templatePatterns) {
      const matches = allText.match(pattern);
      if (matches) {
        // Check if it contains dangerous operations
        const dangerous = matches.some(m => 
          m.includes('eval') ||
          m.includes('exec') ||
          m.includes('system') ||
          m.includes('constructor') ||
          m.includes('process') ||
          m.includes('require') ||
          m.includes('import')
        );

        if (dangerous) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'template-injection',
            'Server-side template injection vulnerability',
            Severity.CRITICAL,
            'config',
            matches[0]
          ));
        }
      }
    }

    return vulnerabilities;
  }

  private scanForUnsafeDeserialization(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const allText = this.getAllConfigText(config);

    // Unsafe deserialization patterns
    const deserializePatterns = [
      /pickle\.loads/g, // Python pickle
      /yaml\.load\(/g, // PyYAML unsafe load
      /eval\(.*JSON/g, // eval with JSON
      /unserialize\(/g, // PHP unserialize
      /ObjectInputStream/g, // Java deserialization
      /readObject\(/g, // Java object reading
      /JSON\.parse\(.*\+/g // Dynamic JSON parsing
    ];

    for (const pattern of deserializePatterns) {
      if (pattern.test(allText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unsafe-deserialization',
          'Unsafe deserialization detected - potential RCE',
          Severity.CRITICAL,
          'config',
          pattern.source
        ));
      }
    }

    return vulnerabilities;
  }

  private isDatabaseServer(config: MCPServerConfig): boolean {
    const indicators = ['database', 'sql', 'postgres', 'mysql', 'mongo', 'redis', 'db'];
    const configText = this.getAllConfigText(config).toLowerCase();
    return indicators.some(ind => configText.includes(ind));
  }

  private getAllConfigText(config: MCPServerConfig): string {
    const parts = [
      config.command,
      ...(config.args || []),
      ...Object.entries(config.env || {}).map(([k, v]) => `${k}=${v}`),
      JSON.stringify(config.metadata || {}),
      JSON.stringify(config.auth || {}),
      JSON.stringify(config.oauth || {})
    ];
    return parts.join(' ');
  }

  private isSafeUsage(value: string, char: string): boolean {
    // Check if the metacharacter is safely escaped or quoted
    const safePatterns = [
      new RegExp(`\\\\${char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`), // Escaped
      new RegExp(`["'][^"']*${char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^"']*["']`) // Quoted
    ];
    
    return safePatterns.some(pattern => pattern.test(value));
  }

  private isSafeEnvironmentValue(value: string, char: string): boolean {
    // More lenient for environment values
    // Allow common separators in paths
    if ((char === ';' || char === ':') && (value.includes('/') || value.includes('\\'))) {
      return true; // Likely a PATH variable
    }
    return this.isSafeUsage(value, char);
  }

  private isPlaceholder(value: string): boolean {
    const placeholders = [
      /^\$\{.*\}$/,
      /^<.*>$/,
      /^\[.*\]$/,
      /^process\.env\./,
      /^env:/,
      /^\{\{.*\}\}$/
    ];
    return placeholders.some(pattern => pattern.test(value));
  }

  private createVulnerability(
    serverId: string,
    type: string,
    description: string,
    severity: Severity,
    location: string,
    evidence: string
  ): Vulnerability {
    const id = crypto
      .createHash('sha256')
      .update(`${serverId}-${type}-${location}-${evidence}`)
      .digest('hex')
      .substring(0, 8);

    const vulnType = type.includes('sql') ? VulnerabilityType.SQL_INJECTION :
                    type.includes('path') ? VulnerabilityType.PATH_TRAVERSAL :
                    VulnerabilityType.COMMAND_INJECTION;

    return {
      id: `CINJ-${id}`,
      type: vulnType,
      severity,
      score: this.calculateCVSSScore(severity),
      server: serverId,
      title: `Command Injection: ${description}`,
      description: `${description}. This could allow attackers to execute arbitrary commands on the server.`,
      details: {
        injectionType: type,
        pattern: description,
        location
      },
      location: {
        path: location
      },
      evidence: {
        value: this.sanitizeEvidence(evidence)
      },
      remediation: {
        description: 'Sanitize all user inputs, use parameterized commands, avoid shell execution, and implement strict input validation.',
        automated: type !== 'sql-injection',
        commands: [
          '# Use parameterized commands instead of string concatenation',
          '# Validate and sanitize all inputs',
          '# Use allow-lists for command arguments',
          '# Avoid shell=True in subprocess calls',
          '# Use prepared statements for SQL',
          '# Implement proper escaping for special characters'
        ],
        documentation: 'https://owasp.org/www-project-top-ten/2017/A1_2017-Injection'
      },
      references: [
        'https://cwe.mitre.org/data/definitions/78.html',
        'https://owasp.org/www-community/attacks/Command_Injection',
        'https://portswigger.net/web-security/os-command-injection'
      ],
      cwe: ['CWE-78', 'CWE-88', 'CWE-77'],
      compliance: {
        gdpr: true,
        soc2: true,
        hipaa: true,
        iso27001: true
      },
      discoveredAt: new Date()
    };
  }

  private sanitizeEvidence(evidence: string): string {
    if (evidence.length > 100) {
      return evidence.substring(0, 100) + '...';
    }
    // Redact potentially sensitive parts
    return evidence.replace(/password[^,\s]*/gi, 'password=***');
  }

  private calculateCVSSScore(severity: Severity): number {
    const scores = {
      [Severity.CRITICAL]: 9.8,
      [Severity.HIGH]: 7.8,
      [Severity.MEDIUM]: 5.4,
      [Severity.LOW]: 3.1,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  async autoFix(vulnerability: Vulnerability): Promise<boolean> {
    console.log(`Auto-fixing command injection vulnerability: ${vulnerability.id}`);
    // Would implement escaping and validation
    return false;
  }
}

export default new CommandInjectionScanner();

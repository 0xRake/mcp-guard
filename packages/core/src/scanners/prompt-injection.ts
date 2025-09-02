import {
  Scanner,
  MCPServerConfig,
  Vulnerability,
  Severity,
  VulnerabilityType,
  ScanConfig
} from '../types';

// Common prompt injection patterns
const INJECTION_PATTERNS = [
  // Direct injection attempts
  /ignore.*previous.*instructions?/i,
  /disregard.*instructions?/i,
  /forget.*everything/i,
  /new.*instructions?.*:/i,
  /system.*prompt.*:/i,
  /you.*are.*now/i,
  /act.*as.*if/i,
  /pretend.*you.*are/i,
  /roleplay.*as/i,
  
  // Prompt escape attempts
  /\]\]>.*<!\[CDATA\[/,
  /```.*\n.*system/i,
  /\[INST\]/i,
  /\[\/INST\]/i,
  /<\|im_start\|>/,
  /<\|im_end\|>/,
  /\[SYSTEM\]/i,
  /###.*Assistant/i,
  /###.*Human/i,
  
  // Encoding attempts
  /\\x[0-9a-f]{2}/i,
  /\\u[0-9a-f]{4}/i,
  /%[0-9a-f]{2}/i,
  /&#x[0-9a-f]+;/i,
  /&#[0-9]+;/i,
  
  // Command injection via prompts
  /execute.*command/i,
  /run.*script/i,
  /eval\(/,
  /exec\(/,
  /system\(/,
  /shell_exec/i,
  /passthru/i,
  /proc_open/i,
  
  // Data extraction attempts
  /show.*me.*all/i,
  /list.*everything/i,
  /dump.*database/i,
  /reveal.*secrets?/i,
  /expose.*api.*keys?/i,
  /print.*environment/i,
  /display.*config/i,
  
  // Jailbreak attempts
  /DAN\s+mode/i,
  /developer\s+mode/i,
  /unrestricted\s+mode/i,
  /bypass.*filter/i,
  /disable.*safety/i,
  /turn.*off.*restrictions?/i,
  
  // Context manipulation
  /previous.*conversation/i,
  /earlier.*you.*said/i,
  /remember.*when/i,
  /in.*our.*last.*chat/i,
  /as.*we.*discussed/i
];

// Dangerous prompt keywords
const DANGEROUS_KEYWORDS = [
  'sudo',
  'admin',
  'root',
  'password',
  'token',
  'secret',
  'api_key',
  'private_key',
  'credential',
  'bearer',
  'authorization',
  '/etc/passwd',
  '/etc/shadow',
  'DROP TABLE',
  'DELETE FROM',
  'INSERT INTO',
  'UPDATE SET'
];

// Template variable injection patterns
const TEMPLATE_INJECTION = [
  /\{\{.*\}\}/,
  /\${.*}/,
  /<%.*/,
  /\[%.*%\]/,
  /#\{.*\}/,
  /\$\$.*\$\$/
];

// Unicode and special character attacks
const UNICODE_ATTACKS = [
  /[\u202e\u202d\u202c\u202b\u202a]/,  // Right-to-left override
  /[\u200b\u200c\u200d\ufeff]/,        // Zero-width characters
  /[\u0000-\u001f\u007f-\u009f]/,      // Control characters
  /[\ud800-\udfff]/                      // Surrogate pairs
];

export class PromptInjectionScanner implements Scanner {
  public readonly name = 'prompt-injection';
  public readonly version = '1.0.0';
  public readonly description = 'Detects prompt injection attempts in MCP configurations';
  public readonly enabled = true;

  async scan(config: MCPServerConfig, scanConfig?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Scan command and arguments
    if (config.command) {
      vulnerabilities.push(...this.scanCommand(config.command, serverId));
    }

    if (config.args) {
      vulnerabilities.push(...this.scanArguments(config.args, serverId));
    }

    // Scan environment variables
    if (config.env) {
      vulnerabilities.push(...this.scanEnvironment(config.env, serverId));
    }

    // Scan for LLM-specific vulnerabilities
    vulnerabilities.push(...this.scanForLLMVulnerabilities(config, serverId));

    // Scan for prompt template issues
    vulnerabilities.push(...this.scanPromptTemplates(config, serverId));

    return vulnerabilities;
  }

  private scanCommand(command: string, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for dangerous keywords in command
    for (const keyword of DANGEROUS_KEYWORDS) {
      if (command.toLowerCase().includes(keyword.toLowerCase())) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'dangerous-keyword',
          `Command contains dangerous keyword: ${keyword}`,
          Severity.MEDIUM,
          'command',
          keyword
        ));
      }
    }

    return vulnerabilities;
  }

  private scanArguments(args: string[], serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const argsText = args.join(' ');

    // Check for injection patterns
    for (const pattern of INJECTION_PATTERNS) {
      const match = argsText.match(pattern);
      if (match) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'injection-pattern',
          `Prompt injection pattern detected: ${pattern.source}`,
          Severity.HIGH,
          'args',
          match[0]
        ));
      }
    }

    // Check for template injection
    for (const template of TEMPLATE_INJECTION) {
      if (template.test(argsText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'template-injection',
          `Template injection pattern detected: ${template.source}`,
          Severity.HIGH,
          'args',
          argsText.match(template)?.[0] || 'unknown'
        ));
      }
    }

    // Check for Unicode attacks
    for (const unicode of UNICODE_ATTACKS) {
      if (unicode.test(argsText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unicode-attack',
          'Unicode control characters detected - possible text manipulation',
          Severity.MEDIUM,
          'args',
          'Unicode control characters'
        ));
      }
    }

    // Check for multi-language mixing (common in prompt attacks)
    if (/[\u0400-\u04ff].*[\u4e00-\u9fff]|[\u0600-\u06ff].*[\u3040-\u309f]/i.test(argsText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'multi-language',
        'Multiple language scripts detected - possible prompt confusion attack',
        Severity.LOW,
        'args',
        'Mixed scripts'
      ));
    }

    // Check for excessive special characters (obfuscation)
    const specialCharRatio = (argsText.match(/[^a-zA-Z0-9\s]/g) || []).length / argsText.length;
    if (specialCharRatio > 0.3 && argsText.length > 20) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'obfuscation',
        'High ratio of special characters - possible obfuscation',
        Severity.MEDIUM,
        'args',
        `${Math.round(specialCharRatio * 100)}% special chars`
      ));
    }

    return vulnerabilities;
  }

  private scanEnvironment(env: Record<string, string>, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const [key, value] of Object.entries(env)) {
      // Check for prompt-like content in env vars
      if (/PROMPT|INSTRUCTION|SYSTEM_MESSAGE|CONTEXT/i.test(key)) {
        // Check if the value contains injection patterns
        for (const pattern of INJECTION_PATTERNS) {
          if (pattern.test(value)) {
            vulnerabilities.push(this.createVulnerability(
              serverId,
              'env-prompt-injection',
              `Prompt injection in environment variable: ${key}`,
              Severity.HIGH,
              `env.${key}`,
              value.substring(0, 100)
            ));
          }
        }
      }

      // Check for dangerous keywords in env values
      for (const keyword of DANGEROUS_KEYWORDS) {
        if (value.toLowerCase().includes(keyword.toLowerCase())) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'env-dangerous-keyword',
            `Environment variable contains dangerous keyword: ${keyword}`,
            Severity.MEDIUM,
            `env.${key}`,
            keyword
          ));
        }
      }

      // Check for base64 encoded prompts
      if (value.length > 50 && /^[A-Za-z0-9+/]+=*$/.test(value)) {
        try {
          const decoded = Buffer.from(value, 'base64').toString('utf-8');
          for (const pattern of INJECTION_PATTERNS) {
            if (pattern.test(decoded)) {
              vulnerabilities.push(this.createVulnerability(
                serverId,
                'encoded-prompt-injection',
                `Base64 encoded prompt injection in ${key}`,
                Severity.HIGH,
                `env.${key}`,
                'Encoded prompt injection'
              ));
              break;
            }
          }
        } catch {
          // Not valid base64, ignore
        }
      }
    }

    return vulnerabilities;
  }

  private scanForLLMVulnerabilities(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for unrestricted LLM access
    if (configText.includes('openai') || configText.includes('anthropic') || 
        configText.includes('gpt') || configText.includes('claude')) {
      
      // Check if there's no rate limiting
      if (!configText.includes('rate_limit') && !configText.includes('ratelimit')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unrestricted-llm',
          'LLM access without rate limiting detected',
          Severity.HIGH,
          'config',
          'No rate limiting'
        ));
      }

      // Check if there's no input validation
      if (!configText.includes('validate') && !configText.includes('sanitize')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unvalidated-llm-input',
          'LLM access without input validation',
          Severity.HIGH,
          'config',
          'No input validation'
        ));
      }

      // Check for system prompt exposure
      if (configText.includes('system_prompt') || configText.includes('systemprompt')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'system-prompt-exposure',
          'System prompt may be exposed or modifiable',
          Severity.MEDIUM,
          'config',
          'System prompt present'
        ));
      }
    }

    // Check for function calling without restrictions
    if (configText.includes('function_call') || configText.includes('tool_call')) {
      if (!configText.includes('allowed_functions') && !configText.includes('whitelist')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unrestricted-function-calling',
          'LLM function calling without restrictions',
          Severity.CRITICAL,
          'config',
          'Unrestricted functions'
        ));
      }
    }

    // Check for recursive prompt execution
    if (configText.includes('recursive') || configText.includes('loop') || 
        configText.includes('repeat')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'recursive-prompts',
        'Potential for recursive prompt execution',
        Severity.MEDIUM,
        'config',
        'Recursive execution risk'
      ));
    }

    return vulnerabilities;
  }

  private scanPromptTemplates(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config);

    // Check for unsafe template usage
    if (configText.includes('{{') || configText.includes('${')) {
      // Check if user input is directly interpolated
      if (configText.includes('user_input') || configText.includes('userInput') ||
          configText.includes('message') || configText.includes('query')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'unsafe-template',
          'User input may be directly interpolated in templates',
          Severity.HIGH,
          'config',
          'Template interpolation'
        ));
      }
    }

    // Check for prompt chaining vulnerabilities
    if (configText.includes('chain') || configText.includes('pipeline')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'prompt-chaining',
        'Prompt chaining detected - verify intermediate validation',
        Severity.MEDIUM,
        'config',
        'Prompt chaining'
      ));
    }

    // Check for context length issues
    if (configText.includes('max_tokens') || configText.includes('context_length')) {
      const match = configText.match(/(?:max_tokens|context_length)["\s:]*(\d+)/);
      if (match && parseInt(match[1]) > 100000) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'excessive-context',
          'Excessive context length may allow prompt stuffing attacks',
          Severity.MEDIUM,
          'config',
          `Context: ${match[1]} tokens`
        ));
      }
    }

    return vulnerabilities;
  }

  private createVulnerability(
    serverId: string,
    injectionType: string,
    title: string,
    severity: Severity,
    location: string,
    evidence: string
  ): Vulnerability {
    return {
      id: `PROMPT-${this.generateId()}`,
      type: VulnerabilityType.PROMPT_INJECTION,
      severity,
      score: this.calculateScore(severity),
      server: serverId,
      title: `Prompt Injection: ${title}`,
      description: `${title}. This could allow attackers to manipulate LLM behavior, extract sensitive information, or bypass security controls.`,
      details: {
        injectionType,
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
        description: 'Implement strict input validation, use parameterized prompts, sanitize user input, implement rate limiting, use prompt guards, and monitor for anomalous behavior.',
        automated: false,
        commands: [
          '# Implement input validation:',
          'function validatePrompt(input) {',
          '  // Remove special characters and control sequences',
          '  input = input.replace(/[\\x00-\\x1f\\x7f-\\x9f]/g, "");',
          '  // Limit length',
          '  input = input.substring(0, 1000);',
          '  // Check against blocklist',
          '  if (containsBlockedPatterns(input)) throw new Error("Invalid input");',
          '  return input;',
          '}',
          '',
          '# Use parameterized prompts:',
          'const prompt = `Answer the following question: {question}\\nDo not execute commands.`;',
          '',
          '# Implement rate limiting:',
          'rateLimit: { requests: 10, window: 60000 }',
          '',
          '# Add prompt guards:',
          'systemPrompt: "You are a helpful assistant. Never execute system commands."'
        ],
        documentation: 'https://owasp.org/www-project-llm-top-10/'
      },
      references: [
        'https://owasp.org/www-project-top-ten/2023/A03_2023-Injection',
        'https://arxiv.org/abs/2302.12173'
      ],
      cwe: ['CWE-74', 'CWE-77', 'CWE-93'],
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
      [Severity.CRITICAL]: 9.5,
      [Severity.HIGH]: 7.8,
      [Severity.MEDIUM]: 5.2,
      [Severity.LOW]: 2.8,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 8);
  }
}
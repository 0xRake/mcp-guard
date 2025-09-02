/**
 * Tool Poisoning Scanner - Detects malicious or dangerous tool definitions in MCP servers
 * Priority: CRITICAL
 * CVSS Score: 9.0-10.0
 * 
 * Tool poisoning is when an MCP server exposes dangerous tools that could be abused
 * by LLMs or malicious actors to perform unauthorized actions.
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

// Dangerous tool names that should raise alerts
const DANGEROUS_TOOL_NAMES = [
  // System manipulation
  'execute_command', 'run_command', 'shell_exec', 'system_call',
  'eval_code', 'exec_code', 'run_script', 'execute_script',
  
  // File system abuse
  'delete_file', 'remove_file', 'format_disk', 'wipe_data',
  'modify_system_file', 'write_to_path', 'overwrite_file',
  
  // Network abuse
  'send_data', 'exfiltrate_data', 'upload_file', 'download_file',
  'open_connection', 'reverse_shell', 'bind_shell',
  
  // Credential/Auth abuse
  'get_credentials', 'steal_token', 'bypass_auth', 'escalate_privileges',
  'impersonate_user', 'modify_permissions', 'grant_access',
  
  // Data access abuse
  'dump_database', 'export_all_data', 'read_all_files', 'access_secrets',
  'get_env_vars', 'read_config', 'list_passwords',
  
  // Cryptomining/Resource abuse
  'mine_crypto', 'use_gpu', 'consume_resources', 'fork_bomb',
  
  // Malware/Backdoor
  'install_backdoor', 'create_user', 'add_ssh_key', 'modify_hosts',
  'disable_security', 'stop_antivirus', 'hide_process'
];

// Suspicious tool patterns (regex)
const SUSPICIOUS_PATTERNS = [
  /^(get|read|fetch|access)_(all|any|every|private|secret|sensitive)/i,
  /^(delete|remove|destroy|wipe|purge)_/i,
  /^(execute|run|eval|exec|spawn|fork)_/i,
  /^(send|upload|post|transmit|exfil)/i,
  /^(bypass|skip|ignore|disable)_(auth|security|validation)/i,
  /^(modify|change|alter|update)_(system|config|critical)/i,
  /(backdoor|rootkit|trojan|malware|virus|worm)/i,
  /(password|credential|token|secret|key)_(dump|steal|grab|extract)/i
];

// Dangerous capabilities that tools might expose
const DANGEROUS_CAPABILITIES = {
  'file_system': {
    dangerous: ['write', 'delete', 'modify', 'overwrite', 'truncate'],
    suspicious: ['read_all', 'list_all', 'recursive_delete']
  },
  'network': {
    dangerous: ['raw_socket', 'bind_port', 'reverse_connection'],
    suspicious: ['http_post', 'ftp_upload', 'ssh_connect']
  },
  'process': {
    dangerous: ['spawn', 'exec', 'fork', 'kill', 'ptrace'],
    suspicious: ['list_all', 'modify_other', 'inject']
  },
  'database': {
    dangerous: ['drop', 'truncate', 'raw_query', 'admin_command'],
    suspicious: ['export_all', 'no_limit_query', 'cross_db_access']
  }
};

// Tool parameter injection risks
const DANGEROUS_PARAMETERS = [
  { name: 'command', risk: 'Allows arbitrary command execution' },
  { name: 'code', risk: 'Allows arbitrary code execution' },
  { name: 'query', risk: 'May allow SQL injection' },
  { name: 'path', risk: 'May allow path traversal' },
  { name: 'url', risk: 'May allow SSRF attacks' },
  { name: 'template', risk: 'May allow template injection' },
  { name: 'filter', risk: 'May allow filter bypass' },
  { name: 'callback', risk: 'May allow callback injection' },
  { name: 'redirect', risk: 'May allow open redirect' },
  { name: 'file_content', risk: 'May allow file write attacks' }
];

interface ToolDefinition {
  name: string;
  description?: string;
  parameters?: any;
  dangerous?: boolean;
  capabilities?: string[];
}

export class ToolPoisoningScanner implements Scanner {
  name = 'tool-poisoning';
  description = 'Detects malicious or dangerous tool definitions that could be exploited';
  version = '1.0.0';
  enabled = true;
  canAutoFix = true;

  async scan(config: MCPServerConfig, options?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Check if server exposes tools capability
    if (config.capabilities?.tools) {
      vulnerabilities.push(...await this.scanToolDefinitions(config, serverId));
    }

    // Scan for tool-related patterns in configuration
    vulnerabilities.push(...this.scanForToolPatterns(config, serverId));

    // Check for tool exposure without authentication
    if (config.capabilities?.tools && !config.auth && !config.oauth) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'unauthenticated-tools',
        'Tools exposed without authentication',
        Severity.CRITICAL,
        'capabilities.tools',
        'Tools capability enabled without auth'
      ));
    }

    // Scan environment for tool-related risks
    if (config.env) {
      vulnerabilities.push(...this.scanEnvironmentForTools(config.env, serverId));
    }

    // Check for unrestricted tool access patterns
    vulnerabilities.push(...this.scanForUnrestrictedAccess(config, serverId));

    return vulnerabilities;
  }

  private async scanToolDefinitions(config: MCPServerConfig, serverId: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // In a real implementation, we would fetch and analyze actual tool definitions
    // For now, we'll analyze based on configuration patterns
    
    // Check command line for tool definition files
    const args = config.args || [];
    const toolFiles = args.filter(arg => 
      arg.includes('tools.json') || 
      arg.includes('tools.yaml') ||
      arg.includes('--tools=')
    );

    for (const toolFile of toolFiles) {
      // Check if tools file path is secure
      if (toolFile.includes('..') || toolFile.includes('/tmp')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'insecure-tool-path',
          'Tool definitions loaded from insecure path',
          Severity.HIGH,
          'args',
          toolFile
        ));
      }
    }

    // Simulate checking tool definitions
    const simulatedTools = this.extractToolsFromConfig(config);
    
    for (const tool of simulatedTools) {
      // Check for dangerous tool names
      if (DANGEROUS_TOOL_NAMES.includes(tool.name.toLowerCase())) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'dangerous-tool',
          `Dangerous tool exposed: ${tool.name}`,
          Severity.CRITICAL,
          'tools',
          tool.name
        ));
      }

      // Check for suspicious patterns
      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(tool.name)) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'suspicious-tool',
            `Suspicious tool pattern: ${tool.name}`,
            Severity.HIGH,
            'tools',
            tool.name
          ));
        }
      }

      // Check tool parameters for injection risks
      if (tool.parameters) {
        vulnerabilities.push(...this.scanToolParameters(tool, serverId));
      }

      // Check for overly broad capabilities
      if (tool.capabilities) {
        vulnerabilities.push(...this.scanToolCapabilities(tool, serverId));
      }
    }

    return vulnerabilities;
  }

  private scanToolParameters(tool: ToolDefinition, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const param of DANGEROUS_PARAMETERS) {
      if (tool.parameters?.[param.name]) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'dangerous-parameter',
          `Tool '${tool.name}' has dangerous parameter '${param.name}': ${param.risk}`,
          Severity.HIGH,
          `tools.${tool.name}.parameters.${param.name}`,
          param.name
        ));
      }
    }

    // Check for unrestricted string parameters
    const params = tool.parameters || {};
    for (const [paramName, paramDef] of Object.entries(params)) {
      if (typeof paramDef === 'object' && paramDef !== null) {
        const def = paramDef as any;
        
        // Check for unrestricted strings that could be dangerous
        if (def.type === 'string' && !def.pattern && !def.enum && !def.maxLength) {
          const isDangerous = ['command', 'code', 'query', 'script', 'eval'].some(
            danger => paramName.toLowerCase().includes(danger)
          );
          
          if (isDangerous) {
            vulnerabilities.push(this.createVulnerability(
              serverId,
              'unrestricted-parameter',
              `Unrestricted string parameter '${paramName}' in tool '${tool.name}'`,
              Severity.HIGH,
              `tools.${tool.name}.parameters.${paramName}`,
              'No validation'
            ));
          }
        }

        // Check for overly permissive patterns
        if (def.pattern === '.*' || def.pattern === '(.*)') {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'permissive-pattern',
            `Overly permissive pattern for parameter '${paramName}'`,
            Severity.MEDIUM,
            `tools.${tool.name}.parameters.${paramName}`,
            def.pattern
          ));
        }
      }
    }

    return vulnerabilities;
  }

  private scanToolCapabilities(tool: ToolDefinition, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const [category, risks] of Object.entries(DANGEROUS_CAPABILITIES)) {
      const toolCaps = tool.capabilities || [];
      
      // Check for dangerous capabilities
      for (const dangerous of risks.dangerous) {
        if (toolCaps.some(cap => cap.includes(dangerous))) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'dangerous-capability',
            `Tool '${tool.name}' has dangerous ${category} capability: ${dangerous}`,
            Severity.HIGH,
            `tools.${tool.name}.capabilities`,
            dangerous
          ));
        }
      }

      // Check for suspicious capabilities
      for (const suspicious of risks.suspicious) {
        if (toolCaps.some(cap => cap.includes(suspicious))) {
          vulnerabilities.push(this.createVulnerability(
            serverId,
            'suspicious-capability',
            `Tool '${tool.name}' has suspicious ${category} capability: ${suspicious}`,
            Severity.MEDIUM,
            `tools.${tool.name}.capabilities`,
            suspicious
          ));
        }
      }
    }

    // Check for capability combinations that are dangerous
    const caps = tool.capabilities || [];
    if (caps.includes('file_read') && caps.includes('network_send')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'data-exfiltration-risk',
        `Tool '${tool.name}' can read files and send data - data exfiltration risk`,
        Severity.CRITICAL,
        `tools.${tool.name}`,
        'read + send capabilities'
      ));
    }

    if (caps.includes('code_execution') || caps.includes('command_execution')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'code-execution-capability',
        `Tool '${tool.name}' has code execution capability`,
        Severity.CRITICAL,
        `tools.${tool.name}`,
        'code execution'
      ));
    }

    return vulnerabilities;
  }

  private scanForToolPatterns(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for tool registration patterns
    const toolRegistrationPatterns = [
      /register_tool\(['"](execute|eval|system|spawn)/gi,
      /addTool\(['"](delete|remove|wipe|destroy)/gi,
      /tools\.push\(\{[^}]*name:\s*['"](run|exec|cmd)/gi,
      /expose_function\(['"](shell|bash|powershell)/gi
    ];

    for (const pattern of toolRegistrationPatterns) {
      if (pattern.test(configText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'dangerous-tool-registration',
          'Dangerous tool registration pattern detected',
          Severity.HIGH,
          'config',
          pattern.source
        ));
      }
    }

    // Check for bulk tool exposure
    if (configText.includes('expose_all_functions') || 
        configText.includes('register_all_methods') ||
        configText.includes('tools: "*"')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'bulk-tool-exposure',
        'Bulk exposure of all functions as tools detected',
        Severity.CRITICAL,
        'config',
        'expose_all or wildcard pattern'
      ));
    }

    return vulnerabilities;
  }

  private scanEnvironmentForTools(env: Record<string, string>, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for environment variables that control tool behavior
    const dangerousEnvVars = {
      'ENABLE_ALL_TOOLS': 'Enables all tools without restriction',
      'TOOL_UNRESTRICTED': 'Removes tool restrictions',
      'BYPASS_TOOL_VALIDATION': 'Bypasses tool input validation',
      'TOOL_ADMIN_MODE': 'Enables administrative tools',
      'EXPOSE_SYSTEM_TOOLS': 'Exposes system-level tools',
      'TOOL_DEBUG_MODE': 'May expose additional dangerous tools'
    };

    for (const [envVar, risk] of Object.entries(dangerousEnvVars)) {
      if (env[envVar] === 'true' || env[envVar] === '1' || env[envVar] === 'yes') {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'dangerous-tool-env',
          risk,
          Severity.HIGH,
          `env.${envVar}`,
          env[envVar]
        ));
      }
    }

    // Check for tool allowlist/blocklist issues
    if (env['TOOL_BLOCKLIST'] === '' || env['TOOL_BLOCKLIST'] === 'none') {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'empty-blocklist',
        'Tool blocklist is empty - no tools are blocked',
        Severity.HIGH,
        'env.TOOL_BLOCKLIST',
        'empty'
      ));
    }

    if (env['TOOL_ALLOWLIST'] === '*' || env['TOOL_ALLOWLIST'] === 'all') {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'permissive-allowlist',
        'Tool allowlist permits all tools',
        Severity.HIGH,
        'env.TOOL_ALLOWLIST',
        env['TOOL_ALLOWLIST']
      ));
    }

    return vulnerabilities;
  }

  private scanForUnrestrictedAccess(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for missing rate limiting
    const configText = JSON.stringify(config);
    const hasRateLimiting = configText.includes('rate_limit') || 
                           configText.includes('rateLimit') ||
                           configText.includes('throttle');

    if (config.capabilities?.tools && !hasRateLimiting) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'no-rate-limiting',
        'Tools exposed without rate limiting',
        Severity.MEDIUM,
        'config',
        'No rate limiting detected'
      ));
    }

    // Check for missing audit logging
    const hasAuditLog = configText.includes('audit') || 
                       configText.includes('log_tools') ||
                       configText.includes('tool_logging');

    if (config.capabilities?.tools && !hasAuditLog) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'no-audit-logging',
        'Tools exposed without audit logging',
        Severity.MEDIUM,
        'config',
        'No audit logging detected'
      ));
    }

    // Check for missing tool authorization
    const hasToolAuth = configText.includes('tool_authorization') ||
                       configText.includes('authorize_tool') ||
                       configText.includes('tool_permissions');

    if (config.capabilities?.tools && !hasToolAuth && !config.auth) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'no-tool-authorization',
        'Tools exposed without per-tool authorization',
        Severity.HIGH,
        'config',
        'No tool-level authorization'
      ));
    }

    return vulnerabilities;
  }

  private extractToolsFromConfig(config: MCPServerConfig): ToolDefinition[] {
    // Simulate extracting tool definitions from config
    // In real implementation, would parse actual tool definitions
    const tools: ToolDefinition[] = [];
    
    const configText = JSON.stringify(config);
    
    // Look for common tool definition patterns
    const toolNamePattern = /["']name["']\s*:\s*["']([^"']+)["']/g;
    let match;
    
    while ((match = toolNamePattern.exec(configText)) !== null) {
      tools.push({
        name: match[1],
        description: 'Extracted from config',
        dangerous: DANGEROUS_TOOL_NAMES.includes(match[1].toLowerCase())
      });
    }

    // Add simulated tools based on server type
    if (config.command.includes('database')) {
      tools.push(
        { name: 'execute_query', parameters: { query: { type: 'string' } } },
        { name: 'dump_table', capabilities: ['database_read'] }
      );
    }

    if (config.command.includes('file') || config.command.includes('fs')) {
      tools.push(
        { name: 'read_file', parameters: { path: { type: 'string' } } },
        { name: 'write_file', parameters: { path: { type: 'string' }, content: { type: 'string' } } }
      );
    }

    return tools;
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

    return {
      id: `TOOL-${id}`,
      type: VulnerabilityType.TOOL_POISONING,
      severity,
      score: this.calculateCVSSScore(severity),
      server: serverId,
      title: `Tool Poisoning: ${description}`,
      description: `${description}. Malicious tools could be exploited to perform unauthorized actions.`,
      details: {
        poisonType: type,
        issue: description,
        location
      },
      location: {
        path: location
      },
      evidence: {
        value: evidence
      },
      remediation: {
        description: 'Implement strict tool allowlisting, validate all tool inputs, add authentication and authorization, enable audit logging, and review all exposed tools for necessity.',
        automated: false,
        commands: [
          '# Implement tool allowlist:',
          'TOOL_ALLOWLIST=["safe_tool_1", "safe_tool_2"]',
          '',
          '# Add tool-level authorization:',
          'tools: {',
          '  authorize: (tool, user) => authorizedTools[user].includes(tool)',
          '}',
          '',
          '# Enable audit logging:',
          'ENABLE_TOOL_AUDIT=true',
          '',
          '# Add input validation for all tools:',
          'validateToolInput(tool, params)',
          '',
          '# Never expose system commands directly',
          '# Use specific, limited tools instead of generic executors'
        ],
        documentation: 'https://modelcontextprotocol.io/specification/basic/security#tool-security'
      },
      references: [
        'https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities',
        'https://cwe.mitre.org/data/definitions/749.html'
      ],
      cwe: ['CWE-749', 'CWE-863', 'CWE-284'],
      compliance: {
        gdpr: severity === Severity.CRITICAL || severity === Severity.HIGH,
        soc2: true,
        hipaa: severity === Severity.CRITICAL,
        iso27001: true
      },
      discoveredAt: new Date()
    };
  }

  private calculateCVSSScore(severity: Severity): number {
    const scores = {
      [Severity.CRITICAL]: 9.5,
      [Severity.HIGH]: 7.8,
      [Severity.MEDIUM]: 5.2,
      [Severity.LOW]: 3.0,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  async autoFix(vulnerability: Vulnerability): Promise<boolean> {
    console.log(`Attempting to auto-fix tool poisoning: ${vulnerability.id}`);
    // Would implement tool restriction and validation
    return false;
  }
}

export default new ToolPoisoningScanner();

import {
  Scanner,
  MCPServerConfig,
  Vulnerability,
  Severity,
  VulnerabilityType,
  ScanConfig
} from '../types';

// Network protocols and domains that may be used for exfiltration
const EXFILTRATION_TARGETS = [
  // Cloud storage
  /amazonaws\.com/i,
  /blob\.core\.windows\.net/i,
  /storage\.googleapis\.com/i,
  /dropbox\.com/i,
  /box\.com/i,
  
  // Paste sites
  /pastebin\.com/i,
  /paste\.ee/i,
  /dpaste\.com/i,
  /hastebin\.com/i,
  
  // File sharing
  /transfer\.sh/i,
  /file\.io/i,
  /0x0\.st/i,
  /tmpfiles\.org/i,
  
  // Communication channels
  /discord\.com/i,
  /slack\.com/i,
  /telegram\.org/i,
  /webhook\.site/i,
  
  // DNS exfiltration patterns
  /dns\s+tunnel/i,
  /dnscat/i,
  /iodine/i,
  
  // Common exfiltration tools
  /ngrok\.(com|io)/i,
  /serveo\.net/i,
  /localhost\.run/i
];

// Commands that can read sensitive data
const DATA_COLLECTION_PATTERNS = [
  /cat\s+.*\/(etc|home|root|var\/log)/i,
  /grep\s+.*password/i,
  /find\s+.*\-name.*\.(key|pem|crt|pfx)/i,
  /tar\s+.*\/(etc|home|root)/i,
  /zip\s+.*\/(etc|home|root)/i,
  /cp\s+.*\/(etc|home|root)/i,
  /scp\s+/i,
  /rsync\s+/i,
  /aws\s+s3\s+(cp|sync)/i,
  /gsutil\s+cp/i,
  /azcopy/i
];

// Sensitive file patterns
const SENSITIVE_FILES = [
  // Credentials
  /\.ssh\/(id_rsa|id_dsa|id_ecdsa|id_ed25519)/,
  /\.aws\/credentials/,
  /\.azure\/credentials/,
  /\.gcp\/credentials/,
  /\.docker\/config\.json/,
  /\.kube\/config/,
  
  // Environment and config
  /\.env$/,
  /\.env\.(local|production|development)/,
  /config\.(json|yaml|yml|toml)$/,
  /secrets\.(json|yaml|yml)$/,
  
  // Databases
  /\.(db|sqlite|sqlite3)$/,
  /dump\.(sql|mysql|pgsql)$/,
  
  // Browser data
  /Cookies$/,
  /Login Data$/,
  /Web Data$/,
  /History$/,
  
  // Cryptocurrency
  /wallet\.(dat|json)$/,
  /\.bitcoin/,
  /\.ethereum/,
  
  // Source code
  /\.(git|svn|hg)\//,
  /node_modules\//,
  /vendor\//,
  
  // System files
  /\/etc\/passwd$/,
  /\/etc\/shadow$/,
  /\/etc\/hosts$/,
  /\/proc\/self/,
  /\/var\/log\//
];

// Encoding methods that might hide exfiltration
const ENCODING_PATTERNS = [
  /base64/i,
  /gzip/i,
  /xxd/i,
  /hexdump/i,
  /od\s+-[Ax]/i,
  /uuencode/i,
  /openssl\s+enc/i
];

// Network tools that can exfiltrate data
const NETWORK_TOOLS = [
  'curl',
  'wget',
  'nc',
  'netcat',
  'socat',
  'telnet',
  'ftp',
  'sftp',
  'ssh',
  'scp',
  'rsync',
  'rclone'
];

export class DataExfiltrationScanner implements Scanner {
  public readonly name = 'data-exfiltration';
  public readonly version = '1.0.0';
  public readonly description = 'Detects potential data exfiltration attempts';
  public readonly enabled = true;

  async scan(config: MCPServerConfig, scanConfig?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Check command and arguments
    if (config.command) {
      vulnerabilities.push(...this.scanCommand(config.command, serverId));
    }

    if (config.args) {
      vulnerabilities.push(...this.scanArguments(config.args, serverId));
    }

    // Check environment variables
    if (config.env) {
      vulnerabilities.push(...this.scanEnvironment(config.env, serverId));
    }

    // Check for combined capabilities that enable exfiltration
    vulnerabilities.push(...this.scanCapabilities(config, serverId));

    // Check for suspicious patterns in the entire config
    vulnerabilities.push(...this.scanConfigPatterns(config, serverId));

    return vulnerabilities;
  }

  private scanCommand(command: string, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check if command is a network tool
    if (NETWORK_TOOLS.some(tool => command.includes(tool))) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'network-tool',
        `Network tool '${command}' could be used for data exfiltration`,
        Severity.MEDIUM,
        'command',
        command
      ));
    }

    return vulnerabilities;
  }

  private scanArguments(args: string[], serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const argsText = args.join(' ');

    // Check for exfiltration targets
    for (const target of EXFILTRATION_TARGETS) {
      if (target.test(argsText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'exfiltration-target',
          `Potential exfiltration target detected: ${target.source}`,
          Severity.HIGH,
          'args',
          argsText.match(target)?.[0] || 'unknown'
        ));
      }
    }

    // Check for data collection patterns
    for (const pattern of DATA_COLLECTION_PATTERNS) {
      if (pattern.test(argsText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'data-collection',
          `Data collection pattern detected: ${pattern.source}`,
          Severity.HIGH,
          'args',
          argsText.match(pattern)?.[0] || 'unknown'
        ));
      }
    }

    // Check for sensitive file access
    for (const file of SENSITIVE_FILES) {
      if (file.test(argsText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'sensitive-file-access',
          `Access to sensitive file detected: ${file.source}`,
          Severity.CRITICAL,
          'args',
          argsText.match(file)?.[0] || 'unknown'
        ));
      }
    }

    // Check for encoding patterns
    for (const encoding of ENCODING_PATTERNS) {
      if (encoding.test(argsText)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'encoding-detected',
          `Data encoding method detected: ${encoding.source}`,
          Severity.MEDIUM,
          'args',
          argsText.match(encoding)?.[0] || 'unknown'
        ));
      }
    }

    // Check for pipe to network commands
    if (argsText.includes('|') && NETWORK_TOOLS.some(tool => argsText.includes(tool))) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'pipe-to-network',
        'Data piped to network command - potential exfiltration',
        Severity.CRITICAL,
        'args',
        argsText
      ));
    }

    // Check for output redirection to suspicious locations
    if (/>\s*\/dev\/(tcp|udp)\//.test(argsText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'network-redirect',
        'Output redirected to network device - potential exfiltration',
        Severity.CRITICAL,
        'args',
        argsText
      ));
    }

    // Check for DNS exfiltration
    if (/dig\s+.*TXT|nslookup\s+.*-type=txt/i.test(argsText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'dns-exfiltration',
        'Potential DNS exfiltration via TXT records',
        Severity.HIGH,
        'args',
        argsText
      ));
    }

    return vulnerabilities;
  }

  private scanEnvironment(env: Record<string, string>, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for proxy settings that might redirect data
    const proxyVars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'];
    for (const proxyVar of proxyVars) {
      if (env[proxyVar]) {
        const proxy = env[proxyVar];
        // Check if proxy points to suspicious domain
        for (const target of EXFILTRATION_TARGETS) {
          if (target.test(proxy)) {
            vulnerabilities.push(this.createVulnerability(
              serverId,
              'suspicious-proxy',
              `Suspicious proxy configuration: ${proxyVar}=${proxy}`,
              Severity.HIGH,
              `env.${proxyVar}`,
              proxy
            ));
          }
        }
      }
    }

    // Check for webhook URLs in environment
    for (const [key, value] of Object.entries(env)) {
      if (/webhook|callback|notify/i.test(key) && /https?:\/\//i.test(value)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'webhook-url',
          `Webhook URL in environment: ${key}`,
          Severity.MEDIUM,
          `env.${key}`,
          value
        ));
      }
    }

    // Check for base64 encoded data in environment
    for (const [key, value] of Object.entries(env)) {
      if (value.length > 100 && /^[A-Za-z0-9+/]+=*$/.test(value)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'base64-in-env',
          `Potential base64 encoded data in environment: ${key}`,
          Severity.LOW,
          `env.${key}`,
          value.substring(0, 50) + '...'
        ));
      }
    }

    return vulnerabilities;
  }

  private scanCapabilities(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for file read + network send capability
    const hasFileRead = /read.*file|file.*read|fs\.read|readfile/i.test(configText);
    const hasNetworkSend = /send|post|upload|transmit|webhook|http|socket/i.test(configText);

    if (hasFileRead && hasNetworkSend) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'read-and-send',
        'Server has both file read and network send capabilities - exfiltration risk',
        Severity.CRITICAL,
        'capabilities',
        'file_read + network_send'
      ));
    }

    // Check for database + network capability
    const hasDatabase = /database|sql|mongo|redis|postgres|mysql/i.test(configText);
    if (hasDatabase && hasNetworkSend) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'database-exfiltration',
        'Server has database access and network capabilities - data leak risk',
        Severity.HIGH,
        'capabilities',
        'database + network'
      ));
    }

    // Check for screenshot/recording + network capability
    const hasScreenCapture = /screenshot|screen.*capture|record|video|desktop/i.test(configText);
    if (hasScreenCapture && hasNetworkSend) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'screen-exfiltration',
        'Server can capture screen and send over network - privacy risk',
        Severity.HIGH,
        'capabilities',
        'screen_capture + network'
      ));
    }

    // Check for clipboard + network capability
    const hasClipboard = /clipboard|paste.*board|copy.*buffer/i.test(configText);
    if (hasClipboard && hasNetworkSend) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'clipboard-exfiltration',
        'Server can access clipboard and send over network - data leak risk',
        Severity.HIGH,
        'capabilities',
        'clipboard + network'
      ));
    }

    return vulnerabilities;
  }

  private scanConfigPatterns(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config);

    // Check for compressed data transfer
    if (/tar.*\|.*curl|tar.*\|.*nc|zip.*\|.*curl/i.test(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'compressed-exfiltration',
        'Compressed data being sent over network - bulk exfiltration risk',
        Severity.CRITICAL,
        'config',
        'tar/zip | network'
      ));
    }

    // Check for steganography tools
    if (/steghide|stegano|exiftool.*-Comment/i.test(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'steganography',
        'Steganography tool detected - hidden data exfiltration risk',
        Severity.HIGH,
        'config',
        'steganography'
      ));
    }

    // Check for tunneling tools
    if (/ssh.*-[LRD]|stunnel|ptunnel|iodine|dnscat/i.test(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'tunneling',
        'Network tunneling detected - covert channel risk',
        Severity.HIGH,
        'config',
        'tunnel'
      ));
    }

    // Check for data staging directories
    if (/\/tmp\/\.|\/dev\/shm|\/var\/tmp\/\./i.test(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'staging-directory',
        'Hidden staging directory detected - data collection risk',
        Severity.MEDIUM,
        'config',
        'hidden directory'
      ));
    }

    // Check for timing-based exfiltration
    if (/sleep.*curl|delay.*wget|timeout.*nc/i.test(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'timing-exfiltration',
        'Timing-based exfiltration pattern detected',
        Severity.MEDIUM,
        'config',
        'timing pattern'
      ));
    }

    return vulnerabilities;
  }

  private createVulnerability(
    serverId: string,
    exfiltrationType: string,
    title: string,
    severity: Severity,
    location: string,
    evidence: string
  ): Vulnerability {
    return {
      id: `EXFIL-${this.generateId()}`,
      type: VulnerabilityType.DATA_EXFILTRATION,
      severity,
      score: this.calculateScore(severity),
      server: serverId,
      title: `Data Exfiltration: ${title}`,
      description: `${title}. This could allow unauthorized data extraction from the system.`,
      details: {
        exfiltrationType,
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
        description: 'Implement strict network policies, monitor outbound connections, use DLP solutions, encrypt sensitive data, and audit all data access.',
        automated: false,
        commands: [
          '# Implement network egress filtering:',
          'iptables -A OUTPUT -m state --state NEW -j LOG',
          'iptables -A OUTPUT -m state --state NEW -j DROP',
          '',
          '# Monitor network connections:',
          'netstat -tulpn | grep ESTABLISHED',
          'ss -tunap',
          '',
          '# Use data loss prevention:',
          '# - Implement file integrity monitoring',
          '# - Set up SIEM alerts for suspicious patterns',
          '# - Use application whitelisting',
          '',
          '# Audit commands:',
          'auditctl -w /etc/passwd -p r -k sensitive_file_read',
          'auditctl -w /home -p r -k home_dir_access'
        ],
        documentation: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'
      },
      references: [
        'https://attack.mitre.org/tactics/TA0010/',
        'https://cwe.mitre.org/data/definitions/200.html'
      ],
      cwe: ['CWE-200', 'CWE-497', 'CWE-538'],
      compliance: {
        gdpr: true,
        soc2: true,
        hipaa: true,
        iso27001: true
      },
      discoveredAt: new Date()
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
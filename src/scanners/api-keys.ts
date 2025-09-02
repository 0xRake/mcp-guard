import { MCPConfig, Vulnerability, Severity, ScanResult } from '../types';

/**
 * Common API key patterns to detect
 */
const API_KEY_PATTERNS = [
  {
    name: 'OpenAI API Key',
    pattern: /sk-[a-zA-Z0-9]{48}/,
    description: 'OpenAI API key detected',
    severity: Severity.CRITICAL
  },
  {
    name: 'Anthropic API Key',
    pattern: /sk-ant-[a-zA-Z0-9]{90,}/,
    description: 'Anthropic API key detected',
    severity: Severity.CRITICAL
  },
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/,
    description: 'AWS Access Key ID detected',
    severity: Severity.CRITICAL
  },
  {
    name: 'AWS Secret Key',
    pattern: /aws[_\-]?secret[_\-]?access[_\-]?key/i,
    description: 'AWS Secret Access Key pattern detected',
    severity: Severity.CRITICAL
  },
  {
    name: 'GitHub Token',
    pattern: /gh[ps]_[a-zA-Z0-9]{36}/,
    description: 'GitHub personal access token detected',
    severity: Severity.CRITICAL
  },
  {
    name: 'Generic API Key',
    pattern: /api[_\-]?key/i,
    description: 'Generic API key pattern detected',
    severity: Severity.HIGH
  },
  {
    name: 'Generic Token',
    pattern: /(?:^|[^a-zA-Z])token[_\-]?(?:$|[^a-zA-Z])/i,
    description: 'Generic token pattern detected',
    severity: Severity.HIGH
  },
  {
    name: 'Generic Secret',
    pattern: /(?:^|[^a-zA-Z])secret[_\-]?(?:$|[^a-zA-Z])/i,
    description: 'Generic secret pattern detected',
    severity: Severity.HIGH
  },
  {
    name: 'Bearer Token',
    pattern: /bearer\s+[a-zA-Z0-9\-._~+\/]+=*/i,
    description: 'Bearer token pattern detected',
    severity: Severity.HIGH
  },
  {
    name: 'Private Key',
    pattern: /private[_\-]?key/i,
    description: 'Private key pattern detected',
    severity: Severity.CRITICAL
  },
  {
    name: 'Password',
    pattern: /(?:^|[^a-zA-Z])password[_\-]?(?:$|[^a-zA-Z])/i,
    description: 'Password pattern detected',
    severity: Severity.HIGH
  }
];

/**
 * Scanner for detecting API keys and sensitive credentials in MCP configurations
 */
export class APIKeyScanner {
  /**
   * Scan MCP configuration for exposed API keys and credentials
   * @param config MCP configuration to scan
   * @returns Array of vulnerabilities found
   */
  static scanForAPIKeys(config: MCPConfig): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    if (!config.mcpServers) {
      return vulnerabilities;
    }

    // Scan each MCP server configuration
    for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
      // Scan environment variables
      if (serverConfig.env) {
        for (const [envKey, envValue] of Object.entries(serverConfig.env)) {
          // Check environment variable names
          const keyVulns = this.checkForPatterns(envKey, serverName, 'environment variable name', envKey);
          vulnerabilities.push(...keyVulns);

          // Check environment variable values
          if (typeof envValue === 'string') {
            const valueVulns = this.checkForPatterns(envValue, serverName, 'environment variable value', envKey);
            vulnerabilities.push(...valueVulns);

            // Additional check for hardcoded secrets
            if (this.isLikelyHardcodedSecret(envValue)) {
              vulnerabilities.push({
                severity: Severity.CRITICAL,
                title: `Hardcoded credential in ${serverName}`,
                description: `The environment variable "${envKey}" in server "${serverName}" contains what appears to be a hardcoded credential. This is a critical security risk.`,
                fix: `Store the credential in a secure location (e.g., system keychain, environment file not in version control) and reference it indirectly. For example:\n` +
                     `1. Store in system environment: export ${envKey}="your-secret"\n` +
                     `2. Reference in config: "${envKey}": "$\{${envKey}\}"\n` +
                     `3. Or use a secrets management service`,
                server: serverName,
                details: {
                  variableName: envKey,
                  type: 'hardcoded_credential'
                }
              });
            }
          }
        }
      }

      // Scan command arguments
      if (serverConfig.args && Array.isArray(serverConfig.args)) {
        for (const arg of serverConfig.args) {
          if (typeof arg === 'string') {
            const argVulns = this.checkForPatterns(arg, serverName, 'command argument', undefined);
            vulnerabilities.push(...argVulns);
          }
        }
      }

      // Scan the command itself
      if (serverConfig.command && typeof serverConfig.command === 'string') {
        const cmdVulns = this.checkForPatterns(serverConfig.command, serverName, 'command', undefined);
        vulnerabilities.push(...cmdVulns);
      }
    }

    return vulnerabilities;
  }

  /**
   * Check a string for API key patterns
   * @param text Text to check
   * @param serverName Name of the MCP server
   * @param context Where the pattern was found (e.g., "environment variable")
   * @param variableName Name of the variable (if applicable)
   * @returns Array of vulnerabilities found
   */
  private static checkForPatterns(
    text: string,
    serverName: string,
    context: string,
    variableName?: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const pattern of API_KEY_PATTERNS) {
      if (pattern.pattern.test(text)) {
        const locationInfo = variableName 
          ? `in ${context} "${variableName}"` 
          : `in ${context}`;

        vulnerabilities.push({
          severity: pattern.severity,
          title: `${pattern.name} detected in ${serverName}`,
          description: `${pattern.description} ${locationInfo} for server "${serverName}". This could expose sensitive credentials.`,
          fix: this.getRemediationSteps(pattern.name, variableName),
          server: serverName,
          details: {
            patternType: pattern.name,
            context,
            variableName
          }
        });
      }
    }

    return vulnerabilities;
  }

  /**
   * Check if a value is likely a hardcoded secret
   * @param value Value to check
   * @returns True if likely a hardcoded secret
   */
  private static isLikelyHardcodedSecret(value: string): boolean {
    // Skip environment variable references
    if (value.includes('${') || value.includes('$(')) {
      return false;
    }

    // Check for common secret patterns
    const secretPatterns = [
      /^sk-[a-zA-Z0-9]{48}/, // OpenAI
      /^sk-ant-[a-zA-Z0-9]{90,}/, // Anthropic
      /^AKIA[0-9A-Z]{16}/, // AWS
      /^gh[ps]_[a-zA-Z0-9]{36}/, // GitHub
      /^[a-f0-9]{32,}$/, // Hex string (possible API key or hash)
      /^[A-Za-z0-9+\/]{40,}={0,2}$/, // Base64 encoded secret
    ];

    return secretPatterns.some(pattern => pattern.test(value));
  }

  /**
   * Get specific remediation steps based on the type of credential
   * @param patternName Name of the detected pattern
   * @param variableName Name of the variable (if applicable)
   * @returns Remediation steps
   */
  private static getRemediationSteps(patternName: string, variableName?: string): string {
    const varName = variableName || 'API_KEY';
    
    const baseSteps = `
1. Remove the hardcoded credential from the configuration file
2. Store the credential securely:
   - Option A: Use system environment variables
     " Set: export ${varName}="your-secret-value"
     " Reference: "${varName}": "$\{${varName}\}"
   
   - Option B: Use a secure secrets file (not in version control)
     " Create .env file with: ${varName}=your-secret-value
     " Add .env to .gitignore
     " Load from .env before starting MCP
   
   - Option C: Use a secrets management service
     " Store in system keychain (macOS), Credential Manager (Windows), or Secret Service (Linux)
     " Use a secrets management tool like 1Password, HashiCorp Vault, or AWS Secrets Manager

3. Rotate the exposed credential immediately
4. Review access logs for any unauthorized usage`;

    // Add specific steps based on the credential type
    const specificSteps: Record<string, string> = {
      'OpenAI API Key': '\n5. Visit https://platform.openai.com/api-keys to rotate your API key',
      'Anthropic API Key': '\n5. Visit https://console.anthropic.com/account/keys to rotate your API key',
      'AWS Access Key': '\n5. Visit AWS IAM Console to rotate your access keys\n6. Enable MFA on your AWS account',
      'GitHub Token': '\n5. Visit https://github.com/settings/tokens to revoke and regenerate your token',
    };

    return baseSteps + (specificSteps[patternName] || '');
  }

  /**
   * Perform a comprehensive API key scan and return results
   * @param config MCP configuration to scan
   * @returns ScanResult with score and vulnerabilities
   */
  static scan(config: MCPConfig): ScanResult {
    const vulnerabilities = this.scanForAPIKeys(config);
    
    // Calculate security score (100 = perfect, 0 = critical issues)
    let score = 100;
    
    for (const vuln of vulnerabilities) {
      switch (vuln.severity) {
        case Severity.CRITICAL:
          score -= 25;
          break;
        case Severity.HIGH:
          score -= 15;
          break;
        case Severity.MEDIUM:
          score -= 10;
          break;
        case Severity.LOW:
          score -= 5;
          break;
      }
    }
    
    // Ensure score doesn't go below 0
    score = Math.max(0, score);
    
    return {
      score,
      vulnerabilities,
      timestamp: new Date()
    };
  }
}
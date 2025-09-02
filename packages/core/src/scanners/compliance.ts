import {
  Scanner,
  MCPServerConfig,
  Vulnerability,
  Severity,
  VulnerabilityType,
  ScanConfig
} from '../types';

// GDPR compliance checks
const GDPR_REQUIREMENTS = {
  dataProtection: ['encryption', 'tls', 'https', 'secure'],
  consent: ['consent', 'opt-in', 'permission', 'agree'],
  rightToErasure: ['delete', 'remove', 'erase', 'purge'],
  dataPortability: ['export', 'download', 'transfer'],
  privacyByDesign: ['privacy', 'anonymous', 'pseudonym'],
  audit: ['log', 'audit', 'track', 'monitor']
};

// SOC2 compliance checks
const SOC2_REQUIREMENTS = {
  security: ['auth', 'encrypt', 'firewall', 'ids'],
  availability: ['backup', 'redundancy', 'failover', 'uptime'],
  processingIntegrity: ['validate', 'verify', 'checksum', 'integrity'],
  confidentiality: ['encrypt', 'access_control', 'classification'],
  privacy: ['consent', 'notice', 'choice', 'access']
};

// HIPAA compliance checks
const HIPAA_REQUIREMENTS = {
  accessControl: ['auth', 'role', 'permission', 'access'],
  encryption: ['encrypt', 'aes', 'tls', 'ssl'],
  auditLogs: ['audit', 'log', 'monitor', 'track'],
  integrity: ['hash', 'signature', 'checksum', 'verify'],
  transmission: ['secure', 'encrypt', 'tls', 'vpn']
};

// ISO 27001 compliance checks
const ISO27001_REQUIREMENTS = {
  riskAssessment: ['risk', 'threat', 'vulnerability', 'assessment'],
  accessControl: ['access', 'auth', 'permission', 'role'],
  cryptography: ['encrypt', 'key', 'certificate', 'crypto'],
  operations: ['backup', 'monitor', 'log', 'incident'],
  communications: ['secure', 'encrypt', 'firewall', 'network']
};

// PCI DSS compliance checks
const PCI_DSS_REQUIREMENTS = {
  cardholderData: ['pan', 'card', 'cvv', 'expiry'],
  strongCrypto: ['aes', 'rsa', 'sha256', 'tls1.2'],
  accessControl: ['mfa', '2fa', 'role', 'least_privilege'],
  monitoring: ['log', 'alert', 'monitor', 'ids'],
  testing: ['pentest', 'scan', 'vulnerability', 'assessment']
};

export class ComplianceScanner implements Scanner {
  public readonly name = 'compliance';
  public readonly version = '1.0.0';
  public readonly description = 'Scans for compliance with GDPR, SOC2, HIPAA, ISO 27001, and PCI DSS';
  public readonly enabled = true;

  async scan(config: MCPServerConfig, scanConfig?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    // Run compliance checks based on scan configuration
    if (!scanConfig || scanConfig.includeCompliance !== false) {
      vulnerabilities.push(...this.checkGDPRCompliance(config, serverId));
      vulnerabilities.push(...this.checkSOC2Compliance(config, serverId));
      vulnerabilities.push(...this.checkHIPAACompliance(config, serverId));
      vulnerabilities.push(...this.checkISO27001Compliance(config, serverId));
      vulnerabilities.push(...this.checkPCIDSSCompliance(config, serverId));
    }

    // Check for general compliance issues
    vulnerabilities.push(...this.checkGeneralCompliance(config, serverId));

    return vulnerabilities;
  }

  private checkGDPRCompliance(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for encryption
    if (!this.hasAnyPattern(configText, GDPR_REQUIREMENTS.dataProtection)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'gdpr-no-encryption',
        'GDPR: No data encryption detected',
        Severity.HIGH,
        'config',
        'Missing encryption',
        'GDPR'
      ));
    }

    // Check for consent mechanism
    if (!this.hasAnyPattern(configText, GDPR_REQUIREMENTS.consent)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'gdpr-no-consent',
        'GDPR: No consent mechanism detected',
        Severity.MEDIUM,
        'config',
        'Missing consent',
        'GDPR'
      ));
    }

    // Check for data deletion capability
    if (!this.hasAnyPattern(configText, GDPR_REQUIREMENTS.rightToErasure)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'gdpr-no-erasure',
        'GDPR: No right to erasure implementation',
        Severity.MEDIUM,
        'config',
        'Missing data deletion',
        'GDPR'
      ));
    }

    // Check for audit logging
    if (!this.hasAnyPattern(configText, GDPR_REQUIREMENTS.audit)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'gdpr-no-audit',
        'GDPR: No audit logging detected',
        Severity.MEDIUM,
        'config',
        'Missing audit logs',
        'GDPR'
      ));
    }

    // Check for data in plaintext
    if (this.hasPersonalData(configText) && !configText.includes('encrypt')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'gdpr-plaintext-data',
        'GDPR: Personal data potentially stored in plaintext',
        Severity.CRITICAL,
        'config',
        'Plaintext personal data',
        'GDPR'
      ));
    }

    return vulnerabilities;
  }

  private checkSOC2Compliance(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check security controls
    if (!this.hasAnyPattern(configText, SOC2_REQUIREMENTS.security)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'soc2-weak-security',
        'SOC2: Insufficient security controls',
        Severity.HIGH,
        'config',
        'Weak security',
        'SOC2'
      ));
    }

    // Check availability measures
    if (!this.hasAnyPattern(configText, SOC2_REQUIREMENTS.availability)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'soc2-no-availability',
        'SOC2: No availability measures (backup, redundancy)',
        Severity.MEDIUM,
        'config',
        'No availability measures',
        'SOC2'
      ));
    }

    // Check data integrity
    if (!this.hasAnyPattern(configText, SOC2_REQUIREMENTS.processingIntegrity)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'soc2-no-integrity',
        'SOC2: No data integrity verification',
        Severity.MEDIUM,
        'config',
        'No integrity checks',
        'SOC2'
      ));
    }

    return vulnerabilities;
  }

  private checkHIPAACompliance(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check if this might be handling PHI
    if (this.hasPHIIndicators(configText)) {
      // Check encryption
      if (!this.hasAnyPattern(configText, HIPAA_REQUIREMENTS.encryption)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'hipaa-no-encryption',
          'HIPAA: PHI without encryption',
          Severity.CRITICAL,
          'config',
          'Unencrypted PHI',
          'HIPAA'
        ));
      }

      // Check access controls
      if (!this.hasAnyPattern(configText, HIPAA_REQUIREMENTS.accessControl)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'hipaa-no-access-control',
          'HIPAA: PHI without proper access controls',
          Severity.CRITICAL,
          'config',
          'No access control',
          'HIPAA'
        ));
      }

      // Check audit logs
      if (!this.hasAnyPattern(configText, HIPAA_REQUIREMENTS.auditLogs)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'hipaa-no-audit',
          'HIPAA: PHI access without audit logging',
          Severity.HIGH,
          'config',
          'No audit logs',
          'HIPAA'
        ));
      }

      // Check transmission security
      if (!this.hasAnyPattern(configText, HIPAA_REQUIREMENTS.transmission)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'hipaa-insecure-transmission',
          'HIPAA: PHI transmission without encryption',
          Severity.CRITICAL,
          'config',
          'Insecure transmission',
          'HIPAA'
        ));
      }
    }

    return vulnerabilities;
  }

  private checkISO27001Compliance(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check access control
    if (!this.hasAnyPattern(configText, ISO27001_REQUIREMENTS.accessControl)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'iso27001-no-access-control',
        'ISO 27001: Missing access control implementation',
        Severity.HIGH,
        'config',
        'No access control',
        'ISO27001'
      ));
    }

    // Check cryptography
    if (!this.hasAnyPattern(configText, ISO27001_REQUIREMENTS.cryptography)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'iso27001-no-crypto',
        'ISO 27001: No cryptographic controls',
        Severity.HIGH,
        'config',
        'No cryptography',
        'ISO27001'
      ));
    }

    // Check operations security
    if (!this.hasAnyPattern(configText, ISO27001_REQUIREMENTS.operations)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'iso27001-weak-operations',
        'ISO 27001: Weak operational security',
        Severity.MEDIUM,
        'config',
        'Weak operations',
        'ISO27001'
      ));
    }

    return vulnerabilities;
  }

  private checkPCIDSSCompliance(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check if handling card data
    if (this.hasCardDataIndicators(configText)) {
      // Check strong cryptography
      if (!this.hasAnyPattern(configText, PCI_DSS_REQUIREMENTS.strongCrypto)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'pci-weak-crypto',
          'PCI DSS: Card data without strong cryptography',
          Severity.CRITICAL,
          'config',
          'Weak cryptography',
          'PCI-DSS'
        ));
      }

      // Check access control
      if (!configText.includes('mfa') && !configText.includes('2fa')) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'pci-no-mfa',
          'PCI DSS: No multi-factor authentication for card data access',
          Severity.HIGH,
          'config',
          'No MFA',
          'PCI-DSS'
        ));
      }

      // Check monitoring
      if (!this.hasAnyPattern(configText, PCI_DSS_REQUIREMENTS.monitoring)) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'pci-no-monitoring',
          'PCI DSS: Card data access without monitoring',
          Severity.HIGH,
          'config',
          'No monitoring',
          'PCI-DSS'
        ));
      }

      // Check for card data in logs
      if (configText.includes('log') && 
          (configText.includes('card') || configText.includes('pan') || configText.includes('cvv'))) {
        vulnerabilities.push(this.createVulnerability(
          serverId,
          'pci-card-data-in-logs',
          'PCI DSS: Potential card data in logs',
          Severity.CRITICAL,
          'config',
          'Card data in logs',
          'PCI-DSS'
        ));
      }
    }

    return vulnerabilities;
  }

  private checkGeneralCompliance(config: MCPServerConfig, serverId: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const configText = JSON.stringify(config).toLowerCase();

    // Check for hardcoded secrets (fails multiple compliance standards)
    if (this.hasHardcodedSecrets(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'hardcoded-secrets',
        'Multiple Standards: Hardcoded secrets detected',
        Severity.CRITICAL,
        'config',
        'Hardcoded secrets',
        'GENERAL'
      ));
    }

    // Check for missing TLS/SSL
    if (!configText.includes('tls') && !configText.includes('ssl') && !configText.includes('https')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'no-tls',
        'Multiple Standards: No TLS/SSL encryption',
        Severity.HIGH,
        'config',
        'No TLS/SSL',
        'GENERAL'
      ));
    }

    // Check for default credentials
    if (this.hasDefaultCredentials(configText)) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'default-credentials',
        'Multiple Standards: Default credentials in use',
        Severity.CRITICAL,
        'config',
        'Default credentials',
        'GENERAL'
      ));
    }

    // Check for missing logging
    if (!configText.includes('log') && !configText.includes('audit')) {
      vulnerabilities.push(this.createVulnerability(
        serverId,
        'no-logging',
        'Multiple Standards: No logging configured',
        Severity.MEDIUM,
        'config',
        'No logging',
        'GENERAL'
      ));
    }

    return vulnerabilities;
  }

  private hasAnyPattern(text: string, patterns: string[]): boolean {
    return patterns.some(pattern => text.includes(pattern));
  }

  private hasPersonalData(text: string): boolean {
    const personalDataPatterns = ['email', 'name', 'address', 'phone', 'ssn', 'dob', 'gender'];
    return this.hasAnyPattern(text, personalDataPatterns);
  }

  private hasPHIIndicators(text: string): boolean {
    const phiPatterns = ['patient', 'medical', 'health', 'diagnosis', 'treatment', 'prescription'];
    return this.hasAnyPattern(text, phiPatterns);
  }

  private hasCardDataIndicators(text: string): boolean {
    const cardPatterns = ['card', 'payment', 'pan', 'cvv', 'expiry', 'cardholder'];
    return this.hasAnyPattern(text, cardPatterns);
  }

  private hasHardcodedSecrets(text: string): boolean {
    // Look for patterns like password=, secret=, key= with actual values
    return /(?:password|secret|key|token)\s*[=:]\s*["'][^"']{8,}/i.test(text);
  }

  private hasDefaultCredentials(text: string): boolean {
    const defaults = ['admin:admin', 'root:root', 'test:test', 'demo:demo', 'password123'];
    return defaults.some(d => text.includes(d));
  }

  private createVulnerability(
    serverId: string,
    vulnerabilityType: string,
    title: string,
    severity: Severity,
    location: string,
    evidence: string,
    standard: string
  ): Vulnerability {
    const complianceFlags = {
      gdpr: standard === 'GDPR' || standard === 'GENERAL',
      soc2: standard === 'SOC2' || standard === 'GENERAL',
      hipaa: standard === 'HIPAA',
      iso27001: standard === 'ISO27001' || standard === 'GENERAL',
      pciDss: standard === 'PCI-DSS'
    };

    return {
      id: `COMPLIANCE-${this.generateId()}`,
      type: VulnerabilityType.COMPLIANCE_VIOLATION,
      severity,
      score: this.calculateScore(severity),
      server: serverId,
      title: `Compliance: ${title}`,
      description: `${title}. This violates ${standard} compliance requirements and may result in regulatory penalties.`,
      details: {
        vulnerabilityType,
        description: title,
        location,
        standard
      },
      location: {
        path: location
      },
      evidence: {
        value: evidence
      },
      remediation: {
        description: `Implement ${standard} compliance controls including encryption, access control, audit logging, and data protection measures.`,
        automated: false,
        commands: this.getRemediationCommands(standard),
        documentation: this.getComplianceDocumentation(standard)
      },
      references: this.getComplianceReferences(standard),
      cwe: ['CWE-693', 'CWE-710', 'CWE-254'],
      compliance: complianceFlags as any,
      discoveredAt: new Date().toISOString()
    };
  }

  private getRemediationCommands(standard: string): string[] {
    const commands: Record<string, string[]> = {
      GDPR: [
        '# Implement encryption:',
        'dataProtection: { encryption: "AES-256", atRest: true, inTransit: true }',
        '# Add consent management:',
        'consent: { required: true, explicit: true, withdrawable: true }',
        '# Implement data deletion:',
        'rightToErasure: { enabled: true, verifyIdentity: true }'
      ],
      HIPAA: [
        '# Enable encryption for PHI:',
        'encryption: { algorithm: "AES-256", keyManagement: "HSM" }',
        '# Implement access controls:',
        'accessControl: { rbac: true, mfa: true, sessionTimeout: 900 }',
        '# Enable audit logging:',
        'auditLog: { enabled: true, immutable: true, retention: "7years" }'
      ],
      'PCI-DSS': [
        '# Use strong cryptography:',
        'crypto: { tls: "1.2+", ciphers: ["AES256-GCM"], keyLength: 2048 }',
        '# Implement MFA:',
        'authentication: { mfa: true, passwordPolicy: "strong" }',
        '# Never log card data:',
        'logging: { maskCardData: true, excludeFields: ["pan", "cvv"] }'
      ],
      GENERAL: [
        '# General compliance measures:',
        'security: { encryption: true, tls: true, authentication: true }',
        'privacy: { dataMinimization: true, purposeLimitation: true }',
        'audit: { logging: true, monitoring: true, alerting: true }'
      ]
    };
    return commands[standard] || commands.GENERAL;
  }

  private getComplianceDocumentation(standard: string): string {
    const docs: Record<string, string> = {
      GDPR: 'https://gdpr.eu/',
      SOC2: 'https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/soc2',
      HIPAA: 'https://www.hhs.gov/hipaa/index.html',
      ISO27001: 'https://www.iso.org/isoiec-27001-information-security.html',
      'PCI-DSS': 'https://www.pcisecuritystandards.org/',
      GENERAL: 'https://owasp.org/www-project-top-ten/'
    };
    return docs[standard] || docs.GENERAL;
  }

  private getComplianceReferences(standard: string): string[] {
    const refs: Record<string, string[]> = {
      GDPR: [
        'https://gdpr.eu/checklist/',
        'https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/'
      ],
      HIPAA: [
        'https://www.hhs.gov/hipaa/for-professionals/security/index.html',
        'https://www.hhs.gov/hipaa/for-professionals/privacy/index.html'
      ],
      'PCI-DSS': [
        'https://www.pcisecuritystandards.org/documents/PCI_DSS_v4-0.pdf',
        'https://www.pcisecuritystandards.org/pci_security/maintaining_payment_security'
      ],
      GENERAL: [
        'https://owasp.org/www-project-top-ten/',
        'https://cwe.mitre.org/top25/'
      ]
    };
    return refs[standard] || refs.GENERAL;
  }

  private calculateScore(severity: Severity): number {
    const scores = {
      [Severity.CRITICAL]: 9.0,
      [Severity.HIGH]: 7.0,
      [Severity.MEDIUM]: 5.0,
      [Severity.LOW]: 3.0,
      [Severity.INFO]: 0.0
    };
    return scores[severity];
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 8);
  }
}
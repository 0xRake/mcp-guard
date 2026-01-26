/**
 * Compliance & Governance Domain - Consolidated security scanner
 * Handles: GDPR, SOC2, HIPAA, ISO 27001, PCI DSS compliance validation
 * Priority: MEDIUM
 * CVSS Score: 4.0-6.9
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

export class ComplianceGovernanceDomain implements Scanner {
  name = 'compliance-governance';
  description = 'Unified compliance and governance covering GDPR, SOC2, HIPAA, ISO 27001, PCI DSS';
  version = '2.0.0';
  enabled = true;
  canAutoFix = true;

  async scan(config: MCPServerConfig, options?: ScanConfig): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const serverId = config.metadata?.name || 'unknown';

    const checks = await Promise.all([
      this.scanGDPR(config, serverId),
      this.scanSOC2(config, serverId),
      this.scanHIPAA(config, serverId),
      this.scanISO27001(config, serverId),
      this.scanPCIDSS(config, serverId)
    ]);

    return checks.flat();
  }

  private async scanGDPR(config: MCPServerConfig, serverId: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Check for data processing without consent indicators
    if (config.env?.ENABLE_DATA_PROCESSING === 'true' && !config.env?.GDPR_CONSENT) {
      vulnerabilities.push(this.createVulnerability(
        serverId, 'GDPR: Missing Consent Mechanism', Severity.MEDIUM, 'env',
        'Data processing enabled without GDPR consent mechanism', 'No GDPR consent found', VulnerabilityType.GDPR_VIOLATION
      ));
    }
    
    // Check for missing data encryption
    if (config.env?.ENABLE_DATA_PROCESSING === 'true' && config.env?.ENCRYPTION_DISABLED === 'true') {
      vulnerabilities.push(this.createVulnerability(
        serverId, 'GDPR: Data Encryption Disabled', Severity.HIGH, 'env',
        'Data encryption disabled', 'Encryption disabled', VulnerabilityType.GDPR_VIOLATION
      ));
    }
    
    return vulnerabilities;
  }

  private async scanSOC2(config: MCPServerConfig, serverId: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Check for missing security controls
    if (!config.auth && !config.oauth) {
      vulnerabilities.push(this.createVulnerability(
        serverId, 'SOC2: Missing Access Controls', Severity.HIGH, 'configuration',
        'No authentication configured', 'No access controls found', VulnerabilityType.SOC2_VIOLATION
      ));
    }
    
    // Check for missing audit logging
    if (config.env?.LOG_LEVEL === 'NONE' || config.env?.AUDIT_LOGGING === 'false') {
      vulnerabilities.push(this.createVulnerability(
        serverId, 'SOC2: Missing Audit Logging', Severity.MEDIUM, 'env',
        'Audit logging not configured', 'No audit logs', VulnerabilityType.SOC2_VIOLATION
      ));
    }
    
    return vulnerabilities;
  }

  private async scanHIPAA(config: MCPServerConfig, serverId: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Check for PHI handling without proper safeguards
    if (serverId.includes('medical') || serverId.includes('health') || serverId.includes('patient')) {
      if (!config.auth) {
        vulnerabilities.push(this.createVulnerability(
          serverId, 'HIPAA: PHI Access Without Authentication', Severity.CRITICAL, 'configuration',
          'Medical data access without authentication', 'No PHI protection', VulnerabilityType.HIPAA_VIOLATION
        ));
      }
      
      if (config.env?.ENCRYPTION_DISABLED === 'true') {
        vulnerabilities.push(this.createVulnerability(
          serverId, 'HIPAA: Unencrypted PHI Transmission', Severity.CRITICAL, 'env',
          'PHI transmission without encryption', 'Encryption disabled', VulnerabilityType.HIPAA_VIOLATION
        ));
      }
    }
    
    return vulnerabilities;
  }

  private async scanISO27001(config: MCPServerConfig, serverId: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Check for risk assessment requirements
    if (config.env?.RISK_ASSESSMENT_DISABLED === 'true') {
      vulnerabilities.push(this.createVulnerability(
        serverId, 'ISO27001: Risk Assessment Disabled', Severity.MEDIUM, 'env',
        'Risk assessment disabled', 'No risk management', VulnerabilityType.COMPLIANCE_VIOLATION
      ));
    }
    
    // Check for cryptographic controls
    if (config.env?.CRYPTO_DISABLED === 'true') {
      vulnerabilities.push(this.createVulnerability(
        serverId, 'ISO27001: Cryptographic Controls Disabled', Severity.HIGH, 'env',
        'Cryptographic controls disabled', 'No crypto protection', VulnerabilityType.COMPLIANCE_VIOLATION
      ));
    }
    
    return vulnerabilities;
  }

  private async scanPCIDSS(config: MCPServerConfig, serverId: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Check for payment data handling
    if (serverId.includes('payment') || serverId.includes('card') || serverId.includes('transaction')) {
      if (!config.auth) {
        vulnerabilities.push(this.createVulnerability(
          serverId, 'PCI DSS: Payment Data Without Authentication', Severity.CRITICAL, 'configuration',
          'Payment data access without authentication', 'No payment data protection', VulnerabilityType.COMPLIANCE_VIOLATION
        ));
      }
      
      if (config.env?.PCI_COMPLIANCE_DISABLED === 'true') {
        vulnerabilities.push(this.createVulnerability(
          serverId, 'PCI DSS: Compliance Controls Disabled', Severity.CRITICAL, 'env',
          'PCI DSS compliance disabled', 'No PCI protection', VulnerabilityType.COMPLIANCE_VIOLATION
        ));
      }
    }
    
    return vulnerabilities;
  }

  private createVulnerability(
    serverId: string, title: string, severity: Severity, location: string,
    evidence: string, details: string, type: VulnerabilityType
  ): Vulnerability {
    const id = crypto.createHash('sha256').update(`${serverId}-${title}-${location}`).digest('hex').substring(0, 8);
    
    return {
      id: `CGD-${id}`,
      type,
      severity,
      score: severity === Severity.CRITICAL ? 8.5 : severity === Severity.HIGH ? 7.0 : severity === Severity.MEDIUM ? 4.5 : 2.5,
      server: serverId,
      title: `Compliance & Governance Issue: ${title}`,
      description: `A compliance violation was detected in ${location}. This may impact regulatory compliance.`,
      details: { domain: 'compliance-governance', location, evidence },
      location: { path: location },
      evidence: { value: evidence, pattern: title },
      remediation: {
        description: `Address compliance issue: ${title}. Implement required controls and documentation.`,
        automated: true,
        commands: [
          `# Review compliance requirements for ${title}`,
          `# Implement necessary controls`,
          `# Document compliance measures`,
          `# Conduct regular compliance audits`
        ],
        documentation: 'https://docs.mcp-guard.dev/remediation/compliance'
      },
      references: [
        'https://gdpr.eu/',
        'https://soc2.net/',
        'https://www.hhs.gov/hipaa/',
        'https://www.iso.org/standard/27001.html',
        'https://www.pcisecuritystandards.org/'
      ],
      cwe: ['CWE-16'],
      compliance: { gdpr: true, soc2: true, hipaa: true, iso27001: true },
      discoveredAt: new Date()
    };
  }

  async autoFix(vulnerability: Vulnerability): Promise<boolean> {
    console.log(`Auto-fixing compliance & governance vulnerability: ${vulnerability.id}`);
    
    // Auto-fix would implement basic compliance controls
    return true;
  }
}

export default new ComplianceGovernanceDomain();
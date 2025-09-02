/**
 * Report generator utility
 * Generates security reports in multiple formats
 */

import { ScanResult, Vulnerability, Severity } from '../types';
import * as fs from 'fs-extra';
import * as path from 'path';

export enum ReportFormat {
  JSON = 'json',
  MARKDOWN = 'markdown',
  HTML = 'html',
  SARIF = 'sarif',
  CSV = 'csv',
  XML = 'xml'
}

export class ReportGenerator {
  /**
   * Generate report in specified format
   */
  static async generate(result: ScanResult, format: ReportFormat): Promise<string> {
    switch (format) {
      case ReportFormat.JSON:
        return this.generateJSON(result);
      case ReportFormat.MARKDOWN:
        return this.generateMarkdown(result);
      case ReportFormat.HTML:
        return this.generateHTML(result);
      case ReportFormat.SARIF:
        return this.generateSARIF(result);
      case ReportFormat.CSV:
        return this.generateCSV(result);
      case ReportFormat.XML:
        return this.generateXML(result);
      default:
        throw new Error(`Unsupported report format: ${format}`);
    }
  }

  /**
   * Save report to file
   */
  static async saveReport(result: ScanResult, format: ReportFormat, filePath: string): Promise<void> {
    const report = await this.generate(result, format);
    const absolutePath = path.resolve(filePath);
    
    await fs.ensureDir(path.dirname(absolutePath));
    await fs.writeFile(absolutePath, report, 'utf-8');
  }

  /**
   * Generate JSON report
   */
  private static generateJSON(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }

  /**
   * Generate Markdown report
   */
  private static generateMarkdown(result: ScanResult): string {
    const lines: string[] = [
      '# MCP-Guard Security Scan Report',
      '',
      `**Scan ID:** ${result.id}`,
      `**Timestamp:** ${result.timestamp}`,
      `**Duration:** ${result.duration}ms`,
      '',
      '## Summary',
      '',
      `- **Security Score:** ${result.summary.score}/100 (Grade: ${result.summary.grade})`,
      `- **Servers Scanned:** ${result.summary.serversScanned}`,
      `- **Total Vulnerabilities:** ${result.summary.vulnerabilitiesFound}`,
      '',
      '### Severity Distribution',
      '',
      `- 🔴 **Critical:** ${result.summary.critical}`,
      `- 🟠 **High:** ${result.summary.high}`,
      `- 🟡 **Medium:** ${result.summary.medium}`,
      `- 🔵 **Low:** ${result.summary.low}`,
      `- ⚪ **Info:** ${result.summary.info}`,
      ''
    ];

    if (result.vulnerabilities.length > 0) {
      lines.push('## Vulnerabilities', '');
      
      result.vulnerabilities.forEach((vuln, index) => {
        lines.push(`### ${index + 1}. ${vuln.title}`);
        lines.push('');
        lines.push(`- **Severity:** ${vuln.severity}`);
        lines.push(`- **Score:** ${vuln.score}/10`);
        lines.push(`- **Server:** ${vuln.server}`);
        lines.push(`- **Type:** ${vuln.type}`);
        lines.push('');
        lines.push('**Description:**');
        lines.push(vuln.description);
        lines.push('');
        
        if (vuln.location) {
          lines.push('**Location:**');
          lines.push(`- Path: ${vuln.location.path}`);
          if (vuln.location.line) {
            lines.push(`- Line: ${vuln.location.line}`);
          }
          lines.push('');
        }
        
        if (vuln.evidence) {
          lines.push('**Evidence:**');
          lines.push('```');
          lines.push(vuln.evidence.value);
          lines.push('```');
          lines.push('');
        }
        
        if (vuln.remediation) {
          lines.push('**Remediation:**');
          lines.push(vuln.remediation.description);
          if (vuln.remediation.commands && vuln.remediation.commands.length > 0) {
            lines.push('');
            lines.push('```bash');
            lines.push(...vuln.remediation.commands);
            lines.push('```');
          }
          lines.push('');
        }
      });
    }

    if (result.recommendations.length > 0) {
      lines.push('## Recommendations', '');
      result.recommendations.forEach((rec, index) => {
        lines.push(`${index + 1}. ${rec}`);
      });
    }

    return lines.join('\n');
  }

  /**
   * Generate HTML report
   */
  private static generateHTML(result: ScanResult): string {
    const severityColors: Record<Severity, string> = {
      CRITICAL: '#dc2626',
      HIGH: '#ea580c',
      MEDIUM: '#ca8a04',
      LOW: '#0284c7',
      INFO: '#6b7280'
    };

    const scoreColor = result.summary.score >= 80 ? '#10b981' :
                      result.summary.score >= 60 ? '#f59e0b' :
                      result.summary.score >= 40 ? '#ea580c' : '#dc2626';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP-Guard Security Report - ${result.id}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
      line-height: 1.6; 
      color: #1f2937; 
      background: #f9fafb;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
    .header { 
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
      color: white; 
      padding: 2rem; 
      border-radius: 12px;
      margin-bottom: 2rem;
    }
    h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
    .subtitle { opacity: 0.9; }
    .summary-grid { 
      display: grid; 
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
      gap: 1.5rem; 
      margin-bottom: 2rem;
    }
    .summary-card {
      background: white;
      padding: 1.5rem;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .score-display {
      font-size: 3rem;
      font-weight: bold;
      color: ${scoreColor};
      text-align: center;
    }
    .grade-display {
      font-size: 2rem;
      text-align: center;
      color: #6b7280;
    }
    .severity-bar {
      display: flex;
      height: 30px;
      border-radius: 4px;
      overflow: hidden;
      margin: 1rem 0;
    }
    .severity-segment {
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-weight: bold;
      font-size: 0.875rem;
    }
    .vulnerability {
      background: white;
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      border-left: 4px solid;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .vuln-critical { border-color: #dc2626; }
    .vuln-high { border-color: #ea580c; }
    .vuln-medium { border-color: #ca8a04; }
    .vuln-low { border-color: #0284c7; }
    .vuln-info { border-color: #6b7280; }
    .severity-badge {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      color: white;
      font-weight: bold;
      font-size: 0.75rem;
      text-transform: uppercase;
    }
    .evidence {
      background: #f3f4f6;
      padding: 1rem;
      border-radius: 4px;
      font-family: monospace;
      overflow-x: auto;
      margin: 1rem 0;
    }
    .remediation {
      background: #ecfdf5;
      border: 1px solid #10b981;
      padding: 1rem;
      border-radius: 4px;
      margin: 1rem 0;
    }
    .recommendation {
      background: #eff6ff;
      border-left: 4px solid #3b82f6;
      padding: 1rem;
      margin: 0.5rem 0;
    }
    .footer {
      text-align: center;
      color: #6b7280;
      margin-top: 3rem;
      padding-top: 2rem;
      border-top: 1px solid #e5e7eb;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔐 MCP-Guard Security Report</h1>
      <div class="subtitle">Scan ID: ${result.id} | ${new Date(result.timestamp).toLocaleString()}</div>
    </div>

    <div class="summary-grid">
      <div class="summary-card">
        <div class="score-display">${result.summary.score}/100</div>
        <div class="grade-display">Grade: ${result.summary.grade}</div>
      </div>
      <div class="summary-card">
        <h3>Scan Statistics</h3>
        <p>Servers: ${result.summary.serversScanned}</p>
        <p>Duration: ${result.duration}ms</p>
        <p>Vulnerabilities: ${result.summary.vulnerabilitiesFound}</p>
      </div>
      <div class="summary-card">
        <h3>Severity Distribution</h3>
        <div class="severity-bar">
          ${result.summary.critical > 0 ? `<div class="severity-segment" style="background: #dc2626; flex: ${result.summary.critical}">${result.summary.critical}</div>` : ''}
          ${result.summary.high > 0 ? `<div class="severity-segment" style="background: #ea580c; flex: ${result.summary.high}">${result.summary.high}</div>` : ''}
          ${result.summary.medium > 0 ? `<div class="severity-segment" style="background: #ca8a04; flex: ${result.summary.medium}">${result.summary.medium}</div>` : ''}
          ${result.summary.low > 0 ? `<div class="severity-segment" style="background: #0284c7; flex: ${result.summary.low}">${result.summary.low}</div>` : ''}
        </div>
        <p>Critical: ${result.summary.critical} | High: ${result.summary.high} | Medium: ${result.summary.medium} | Low: ${result.summary.low}</p>
      </div>
    </div>

    ${result.vulnerabilities.length > 0 ? `
    <h2>Vulnerabilities</h2>
    ${result.vulnerabilities.map(vuln => `
      <div class="vulnerability vuln-${vuln.severity.toLowerCase()}">
        <span class="severity-badge" style="background: ${severityColors[vuln.severity]}">${vuln.severity}</span>
        <h3 style="display: inline; margin-left: 1rem;">${vuln.title}</h3>
        <p style="margin-top: 1rem;"><strong>Server:</strong> ${vuln.server} | <strong>Type:</strong> ${vuln.type}</p>
        <p>${vuln.description}</p>
        ${vuln.evidence ? `<div class="evidence">${vuln.evidence.value}</div>` : ''}
        ${vuln.remediation ? `<div class="remediation"><strong>Fix:</strong> ${vuln.remediation.description}</div>` : ''}
      </div>
    `).join('')}
    ` : '<h2 style="color: #10b981;">✅ No vulnerabilities found!</h2>'}

    ${result.recommendations.length > 0 ? `
    <h2>Recommendations</h2>
    ${result.recommendations.map(rec => `
      <div class="recommendation">${rec}</div>
    `).join('')}
    ` : ''}

    <div class="footer">
      <p>Generated by MCP-Guard v${result.metadata.version} | ${result.metadata.scanner}</p>
    </div>
  </div>
</body>
</html>`;
  }

  /**
   * Generate SARIF report for CI/CD integration
   */
  private static generateSARIF(result: ScanResult): string {
    const sarif = {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'MCP-Guard',
            version: result.metadata.version,
            informationUri: 'https://github.com/mcp-guard/mcp-guard',
            rules: result.vulnerabilities.map(vuln => ({
              id: vuln.id,
              name: vuln.type,
              shortDescription: { text: vuln.title },
              fullDescription: { text: vuln.description },
              defaultConfiguration: {
                level: this.severityToSarifLevel(vuln.severity)
              },
              help: {
                text: vuln.remediation?.description || 'No remediation available',
                markdown: vuln.remediation?.description || 'No remediation available'
              }
            }))
          }
        },
        results: result.vulnerabilities.map(vuln => ({
          ruleId: vuln.id,
          level: this.severityToSarifLevel(vuln.severity),
          message: {
            text: vuln.description
          },
          locations: vuln.location ? [{
            physicalLocation: {
              artifactLocation: {
                uri: vuln.server
              },
              region: {
                startLine: vuln.location.line || 1,
                startColumn: vuln.location.column || 1
              }
            }
          }] : [],
          fixes: vuln.remediation?.automated ? [{
            description: {
              text: vuln.remediation.description
            }
          }] : []
        }))
      }]
    };

    return JSON.stringify(sarif, null, 2);
  }

  /**
   * Generate CSV report
   */
  private static generateCSV(result: ScanResult): string {
    const headers = ['ID', 'Severity', 'Score', 'Server', 'Type', 'Title', 'Description', 'Location', 'Remediation'];
    const rows = [headers];

    result.vulnerabilities.forEach(vuln => {
      rows.push([
        vuln.id,
        vuln.severity,
        vuln.score.toString(),
        vuln.server,
        vuln.type,
        `"${vuln.title.replace(/"/g, '""')}"`,
        `"${vuln.description.replace(/"/g, '""')}"`,
        vuln.location?.path || '',
        `"${vuln.remediation?.description.replace(/"/g, '""') || ''}"`
      ]);
    });

    return rows.map(row => row.join(',')).join('\n');
  }

  /**
   * Generate XML report
   */
  private static generateXML(result: ScanResult): string {
    const escapeXml = (str: string): string => {
      return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
    };

    const lines = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<scan-result>',
      `  <id>${result.id}</id>`,
      `  <timestamp>${result.timestamp}</timestamp>`,
      `  <duration>${result.duration}</duration>`,
      '  <summary>',
      `    <score>${result.summary.score}</score>`,
      `    <grade>${result.summary.grade}</grade>`,
      `    <servers-scanned>${result.summary.serversScanned}</servers-scanned>`,
      `    <vulnerabilities-found>${result.summary.vulnerabilitiesFound}</vulnerabilities-found>`,
      `    <critical>${result.summary.critical}</critical>`,
      `    <high>${result.summary.high}</high>`,
      `    <medium>${result.summary.medium}</medium>`,
      `    <low>${result.summary.low}</low>`,
      `    <info>${result.summary.info}</info>`,
      '  </summary>',
      '  <vulnerabilities>'
    ];

    result.vulnerabilities.forEach(vuln => {
      lines.push('    <vulnerability>');
      lines.push(`      <id>${vuln.id}</id>`);
      lines.push(`      <severity>${vuln.severity}</severity>`);
      lines.push(`      <score>${vuln.score}</score>`);
      lines.push(`      <server>${escapeXml(vuln.server)}</server>`);
      lines.push(`      <type>${vuln.type}</type>`);
      lines.push(`      <title>${escapeXml(vuln.title)}</title>`);
      lines.push(`      <description>${escapeXml(vuln.description)}</description>`);
      
      if (vuln.location) {
        lines.push('      <location>');
        lines.push(`        <path>${escapeXml(vuln.location.path)}</path>`);
        if (vuln.location.line) {
          lines.push(`        <line>${vuln.location.line}</line>`);
        }
        lines.push('      </location>');
      }
      
      if (vuln.remediation) {
        lines.push('      <remediation>');
        lines.push(`        <description>${escapeXml(vuln.remediation.description)}</description>`);
        lines.push(`        <automated>${vuln.remediation.automated}</automated>`);
        lines.push('      </remediation>');
      }
      
      lines.push('    </vulnerability>');
    });

    lines.push('  </vulnerabilities>');
    
    if (result.recommendations.length > 0) {
      lines.push('  <recommendations>');
      result.recommendations.forEach(rec => {
        lines.push(`    <recommendation>${escapeXml(rec)}</recommendation>`);
      });
      lines.push('  </recommendations>');
    }
    
    lines.push('</scan-result>');

    return lines.join('\n');
  }

  /**
   * Convert severity to SARIF level
   */
  private static severityToSarifLevel(severity: Severity): string {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'note';
      case 'INFO':
      default:
        return 'none';
    }
  }
}
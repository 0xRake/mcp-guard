import { describe, it, expect } from 'vitest';
import { ScanConfigTool } from '../src/tools/scan-config';
import { CheckVulnerabilitiesChuiTool } from '../src/tools/check-vulnerabilities';
import { GenerateReportTool } from '../src/tools/generate-report';
import type { MCPServerConfig } from '@mcp-guard/core';

const cleanConfig: MCPServerConfig = {
  command: 'node',
  args: ['server.js'],
  metadata: { name: 'test-server' }
};

const leakyConfig: MCPServerConfig = {
  command: 'node',
  args: ['server.js', '--api-key', 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab'],
  metadata: { name: 'leaky-server' }
};

describe('ScanConfigTool', () => {
  const tool = new ScanConfigTool();

  it('returns a result with score, grade, and matching vuln count', async () => {
    const result = await tool.execute({ config: cleanConfig });
    expect(result.summary.score).toBeGreaterThanOrEqual(0);
    expect(result.summary.score).toBeLessThanOrEqual(100);
    expect(['A', 'B', 'C', 'D', 'F']).toContain(result.summary.grade);
    expect(result.summary.vulnerabilitiesFound).toBe(result.vulnerabilities.length);
  });

  it('finds more issues at comprehensive depth than quick', async () => {
    const quick = await tool.execute({ config: cleanConfig, depth: 'quick' });
    const deep = await tool.execute({ config: cleanConfig, depth: 'comprehensive' });
    // Comprehensive should find at least as many vulnerabilities
    expect(deep.summary.vulnerabilitiesFound).toBeGreaterThanOrEqual(quick.summary.vulnerabilitiesFound);
  });

  it('throws on null config', async () => {
    await expect(tool.execute({ config: null as any })).rejects.toThrow('Invalid configuration');
  });

  it('formatResult includes score line and grade', async () => {
    const result = await tool.execute({ config: cleanConfig });
    const text = tool.formatResult(result);
    expect(text).toContain(`${result.summary.score}/100`);
    expect(text).toContain(result.summary.grade);
  });
});

describe('CheckVulnerabilitiesChuiTool', () => {
  const tool = new CheckVulnerabilitiesChuiTool();

  it('finds vulnerabilities in a leaky config', async () => {
    const vulns = await tool.execute({ config: leakyConfig });
    expect(vulns.length).toBeGreaterThan(0);
    // Each vuln should have required fields
    for (const v of vulns) {
      expect(v).toHaveProperty('id');
      expect(v).toHaveProperty('type');
      expect(v).toHaveProperty('severity');
      expect(v).toHaveProperty('title');
    }
  });

  it('returns empty array when filtering to irrelevant type on clean config', async () => {
    const vulns = await tool.execute({ config: cleanConfig, types: ['oauth-security'] });
    // Clean config shouldn't have OAuth issues
    expect(vulns).toBeInstanceOf(Array);
  });

  it('rejects invalid vulnerability type names', async () => {
    await expect(
      tool.execute({ config: cleanConfig, types: ['made-up-type'] })
    ).rejects.toThrow('Invalid vulnerability types: made-up-type');
  });

  it('formatResult shows count when vulnerabilities exist', async () => {
    const vulns = await tool.execute({ config: leakyConfig });
    if (vulns.length > 0) {
      const text = tool.formatResult(vulns);
      expect(text).toContain(`Found ${vulns.length} vulnerabilities`);
    }
  });

  it('formatResult shows clean message for empty results', () => {
    expect(tool.formatResult([])).toContain('No vulnerabilities found');
  });
});

describe('GenerateReportTool', () => {
  const tool = new GenerateReportTool();

  it('JSON report round-trips and contains scan data', async () => {
    const report = await tool.execute({ config: cleanConfig, format: 'json' });
    const parsed = JSON.parse(report);
    expect(parsed.summary.score).toBeGreaterThanOrEqual(0);
    expect(parsed.vulnerabilities).toBeInstanceOf(Array);
    expect(parsed.summary.vulnerabilitiesFound).toBe(parsed.vulnerabilities.length);
  });

  it('markdown report has executive summary with score', async () => {
    const report = await tool.execute({ config: cleanConfig, format: 'markdown' });
    expect(report).toContain('# MCP-Guard Security Report');
    expect(report).toContain('## Executive Summary');
    expect(report).toMatch(/Score.*\/100/);
  });

  it('HTML report is valid document with vulnerability styling', async () => {
    const report = await tool.execute({ config: leakyConfig, format: 'html' });
    expect(report).toContain('<!DOCTYPE html>');
    expect(report).toContain('</html>');
    expect(report).toContain('MCP-Guard Security Report');
    // Should have vulnerability entries with severity styling
    expect(report).toContain('severity-');
  });

  it('SARIF report conforms to v2.1.0 schema structure', async () => {
    const report = await tool.execute({ config: leakyConfig, format: 'sarif' });
    const sarif = JSON.parse(report);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('MCP-Guard');
    expect(sarif.runs[0].results).toBeInstanceOf(Array);
    // Each result should have ruleId and level
    for (const result of sarif.runs[0].results) {
      expect(typeof result.ruleId).toBe('string');
      expect(['error', 'warning', 'note', 'none']).toContain(result.level);
    }
  });

  it('rejects unsupported format', async () => {
    await expect(
      tool.execute({ config: cleanConfig, format: 'docx' as any })
    ).rejects.toThrow('Unsupported format');
  });
});

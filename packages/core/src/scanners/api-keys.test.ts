import { describe, it, expect } from 'vitest';
import { APIKeyScanner } from './api-keys';
import { MCPServerConfig, Severity, VulnerabilityType } from '../types';

describe('APIKeyScanner', () => {
  const scanner = new APIKeyScanner();

  it('should detect OpenAI API keys in command arguments', async () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js', '--api-key', 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab'],
      metadata: { name: 'test-server' }
    };

    const vulnerabilities = await scanner.scan(config);
    
    expect(vulnerabilities).toHaveLength(1);
    expect(vulnerabilities[0].type).toBe(VulnerabilityType.EXPOSED_API_KEY);
    expect(vulnerabilities[0].severity).toBe(Severity.CRITICAL);
    expect(vulnerabilities[0].title).toContain('OpenAI');
  });

  it('should detect Anthropic API keys', async () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: {
        'ANTHROPIC_API_KEY': 'sk-ant-' + 'a'.repeat(100)
      },
      metadata: { name: 'test-server' }
    };

    const vulnerabilities = await scanner.scan(config);
    
    expect(vulnerabilities.length).toBeGreaterThan(0);
    expect(vulnerabilities[0].title).toContain('Anthropic');
  });

  it('should detect AWS credentials', async () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: {
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
      },
      metadata: { name: 'test-server' }
    };

    const vulnerabilities = await scanner.scan(config);
    
    expect(vulnerabilities.length).toBeGreaterThanOrEqual(2);
    const awsVuln = vulnerabilities.find(v => v.title.includes('AWS'));
    expect(awsVuln).toBeDefined();
    expect(awsVuln?.severity).toBe(Severity.CRITICAL);
  });

  it('should detect hardcoded passwords in auth config', async () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      auth: {
        type: 'basic',
        credentials: {
          username: 'admin',
          password: 'supersecretpassword123'
        }
      },
      metadata: { name: 'test-server' }
    };

    const vulnerabilities = await scanner.scan(config);
    
    expect(vulnerabilities.length).toBeGreaterThan(0);
    const passwordVuln = vulnerabilities.find(v => v.title.includes('Password'));
    expect(passwordVuln).toBeDefined();
    expect(passwordVuln?.severity).toBe(Severity.HIGH);
  });

  it('should not flag placeholder values', async () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: {
        'API_KEY': '${API_KEY}',
        'SECRET': '<your-secret-here>',
        'TOKEN': 'process.env.TOKEN',
        'PASSWORD': '[PLACEHOLDER]'
      },
      metadata: { name: 'test-server' }
    };

    const vulnerabilities = await scanner.scan(config);
    
    expect(vulnerabilities).toHaveLength(0);
  });

  it('should detect database connection strings', async () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: {
        'DATABASE_URL': 'mongodb://user:password123@localhost:27017/mydb',
        'POSTGRES_URL': 'postgresql://dbuser:secretpass@database.server.com:5432/mydb'
      },
      metadata: { name: 'test-server' }
    };

    const vulnerabilities = await scanner.scan(config);
    
    expect(vulnerabilities.length).toBeGreaterThanOrEqual(2);
    expect(vulnerabilities.
/**
 * Configuration validator
 * Validates MCP server configurations for security and correctness
 */

import { z } from 'zod';
import { MCPServerConfig, AuthConfig, OAuthConfig } from '../types';
import { logger } from '../utils/logger';

// Zod schemas for validation
const AuthConfigSchema = z.object({
  type: z.enum(['basic', 'bearer', 'oauth', 'custom']),
  credentials: z.record(z.string()).optional(),
  token: z.string().optional(),
  oauth: z.object({
    clientId: z.string(),
    clientSecret: z.string().optional(),
    authorizationUrl: z.string().url().optional(),
    tokenUrl: z.string().url().optional(),
    scopes: z.array(z.string()).optional()
  }).optional()
});

const OAuthConfigSchema = z.object({
  authorizationServer: z.string().url(),
  clientId: z.string().optional(),
  scopes: z.array(z.string()).optional(),
  pkce: z.boolean().optional(),
  metadata: z.object({
    issuer: z.string(),
    authorization_endpoint: z.string().url().optional(),
    token_endpoint: z.string().url().optional(),
    userinfo_endpoint: z.string().url().optional(),
    jwks_uri: z.string().url().optional()
  }).optional()
});

const ServerCapabilitiesSchema = z.object({
  tools: z.boolean().optional(),
  prompts: z.boolean().optional(),
  resources: z.boolean().optional(),
  logging: z.boolean().optional()
});

const ServerMetadataSchema = z.object({
  name: z.string().optional(),
  version: z.string().optional(),
  description: z.string().optional(),
  homepage: z.string().url().optional(),
  author: z.string().optional()
});

export const MCPServerConfigSchema = z.object({
  command: z.string().min(1),
  args: z.array(z.string()).optional(),
  env: z.record(z.string()).optional(),
  auth: AuthConfigSchema.optional(),
  oauth: OAuthConfigSchema.optional(),
  capabilities: ServerCapabilitiesSchema.optional(),
  metadata: ServerMetadataSchema.optional()
});

export class ConfigValidator {
  /**
   * Validate a single MCP server configuration
   */
  static validate(config: unknown): MCPServerConfig {
    try {
      return MCPServerConfigSchema.parse(config);
    } catch (error) {
      if (error instanceof z.ZodError) {
        const issues = error.errors.map(e => `${e.path.join('.')}: ${e.message}`);
        throw new Error(`Invalid configuration:\n${issues.join('\n')}`);
      }
      throw error;
    }
  }

  /**
   * Validate multiple configurations
   */
  static validateMultiple(configs: Record<string, unknown>): Record<string, MCPServerConfig> {
    const validated: Record<string, MCPServerConfig> = {};
    const errors: string[] = [];

    for (const [name, config] of Object.entries(configs)) {
      try {
        validated[name] = this.validate(config);
      } catch (error) {
        errors.push(`Server "${name}": ${error}`);
      }
    }

    if (errors.length > 0) {
      throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
    }

    return validated;
  }

  /**
   * Check for security issues in configuration
   */
  static checkSecurityIssues(config: MCPServerConfig): string[] {
    const issues: string[] = [];

    // Check for hardcoded secrets
    if (config.env) {
      for (const [key, value] of Object.entries(config.env)) {
        if (this.looksLikeSecret(key, value)) {
          issues.push(`Potential hardcoded secret in environment variable: ${key}`);
        }
      }
    }

    // Check for missing authentication
    if (config.capabilities?.tools && !config.auth && !config.oauth) {
      issues.push('Tools capability enabled without authentication');
    }

    // Check for insecure protocols
    if (config.command.includes('http://') && !config.command.includes('http://localhost')) {
      issues.push('Using insecure HTTP protocol');
    }

    // Check for dangerous commands
    const dangerousCommands = ['rm', 'del', 'format', 'sudo', 'chmod', 'chown'];
    if (dangerousCommands.some(cmd => config.command.includes(cmd))) {
      issues.push('Potentially dangerous command detected');
    }

    // Check for weak authentication
    if (config.auth?.type === 'basic' && config.auth.credentials) {
      const { username, password } = config.auth.credentials;
      if (password && this.isWeakPassword(password)) {
        issues.push('Weak password detected in basic authentication');
      }
    }

    return issues;
  }

  /**
   * Sanitize configuration by removing sensitive data
   */
  static sanitize(config: MCPServerConfig): MCPServerConfig {
    const sanitized = { ...config };

    // Sanitize environment variables
    if (sanitized.env) {
      const sanitizedEnv: Record<string, string> = {};
      for (const [key, value] of Object.entries(sanitized.env)) {
        if (this.looksLikeSecret(key, value)) {
          sanitizedEnv[key] = '[REDACTED]';
        } else {
          sanitizedEnv[key] = value;
        }
      }
      sanitized.env = sanitizedEnv;
    }

    // Sanitize auth credentials
    if (sanitized.auth?.credentials) {
      const sanitizedCreds = { ...sanitized.auth.credentials };
      if (sanitizedCreds.password) {
        sanitizedCreds.password = '[REDACTED]';
      }
      if (sanitizedCreds.token) {
        sanitizedCreds.token = '[REDACTED]';
      }
      sanitized.auth = {
        ...sanitized.auth,
        credentials: sanitizedCreds
      };
    }

    // Sanitize OAuth client secret
    if (sanitized.oauth && 'clientSecret' in sanitized.oauth) {
      sanitized.oauth = {
        ...sanitized.oauth,
        clientSecret: '[REDACTED]'
      } as any;
    }

    return sanitized;
  }

  /**
   * Check if a value looks like a secret
   */
  private static looksLikeSecret(key: string, value: string): boolean {
    const secretKeywords = [
      'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
      'auth', 'credential', 'private', 'priv_key', 'access_key', 'client_secret'
    ];

    const keyLower = key.toLowerCase();
    
    // Check if key contains secret keywords
    if (secretKeywords.some(keyword => keyLower.includes(keyword))) {
      // Don't flag placeholders
      if (value.includes('${') || value.includes('$(') || value === '[PLACEHOLDER]') {
        return false;
      }
      // Don't flag environment variable references
      if (value.startsWith('process.env.') || value.startsWith('$')) {
        return false;
      }
      return true;
    }

    // Check for common secret patterns
    const secretPatterns = [
      /^sk-[a-zA-Z0-9]{20,}$/,  // OpenAI style
      /^[a-zA-Z0-9]{32,}$/,      // Generic long key
      /^ghp_[a-zA-Z0-9]{36}$/,   // GitHub token
      /^gho_[a-zA-Z0-9]{36}$/,   // GitHub OAuth
      /^github_pat_[a-zA-Z0-9_]{82}$/ // GitHub PAT
    ];

    return secretPatterns.some(pattern => pattern.test(value));
  }

  /**
   * Check if a password is weak
   */
  private static isWeakPassword(password: string): boolean {
    const weakPasswords = [
      'password', '123456', 'password123', 'admin', 'letmein',
      'qwerty', 'abc123', '111111', 'password1', 'admin123'
    ];

    if (weakPasswords.includes(password.toLowerCase())) {
      return true;
    }

    // Check for common patterns
    if (password.length < 8) {
      return true;
    }

    // All numbers
    if (/^\d+$/.test(password)) {
      return true;
    }

    // All lowercase letters
    if (/^[a-z]+$/.test(password)) {
      return true;
    }

    return false;
  }

  /**
   * Validate OAuth configuration
   */
  static validateOAuth(config: OAuthConfig): void {
    // Check for required OAuth 2.1 features
    if (!config.pkce && config.pkce !== false) {
      logger.warn('OAuth configuration missing PKCE - recommended for OAuth 2.1 compliance');
    }

    if (!config.authorizationServer.startsWith('https://')) {
      throw new Error('OAuth authorization server must use HTTPS');
    }

    if (config.metadata?.issuer && config.metadata.issuer !== config.authorizationServer) {
      logger.warn('OAuth issuer does not match authorization server');
    }
  }

  /**
   * Merge configurations with defaults
   */
  static applyDefaults(config: Partial<MCPServerConfig>): MCPServerConfig {
    return {
      command: config.command || '',
      args: config.args || [],
      env: config.env || {},
      metadata: {
        name: config.metadata?.name || 'unnamed-server',
        version: config.metadata?.version || '1.0.0',
        ...config.metadata
      },
      capabilities: {
        tools: false,
        prompts: false,
        resources: false,
        logging: false,
        ...config.capabilities
      },
      ...config
    } as MCPServerConfig;
  }
}
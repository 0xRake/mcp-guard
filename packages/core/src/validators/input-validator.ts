/**
 * Input validator
 * Validates and sanitizes user inputs to prevent injection attacks
 */

import { z } from 'zod';

export class InputValidator {
  /**
   * Validate and sanitize file paths
   */
  static validatePath(path: string): string {
    // Remove null bytes
    let sanitized = path.replace(/\0/g, '');
    
    // Prevent path traversal
    if (sanitized.includes('..')) {
      throw new Error('Path traversal detected');
    }
    
    // Remove leading/trailing whitespace
    sanitized = sanitized.trim();
    
    // Check for invalid characters
    const invalidChars = ['<', '>', '|', '\n', '\r', '\t'];
    if (invalidChars.some(char => sanitized.includes(char))) {
      throw new Error('Invalid characters in path');
    }
    
    return sanitized;
  }

  /**
   * Validate command arguments
   */
  static validateCommandArgs(args: string[]): string[] {
    return args.map(arg => {
      // Remove null bytes
      let sanitized = arg.replace(/\0/g, '');
      
      // Check for shell metacharacters
      const shellMetachars = [';', '|', '&', '$', '`', '\\', '(', ')', '<', '>', '*', '?', '[', ']', '{', '}'];
      
      // If arg contains shell metacharacters, quote it
      if (shellMetachars.some(char => sanitized.includes(char))) {
        // Escape single quotes and wrap in single quotes
        sanitized = `'${sanitized.replace(/'/g, "'\\''")}'`;
      }
      
      return sanitized;
    });
  }

  /**
   * Validate environment variables
   */
  static validateEnvVars(env: Record<string, string>): Record<string, string> {
    const validated: Record<string, string> = {};
    
    for (const [key, value] of Object.entries(env)) {
      // Validate key
      if (!/^[A-Z_][A-Z0-9_]*$/i.test(key)) {
        throw new Error(`Invalid environment variable name: ${key}`);
      }
      
      // Sanitize value
      validated[key] = value.replace(/\0/g, '');
    }
    
    return validated;
  }

  /**
   * Validate URL
   */
  static validateUrl(url: string): string {
    try {
      const parsed = new URL(url);
      
      // Only allow http(s) and file protocols
      if (!['http:', 'https:', 'file:'].includes(parsed.protocol)) {
        throw new Error(`Invalid protocol: ${parsed.protocol}`);
      }
      
      // Check for localhost/private IPs (SSRF prevention)
      const hostname = parsed.hostname.toLowerCase();
      if (this.isPrivateIP(hostname) && !this.isAllowedLocalhost(hostname)) {
        throw new Error('Access to private IP addresses is restricted');
      }
      
      return url;
    } catch (error) {
      throw new Error(`Invalid URL: ${error}`);
    }
  }

  /**
   * Validate JSON input
   */
  static validateJSON(input: string): any {
    try {
      // Remove BOM if present
      const cleaned = input.replace(/^\uFEFF/, '');
      
      // Parse and validate
      const parsed = JSON.parse(cleaned);
      
      // Check for prototype pollution
      if (this.hasPrototypePollution(parsed)) {
        throw new Error('Potential prototype pollution detected');
      }
      
      return parsed;
    } catch (error) {
      throw new Error(`Invalid JSON: ${error}`);
    }
  }

  /**
   * Validate scan depth option
   */
  static validateScanDepth(depth: string): string {
    const validDepths = ['quick', 'standard', 'comprehensive', 'paranoid'];
    
    if (!validDepths.includes(depth)) {
      throw new Error(`Invalid scan depth. Must be one of: ${validDepths.join(', ')}`);
    }
    
    return depth;
  }

  /**
   * Validate output format
   */
  static validateOutputFormat(format: string): string {
    const validFormats = ['json', 'markdown', 'html', 'sarif', 'csv', 'xml', 'console'];
    
    if (!validFormats.includes(format.toLowerCase())) {
      throw new Error(`Invalid output format. Must be one of: ${validFormats.join(', ')}`);
    }
    
    return format.toLowerCase();
  }

  /**
   * Sanitize HTML content
   */
  static sanitizeHTML(html: string): string {
    // Basic HTML sanitization
    return html
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/&(?!(lt|gt|quot|#39|amp);)/g, '&amp;');
  }

  /**
   * Validate and sanitize server name
   */
  static validateServerName(name: string): string {
    // Allow alphanumeric, dash, underscore
    if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
      throw new Error('Invalid server name. Use only letters, numbers, dash, and underscore.');
    }
    
    // Limit length
    if (name.length > 100) {
      throw new Error('Server name too long (max 100 characters)');
    }
    
    return name;
  }

  /**
   * Check if hostname is a private IP
   */
  private static isPrivateIP(hostname: string): boolean {
    // Check for localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
      return true;
    }
    
    // Check for private IP ranges
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^169\.254\./,  // Link-local
      /^fc00:/,        // IPv6 private
      /^fe80:/         // IPv6 link-local
    ];
    
    return privateRanges.some(range => range.test(hostname));
  }

  /**
   * Check if localhost access is allowed
   */
  private static isAllowedLocalhost(hostname: string): boolean {
    // Allow localhost for development
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  }

  /**
   * Check for prototype pollution
   */
  private static hasPrototypePollution(obj: any): boolean {
    if (typeof obj !== 'object' || obj === null) {
      return false;
    }
    
    // Check for dangerous keys
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    
    for (const key in obj) {
      if (dangerousKeys.includes(key)) {
        return true;
      }
      
      // Recursive check
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        if (this.hasPrototypePollution(obj[key])) {
          return true;
        }
      }
    }
    
    return false;
  }

  /**
   * Create a schema validator
   */
  static createSchema<T>(schema: z.ZodSchema<T>) {
    return (input: unknown): T => {
      try {
        return schema.parse(input);
      } catch (error) {
        if (error instanceof z.ZodError) {
          const issues = error.errors.map(e => `${e.path.join('.')}: ${e.message}`);
          throw new Error(`Validation failed:\n${issues.join('\n')}`);
        }
        throw error;
      }
    };
  }
}
/**
 * Type definitions for MCP configuration structures
 */

/**
 * Severity levels for vulnerabilities
 */
export enum Severity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

/**
 * Individual vulnerability found during scanning
 */
export interface Vulnerability {
  severity: Severity;
  title: string;
  description: string;
  fix: string;
  server?: string; // MCP server name where vulnerability was found
  details?: Record<string, any>; // Additional context-specific details
}

/**
 * Result of a security scan
 */
export interface ScanResult {
  score: number; // Security score (0-100, where 100 is most secure)
  vulnerabilities: Vulnerability[];
  timestamp?: Date;
  configPath?: string;
}

/**
 * MCP server configuration
 */
export interface MCPServer {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  [key: string]: any; // Allow additional properties
}

/**
 * Main MCP configuration structure from claude_desktop_config.json
 */
export interface MCPConfig {
  mcpServers?: Record<string, MCPServer>;
  [key: string]: any; // Allow additional top-level properties
}

/**
 * Options for parsing configuration
 */
export interface ConfigParseOptions {
  throwOnError?: boolean;
  validateSchema?: boolean;
}

/**
 * Result of parsing a configuration file
 */
export interface ParseResult {
  success: boolean;
  config?: MCPConfig;
  error?: Error;
  warnings?: string[];
}
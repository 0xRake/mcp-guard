import * as fs from 'fs';
import * as path from 'path';
import { MCPConfig, ParseResult, ConfigParseOptions } from '../types';

/**
 * Parse MCP configuration from claude_desktop_config.json
 */
export class ConfigParser {
  /**
   * Read and parse MCP configuration from a file
   * @param configPath Path to claude_desktop_config.json
   * @param options Parsing options
   * @returns ParseResult with config or error information
   */
  static async parseConfig(
    configPath: string,
    options: ConfigParseOptions = {}
  ): Promise<ParseResult> {
    const { throwOnError = false, validateSchema = true } = options;
    const warnings: string[] = [];

    try {
      // Check if file exists
      if (!fs.existsSync(configPath)) {
        const error = new Error(`Configuration file not found: ${configPath}`);
        if (throwOnError) throw error;
        return {
          success: false,
          error,
          warnings
        };
      }

      // Read file content
      const content = await fs.promises.readFile(configPath, 'utf-8');
      
      // Parse JSON
      let config: MCPConfig;
      try {
        config = JSON.parse(content);
      } catch (parseError) {
        const error = new Error(`Invalid JSON in configuration file: ${parseError}`);
        if (throwOnError) throw error;
        return {
          success: false,
          error,
          warnings
        };
      }

      // Validate schema if requested
      if (validateSchema) {
        const validation = this.validateConfig(config);
        if (!validation.valid) {
          warnings.push(...validation.warnings);
          if (validation.errors.length > 0) {
            const error = new Error(`Configuration validation failed: ${validation.errors.join(', ')}`);
            if (throwOnError) throw error;
            return {
              success: false,
              config,
              error,
              warnings
            };
          }
        }
      }

      return {
        success: true,
        config,
        warnings
      };

    } catch (error) {
      if (throwOnError) throw error;
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
        warnings
      };
    }
  }

  /**
   * Parse MCP configuration synchronously
   * @param configPath Path to claude_desktop_config.json
   * @param options Parsing options
   * @returns ParseResult with config or error information
   */
  static parseConfigSync(
    configPath: string,
    options: ConfigParseOptions = {}
  ): ParseResult {
    const { throwOnError = false, validateSchema = true } = options;
    const warnings: string[] = [];

    try {
      // Check if file exists
      if (!fs.existsSync(configPath)) {
        const error = new Error(`Configuration file not found: ${configPath}`);
        if (throwOnError) throw error;
        return {
          success: false,
          error,
          warnings
        };
      }

      // Read file content
      const content = fs.readFileSync(configPath, 'utf-8');
      
      // Parse JSON
      let config: MCPConfig;
      try {
        config = JSON.parse(content);
      } catch (parseError) {
        const error = new Error(`Invalid JSON in configuration file: ${parseError}`);
        if (throwOnError) throw error;
        return {
          success: false,
          error,
          warnings
        };
      }

      // Validate schema if requested
      if (validateSchema) {
        const validation = this.validateConfig(config);
        if (!validation.valid) {
          warnings.push(...validation.warnings);
          if (validation.errors.length > 0) {
            const error = new Error(`Configuration validation failed: ${validation.errors.join(', ')}`);
            if (throwOnError) throw error;
            return {
              success: false,
              config,
              error,
              warnings
            };
          }
        }
      }

      return {
        success: true,
        config,
        warnings
      };

    } catch (error) {
      if (throwOnError) throw error;
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
        warnings
      };
    }
  }

  /**
   * Validate MCP configuration structure
   * @param config Configuration to validate
   * @returns Validation result with errors and warnings
   */
  private static validateConfig(config: MCPConfig): {
    valid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check if config is an object
    if (typeof config !== 'object' || config === null) {
      errors.push('Configuration must be a valid object');
      return { valid: false, errors, warnings };
    }

    // Check mcpServers section
    if (config.mcpServers) {
      if (typeof config.mcpServers !== 'object') {
        errors.push('mcpServers must be an object');
      } else {
        // Validate each server configuration
        for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
          // Check required fields
          if (!serverConfig.command) {
            errors.push(`Server "${serverName}" missing required field: command`);
          } else if (typeof serverConfig.command !== 'string') {
            errors.push(`Server "${serverName}" command must be a string`);
          }

          // Check optional fields
          if (serverConfig.args !== undefined) {
            if (!Array.isArray(serverConfig.args)) {
              errors.push(`Server "${serverName}" args must be an array`);
            } else if (!serverConfig.args.every(arg => typeof arg === 'string')) {
              errors.push(`Server "${serverName}" args must contain only strings`);
            }
          }

          if (serverConfig.env !== undefined) {
            if (typeof serverConfig.env !== 'object' || serverConfig.env === null) {
              errors.push(`Server "${serverName}" env must be an object`);
            } else {
              // Check that all env values are strings
              for (const [key, value] of Object.entries(serverConfig.env)) {
                if (typeof value !== 'string') {
                  warnings.push(`Server "${serverName}" env variable "${key}" should be a string`);
                }
              }
            }
          }
        }
      }
    } else {
      warnings.push('No mcpServers section found in configuration');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Extract MCP servers from configuration
   * @param config MCP configuration
   * @returns Map of server names to configurations
   */
  static extractServers(config: MCPConfig): Map<string, any> {
    const servers = new Map<string, any>();
    
    if (config.mcpServers) {
      for (const [name, serverConfig] of Object.entries(config.mcpServers)) {
        servers.set(name, serverConfig);
      }
    }
    
    return servers;
  }

  /**
   * Get default configuration path based on OS
   * @returns Default path to claude_desktop_config.json
   */
  static getDefaultConfigPath(): string {
    const platform = process.platform;
    const homeDir = process.env.HOME || process.env.USERPROFILE || '';
    
    switch (platform) {
      case 'darwin': // macOS
        return path.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
      case 'win32': // Windows
        return path.join(process.env.APPDATA || '', 'Claude', 'claude_desktop_config.json');
      default: // Linux and others
        return path.join(homeDir, '.config', 'claude', 'claude_desktop_config.json');
    }
  }
}
/**
 * Configuration loader utility
 * Handles loading and parsing MCP configurations from various sources
 */

import * as fs from 'fs-extra';
import * as path from 'path';
import { MCPServerConfig, ClaudeDesktopConfig } from '../types';
import { logger } from './logger';

export class ConfigLoader {
  /**
   * Load Claude Desktop configuration from default locations
   */
  static async loadClaudeDesktopConfig(): Promise<ClaudeDesktopConfig | null> {
    const configPaths = [
      // macOS
      path.join(process.env.HOME || '', 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      // Windows
      path.join(process.env.APPDATA || '', 'Claude', 'claude_desktop_config.json'),
      // Linux
      path.join(process.env.HOME || '', '.config', 'Claude', 'claude_desktop_config.json'),
      // Alternative Linux
      path.join(process.env.HOME || '', '.claude', 'claude_desktop_config.json')
    ];

    for (const configPath of configPaths) {
      try {
        if (await fs.pathExists(configPath)) {
          logger.debug(`Found Claude config at: ${configPath}`);
          const config = await fs.readJson(configPath);
          return config as ClaudeDesktopConfig;
        }
      } catch (error) {
        logger.warn(`Failed to read config from ${configPath}:`, error);
      }
    }

    logger.warn('No Claude Desktop configuration found in default locations');
    return null;
  }

  /**
   * Load configuration from a specific file path
   */
  static async loadConfigFile(filePath: string): Promise<Record<string, MCPServerConfig>> {
    try {
      const absolutePath = path.resolve(filePath);
      
      if (!await fs.pathExists(absolutePath)) {
        throw new Error(`Configuration file not found: ${absolutePath}`);
      }

      const content = await fs.readJson(absolutePath);
      
      // Handle different config formats
      if (content.mcpServers) {
        return content.mcpServers;
      } else if (content.servers) {
        return content.servers;
      } else if (typeof content === 'object') {
        // Assume it's a direct server config object
        return content;
      }

      throw new Error('Invalid configuration format');
    } catch (error) {
      logger.error(`Failed to load config from ${filePath}:`, error);
      throw error;
    }
  }

  /**
   * Load configuration from environment variables
   */
  static loadFromEnvironment(): Record<string, MCPServerConfig> {
    const configs: Record<string, MCPServerConfig> = {};
    
    // Look for MCP_SERVER_* environment variables
    Object.keys(process.env).forEach(key => {
      if (key.startsWith('MCP_SERVER_')) {
        const serverName = key.replace('MCP_SERVER_', '').toLowerCase();
        try {
          const configJson = process.env[key];
          if (configJson) {
            configs[serverName] = JSON.parse(configJson);
            logger.debug(`Loaded server config from env: ${serverName}`);
          }
        } catch (error) {
          logger.warn(`Failed to parse env config ${key}:`, error);
        }
      }
    });

    return configs;
  }

  /**
   * Validate configuration structure
   */
  static validateConfig(config: any): config is MCPServerConfig {
    if (!config || typeof config !== 'object') {
      return false;
    }

    // Required: command
    if (typeof config.command !== 'string' || !config.command) {
      logger.warn('Invalid config: missing or invalid "command" field');
      return false;
    }

    // Optional but validated if present
    if (config.args && !Array.isArray(config.args)) {
      logger.warn('Invalid config: "args" must be an array');
      return false;
    }

    if (config.env && typeof config.env !== 'object') {
      logger.warn('Invalid config: "env" must be an object');
      return false;
    }

    return true;
  }

  /**
   * Merge multiple configuration sources
   */
  static mergeConfigs(...configs: Record<string, MCPServerConfig>[]): Record<string, MCPServerConfig> {
    const merged: Record<string, MCPServerConfig> = {};

    for (const config of configs) {
      Object.entries(config).forEach(([name, serverConfig]) => {
        if (this.validateConfig(serverConfig)) {
          merged[name] = serverConfig;
        }
      });
    }

    return merged;
  }

  /**
   * Expand environment variables in configuration
   */
  static expandEnvironmentVariables(config: MCPServerConfig): MCPServerConfig {
    const expanded = { ...config };

    // Expand in command
    if (expanded.command) {
      expanded.command = this.expandEnvString(expanded.command);
    }

    // Expand in args
    if (expanded.args) {
      expanded.args = expanded.args.map(arg => this.expandEnvString(arg));
    }

    // Expand in env values
    if (expanded.env) {
      const expandedEnv: Record<string, string> = {};
      Object.entries(expanded.env).forEach(([key, value]) => {
        expandedEnv[key] = this.expandEnvString(value);
      });
      expanded.env = expandedEnv;
    }

    return expanded;
  }

  /**
   * Expand environment variables in a string
   */
  private static expandEnvString(str: string): string {
    return str.replace(/\$\{([^}]+)\}/g, (match, envVar) => {
      return process.env[envVar] || match;
    }).replace(/\$([A-Z_][A-Z0-9_]*)/g, (match, envVar) => {
      return process.env[envVar] || match;
    });
  }
}
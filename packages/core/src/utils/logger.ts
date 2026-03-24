/**
 * Logger interface and factories for MCP-Guard.
 *
 * The library never writes to stdout/stderr directly.
 * Consumers inject a Logger via MCPGuardOptions; the default is silent.
 */

export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4
}

export const noopLogger: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {}
};

/**
 * Logger that writes to stderr. Safe for CLI tools and MCP servers
 * where stdout is reserved for data or protocol messages.
 */
export function createStderrLogger(level: LogLevel = LogLevel.INFO, prefix = '[mcp-guard]'): Logger {
  return {
    debug(message, ...args) {
      if (level <= LogLevel.DEBUG) process.stderr.write(`${prefix} DEBUG ${message} ${args.length ? JSON.stringify(args) : ''}\n`);
    },
    info(message, ...args) {
      if (level <= LogLevel.INFO) process.stderr.write(`${prefix} INFO  ${message} ${args.length ? JSON.stringify(args) : ''}\n`);
    },
    warn(message, ...args) {
      if (level <= LogLevel.WARN) process.stderr.write(`${prefix} WARN  ${message} ${args.length ? JSON.stringify(args) : ''}\n`);
    },
    error(message, ...args) {
      if (level <= LogLevel.ERROR) process.stderr.write(`${prefix} ERROR ${message} ${args.length ? JSON.stringify(args) : ''}\n`);
    }
  };
}

// Backwards-compatible singleton — defaults to no-op.
// Internal code that imported `logger` will now be silent unless
// a consumer injects a real logger via MCPGuardOptions.
export const logger: Logger = noopLogger;

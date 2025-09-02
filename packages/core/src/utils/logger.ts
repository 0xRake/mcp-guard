/**
 * Logger utility for MCP-Guard
 * Provides colored console output and log levels
 */

import chalk from 'chalk';

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4
}

export class Logger {
  private static instance: Logger;
  private logLevel: LogLevel = LogLevel.INFO;
  private prefix: string = '[MCP-Guard]';

  private constructor() {}

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  static resetInstance(): void {
    Logger.instance = undefined as any;
  }

  setLogLevel(level: LogLevel): void {
    this.logLevel = level;
  }

  setPrefix(prefix: string): void {
    this.prefix = prefix;
  }

  debug(message: string, ...args: any[]): void {
    if (this.logLevel <= LogLevel.DEBUG) {
      console.log(chalk.gray(`${this.prefix} [DEBUG]`), message, ...args);
    }
  }

  info(message: string, ...args: any[]): void {
    if (this.logLevel <= LogLevel.INFO) {
      console.log(chalk.blue(`${this.prefix} [INFO]`), message, ...args);
    }
  }

  success(message: string, ...args: any[]): void {
    if (this.logLevel <= LogLevel.INFO) {
      console.log(chalk.green(`${this.prefix} ✓`), message, ...args);
    }
  }

  warn(message: string, ...args: any[]): void {
    if (this.logLevel <= LogLevel.WARN) {
      console.warn(chalk.yellow(`${this.prefix} [WARN]`), message, ...args);
    }
  }

  error(message: string, ...args: any[]): void {
    if (this.logLevel <= LogLevel.ERROR) {
      console.error(chalk.red(`${this.prefix} [ERROR]`), message, ...args);
    }
  }

  table(data: any): void {
    if (this.logLevel <= LogLevel.INFO) {
      console.table(data);
    }
  }

  group(label: string): void {
    if (this.logLevel <= LogLevel.INFO) {
      console.group(chalk.cyan(`${this.prefix} ${label}`));
    }
  }

  groupEnd(): void {
    if (this.logLevel <= LogLevel.INFO) {
      console.groupEnd();
    }
  }

  time(label: string): void {
    if (this.logLevel <= LogLevel.DEBUG) {
      console.time(`${this.prefix} ${label}`);
    }
  }

  timeEnd(label: string): void {
    if (this.logLevel <= LogLevel.DEBUG) {
      console.timeEnd(`${this.prefix} ${label}`);
    }
  }
}

export const logger = Logger.getInstance();
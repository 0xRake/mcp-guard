/**
 * Core type definitions for MCP-Guard
 * Following OAuth 2.1 and latest MCP security specifications
 */

// Severity levels based on CVSS 3.1
export enum Severity {
  CRITICAL = 'CRITICAL', // 9.0-10.0
  HIGH = 'HIGH',         // 7.0-8.9
  MEDIUM = 'MEDIUM',     // 4.0-6.9
  LOW = 'LOW',           // 0.1-3.9
  INFO = 'INFO'          // 0.0
}

// Vulnerability categories based on OWASP and MCP-specific threats
export enum VulnerabilityType {
  // Authentication & Authorization
  EXPOSED_API_KEY = 'EXPOSED_API_KEY',
  MISSING_AUTHENTICATION = 'MISSING_AUTHENTICATION',
  WEAK_AUTHENTICATION = 'WEAK_AUTHENTICATION',
  OAUTH_TOKEN_LEAKAGE = 'OAUTH_TOKEN_LEAKAGE',
  INVALID_JWT_CONFIGURATION = 'INVALID_JWT_CONFIGURATION',
  
  // Injection Attacks
  COMMAND_INJECTION = 'COMMAND_INJECTION',
  PROMPT_INJECTION = 'PROMPT_INJECTION',
  SQL_INJECTION = 'SQL_INJECTION',
  PATH_TRAVERSAL = 'PATH_TRAVERSAL',
  
  // MCP-Specific
  TOOL_POISONING = 'TOOL_POISONING',
  ANSI_ESCAPE_SEQUENCE = 'ANSI_ESCAPE_SEQUENCE',
  CONFUSED_DEPUTY = 'CONFUSED_DEPUTY',
  CROSS_SERVER_CONTAMINATION = 'CROSS_SERVER_CONTAMINATION',
  
  // Data Security
  DATA_EXFILTRATION = 'DATA_EXFILTRATION',
  SSRF = 'SSRF',
  UNENCRYPTED_STORAGE = 'UNENCRYPTED_STORAGE',
  INSECURE_TRANSMISSION = 'INSECURE_TRANSMISSION',
  
  // Configuration
  MISCONFIGURATION = 'MISCONFIGURATION',
  EXCESSIVE_PERMISSIONS = 'EXCESSIVE_PERMISSIONS',
  MISSING_RATE_LIMITING = 'MISSING_RATE_LIMITING',
  CORS_MISCONFIGURATION = 'CORS_MISCONFIGURATION',
  
  // Compliance
  GDPR_VIOLATION = 'GDPR_VIOLATION',
  SOC2_VIOLATION = 'SOC2_VIOLATION',
  COMPLIANCE_VIOLATION = 'COMPLIANCE_VIOLATION',
  HIPAA_VIOLATION = 'HIPAA_VIOLATION',
  
  // Multi-tenancy
  TENANT_ISOLATION_FAILURE = 'TENANT_ISOLATION_FAILURE',
  RESOURCE_SHARING_VIOLATION = 'RESOURCE_SHARING_VIOLATION'
}

// MCP Server configuration structure
export interface MCPServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  auth?: AuthConfig;
  oauth?: OAuthConfig;
  capabilities?: ServerCapabilities;
  metadata?: ServerMetadata;
}

// OAuth 2.1 compliant configuration
export interface OAuthConfig {
  authorizationServer: string;
  clientId?: string;
  scopes?: string[];
  pkce?: boolean;
  metadata?: OAuthMetadata;
}

export interface OAuthMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri?: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
}

export interface AuthConfig {
  type: 'bearer' | 'basic' | 'apikey' | 'custom';
  token?: string;
  credentials?: {
    username: string;
    password: string;
  };
}

export interface ServerCapabilities {
  tools?: boolean;
  resources?: boolean;
  prompts?: boolean;
  sampling?: boolean;
}

export interface ServerMetadata {
  name?: string;
  version?: string;
  description?: string;
  homepage?: string;
  author?: string;
}

// Claude Desktop configuration
export interface ClaudeDesktopConfig {
  mcpServers: Record<string, MCPServerConfig>;
  globalSettings?: {
    debug?: boolean;
    timeout?: number;
    maxRetries?: number;
  };
}

// Vulnerability detection result
export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  score: number; // CVSS score 0-10
  server: string;
  title: string;
  description: string;
  details?: Record<string, any>;
  location?: {
    file?: string;
    line?: number;
    column?: number;
    path?: string;
  };
  evidence?: {
    code?: string;
    value?: string;
    pattern?: string;
  };
  remediation: {
    description: string;
    automated: boolean;
    commands?: string[];
    documentation?: string;
  };
  references?: string[];
  cwe?: string[]; // Common Weakness Enumeration IDs
  compliance?: {
    gdpr?: boolean;
    soc2?: boolean;
    hipaa?: boolean;
    iso27001?: boolean;
  };
  discoveredAt: Date;
}

// Scan configuration
export interface ScanConfig {
  depth: 'quick' | 'standard' | 'comprehensive' | 'paranoid';
  targets?: string[];
  excludeServers?: string[];
  excludeTypes?: VulnerabilityType[];
  includeCompliance?: boolean;
  autoFix?: boolean;
  outputFormat?: 'json' | 'sarif' | 'pdf' | 'markdown' | 'html';
  silent?: boolean;
  parallel?: boolean;
  timeout?: number;
  oauth?: {
    validate?: boolean;
    discoveryUrl?: string;
  };
}

// Scan result
export interface ScanResult {
  id: string;
  timestamp: Date;
  duration: number; // milliseconds
  config: ScanConfig;
  summary: {
    score: number; // 0-100
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
    serversScanned: number;
    vulnerabilitiesFound: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  vulnerabilities: Vulnerability[];
  metadata: {
    scanner: string;
    version: string;
    signatures: string;
    rules: number;
  };
  recommendations: string[];
  compliance?: ComplianceReport;
}

// Compliance report
export interface ComplianceReport {
  frameworks: {
    gdpr?: ComplianceStatus;
    soc2?: ComplianceStatus;
    hipaa?: ComplianceStatus;
    iso27001?: ComplianceStatus;
  };
  overallCompliance: number; // percentage
  gaps: ComplianceGap[];
  recommendations: string[];
}

export interface ComplianceStatus {
  compliant: boolean;
  score: number; // 0-100
  controls: {
    passed: number;
    failed: number;
    notApplicable: number;
  };
  findings: string[];
}

export interface ComplianceGap {
  framework: string;
  control: string;
  description: string;
  severity: Severity;
  remediation: string;
}

// Scanner interface
export interface Scanner {
  name: string;
  description: string;
  version: string;
  enabled: boolean;
  scan(config: MCPServerConfig, options?: ScanConfig): Promise<Vulnerability[]>;
  canAutoFix?: boolean;
  autoFix?(vulnerability: Vulnerability): Promise<boolean>;
}

// Security badge
export interface SecurityBadge {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  color: string;
  svg: string;
  url: string;
  timestamp: Date;
}

// Monitoring event
export interface MonitoringEvent {
  id: string;
  timestamp: Date;
  server: string;
  tool?: string;
  action: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details?: Record<string, any>;
  blocked?: boolean;
  user?: string;
  sessionId?: string;
}

// Real-time protection policy
export interface ProtectionPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rules: PolicyRule[];
  actions: PolicyAction[];
  priority: number;
}

export interface PolicyRule {
  type: 'allow' | 'deny' | 'monitor';
  condition: {
    server?: string;
    tool?: string;
    pattern?: RegExp;
    severity?: Severity;
  };
}

export interface PolicyAction {
  type: 'block' | 'alert' | 'log' | 'sandbox' | 'prompt';
  notification?: {
    email?: string;
    slack?: string;
    webhook?: string;
  };
}

// API response types
export interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  metadata?: {
    timestamp: Date;
    requestId: string;
    version: string;
  };
}

export interface PaginatedResponse<T> extends APIResponse<T[]> {
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

// Export utility type guards
export const isCritical = (severity: Severity): boolean => 
  severity === Severity.CRITICAL;

export const isHighOrCritical = (severity: Severity): boolean =>
  severity === Severity.CRITICAL || severity === Severity.HIGH;

export const requiresHumanInLoop = (type: VulnerabilityType): boolean => {
  const dangerous = [
    VulnerabilityType.COMMAND_INJECTION,
    VulnerabilityType.DATA_EXFILTRATION,
    VulnerabilityType.TOOL_POISONING,
    VulnerabilityType.SQL_INJECTION
  ];
  return dangerous.includes(type);
};

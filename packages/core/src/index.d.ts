declare module '@mcp-guard/core' {
  export interface MCPServerConfig {
    name?: string;
    version?: string;
    description?: string;
    command?: string;
    args?: string[];
    env?: Record<string, string>;
    tools?: Tool[];
    prompts?: Prompt[];
    resources?: Resource[];
    oauth?: OAuthConfig;
    auth?: AuthConfig;
    metadata?: {
      name?: string;
      [key: string]: any;
    };
    [key: string]: any;
  }

  export interface Tool {
    name: string;
    description?: string;
    parameters?: any;
    inputSchema?: any;
  }

  export interface Prompt {
    name: string;
    template?: string;
    description?: string;
  }

  export interface Resource {
    uri: string;
    sensitive?: boolean;
    description?: string;
  }

  export interface OAuthConfig {
    clientId?: string;
    clientSecret?: string;
    scopes?: string[];
    pkce?: boolean;
  }

  export interface AuthConfig {
    type?: string;
    token?: string;
  }

  export interface Vulnerability {
    id: string;
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    title: string;
    description: string;
    server: string;
    remediation?: {
      steps: string[];
      automated: boolean;
    };
  }

  export interface ScanResult {
    summary: {
      score: number;
      grade: string;
      serversScanned: number;
      vulnerabilitiesFound: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    vulnerabilities: Vulnerability[];
    recommendations: string[];
  }

  export interface ScanConfig {
    depth?: 'quick' | 'standard' | 'comprehensive';
    excludeTypes?: string[];
    includeCompliance?: boolean;
    autoFix?: boolean;
  }

  export class MCPGuard {
    constructor();
    scan(servers: Record<string, MCPServerConfig>, config?: ScanConfig): Promise<ScanResult>;
    quickScan(servers: Record<string, MCPServerConfig>): Promise<ScanResult>;
    comprehensiveScan(servers: Record<string, MCPServerConfig>): Promise<ScanResult>;
  }

  export default MCPGuard;
}
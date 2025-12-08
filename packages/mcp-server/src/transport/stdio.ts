import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { RequestHandlerOptions } from '@modelcontextprotocol/sdk/types.js';

export class MCPStdioTransport {
  private transport: StdioServerTransport;
  private server: Server;

  constructor(server: Server) {
    this.server = server;
    this.transport = new StdioServerTransport();
  }

  async start(): Promise<void> {
    // Set up error handling
    this.transport.onError = (error) => {
      console.error('[Transport Error]:', error);
    };

    // Connect the server to the transport
    await this.server.connect(this.transport);
    
    console.error('MCP-Guard server started on stdio transport');
  }

  async stop(): Promise<void> {
    await this.server.close();
    console.error('MCP-Guard server stopped');
  }
}

export function createStdioTransport(server: Server): MCPStdioTransport {
  return new MCPStdioTransport(server);
}
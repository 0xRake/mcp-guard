#!/bin/bash

# MCP-Guard Installation Script for Claude Desktop
# This script installs the MCP-Guard server for use with Claude Desktop

set -e

echo "🛡️ MCP-Guard Installation Script"
echo "================================"
echo ""

# Check if Claude Desktop config directory exists
CLAUDE_CONFIG_DIR="$HOME/Library/Application Support/Claude"
if [ ! -d "$CLAUDE_CONFIG_DIR" ]; then
    echo "❌ Claude Desktop configuration directory not found."
    echo "Please ensure Claude Desktop is installed."
    exit 1
fi

# Get the absolute path of the current directory
MCP_SERVER_PATH="$(cd "$(dirname "$0")" && pwd)"

echo "📍 MCP Server Path: $MCP_SERVER_PATH"
echo ""

# Check if the server is built
if [ ! -f "$MCP_SERVER_PATH/dist/server.js" ]; then
    echo "⚠️ Server not built. Building now..."
    npm run build
fi

# Create or update Claude Desktop config
CLAUDE_CONFIG_FILE="$CLAUDE_CONFIG_DIR/claude_desktop_config.json"

echo "📝 Updating Claude Desktop configuration..."

# Check if config file exists
if [ -f "$CLAUDE_CONFIG_FILE" ]; then
    echo "Found existing configuration. Creating backup..."
    cp "$CLAUDE_CONFIG_FILE" "$CLAUDE_CONFIG_FILE.backup"
fi

# Create the configuration
cat > "$CLAUDE_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "mcp-guard": {
      "command": "node",
      "args": [
        "$MCP_SERVER_PATH/dist/server.js"
      ],
      "env": {
        "NODE_ENV": "production",
        "MCP_GUARD_LOG_LEVEL": "info"
      }
    }
  }
}
EOF

echo "✅ Configuration updated successfully!"
echo ""
echo "📋 Next Steps:"
echo "1. Restart Claude Desktop"
echo "2. Look for 'mcp-guard' in the available tools"
echo "3. Use the following tools:"
echo "   - scan_config: Scan configurations for vulnerabilities"
echo "   - check_vulnerabilities: Check specific vulnerability types"
echo "   - monitor_traffic: Monitor real-time traffic"
echo "   - generate_report: Generate security reports"
echo ""
echo "🎉 Installation complete!"
#!/bin/bash

# MCP-Guard Project Export Script
# This script packages everything needed for Claude Project

echo "📦 Packaging MCP-Guard for Claude Project..."

# Create export directory
EXPORT_DIR="mcp-guard-claude-project"
mkdir -p $EXPORT_DIR

# Copy key files
echo "📄 Copying project files..."
cp PROJECT_KNOWLEDGE.md $EXPORT_DIR/
cp CODE_ARCHIVE.md $EXPORT_DIR/
cp -r .mcp-guard-build $EXPORT_DIR/
cp package.json $EXPORT_DIR/
cp tsconfig.json $EXPORT_DIR/
cp turbo.json $EXPORT_DIR/
cp pnpm-workspace.yaml $EXPORT_DIR/

# Copy source code
echo "📁 Copying source code..."
mkdir -p $EXPORT_DIR/packages/core/src/types
cp -r packages/core/src/types/* $EXPORT_DIR/packages/core/src/types/
cp packages/core/package.json $EXPORT_DIR/packages/core/

# Create instructions file
cat > $EXPORT_DIR/CLAUDE_PROJECT_SETUP.md << 'EOF'
# Claude Project Setup Instructions

## 1. Create New Claude Project
- Name: "MCP-Guard Development"
- Description: "Enterprise security scanner for MCP servers"

## 2. Upload These Files as Project Knowledge
- PROJECT_KNOWLEDGE.md (Main documentation)
- CODE_ARCHIVE.md (All implemented code)
- .mcp-guard-build/build-memory.json (Current state)

## 3. Set Project Custom Instructions
```
You are developing MCP-Guard, an enterprise-grade security scanner for Model Context Protocol servers.

Key Information:
- Repository: /Users/rake/Developer/GitHub/mcp-guard
- Language: TypeScript (strict mode)
- Architecture: Monorepo with pnpm
- Current Phase: Core package implementation

When continuing development:
1. Check build-memory.json for current status
2. Reference PROJECT_KNOWLEDGE.md for specifications
3. Use CODE_ARCHIVE.md for existing code patterns
4. Update progress after each implementation
5. Follow OAuth 2.1 and MCP security best practices

Priority: Ship MVP first, enhance iteratively
```

## 4. Quick Start Commands

### First Message in New Chat
"Check MCP-Guard status and continue from current step"

### Continue Specific Tasks
- "Implement the next scanner from the list"
- "Build the CLI package"
- "Create the MCP server"
- "Set up the web dashboard"

## 5. Key Files to Reference

- **PROJECT_KNOWLEDGE.md**: Complete specifications and plan
- **CODE_ARCHIVE.md**: All implemented code
- **build-memory.json**: Current build state
- **types/index.ts**: TypeScript definitions

## 6. Development Workflow

1. Start each session by checking status
2. Implement one component at a time
3. Save progress to memory system
4. Test before moving to next component
5. Update documentation as you go

## Remember

- MVP First: 3 scanners, basic CLI, simple MCP server
- OAuth 2.1: Full compliance required
- Security: Follow MCP security best practices
- Testing: Each component needs tests
- Documentation: Keep README updated

Good luck with the build! 🚀
EOF

# Create zip archive
echo "🗜️ Creating archive..."
zip -r mcp-guard-project.zip $EXPORT_DIR

echo "✅ Export complete!"
echo ""
echo "📋 Next Steps:"
echo "1. Upload mcp-guard-project.zip to Claude"
echo "2. Extract and upload individual files to Project Knowledge"
echo "3. Follow instructions in CLAUDE_PROJECT_SETUP.md"
echo ""
echo "Files created:"
echo "  - $EXPORT_DIR/ (directory with all files)"
echo "  - mcp-guard-project.zip (compressed archive)"

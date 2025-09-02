{
  `path`: `/Users/rake/Developer/GitHub/mcp-guard/test-everything.sh`,
  `content`: `#!/bin/bash

# MCP-Guard Complete Test Script
# This script tests all components built from Claude
# Usage: ./test-everything.sh

set -e  # Exit on error

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
CYAN='\\033[0;36m'
NC='\\033[0m' # No Color
BOLD='\\033[1m'

# Counters
PASSED=0
FAILED=0
TOTAL=0

# Print header
echo -e \"${CYAN}${BOLD}\"
echo \"╔═══════════════════════════════════════════════════════════╗\"
echo \"║                                                           ║\"
echo \"║     🔐 MCP-Guard Complete Test Suite                      ║\"
echo \"║     Testing all 4 scanners and components                ║\"
echo \"║                                                           ║\"
echo \"╚═══════════════════════════════════════════════════════════╝\"
echo -e \"${NC}\
\"

# Function to print section headers
section() {
    echo -e \"\
${YELLOW}${BOLD}============================================================\"
    echo -e \"  $1\"
    echo -e \"============================================================${NC}\
\"
}

# Function to check if file exists
check_file() {
    TOTAL=$((TOTAL + 1))
    if [ -f \"$1\" ]; then
        echo -e \"${GREEN}  ✅ $2${NC}\"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e \"${RED}  ❌ $2 (missing: $1)${NC}\"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# Function to check if directory exists
check_dir() {
    TOTAL=$((TOTAL + 1))
    if [ -d \"$1\" ]; then
        echo -e \"${GREEN}  ✅ $2${NC}\"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e \"${RED}  ❌ $2 (missing: $1)${NC}\"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# Function to run command and check result
run_command() {
    TOTAL=$((TOTAL + 1))
    echo -e \"${BLUE}  ℹ️  Running: $1${NC}\"
    if eval \"$1\" > /tmp/mcp-test-output.txt 2>&1; then
        echo -e \"${GREEN}  ✅ $2${NC}\"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e \"${RED}  ❌ $2${NC}\"
        echo -e \"${RED}     Error: $(head -n 1 /tmp/mcp-test-output.txt)${NC}\"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# Save current directory
PROJECT_ROOT=$(pwd)
CORE_PACKAGE=\"$PROJECT_ROOT/packages/core\"

# 1. PROJECT STRUCTURE VALIDATION
section \"1. PROJECT STRUCTURE VALIDATION\"

check_file \"package.json\" \"Root package.json\"
check_file \"pnpm-workspace.yaml\" \"PNPM workspace config\"
check_file \"turbo.json\" \"Turbo configuration\"
check_file \"tsconfig.json\" \"TypeScript config\"
check_dir \".mcp-guard-build\" \"Build memory directory\"
check_file \".mcp-guard-build/build-memory.json\" \"Build memory file\"
check_dir \"packages\" \"Packages directory\"
check_dir \"packages/core\" \"Core package\"
check_dir \"packages/cli\" \"CLI package directory\"
check_dir \"packages/mcp-server\" \"MCP server directory\"

# 2. CORE PACKAGE STRUCTURE
section \"2. CORE PACKAGE STRUCTURE\"

check_file \"packages/core/package.json\" \"Core package.json\"
check_file \"packages/core/tsup.config.ts\" \"Build configuration\"
check_file \"packages/core/vitest.config.ts\" \"Test configuration\"
check_file \"packages/core/README.md\" \"Core documentation\"
check_dir \"packages/core/src\" \"Source directory\"
check_dir \"packages/core/test\" \"Test directory\"
check_dir \"packages/core/examples\" \"Examples directory\"

# 3. SCANNER IMPLEMENTATIONS
section \"3. SCANNER IMPLEMENTATIONS\"

check_file \"packages/core/src/index.ts\" \"Core entry point\"
check_file \"packages/core/src/types/index.ts\" \"Type definitions\"
check_file \"packages/core/src/scanners/api-keys.ts\" \"API Key Scanner\"
check_file \"packages/core/src/scanners/authentication.ts\" \"Authentication Scanner\"
check_file \"packages/core/src/scanners/command-injection.ts\" \"Command Injection Scanner\"
check_file \"packages/core/src/scanners/tool-poisoning.ts\" \"Tool Poisoning Scanner\"

# Count lines of code for each scanner
if [ -f \"packages/core/src/scanners/api-keys.ts\" ]; then
    LINES=$(wc -l < \"packages/core/src/scanners/api-keys.ts\")
    echo -e \"${CYAN}    └─ API Keys Scanner: $LINES lines${NC}\"
fi
if [ -f \"packages/core/src/scanners/authentication.ts\" ]; then
    LINES=$(wc -l < \"packages/core/src/scanners/authentication.ts\")
    echo -e \"${CYAN}    └─ Authentication Scanner: $LINES lines${NC}\"
fi
if [ -f \"packages/core/src/scanners/command-injection.ts\" ]; then
    LINES=$(wc -l < \"packages/core/src/scanners/command-injection.ts\")
    echo -e \"${CYAN}    └─ Command Injection Scanner: $LINES lines${NC}\"
fi
if [ -f \"packages/core/src/scanners/tool-poisoning.ts\" ]; then
    LINES=$(wc -l < \"packages/core/src/scanners/tool-poisoning.ts\")
    echo -e \"${CYAN}    └─ Tool Poisoning Scanner: $LINES lines${NC}\"
fi

# 4. TEST FILES
section \"4. TEST FILES\"

check_file \"packages/core/test/api-keys.test.ts\" \"API Keys tests\"
check_file \"packages/core/test/authentication.test.ts\" \"Authentication tests\"
check_file \"packages/core/test/command-injection.test.ts\" \"Command Injection tests\"
check_file \"packages/core/test/tool-poisoning.test.ts\" \"Tool Poisoning tests\"

# Count test cases
TOTAL_TEST_CASES=0
for test_file in packages/core/test/*.test.ts; do
    if [ -f \"$test_file\" ]; then
        COUNT=$(grep -c \"it(\" \"$test_file\" || true)
        TOTAL_TEST_CASES=$((TOTAL_TEST_CASES + COUNT))
        echo -e \"${CYAN}    └─ $(basename $test_file): $COUNT test cases${NC}\"
    fi
done
echo -e \"${BOLD}  Total test cases: $TOTAL_TEST_CASES${NC}\"

# 5. DEMO SCRIPTS
section \"5. DEMO SCRIPTS\"

check_file \"packages/core/examples/scan-demo.ts\" \"Basic scan demo\"
check_file \"packages/core/examples/complete-demo.ts\" \"Complete demo\"
check_file \"packages/core/examples/all-scanners-demo.ts\" \"All scanners demo\"

# 6. DOCUMENTATION
section \"6. DOCUMENTATION\"

check_file \"PROJECT_KNOWLEDGE.md\" \"Project knowledge base\"
check_file \"CODE_ARCHIVE.md\" \"Code archive\"
check_file \"packages/core/README.md\" \"Core README\"

# 7. DEPENDENCIES AND BUILD
section \"7. DEPENDENCIES AND BUILD\"

cd \"$CORE_PACKAGE\"

# Check if node_modules exists, if not install
if [ ! -d \"node_modules\" ]; then
    echo -e \"${YELLOW}  ⚠️  Dependencies not installed. Installing...${NC}\"
    if command -v pnpm &> /dev/null; then
        run_command \"pnpm install --no-frozen-lockfile\" \"Dependencies installed (pnpm)\"
    elif command -v npm &> /dev/null; then
        run_command \"npm install\" \"Dependencies installed (npm)\"
    else
        echo -e \"${RED}  ❌ No package manager found (pnpm or npm)${NC}\"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e \"${GREEN}  ✅ Dependencies already installed${NC}\"
    PASSED=$((PASSED + 1))
fi

# Try to build
if command -v pnpm &> /dev/null; then
    run_command \"pnpm build\" \"Build successful\"
elif command -v npm &> /dev/null; then
    run_command \"npm run build\" \"Build successful\"
fi

# Check if dist directory was created
check_dir \"dist\" \"Build output created\"

# 8. RUN TESTS
section \"8. RUNNING TESTS\"

if command -v pnpm &> /dev/null; then
    run_command \"pnpm test --run\" \"All tests executed\"
elif command -v npm &> /dev/null; then
    run_command \"npm test\" \"All tests executed\"
fi

cd \"$PROJECT_ROOT\"

# 9. BUILD MEMORY VALIDATION
section \"9. BUILD MEMORY VALIDATION\"

if [ -f \".mcp-guard-build/build-memory.json\" ]; then
    # Extract key information from build memory
    SCANNERS_COUNT=$(grep -o '\"name\":' .mcp-guard-build/build-memory.json | wc -l)
    CURRENT_PHASE=$(grep '\"currentPhase\":' .mcp-guard-build/build-memory.json | head -1 | cut -d'\"' -f4)
    
    echo -e \"${GREEN}  ✅ Build memory valid${NC}\"
    echo -e \"${CYAN}    └─ Current phase: $CURRENT_PHASE${NC}\"
    echo -e \"${CYAN}    └─ Scanners recorded: ~$SCANNERS_COUNT${NC}\"
    PASSED=$((PASSED + 1))
else
    echo -e \"${RED}  ❌ Build memory missing${NC}\"
    FAILED=$((FAILED + 1))
fi

# 10. FINAL SUMMARY
section \"TEST SUMMARY\"

PERCENTAGE=$((PASSED * 100 / TOTAL))

echo -e \"${BOLD}\
📊 Results:${NC}\"
echo -e \"${GREEN}  ✅ Passed: $PASSED${NC}\"
echo -e \"${RED}  ❌ Failed: $FAILED${NC}\"
echo -e \"${BOLD}  📈 Success Rate: $PERCENTAGE%${NC}\"

# Determine grade
if [ $PERCENTAGE -ge 95 ]; then
    GRADE=\"${GREEN}A - Production Ready! 🎉${NC}\"
elif [ $PERCENTAGE -ge 85 ]; then
    GRADE=\"${GREEN}B - Nearly Complete${NC}\"
elif [ $PERCENTAGE -ge 75 ]; then
    GRADE=\"${YELLOW}C - Functional${NC}\"
elif [ $PERCENTAGE -ge 60 ]; then
    GRADE=\"${YELLOW}D - Needs Work${NC}\"
else
    GRADE=\"${RED}F - Major Issues${NC}\"
fi

echo -e \"${BOLD}\
🎯 Build Grade: $GRADE${NC}\"

# Next steps
echo -e \"\
${CYAN}${BOLD}📝 Next Steps:${NC}\"
if [ $FAILED -eq 0 ]; then
    echo -e \"${CYAN}  1. All tests passed! Ready for CLI development${NC}\"
    echo -e \"${CYAN}  2. Run: cd packages/core && npm publish --access public${NC}\"
    echo -e \"${CYAN}  3. Build CLI: Create packages/cli/src/index.ts${NC}\"
else
    echo -e \"${CYAN}  1. Fix the $FAILED failed tests${NC}\"
    echo -e \"${CYAN}  2. Run this script again: ./test-everything.sh${NC}\"
    echo -e \"${CYAN}  3. Continue with development${NC}\"
fi

echo -e \"\
${CYAN}${BOLD}💡 To continue in Claude Code:${NC}\"
echo -e \"${CYAN}  claude-code --include \\\".mcp-guard-build\\\" --include \\\"packages/core\\\"${NC}\"
echo -e \"${CYAN}  Then say: \\\"Continue MCP-Guard from build-memory.json\\\"${NC}\
\"

# Clean up temp file
rm -f /tmp/mcp-test-output.txt

# Exit with appropriate code
if [ $FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi
`
}

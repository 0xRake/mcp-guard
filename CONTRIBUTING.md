# Contributing to MCP-Guard

## Getting Started

```bash
git clone https://github.com/0xRake/mcp-guard.git
cd mcp-guard
pnpm install
pnpm build
pnpm test
```

Requires Node.js >= 20 and pnpm >= 8.

## Project Structure

```
packages/
  core/        Scanning engine and security domains
  cli/         Command-line interface
  api/         Fastify REST API
  mcp-server/  MCP protocol server
  web/         Next.js dashboard
```

## Development Workflow

1. Create a branch from `main`: `git checkout -b feat/your-feature`
2. Make your changes
3. Run `pnpm build && pnpm test && pnpm lint` to verify
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation only
   - `test:` adding or updating tests
   - `chore:` maintenance tasks
5. Push and open a pull request against `main`

## Pull Requests

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation if behavior changes
- All CI checks must pass before merge

## Adding a Security Scanner

MCP-Guard uses a domain-based scanner architecture. To add a new vulnerability check:

1. Identify which domain it belongs to (see `packages/core/src/domains/`)
2. Add detection logic within the appropriate domain scanner
3. Add test cases in `packages/core/tests/`
4. Run the full test suite: `pnpm test`

If the check doesn't fit an existing domain, open an issue to discuss before creating a new one.

## Testing

- Framework: [Vitest](https://vitest.dev/)
- Run all tests: `pnpm test`
- Run a specific package: `pnpm --filter @mcp-guard/core test`
- Watch mode: `pnpm --filter @mcp-guard/core test:watch`

Tests should verify behavior, not implementation details. Test what the scanner detects, not how it detects it.

## Code Style

- TypeScript strict mode is enforced
- ESLint and Prettier run on commit via pre-commit hooks
- No `any` types without justification
- No `console.log` in library code — use the Logger interface

## Reporting Issues

Use [GitHub Issues](https://github.com/0xRake/mcp-guard/issues) with the provided templates. For security vulnerabilities, see [SECURITY.md](SECURITY.md).

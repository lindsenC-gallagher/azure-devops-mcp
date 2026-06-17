# Repository guidance for Claude Code

## CI gate — run before pushing to origin

CI (`.github/workflows`, "Build MCP Server") will **fail the push** if any of the
checks below fail. Before pushing changes to `origin`, run them locally and make
sure they all pass — fix any failures rather than pushing and waiting for CI:

```bash
npm run build          # tsc compile + chmod
npm run validate-tools # tsc --noEmit + tool-name/param validation
npm test               # jest (all suites must pass)
npm run eslint         # lint — fails on any error
npm run format-check   # prettier --check
```

One-liner to gate a push:

```bash
npm run build && npm run validate-tools && npm test && npm run eslint && npm run format-check
```

Notes:

- `npm run eslint` is strict — e.g. `@typescript-eslint/no-non-null-assertion`
  is an **error**, including in test files. Avoid `!` non-null assertions; prefer
  typing the value so the assertion isn't needed.
- Auto-fix where possible: `npm run eslint-fix` and `npm run format` (`prettier --write .`).
- Per the global rule: ship matching spec/test updates in the same change as the code.

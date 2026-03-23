# Contributing to @svrnsec/pulse

Thank you for your interest in contributing.  This document covers how to get
started, the coding standards we follow, and how to submit a pull request.

---

## Table of Contents

1. [Project Philosophy](#project-philosophy)
2. [Development Setup](#development-setup)
3. [Project Structure](#project-structure)
4. [Making Changes](#making-changes)
5. [Testing](#testing)
6. [Pull Request Guidelines](#pull-request-guidelines)
7. [Reporting Bugs](#reporting-bugs)
8. [Security Issues](#security-issues)

---

## Project Philosophy

`@svrnsec/pulse` is built on one principle: **hardware physics cannot lie**.

Every contribution should preserve these invariants:

1. **No database of bad actors** — detection is physics-based (thermal jitter, DRAM
   refresh, OS scheduler quanta), not signature matching.
2. **Local-first, sovereign** — the library runs entirely in the user's browser/server.
   Zero data is sent to third-party APIs.  No phone-home.
3. **Minimal data surface** — raw timing arrays never leave the device.  Only
   statistical summaries travel over the wire.
4. **No runtime dependencies beyond `@noble/hashes`** — every byte added to the
   browser bundle must be justified.

---

## Development Setup

### Prerequisites

| Tool       | Version  |
|------------|----------|
| Node.js    | ≥ 18     |
| npm        | ≥ 9      |
| Rust       | ≥ 1.76 (for WASM changes only) |
| wasm-pack  | ≥ 0.12   (for WASM changes only) |

### Install

```bash
git clone https://github.com/ayronny14-alt/Svrn-Pulse-Secturity.git
cd Svrn-Pulse-Secturity
npm install
cd server && npm install && cd ..
```

### Build

```bash
# JavaScript bundle only (no Rust required)
npm run build:js

# Full build including WASM (requires Rust + wasm-pack)
npm run build
```

### Run the demo

```bash
# Node.js demo
npm run demo

# Browser demo — just open demo/web/index.html in any browser
```

### Run the API server

```bash
cp server/.env.example server/.env   # fill in your values
node server/index.js
```

---

## Project Structure

```
sovereign-pulse/
├── src/
│   ├── index.js              # Public API — pulse(), _runProbe()
│   ├── fingerprint.js        # Fingerprint.collect() + ProofPayload builder
│   ├── collector/
│   │   ├── entropy.js        # WASM timing probe orchestration
│   │   ├── adaptive.js       # Adaptive early-exit probe
│   │   ├── bio.js            # Biometric (mouse/keyboard) collector
│   │   └── canvas.js         # WebGL renderer fingerprint
│   ├── heuristics/           # Physics-law coherence checkers (EJR, Hurst, etc.)
│   ├── proof/
│   │   ├── fingerprint.js    # canonicalJson, ProofPayload types
│   │   └── validator.js      # Server-side proof validator (NODE ONLY)
│   ├── registry/             # VM classification registry + serializer
│   ├── middleware/           # Express + Next.js middleware helpers
│   └── integrations/
│       └── react.js          # usePulse() React hook
├── crates/                   # Rust source for WASM probe
├── server/                   # Self-hosted Express API (optional)
├── demo/                     # Demo scripts
├── .github/workflows/        # CI + npm publish
└── index.d.ts                # TypeScript declarations
```

---

## Making Changes

### Branches

| Branch | Purpose |
|--------|---------|
| `main` | Stable, released code |
| `dev`  | Integration branch — PRs target here |
| `feat/*` | New features |
| `fix/*`  | Bug fixes |
| `docs/*` | Documentation only |

### Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(heuristics): add spectral flatness check for audio entropy
fix(validator): reject payloads with prototype pollution keys
docs(readme): clarify EJR threshold derivation
perf(adaptive): reduce batch evaluation from 50→25 iterations
```

Types: `feat`, `fix`, `docs`, `perf`, `refactor`, `test`, `chore`

---

## Testing

```bash
npm test                    # run all tests
npm test -- --testPathPattern=validator   # specific file
```

When adding a feature, include tests that cover:
- The happy path (real hardware simulation)
- VM / datacenter simulation
- Edge cases (missing fields, extreme values)

For the validator specifically, add test cases for:
- Valid proofs that should pass
- Tampered hashes (should return `HASH_MISMATCH_PAYLOAD_TAMPERED`)
- Missing required fields
- Prototype pollution attempts

---

## Pull Request Guidelines

1. **Fork** the repo and create a branch from `dev`
2. **Make your changes** — keep them focused and atomic
3. **Write or update tests** — PRs without tests for new logic may be delayed
4. **Run `npm test`** and ensure all tests pass
5. **Open a PR against `dev`** with a clear description:
   - What problem does this solve?
   - How does it solve it?
   - Are there any trade-offs or caveats?

### PR Checklist

- [ ] Tests pass locally (`npm test`)
- [ ] No new runtime dependencies added without discussion
- [ ] Bundle size impact considered for browser-facing changes
- [ ] `index.d.ts` updated if public API changed
- [ ] `CHANGELOG` or PR description explains the change
- [ ] Physics invariants preserved (detection remains database-free)

---

## Reporting Bugs

Open a [GitHub Issue](https://github.com/ayronny14-alt/Svrn-Pulse-Secturity/issues) with:

- **Environment**: OS, browser, Node.js version
- **Reproduction steps**: minimal code that demonstrates the bug
- **Expected behavior** vs **actual behavior**
- **Logs or error messages** if applicable

---

## Security Issues

**Do not open public issues for security vulnerabilities.**

See [SECURITY.md](./SECURITY.md) for the responsible disclosure process.

---

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](./LICENSE).

# Changelog

All notable changes to `@svrnsec/pulse` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-03-28

Comprehensive security audit and hardening release. **56 findings fixed** across
the entire codebase. All integrators should upgrade.

### Security

- **Timing-safe API key lookup** using `crypto.timingSafeEqual` to prevent
  timing side-channel attacks on authentication
- **Timing-safe BLAKE3 hash comparison** in the proof validator
- **Timing-safe engagement token verification** using synchronous
  `timingSafeEqual` with XOR fallback for environments without native crypto
- **SSRF prevention**: webhook URLs are now validated against private/reserved
  IP ranges before dispatch
- **Nonce store isolation**: nonce Maps are scoped per factory instance,
  preventing cross-tenant nonce leaks in multi-tenant deployments
- **Webhook secret validation at startup**: rejects default/placeholder secrets
  in production environments
- **HMAC secret minimum raised** from 16 to 32 characters (256-bit minimum)
- **Recursive prototype pollution guard** applied to all nested payload objects
  in the validator
- **Server-side jitterScore enforcement**: dynamic threshold now uses
  server-recomputed `jitterScore`, never the client-supplied `finalScore`
- **SharedArrayBuffer per-call allocation** replaces shared singleton to prevent
  cross-request data leakage
- **Next.js nonce store scoped per middleware instance** to prevent cross-request
  nonce collisions
- **Health endpoint stripped of nonce count** to avoid leaking server state
- **Express middleware allowlists response fields** to prevent accidental data
  exposure
- **Usage store validates type allowlist** to reject unexpected metric types
- **`minJitterScore` floor enforced** at 0.55 server-side default

### Changed

- **`decodeToken` renamed to `decodeTokenUnsafe`** with a deprecation wrapper
  on the old name, to clearly communicate that it does not verify signatures
- **Rate limiter uses weighted costs**: challenge endpoints consume 0.5 units
  instead of a full unit
- **CJS build output filename corrected** to `dist/pulse.cjs`
- **`hardwareId` extended to 32 hex characters** (128-bit collision resistance)
- **Graceful shutdown** now exits with code 0
- **Webhook failures logged as structured JSON** for audit trail integration
- **Bessel-corrected variance** in LLM detector for unbiased estimates
- **Deterministic PRNG** for reproducible bootstrap confidence intervals
- **O(n) similarity graph** replaces O(n^2) full-scan in coordinated behavior
  detection
- **PSD peak search skips DC bin** to avoid false frequency matches
- **ANGLE pattern matching tightened** to eliminate false positives on real
  consumer hardware
- **SAB busy-wait capped at 10,000 iterations** to prevent infinite loops

### Fixed

- React integration: `autoRun` moved from render body into `useEffect` to
  prevent side effects during React render phase
- React and React Native integrations: `res.ok` checks added to all fetch calls
- WebGL resources properly deleted after use to prevent GPU memory leaks
- GPU device and buffers destroyed in `finally` blocks
- Bio collector: `_lastKey` capped and `_lastMouse` cleared on `stop()`
- Sensor subscriptions wrapped in `try/finally` for guaranteed cleanup
- `update-notifier` uses `createRequire` for ESM compatibility on Node 18+
- CLI `--generate-secret` flag ordering fixed
- LCG in WASM module seeded from `perf_now()` instead of a fixed constant
- Tests updated for 32-character secret minimum and `decodeTokenUnsafe` rename

### Added

- GPU verdict union type completed in `index.d.ts`
- Engagement token types added to TypeScript declarations

## [0.7.0] - 2026-03-23

### Added

- **Coordinated Inauthentic Behavior detection**: 5-layer analysis including
  temporal clustering, fingerprint collision, crystal oscillator drift
  convergence, mutual information matrix, and entropy velocity tracking
- **Louvain-lite community detection** on pairwise mutual information graphs
  to identify bot farm clusters
- **Refraction calibration module**: timer-adaptive calibration that detects
  `performance.now()` precision clamping and rescales scoring thresholds
  accordingly

### Fixed

- False synthetic detection on real hardware in browsers with Spectre timer
  mitigations
- Event listener leak in idle attestation `stop()` (was leaking anonymous
  closures)
- HMAC body contamination risk in engagement token verify path
- O(n^2) Louvain `communityDegree` replaced with O(1) incremental Map
- `driftRates` returns plain object instead of Map (Map silently becomes `{}`
  under `JSON.stringify`)
- `package.json` main field aligned to `dist/pulse.cjs`

## [0.6.0] - 2026-03-23

### Added

- **Authenticity Audit** (`authenticityAudit()`): statistically rigorous
  estimate of human vs. bot ratio in a user cohort using hardware physics
- Cluster-based analysis combining ENF deviation, DRAM verdict, thermal label,
  and temporal bucketing
- Bootstrap confidence intervals on human-rate estimates
- Stable per-cluster fingerprinting for cross-window farm identification
- Grade system: CLEAN / LOW_FRAUD / MODERATE_FRAUD / HIGH_FRAUD

### Fixed

- Four production bugs: sync DRAM collector wrapped in `Promise.resolve()`,
  `crossOriginIsolated` reference guard for Node.js, CJS require path
  corrected, documentation references updated to `@svrnsec/pulse`

## [0.5.0] - 2026-03-23

### Added

- **Proof-of-Idle attestation**: hash-chained DRAM probe measurements across
  idle windows with Newton cooling curve discrimination
- **Population entropy analysis**: 5-test sybil detection (timestamp rhythm,
  entropy dispersion, thermal diversity, idle plausibility, ENF phase coherence)
- **Engagement tokens**: 30-second TTL HMAC-SHA256 compact tokens with async
  nonce consumption and advisory risk signals
- TrustScore integration for idle attestation results
- 92 adversarial stress tests across 5 attack categories

## [0.4.0] - 2026-03-23

### Added

- **TrustScore engine**: 0-100 composite score with A/B/C/D/F grading and
  per-signal weighted scoring (Physics 40, ENF 20, GPU 15, DRAM 15, Bio 10)
- **HMAC-signed challenge protocol**: `createChallenge()` / `verifyChallenge()`
  with timing-safe verification and replay prevention
- **CLI tool** (`npx svrnsec-pulse`): scan, challenge, and version commands
  with `--json` output support
- **React Native hook** (`usePulseNative()`): accelerometer tremor, gyroscope
  micro-rotation, and touch dwell timing analysis
- Sub-path exports for `./challenge`, `./trust`, `./react-native`

## [0.3.1] - 2026-03-22

### Added

- Full signal integration: ENF, GPU thermal, DRAM refresh, and LLM detectors
  run in parallel and are included in the proof payload
- Update notifier with styled terminal notification
- ANSI-colored probe result card for terminal DX
- Extended TypeScript declarations for all signal types

## [0.3.0] - 2026-03-22

### Added

- **Electrical Network Frequency (ENF) detection**: geographic attestation via
  power grid physics without IP geolocation or permissions
- **WebGPU thermal probe**: compute shader timing variance across cold/load/hot
  phases to detect software renderers
- **DRAM refresh cycle detector**: identifies 7.8ms JEDEC tREFI periodicity
  absent in virtual memory subsystems
- **SharedArrayBuffer microsecond timer**: bypasses browser timer clamping
  (requires `crossOriginIsolated`)
- **LLM agent behavioral fingerprint**: detects AI-driven automation via
  think-time distributions, mouse path smoothness, correction rates, and
  tremor analysis

## [0.2.0] - 2026-03-22

### Added

- Adaptive early exit: VMs detected at 50 iterations (~0.9s, 75% faster)
- Bio-binding: mouse/keyboard interference coefficient collector

### Changed

- Package bumped to v0.2.0 with exports for all new collector modules

## [0.1.1] - 2026-03-22

### Added

- Zero-latency stage-3 coherence analysis with 6 orthogonal checks
- Dynamic threshold scaling based on evidence weight
- Server-side independent threshold recomputation

### Fixed

- QE cliff edge eliminated with partial-credit ramp for borderline entropy
- Physical floor against penalty compounding on legitimate hardware
- Cross-signal forgery detection for physically impossible metric combinations
- Client-controlled `minJitterScore` clamped server-side (floor 0.50)
- EJR/QE phase trajectory contradiction is now a hard kill in stage 2
- Early verdict threshold tightened from 0.60 to 0.70

### Security

- Expanded datacenter GPU blocklist (H200, B100, B200, GH200, MI-series,
  Inferentia, Trainium, TPU)
- Strict schema validation with prototype pollution rejection in validator
- Full security header suite on server (HSTS, CSP, X-Frame-Options, etc.)

## [0.1.0] - 2026-03-22

### Added

- Initial release of `@svrnsec/pulse`
- Rust/WASM entropy probe (64x64 branch-heavy matrix multiply)
- Cross-metric heuristic engine with 5 physical law coherence checks
- Entropy-Jitter Ratio thermal feedback signal
- Picket Fence detector for hypervisor scheduler rhythm
- Provider fingerprinting: KVM, Xen, Nitro, VMware, Hyper-V, GCP
- BLAKE3 proof commitment (~1.6KB payload)
- Express/Fastify/Hono middleware
- Next.js App Router HOC with challenge handler
- React `usePulse()` hook
- Full TypeScript declarations
- Optional hosted API server (Docker + Redis)
- 43 tests passing

[0.8.0]: https://github.com/AaronSVRN/svrn-pulse/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/AaronSVRN/svrn-pulse/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/AaronSVRN/svrn-pulse/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/AaronSVRN/svrn-pulse/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/AaronSVRN/svrn-pulse/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/AaronSVRN/svrn-pulse/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/AaronSVRN/svrn-pulse/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/AaronSVRN/svrn-pulse/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/AaronSVRN/svrn-pulse/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AaronSVRN/svrn-pulse/releases/tag/v0.1.0

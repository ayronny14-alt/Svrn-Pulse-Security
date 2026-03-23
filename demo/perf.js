/**
 * @sovereign/pulse — Real Performance Benchmark
 * Measures every stage of the pipeline with actual wall-clock timings.
 *
 *   node demo/perf.js
 */

import { computeStats, classifyJitter, computeHurst,
         detectQuantizationEntropy, detectThermalSignature } from '../src/analysis/jitter.js';
import { runHeuristicEngine }   from '../src/analysis/heuristic.js';
import { detectProvider }       from '../src/analysis/provider.js';
import { buildProof, buildCommitment, blake3HexStr } from '../src/proof/fingerprint.js';
import { validateProof, generateNonce } from '../src/proof/validator.js';
import { serializeSignature, matchRegistry, KNOWN_PROFILES } from '../src/registry/serializer.js';

// ── helpers ──────────────────────────────────────────────────────────────────

const B  = s => `\x1b[34m${s}\x1b[0m`;
const G  = s => `\x1b[32m${s}\x1b[0m`;
const Y  = s => `\x1b[33m${s}\x1b[0m`;
const R  = s => `\x1b[31m${s}\x1b[0m`;
const W  = s => `\x1b[1m${s}\x1b[0m`;
const D  = s => `\x1b[2m${s}\x1b[0m`;

function hr() { console.log(D('─'.repeat(62))); }
function h1(t) { console.log(); console.log(W(B(`  ◈  ${t}`))); hr(); }

/** Run fn N times, return { mean, min, max, p50, p95, p99, samples } in ms */
function bench(fn, n = 200) {
  // Warm up (3 runs, discard)
  for (let i = 0; i < 3; i++) fn();

  const times = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    fn();
    times.push(performance.now() - t0);
  }
  times.sort((a, b) => a - b);
  const mean = times.reduce((s, v) => s + v, 0) / n;
  const p = pct => times[Math.floor(pct * n / 100)];
  return { mean, min: times[0], max: times[n-1], p50: p(50), p95: p(95), p99: p(99), samples: n };
}

async function benchAsync(fn, n = 50) {
  for (let i = 0; i < 3; i++) await fn();
  const times = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    await fn();
    times.push(performance.now() - t0);
  }
  times.sort((a, b) => a - b);
  const mean = times.reduce((s, v) => s + v, 0) / n;
  const p = pct => times[Math.floor(pct * n / 100)];
  return { mean, min: times[0], max: times[n-1], p50: p(50), p95: p(95), p99: p(99), samples: n };
}

function fmtMs(ms) {
  if (ms < 0.001) return (ms * 1000).toFixed(2) + ' µs';
  if (ms < 1)     return ms.toFixed(3) + ' ms';
  return ms.toFixed(2) + ' ms';
}

function colourMs(ms, warnAt, badAt) {
  const s = fmtMs(ms);
  if (ms < warnAt) return G(s);
  if (ms < badAt)  return Y(s);
  return R(s);
}

function row(label, r, warnAt = 1, badAt = 5) {
  const l = label.padEnd(32);
  const mean = colourMs(r.mean, warnAt, badAt);
  const p95  = colourMs(r.p95,  warnAt * 2, badAt * 2);
  const p99  = colourMs(r.p99,  warnAt * 3, badAt * 3);
  const min  = D(fmtMs(r.min));
  console.log(`  ${l}  mean=${mean.padEnd(20)}  p95=${p95.padEnd(20)}  p99=${p99}`);
}

// ── synthetic data ────────────────────────────────────────────────────────────

function makeLcg(seed) {
  let s = seed >>> 0;
  return () => { s = Math.imul(s, 1664525) + 1013904223 >>> 0; return s / 0xFFFFFFFF; };
}
function gauss(rand) {
  return Math.sqrt(-2 * Math.log(Math.max(1e-12, rand()))) * Math.cos(2 * Math.PI * rand());
}

function realTimings(n = 200) {
  const r = makeLcg(0xBEEF);
  let b = 5.0;
  return Array.from({ length: n }, () => Math.max(0.5, (b += 0.001) + gauss(r) * 0.55 + (r() > 0.94 ? r() * 4 : 0)));
}
function vmTimings(n = 200) {
  return Array.from({ length: n }, (_, i) =>
    Math.round((5.0 + (Math.random() - 0.5) * 0.18) * 10) / 10 + (i % 50 < 3 ? 1.8 : 0));
}

const REAL = realTimings(200);
const VM   = vmTimings(200);
const REAL_JITTER = classifyJitter(REAL);
const VM_JITTER   = classifyJitter(VM);

// ── mock objects ──────────────────────────────────────────────────────────────

const CANVAS_REAL = { webglRenderer: 'NVIDIA GeForce GTX 1650 Super/PCIe/SSE2', webglVendor: 'NVIDIA Corporation', isSoftwareRenderer: false, available: true, extensionCount: 38, webglVersion: 2 };
const CANVAS_VM   = { webglRenderer: 'llvmpipe (LLVM 15)', webglVendor: 'Mesa', isSoftwareRenderer: true, available: true, extensionCount: 12, webglVersion: 1 };
const AUDIO       = { available: true, workletAvailable: true, callbackJitterCV: 0.08, noiseFloorMean: 0.0001, noiseFloorStd: 0.00002, sampleRate: 44100, callbackCount: 340, jitterMeanMs: 5.8, jitterP95Ms: 7.2, noiseFloorStd: 0.00002 };
const BIO         = { mouse: { sampleCount: 85, ieiMean: 15.8, ieiCV: 0.38, velocityP50: 0.48, velocityP95: 2.3, angularJerkMean: 0.003, pressureVariance: 0 }, keyboard: { sampleCount: 14, dwellMean: 92, dwellCV: 0.24, ikiMean: 195, ikiCV: 0.44 }, interferenceCoefficient: 0.21, hasActivity: true, durationMs: 3000 };
const ENTROPY     = { timings: REAL, memTimings: REAL.map(t => t * 0.4), autocorrelations: { lag1: 0.07, lag2: 0.03, lag3: 0.02, lag5: 0.01, lag10: 0.00, lag25: 0.03, lag50: 0.04 }, timerGranularityMs: 0.1, checksum: '0xDEADBEEF', collectedAt: Date.now(), iterations: 200, matrixSize: 64, phases: { cold: { qe: 3.2, mean: 4.95 }, load: { qe: 3.5, mean: 5.05 }, hot: { qe: 3.8, mean: 5.20 }, entropyJitterRatio: 1.19 } };

const NONCE = generateNonce();

// Pre-build payload + commitment for validation benchmarks
const PAYLOAD = buildProof({ entropy: ENTROPY, jitter: REAL_JITTER, bio: BIO, canvas: CANVAS_REAL, audio: AUDIO, nonce: NONCE });
const { hash: HASH } = buildCommitment(PAYLOAD);

// ── mock fingerprint for registry ─────────────────────────────────────────────
const MOCK_FP = {
  isSynthetic: false, profile: 'analog-fog', providerId: 'physical',
  _raw: { jitter: REAL_JITTER, heuristic: { entropyJitterRatio: 1.18, picketFence: { detected: false }, coherenceFlags: [] }, entropy: { autocorrelations: ENTROPY.autocorrelations }, canvas: CANVAS_REAL, audio: AUDIO, bioSnapshot: {} },
  metrics: () => ({ cv: REAL_JITTER.stats?.cv, hurstExponent: REAL_JITTER.hurstExponent, quantizationEntropy: REAL_JITTER.quantizationEntropy, autocorrLag1: REAL_JITTER.autocorrelations?.lag1, autocorrLag50: 0.04, outlierRate: REAL_JITTER.outlierRate, thermalPattern: 'sawtooth', entropyJitterRatio: 1.18, picketFence: false, provider: 'Physical Hardware', providerConfidence: 90, schedulerQuantumMs: null, webglRenderer: CANVAS_REAL.webglRenderer, isSoftwareRenderer: false, hardwareId: 'abc123' }),
};

// =============================================================================
// Run benchmarks
// =============================================================================

console.clear();
console.log(W(G('\n  @sovereign/pulse — Performance Benchmark')));
console.log(D(`  ${new Date().toISOString()}  ·  Node.js ${process.version}\n`));

// ── 1. Statistical Analysis ───────────────────────────────────────────────────
h1('1. Statistical Analysis  (n=200 timing samples)');
console.log();

const r_stats  = bench(() => computeStats(REAL));
const r_hurst  = bench(() => computeHurst(REAL));
const r_qe     = bench(() => detectQuantizationEntropy(REAL));
const r_therm  = bench(() => detectThermalSignature(REAL));
const r_jitter = bench(() => classifyJitter(REAL));

row('computeStats()',             r_stats,  0.05, 0.5);
row('computeHurst()',             r_hurst,  0.1,  1.0);
row('detectQuantizationEntropy()', r_qe,   0.05, 0.5);
row('detectThermalSignature()',   r_therm,  0.05, 0.5);
row('classifyJitter()  [full]',   r_jitter, 0.5,  5.0);

// ── 2. Heuristic Engine ───────────────────────────────────────────────────────
h1('2. Heuristic Engine  (cross-metric analysis)');
console.log();

const r_heurReal = bench(() => runHeuristicEngine({ jitter: REAL_JITTER, phases: ENTROPY.phases, autocorrelations: ENTROPY.autocorrelations }));
const r_heurVM   = bench(() => runHeuristicEngine({ jitter: VM_JITTER,   phases: null,           autocorrelations: { lag1: 0.66, lag50: 0.55, lag25: 0.32 } }));
const r_provider = bench(() => detectProvider({ jitter: REAL_JITTER, autocorrelations: ENTROPY.autocorrelations, canvas: CANVAS_REAL, phases: ENTROPY.phases }));
const r_provVM   = bench(() => detectProvider({ jitter: VM_JITTER,   autocorrelations: { lag1: 0.66, lag25: 0.32, lag50: 0.55 }, canvas: CANVAS_VM, phases: null }));

row('runHeuristicEngine() [real]',  r_heurReal,  0.05, 0.5);
row('runHeuristicEngine() [vm]',    r_heurVM,    0.05, 0.5);
row('detectProvider()     [real]',  r_provider,  0.05, 0.5);
row('detectProvider()     [vm]',    r_provVM,    0.05, 0.5);

// ── 3. Proof & Commitment ─────────────────────────────────────────────────────
h1('3. Proof Generation  (BLAKE3 hashing)');
console.log();

const r_buildProof = bench(() => buildProof({ entropy: ENTROPY, jitter: REAL_JITTER, bio: BIO, canvas: CANVAS_REAL, audio: AUDIO, nonce: NONCE }));
const r_buildComm  = bench(() => buildCommitment(PAYLOAD));
const r_nonce      = bench(() => generateNonce());
const r_b3str      = bench(() => blake3HexStr('the quick brown fox jumps over the lazy dog'));
const r_b3big      = bench(() => blake3HexStr(JSON.stringify(PAYLOAD)));

row('buildProof()',          r_buildProof, 0.1, 1.0);
row('buildCommitment()',     r_buildComm,  0.1, 1.0);
row('generateNonce()',       r_nonce,      0.01, 0.1);
row('blake3Hex() [short]',  r_b3str,      0.01, 0.1);
row('blake3Hex() [payload ~1.6KB]', r_b3big, 0.05, 0.5);

// ── 4. Server Validation ──────────────────────────────────────────────────────
h1('4. Server-Side Validation');
console.log();

const r_valid = await benchAsync(() => validateProof(PAYLOAD, HASH, { minJitterScore: 0.55 }), 100);
// Tampered proof (fails at hash check — cheapest path)
const tampered = JSON.parse(JSON.stringify(PAYLOAD));
tampered.classification.jitterScore = 0.99;
const r_tamper = await benchAsync(() => validateProof(tampered, HASH), 100);
// With nonce check
const r_ncheck = await benchAsync(() => validateProof(PAYLOAD, HASH, { checkNonce: async () => true }), 100);

row('validateProof() [valid]',          r_valid,  0.5, 5.0);
row('validateProof() [tampered, fast]', r_tamper, 0.5, 5.0);
row('validateProof() [+async nonce]',   r_ncheck, 0.5, 5.0);

// ── 5. Registry ───────────────────────────────────────────────────────────────
h1('5. SVRN Registry');
console.log();

const sig          = serializeSignature(MOCK_FP);
const r_serialize  = bench(() => serializeSignature(MOCK_FP));
const r_match      = bench(() => matchRegistry(sig, KNOWN_PROFILES));
const r_matchBig   = bench(() => matchRegistry(sig, [...KNOWN_PROFILES, ...KNOWN_PROFILES, ...KNOWN_PROFILES])); // 15-entry registry

row('serializeSignature()',       r_serialize, 0.1, 1.0);
row('matchRegistry() [5 profiles]',  r_match,    0.05, 0.5);
row('matchRegistry() [15 profiles]', r_matchBig, 0.1,  1.0);

// ── 6. End-to-End pipeline (JS-only, no WASM) ─────────────────────────────────
h1('6. Full JS Pipeline  (no WASM, JS analysis only)');
console.log();

const r_e2e = bench(() => {
  const j  = classifyJitter(REAL);
  const h  = runHeuristicEngine({ jitter: j, phases: ENTROPY.phases, autocorrelations: ENTROPY.autocorrelations });
  const p  = detectProvider({ jitter: j, autocorrelations: ENTROPY.autocorrelations, canvas: CANVAS_REAL, phases: ENTROPY.phases });
  const pl = buildProof({ entropy: ENTROPY, jitter: j, bio: BIO, canvas: CANVAS_REAL, audio: AUDIO, nonce: NONCE });
  return buildCommitment(pl);
}, 100);

row('Full pipeline (classify→heuristic→provider→proof→hash)', r_e2e, 1.0, 10.0);
console.log();
console.log(D('  Note: WASM matrix-multiply probe takes 3–5s (real hardware timing collection)'));
console.log(D('        The above measures only the JS analysis + proof generation.'));

// ── Summary table ─────────────────────────────────────────────────────────────
h1('Summary — What Devs Actually Wait For');
console.log();

const stages = [
  ['WASM probe (200 iter, real hardware)',  '~3,500ms', '~5,000ms',  'inherent — measuring real physics'],
  ['Bio signal collection',                '~3,000ms', '~3,000ms',  'runs in parallel with WASM'],
  ['JS analysis pipeline',                 fmtMs(r_e2e.mean), fmtMs(r_e2e.p95), 'classify + heuristic + provider + proof'],
  ['Server validation',                    fmtMs(r_valid.mean), fmtMs(r_valid.p95), 'per request, server-side'],
  ['Registry match (5 profiles)',          fmtMs(r_match.mean), fmtMs(r_match.p95), 'per request, optional'],
];

console.log('  ' + 'Stage'.padEnd(40) + 'Mean'.padEnd(14) + 'p95'.padEnd(14) + 'Notes');
console.log('  ' + D('─'.repeat(90)));
for (const [stage, mean, p95, note] of stages) {
  const isSlow = stage.startsWith('WASM') || stage.startsWith('Bio');
  const meanStr = isSlow ? Y(String(mean).padEnd(14)) : G(String(mean).padEnd(14));
  const p95Str  = isSlow ? Y(String(p95).padEnd(14))  : G(String(p95).padEnd(14));
  console.log(`  ${stage.padEnd(40)}${meanStr}${p95Str}${D(note)}`);
}

console.log();
console.log('  ' + W('Total user-facing latency:') + '  ' + Y('~3.5s – 5s') + D('  (dominated by WASM probe, runs once per action)'));
console.log('  ' + W('Server validation latency:') + '  ' + G(fmtMs(r_valid.mean)) + D('  per request'));
console.log();

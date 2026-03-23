/**
 * @svrnsec/pulse — Refraction
 *
 * The same physics signal "refracts" through different measurement mediums.
 * A browser's clamped performance.now() (~100μs Spectre mitigation) shifts
 * every statistical distribution compared to Node.js process.hrtime.bigint().
 *
 * Instead of maintaining two sets of hardcoded thresholds, Refraction:
 *   1. Probes the timer to measure actual resolution
 *   2. Detects the execution environment (browser, Node, Deno, worker, etc.)
 *   3. Computes a calibration profile that shifts all scoring bands
 *   4. Exposes the profile so every downstream analyzer (jitter, trustScore,
 *      population entropy) can score against the correct baseline
 *
 * Core insight:
 *   A VM in Node.js and real hardware in a browser can produce identical
 *   Hurst exponents. Without knowing the medium, the score is meaningless.
 *   Refraction makes the medium explicit.
 *
 * Usage:
 *   import { calibrate, getProfile } from '@svrnsec/pulse/refraction'
 *   const profile = await calibrate()      // run once at init
 *   const score   = classifyJitter(timings, { refraction: profile })
 */

// ─── Environment detection ───────────────────────────────────────────────────

const ENV = Object.freeze({
  NODE:       'node',
  BROWSER:    'browser',
  WORKER:     'worker',      // Web Worker / Service Worker
  DENO:       'deno',
  BUN:        'bun',
  UNKNOWN:    'unknown',
});

/**
 * Detect the current JS runtime without relying on user-agent sniffing.
 * Uses capability detection — what APIs exist, not what strings say.
 */
function detectEnvironment() {
  // Deno has Deno global
  if (typeof globalThis.Deno !== 'undefined') return ENV.DENO;
  // Bun has Bun global
  if (typeof globalThis.Bun !== 'undefined') return ENV.BUN;
  // Node.js has process.versions.node
  if (typeof globalThis.process !== 'undefined' &&
      globalThis.process.versions?.node) return ENV.NODE;
  // Web Worker has self but no document
  if (typeof globalThis.WorkerGlobalScope !== 'undefined') return ENV.WORKER;
  // Browser has window + document
  if (typeof globalThis.window !== 'undefined' &&
      typeof globalThis.document !== 'undefined') return ENV.BROWSER;
  return ENV.UNKNOWN;
}

// ─── Timer resolution probe ──────────────────────────────────────────────────

/**
 * Measure the actual timer resolution by collecting minimum non-zero deltas.
 * Returns resolution in microseconds.
 *
 * Browser (Spectre-mitigated): typically 100μs
 * Node.js hrtime:              typically < 1μs
 * Node.js performance.now():   typically ~1μs
 *
 * We probe with performance.now() since it's cross-platform.
 * In Node.js we also check process.hrtime.bigint() availability.
 */
function probeTimerResolution(iterations = 500) {
  const deltas = [];
  const pnow = typeof performance !== 'undefined' && performance.now
    ? () => performance.now()
    : () => Date.now();  // fallback — 1ms resolution

  for (let i = 0; i < iterations; i++) {
    const t0 = pnow();
    // Minimal work — just enough to not get optimized away
    let x = 0;
    for (let j = 0; j < 10; j++) x += j;
    const t1 = pnow();
    const dt = t1 - t0;
    if (dt > 0) deltas.push(dt);
    if (x === -1) deltas.push(0); // prevent dead code elimination
  }

  if (deltas.length === 0) return { resolutionUs: 1000, grain: 'coarse' };

  deltas.sort((a, b) => a - b);

  // Minimum non-zero delta = timer resolution floor
  const minDelta = deltas[0];
  // Median gives stable estimate
  const medDelta = deltas[Math.floor(deltas.length / 2)];
  // Count unique values — clamped timers produce few unique values
  const unique = new Set(deltas.map(d => d.toFixed(4))).size;
  const uniqueRatio = unique / deltas.length;

  const resolutionUs = minDelta * 1000; // ms → μs

  let grain;
  if (resolutionUs < 5)        grain = 'nanosecond';  // < 5μs — Node.js / Deno
  else if (resolutionUs < 50)  grain = 'fine';         // 5–50μs — some browsers with relaxed policy
  else if (resolutionUs < 200) grain = 'clamped';      // 50–200μs — standard Spectre mitigation
  else                         grain = 'coarse';       // > 200μs — aggressive clamping or Date.now()

  return {
    resolutionUs: +resolutionUs.toFixed(2),
    minDeltaMs:   +minDelta.toFixed(6),
    medDeltaMs:   +medDelta.toFixed(6),
    uniqueRatio:  +uniqueRatio.toFixed(4),
    grain,
    samples:      deltas.length,
  };
}

/**
 * Check if high-resolution timer is available (Node.js process.hrtime).
 */
function hasHrtime() {
  return typeof globalThis.process !== 'undefined' &&
         typeof globalThis.process.hrtime?.bigint === 'function';
}

// ─── Threshold profile ───────────────────────────────────────────────────────

/**
 * Scoring thresholds shift based on timer grain.
 *
 * Why each threshold changes:
 *
 * CV (Coefficient of Variation):
 *   Clamped timers absorb small jitter → CV appears lower on real hardware.
 *   But heavy ops (32K+) push deltas above clamp floor, creating burst variance.
 *   Browser real HW: CV 0.01–0.90.  Node real HW: CV 0.04–0.35.
 *
 * Hurst Exponent:
 *   Timer clamping introduces quantization steps that shift H upward.
 *   Browser real HW: H 0.15–0.82.  Node real HW: H 0.25–0.55.
 *
 * Autocorrelation:
 *   Browser event loop scheduling adds baseline AC ~0.3–0.5 on real hardware.
 *   VMs in browser still show higher AC > 0.65 from hypervisor tick.
 *   Node real HW: AC < 0.20.  Browser real HW: AC < 0.50.
 *
 * Quantization Entropy:
 *   Fewer unique timer values → fewer populated bins → lower QE.
 *   Node real HW: QE > 3.0.  Browser real HW: QE > 0.8.
 *
 * Unique Value Ratio:
 *   Clamped timers repeat values more.
 *   Node real HW: UVR > 0.60.  Browser real HW: UVR > 0.15.
 */

const PROFILES = {
  nanosecond: {
    label: 'High-resolution timer (Node.js / Deno)',
    cv:    { floor: 0.04, ceil: 0.35, vmFloor: 0.02 },
    hurst: { floor: 0.25, ceil: 0.55, vmCeil: 0.60 },
    ac:    { pass: 0.20,  warn: 0.35, fail: 0.50 },
    qe:    { pass: 3.0,   warn: 1.5 },
    uvr:   { pass: 0.60,  warn: 0.30 },
    dram:  { elFloor: 2, mcvFloor: 0.04 },
  },
  fine: {
    label: 'Fine timer (relaxed browser policy)',
    cv:    { floor: 0.02, ceil: 0.60, vmFloor: 0.01 },
    hurst: { floor: 0.20, ceil: 0.70, vmCeil: 0.75 },
    ac:    { pass: 0.35,  warn: 0.50, fail: 0.60 },
    qe:    { pass: 1.5,   warn: 0.8 },
    uvr:   { pass: 0.30,  warn: 0.15 },
    dram:  { elFloor: 3, mcvFloor: 0.03 },
  },
  clamped: {
    label: 'Spectre-mitigated browser timer (~100μs)',
    cv:    { floor: 0.01, ceil: 0.90, vmFloor: 0.005 },
    hurst: { floor: 0.15, ceil: 0.82, vmCeil: 0.88 },
    ac:    { pass: 0.50,  warn: 0.60, fail: 0.70 },
    qe:    { pass: 0.8,   warn: 0.5 },
    uvr:   { pass: 0.15,  warn: 0.08 },
    dram:  { elFloor: 5, mcvFloor: 0.02 },
  },
  coarse: {
    label: 'Coarse timer (aggressive clamping / Date.now)',
    cv:    { floor: 0.005, ceil: 1.0, vmFloor: 0.002 },
    hurst: { floor: 0.10, ceil: 0.88, vmCeil: 0.92 },
    ac:    { pass: 0.55,  warn: 0.65, fail: 0.75 },
    qe:    { pass: 0.5,   warn: 0.3 },
    uvr:   { pass: 0.08,  warn: 0.04 },
    dram:  { elFloor: 5, mcvFloor: 0.02 },
  },
};

// ─── Calibration ─────────────────────────────────────────────────────────────

/** @type {RefractionProfile|null} */
let _cached = null;

/**
 * Run the full calibration sequence. Call once at init; results are cached.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.force=false]  - bypass cache and re-probe
 * @returns {Promise<RefractionProfile>}
 */
export async function calibrate(opts = {}) {
  if (_cached && !opts.force) return _cached;

  const env    = detectEnvironment();
  const timer  = probeTimerResolution();
  const hrtime = hasHrtime();

  // If Node.js with hrtime, always use nanosecond profile regardless of
  // performance.now() resolution (which may be coarser on some builds).
  const grain = (env === ENV.NODE && hrtime) ? 'nanosecond' : timer.grain;
  const thresholds = PROFILES[grain];

  _cached = Object.freeze({
    env,
    timer,
    grain,
    hrtime,
    thresholds,
    label: thresholds.label,
    calibratedAt: Date.now(),
  });

  return _cached;
}

/**
 * Get the cached profile. Returns null if calibrate() hasn't been called.
 * @returns {RefractionProfile|null}
 */
export function getProfile() {
  return _cached;
}

/**
 * Synchronous calibration for environments that can't await.
 * Slightly less accurate than async version but sufficient for most cases.
 */
export function calibrateSync() {
  if (_cached) return _cached;

  const env    = detectEnvironment();
  const timer  = probeTimerResolution();
  const hrtime = hasHrtime();
  const grain  = (env === ENV.NODE && hrtime) ? 'nanosecond' : timer.grain;
  const thresholds = PROFILES[grain];

  _cached = Object.freeze({
    env,
    timer,
    grain,
    hrtime,
    thresholds,
    label: thresholds.label,
    calibratedAt: Date.now(),
  });

  return _cached;
}

/**
 * Reset cached profile. Useful for testing.
 */
export function resetProfile() {
  _cached = null;
}

// ─── Threshold accessors ─────────────────────────────────────────────────────

/**
 * Get the active thresholds for a specific signal.
 * Falls back to 'clamped' profile if not calibrated (safe default).
 *
 * @param {'cv'|'hurst'|'ac'|'qe'|'uvr'|'dram'} signal
 * @returns {object}
 */
export function getThresholds(signal) {
  const profile = _cached?.thresholds ?? PROFILES.clamped;
  return profile[signal];
}

/**
 * Score a value against refraction-aware thresholds.
 * Returns { score: 0-1, pass: boolean, flag: string|null }
 *
 * @param {'cv'|'hurst'|'ac'|'qe'|'uvr'} signal
 * @param {number} value
 * @returns {{ score: number, pass: boolean, flag: string|null }}
 */
export function scoreSignal(signal, value) {
  const t = getThresholds(signal);

  switch (signal) {
    case 'cv': {
      if (value >= t.floor && value <= t.ceil) return { score: 1, pass: true, flag: null };
      if (value < t.vmFloor) return { score: 0.3, pass: false, flag: 'CV_FLAT_HYPERVISOR' };
      if (value < t.floor) return { score: 0.6 + (value - t.vmFloor) / (t.floor - t.vmFloor) * 0.4, pass: false, flag: 'CV_LOW_BORDERLINE' };
      if (value > t.ceil) return { score: 0.6, pass: false, flag: 'CV_HIGH_BURST' };
      return { score: 0.5, pass: false, flag: 'CV_ANOMALOUS' };
    }
    case 'hurst': {
      if (value >= t.floor && value <= t.ceil) return { score: 1, pass: true, flag: null };
      if (value > t.vmCeil) return { score: 0.3, pass: false, flag: 'HURST_PERSISTENT_VM' };
      if (value > t.ceil) return { score: 0.6, pass: false, flag: 'HURST_HIGH_BORDERLINE' };
      if (value < t.floor) return { score: 0.65, pass: false, flag: 'HURST_WEAK' };
      return { score: 0.5, pass: false, flag: 'HURST_ANOMALOUS' };
    }
    case 'ac': {
      if (value < t.pass) return { score: 1, pass: true, flag: null };
      if (value < t.warn) return { score: 0.7, pass: false, flag: 'AC_MODERATE' };
      if (value < t.fail) return { score: 0.5, pass: false, flag: 'AC_HIGH' };
      return { score: 0.2, pass: false, flag: 'AC_VM_PERIODIC' };
    }
    case 'qe': {
      if (value >= t.pass) return { score: 1, pass: true, flag: null };
      if (value >= t.warn) return { score: 0.75, pass: false, flag: 'QE_LOW_BORDERLINE' };
      return { score: 0.35, pass: false, flag: 'QE_QUANTIZED' };
    }
    case 'uvr': {
      if (value >= t.pass) return { score: 1, pass: true, flag: null };
      if (value >= t.warn) return { score: 0.7, pass: false, flag: 'UVR_LOW_DIVERSITY' };
      return { score: 0.3, pass: false, flag: 'UVR_CLAMPED' };
    }
    default:
      return { score: 0.5, pass: false, flag: 'UNKNOWN_SIGNAL' };
  }
}

// ─── Composite scoring ───────────────────────────────────────────────────────

/**
 * Score an entire jitter analysis result through the refraction lens.
 * This is the primary API — pass your raw stats and get back a
 * refraction-aware score with full breakdown.
 *
 * @param {object} stats - { cv, hurst, ac1, qe, uvr }
 * @returns {{ score: number, signals: object, flags: string[], profile: string }}
 */
export function scoreJitter(stats) {
  const profile = _cached ?? calibrateSync();

  const cv    = scoreSignal('cv',    stats.cv);
  const hurst = scoreSignal('hurst', stats.hurst ?? stats.H);
  const ac    = scoreSignal('ac',    stats.ac1 ?? stats.a1);
  const qe    = scoreSignal('qe',    stats.qe ?? stats.QE);
  const uvr   = scoreSignal('uvr',   stats.uvr ?? stats.ur);

  const flags = [cv, hurst, ac, qe, uvr]
    .map(s => s.flag)
    .filter(Boolean);

  // Weighted fusion — same weights regardless of medium
  const raw = cv.score * 0.20 +
              hurst.score * 0.20 +
              ac.score * 0.20 +
              qe.score * 0.15 +
              uvr.score * 0.25;

  return {
    score:   +Math.min(0.99, Math.max(0.01, raw)).toFixed(4),
    signals: { cv, hurst, ac, qe, uvr },
    flags,
    grain:   profile.grain,
    profile: profile.label,
  };
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export {
  ENV,
  PROFILES,
  detectEnvironment,
  probeTimerResolution,
  hasHrtime,
};

/**
 * @typedef {object} RefractionProfile
 * @property {string}  env           - 'node' | 'browser' | 'worker' | 'deno' | 'bun' | 'unknown'
 * @property {object}  timer         - { resolutionUs, minDeltaMs, medDeltaMs, uniqueRatio, grain, samples }
 * @property {string}  grain         - 'nanosecond' | 'fine' | 'clamped' | 'coarse'
 * @property {boolean} hrtime        - true if process.hrtime.bigint() is available
 * @property {object}  thresholds    - the active PROFILES[grain] threshold set
 * @property {string}  label         - human-readable description
 * @property {number}  calibratedAt  - Date.now() when calibration ran
 */

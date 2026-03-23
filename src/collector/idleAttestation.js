/**
 * @svrnsec/pulse — Idle Attestation Collector
 *
 * Click farms run thousands of real devices at sustained maximum throughput —
 * they physically cannot let a device idle. This module builds a cryptographic
 * proof that a device experienced a genuine rest period between interactions:
 * thermal cooling, CPU clock-scaling, and a hash-chained measurement sequence
 * that cannot be back-filled faster than real time.
 *
 * Physics basis
 * ─────────────
 *   Real device between interactions:
 *     → CPU frequency drops via DVFS (Dynamic Voltage/Frequency Scaling)
 *     → DRAM access latency rises as the front-side bus slows down
 *     → Thermal mass of die + PCB means temperature decays exponentially
 *     → Timing variance follows Newton's Law of Cooling — a smooth curve
 *
 *   Click farm device with paused script:
 *     → CPU load drops from ~100% to ~0% INSTANTLY (OS task queue emptied)
 *     → DRAM timing shows a STEP FUNCTION, not an exponential curve
 *     → The step is economically forced: farm scripts resume within 90s
 *       to maintain throughput; real thermal settling takes minutes
 *
 * Hash chain
 * ──────────
 *   Each idle sample produces a chain node:
 *     node[n].hash = SHA-256(node[n-1].hash ‖ ts ‖ meanMs ‖ variance)
 *
 *   The chain proves samples were taken in sequence at regular intervals.
 *   N nodes at 30-second intervals = (N−1)×30s minimum elapsed time.
 *   It cannot be fabricated faster than real time without the server
 *   noticing the timing impossibility.
 *
 * Thermal transition taxonomy
 * ───────────────────────────
 *   hot_to_cold    → smooth exponential variance decay  (genuine cooling ✓)
 *   cold           → device was already at rest temperature (genuine idle ✓)
 *   cooling        → mild, ongoing decay (genuine idle ✓)
 *   warming        → device heating up (uncommon during idle)
 *   sustained_hot  → elevated variance throughout (click farm: constant load ✗)
 *   step_function  → abrupt single-interval drop (click farm: script paused ✗)
 *   unknown        → insufficient samples to classify
 */

import { sha256 }               from '@noble/hashes/sha256';
import { bytesToHex,
         utf8ToBytes,
         randomBytes }          from '@noble/hashes/utils';

// ── Constants ─────────────────────────────────────────────────────────────────

/** Minimum idle duration before issuing a proof.
 *  Farm scripts pause for < 30s to maintain throughput.
 *  This threshold creates a real economic cost: 45s idle × 1000 devices =
 *  12.5 device-hours of forced downtime per 1000 tokens. */
const MIN_IDLE_MS             = 45_000;

/** Sampling interval. 30s gives 3 nodes in a 90s session — enough to
 *  differentiate a cooling curve from a step function. */
const SAMPLE_INTERVAL_MS      = 30_000;

/** Grace period after focus/visibility loss before declaring idle.
 *  Absorbs rapid tab switches and accidental blur events. */
const IDLE_WATCH_GRACE_MS     = 5_000;

/** Mini probe buffer — 16 MB exceeds L3 cache on most consumer devices,
 *  forcing reads to DRAM. Small enough that the probe finishes in < 100ms,
 *  so we don't meaningfully disturb the idle state we're measuring. */
const MINI_BUFFER_MB          = 16;

/** Mini probe iteration count. ~80ms total wall-clock time. */
const MINI_ITERATIONS         = 80;

/** Variance at or below this value indicates a device at rest temperature.
 *  Calibrated from empirical measurements on idle consumer hardware. */
const COLD_VARIANCE_THRESHOLD = 0.003;

/** Variance above this value indicates sustained CPU load — characteristic
 *  of click farm operation (continuous task execution). */
const HOT_VARIANCE_THRESHOLD  = 0.025;

/** If more than this fraction of the total variance drop happens in the
 *  first sample interval, we classify the transition as 'step_function'. */
const STEP_FUNCTION_RATIO     = 0.75;

// ── State machine ─────────────────────────────────────────────────────────────

/** @enum {string} */
const State = Object.freeze({
  ACTIVE:         'active',         // device in normal use
  IDLE_WATCH:     'idle_watch',     // focus lost, in grace period
  IDLE_SAMPLING:  'idle_sampling',  // sampling in progress, chain building
  IDLE_COMMITTED: 'idle_committed', // proof ready to consume
});

// ── createIdleMonitor ─────────────────────────────────────────────────────────

/**
 * Create a stateful idle monitor for the current session.
 *
 * **Browser**: automatically hooks `visibilitychange` and `blur`/`focus`.
 * Call `monitor.start()` once on page load and `monitor.stop()` on unload.
 *
 * **Node.js / React Native**: call `monitor.declareIdle()` and
 * `monitor.declareActive()` manually to drive the state machine.
 *
 * @param {object}  [opts]
 * @param {number}  [opts.minIdleMs=45000]         minimum idle ms for valid proof
 * @param {number}  [opts.sampleIntervalMs=30000]   thermal sampling interval
 * @param {string}  [opts.sessionNonce]             ties hash chain to this session
 * @returns {IdleMonitor}
 */
export function createIdleMonitor(opts = {}) {
  const {
    minIdleMs        = MIN_IDLE_MS,
    sampleIntervalMs = SAMPLE_INTERVAL_MS,
    sessionNonce     = bytesToHex(randomBytes(8)),
  } = opts;

  // ── Mutable private state (encapsulated in closure — no global mutation) ───
  let _state         = State.ACTIVE;
  let _idleStartMs   = 0;
  let _watchTimer    = null;
  let _sampleTimer   = null;
  let _chain         = _genesisHash(sessionNonce);
  let _samples       = /** @type {ThermalSample[]} */ ([]);
  let _pendingProof  = null;
  let _probeBuffer   = null;  // allocated lazily on first sample, then reused

  // ── State transition: ACTIVE / IDLE_COMMITTED → IDLE_WATCH ───────────────
  function _enterWatch() {
    if (_state !== State.ACTIVE && _state !== State.IDLE_COMMITTED) return;
    // Discard any unconsumed proof — a new idle cycle supersedes the old one.
    _pendingProof = null;
    _state        = State.IDLE_WATCH;
    _watchTimer   = setTimeout(_enterSampling, IDLE_WATCH_GRACE_MS);
  }

  // ── State transition: IDLE_WATCH → IDLE_SAMPLING ──────────────────────────
  function _enterSampling() {
    _state       = State.IDLE_SAMPLING;
    _idleStartMs = Date.now();
    _samples     = [];
    _chain       = _genesisHash(`${sessionNonce}:${_idleStartMs}`);

    // Take first sample immediately, then on interval
    _tick();
    _sampleTimer = setInterval(_tick, sampleIntervalMs);
  }

  // ── Periodic sample tick ───────────────────────────────────────────────────
  function _tick() {
    // Allocate probe buffer once; reuse to avoid GC pressure every 30s
    if (!_probeBuffer) _probeBuffer = _allocBuffer();
    const sample = _miniProbe(_probeBuffer);
    _samples.push(sample);
    _chain = _chainStep(_chain, sample);
  }

  // ── State transition: IDLE_SAMPLING → IDLE_COMMITTED or ACTIVE ────────────
  function _commitOrReset() {
    clearTimeout(_watchTimer);
    clearInterval(_sampleTimer);
    _watchTimer  = null;
    _sampleTimer = null;

    const idleDurationMs   = Date.now() - _idleStartMs;
    const hasEnoughTime    = idleDurationMs  >= minIdleMs;
    const hasEnoughSamples = _samples.length >= 2;

    if (_state === State.IDLE_SAMPLING && hasEnoughTime && hasEnoughSamples) {
      _pendingProof = _buildProof(_chain, _samples, idleDurationMs);
      _state        = State.IDLE_COMMITTED;
    } else {
      _reset();
    }
  }

  // ── Reset to ACTIVE ────────────────────────────────────────────────────────
  function _reset() {
    _state        = State.ACTIVE;
    _idleStartMs  = 0;
    _samples      = [];
    _pendingProof = null;
    _chain        = _genesisHash(sessionNonce);
  }

  // ── Browser event handlers ─────────────────────────────────────────────────
  const _onHide = () => _enterWatch();
  const _onShow = () => { if (_state !== State.ACTIVE) _commitOrReset(); };

  // ── Public API ────────────────────────────────────────────────────────────

  /** Register browser event listeners. No-op in non-browser environments. */
  function start() {
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange',
        () => (document.hidden ? _onHide() : _onShow()));
    }
    if (typeof window !== 'undefined') {
      window.addEventListener('blur',  _onHide);
      window.addEventListener('focus', _onShow);
    }
    return api;
  }

  /** Deregister browser event listeners and cancel pending timers. */
  function stop() {
    clearTimeout(_watchTimer);
    clearInterval(_sampleTimer);
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', _onHide);
    }
    if (typeof window !== 'undefined') {
      window.removeEventListener('blur',  _onHide);
      window.removeEventListener('focus', _onShow);
    }
    return api;
  }

  /** Manual idle declaration for Node.js or non-browser environments. */
  function declareIdle()   { _enterWatch();       return api; }

  /** Manual active declaration for Node.js or non-browser environments. */
  function declareActive() { _commitOrReset();    return api; }

  /**
   * Consume the pending idle proof — one-time read that resets the monitor.
   * Returns null if no valid proof is ready (device hasn't been idle long enough).
   *
   * @returns {IdleProof|null}
   */
  function getProof() {
    if (_state !== State.IDLE_COMMITTED || !_pendingProof) return null;
    const proof = { ..._pendingProof, capturedAt: Date.now() };
    _reset();
    return proof;
  }

  /** Current state machine state — useful for debugging and tests. */
  function getState() { return _state; }

  const api = { start, stop, getProof, getState, declareIdle, declareActive };
  return api;
}

// ── analyseIdleProof ──────────────────────────────────────────────────────────

/**
 * Validate the physical plausibility of an IdleProof before embedding it in
 * an engagement token. Returns advisory warnings without rejecting outright —
 * the server-side verifier makes the final call.
 *
 * @param {IdleProof} proof
 * @returns {{ plausible: boolean, reason?: string, warnings: string[] }}
 */
export function analyseIdleProof(proof) {
  if (!proof) return { plausible: false, reason: 'no_proof', warnings: [] };

  const warnings = [];

  if (proof.idleDurationMs < MIN_IDLE_MS) {
    return { plausible: false, reason: 'idle_too_short', warnings };
  }

  if (proof.samples < 2) {
    return { plausible: false, reason: 'insufficient_chain_samples', warnings };
  }

  if (!proof.chain || proof.chain.length !== 64) {
    return { plausible: false, reason: 'malformed_chain_hash', warnings };
  }

  if (proof.thermalTransition === 'step_function') {
    warnings.push('abrupt_cpu_transition_detected');
  }
  if (proof.thermalTransition === 'sustained_hot') {
    warnings.push('no_thermal_decay_observed');
  }
  if (proof.coolingMonotonicity < 0.3 && proof.samples >= 3) {
    warnings.push('non_monotonic_cooling_curve');
  }

  return { plausible: true, warnings };
}

// ── Internal: mini DRAM probe ─────────────────────────────────────────────────

/**
 * Lightweight DRAM probe: 16 MB buffer, 80 iterations, < 100ms.
 * Returns mean iteration time (reflects CPU clock frequency) and
 * variance (reflects thermal noise intensity).
 *
 * Exported for unit testing — not part of the public API surface.
 *
 * @param {Float64Array} buf  pre-allocated cache-busting buffer
 * @returns {ThermalSample}
 */
export function _miniProbe(buf) {
  const pass   = _calibratePass(buf);
  const timings = new Float64Array(MINI_ITERATIONS);
  let   dummy   = 0;

  for (let i = 0; i < MINI_ITERATIONS; i++) {
    const t0 = performance.now();
    for (let j = 0; j < pass; j++) dummy += buf[j];
    timings[i] = performance.now() - t0;
  }

  // Prevent dead-code elimination of the memory reads
  if (dummy === 0) buf[0] = 1;

  const mean     = _mean(timings, MINI_ITERATIONS);
  const variance = _variance(timings, MINI_ITERATIONS, mean);

  return {
    ts:       Date.now(),
    meanMs:   +mean.toFixed(4),
    variance: +variance.toFixed(6),
  };
}

function _allocBuffer() {
  const elements = (MINI_BUFFER_MB * 1024 * 1024) / 8;
  try {
    const buf    = new Float64Array(elements);
    const stride = 64 / 8; // one element per 64-byte cache line
    for (let i = 0; i < elements; i += stride) buf[i] = i;
    return buf;
  } catch {
    // Memory-constrained fallback — smaller buffer means weaker signal
    return new Float64Array(8_192);
  }
}

function _calibratePass(buf) {
  // Dynamically size the pass so each iteration takes ~1ms wall-clock.
  // This self-calibrates across device classes (desktop, mobile, low-end).
  const target  = 1.0; // ms
  let   n       = Math.min(50_000, buf.length);
  let   dummy   = 0;

  // Warm-up (ensures first measurement isn't cold-start biased)
  for (let i = 0; i < n; i++) dummy += buf[i];

  const t0      = performance.now();
  for (let i    = 0; i < n; i++) dummy += buf[i];
  const elapsed = performance.now() - t0;
  if (dummy === 0) buf[0] = 1;

  return elapsed > 0
    ? Math.min(buf.length, Math.round(n * target / elapsed))
    : n;
}

// ── Internal: hash chain ──────────────────────────────────────────────────────

function _genesisHash(seed) {
  return bytesToHex(sha256(utf8ToBytes(`pulse:idle:genesis:${seed}`)));
}

function _chainStep(prevHex, sample) {
  // Each node commits to: previous state, exact timestamp, CPU freq proxy, thermal noise
  const input = `${prevHex}:${sample.ts}:${sample.meanMs}:${sample.variance}`;
  return bytesToHex(sha256(utf8ToBytes(input)));
}

// ── Internal: thermal classification ─────────────────────────────────────────

/**
 * Classify the thermal transition from an ordered sequence of samples.
 *
 * The key discriminator is whether the variance follows a smooth exponential
 * decay (genuine cooling) or drops abruptly in one interval (farm script pause).
 *
 * @param {ThermalSample[]} samples
 * @returns {{ transition: string, coolingMonotonicity: number }}
 */
function _classifyThermal(samples) {
  if (samples.length < 2) {
    return { transition: 'unknown', coolingMonotonicity: 0 };
  }

  const variances = samples.map(s => s.variance);
  const first     = variances[0];
  const last      = variances[variances.length - 1];

  // Cooling monotonicity: fraction of consecutive pairs where variance decreased
  let decreasingPairs = 0;
  for (let i = 1; i < variances.length; i++) {
    if (variances[i] < variances[i - 1]) decreasingPairs++;
  }
  const coolingMonotonicity = +(decreasingPairs / (variances.length - 1)).toFixed(3);

  // Step function detection: > STEP_FUNCTION_RATIO of total drop in first interval
  if (variances.length >= 3) {
    const firstDrop = Math.max(0, first - variances[1]);
    const totalDrop = Math.max(0, first - last);
    const isSignificantDrop = totalDrop > first * 0.15;      // must be >15% absolute drop
    const stepRatio = totalDrop > 1e-9 ? firstDrop / totalDrop : 0;

    if (isSignificantDrop && stepRatio > STEP_FUNCTION_RATIO) {
      return { transition: 'step_function', coolingMonotonicity };
    }
  }

  // Classify by absolute variance levels and direction
  if (first < COLD_VARIANCE_THRESHOLD) {
    return { transition: 'cold', coolingMonotonicity };
  }
  if (last > first * 1.10) {
    return { transition: 'warming', coolingMonotonicity };
  }
  if (first > HOT_VARIANCE_THRESHOLD && last > HOT_VARIANCE_THRESHOLD * 0.85) {
    return { transition: 'sustained_hot', coolingMonotonicity };
  }
  if ((first - last) / (first + 1e-9) > 0.12 && coolingMonotonicity >= 0.5) {
    return { transition: 'hot_to_cold', coolingMonotonicity };
  }

  return { transition: 'cooling', coolingMonotonicity };
}

function _buildProof(chain, samples, idleDurationMs) {
  const { transition, coolingMonotonicity } = _classifyThermal(samples);
  return {
    chain,
    samples:             samples.length,
    idleDurationMs,
    thermalTransition:   transition,
    coolingMonotonicity,
    baselineVariance:    +(samples[0]?.variance ?? 0).toFixed(6),
    finalVariance:       +(samples[samples.length - 1]?.variance ?? 0).toFixed(6),
  };
}

// ── Internal: statistics ──────────────────────────────────────────────────────

function _mean(arr, n) {
  let s = 0;
  for (let i = 0; i < n; i++) s += arr[i];
  return s / n;
}

function _variance(arr, n, mean) {
  let s = 0;
  for (let i = 0; i < n; i++) s += (arr[i] - mean) ** 2;
  return s / n;
}

// ── JSDoc types ───────────────────────────────────────────────────────────────

/**
 * @typedef {object} ThermalSample
 * @property {number} ts        Unix ms timestamp of this measurement
 * @property {number} meanMs    Mean DRAM iteration time — proxy for CPU clock frequency
 * @property {number} variance  Variance of iteration times — proxy for thermal noise
 */

/**
 * @typedef {object} IdleProof
 * @property {string}  chain               Final SHA-256 hash in the measurement chain
 * @property {number}  samples             Number of chain nodes (≥ 2 for a valid proof)
 * @property {number}  idleDurationMs      Total elapsed idle time (ms)
 * @property {string}  thermalTransition   'hot_to_cold'|'cold'|'cooling'|'warming'|'sustained_hot'|'step_function'|'unknown'
 * @property {number}  coolingMonotonicity Fraction of sample pairs with decreasing variance (0–1)
 * @property {number}  baselineVariance    Timing variance at idle start
 * @property {number}  finalVariance       Timing variance at idle end
 * @property {number}  capturedAt          Unix ms when proof was consumed (set by getProof)
 */

/**
 * @typedef {object} IdleMonitor
 * @property {() => IdleMonitor}       start          Register browser event listeners
 * @property {() => IdleMonitor}       stop           Deregister listeners and cancel timers
 * @property {() => IdleProof|null}    getProof       Consume pending proof (one-time)
 * @property {() => string}            getState       Current state machine state
 * @property {() => IdleMonitor}       declareIdle    Manually trigger idle (Node.js)
 * @property {() => IdleMonitor}       declareActive  Manually trigger active (Node.js)
 */

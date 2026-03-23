/**
 * @sovereign/pulse — Entropy Collector
 *
 * Bridges the Rust/WASM matrix-multiply probe into JavaScript.
 * The WASM module is lazily initialised once and cached for subsequent calls.
 */

import { collectEntropyAdaptive } from './adaptive.js';

// ---------------------------------------------------------------------------
// WASM loader (lazy singleton)
// ---------------------------------------------------------------------------
let _wasmModule   = null;
let _initPromise  = null;

/**
 * Initialise (or return the cached) WASM module.
 * Works in browsers (via fetch), in Electron (Node.js context), and in
 * Jest/Vitest via a manual WASM path override.
 *
 * @param {string} [wasmPath] – override path/URL to the .wasm binary
 */
async function initWasm(wasmPath) {
  if (_wasmModule) return _wasmModule;
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    // Dynamic import so bundlers can tree-shake this for server-only builds.
    const { default: init, run_entropy_probe, run_memory_probe, compute_autocorrelation } =
      await import('../../pkg/pulse_core.js');

    const url = wasmPath ?? new URL('../../pkg/pulse_core_bg.wasm', import.meta.url).href;
    await init(url);

    _wasmModule = { run_entropy_probe, run_memory_probe, compute_autocorrelation };
    return _wasmModule;
  })();

  return _initPromise;
}

// ---------------------------------------------------------------------------
// collectEntropy
// ---------------------------------------------------------------------------

/**
 * Run the WASM entropy probe and return raw timing data.
 *
 * @param {object}  opts
 * @param {number}  [opts.iterations=200]  - number of matrix-multiply rounds
 * @param {number}  [opts.matrixSize=64]   - N for the N×N matrices
 * @param {number}  [opts.memSizeKb=512]   - size of the memory bandwidth probe
 * @param {number}  [opts.memIterations=50]
 * @param {boolean} [opts.phased=true]     - run cold/load/hot phases for entropy-jitter ratio
 * @param {string}  [opts.wasmPath]        - optional custom WASM binary path
 *
 * @returns {Promise<EntropyResult>}
 */
export async function collectEntropy(opts = {}) {
  const {
    iterations        = 200,
    matrixSize        = 64,
    memSizeKb         = 512,
    memIterations     = 50,
    phased            = true,
    adaptive          = false,
    adaptiveThreshold = 0.85,
    onBatch,
    wasmPath,
  } = opts;

  const wasm    = await initWasm(wasmPath);
  const t_start = Date.now();

  let phases = null;
  let timings, resolutionProbe, checksum, timerGranularityMs;
  let _adaptiveInfo = null;

  // ── Adaptive mode: smart early exit, fastest for obvious VMs ──────────
  if (adaptive) {
    const r = await collectEntropyAdaptive(wasm, {
      minIterations:   50,
      maxIterations:   iterations,
      batchSize:       25,
      vmThreshold:     adaptiveThreshold,
      hwThreshold:     0.80,
      hwMinIterations: 75,
      matrixSize,
      onBatch,
    });
    timings            = r.timings;
    resolutionProbe    = r.resolutionProbe ?? [];
    checksum           = r.checksum;
    timerGranularityMs = r.timerGranularityMs;
    _adaptiveInfo      = { earlyExit: r.earlyExit, batches: r.batches, elapsedMs: r.elapsedMs };

  // ── Phased collection: cold → load → hot ──────────────────────────────
  // Each phase runs a separate WASM probe.  On real hardware, sustained load
  // increases thermal noise so Phase 3 (hot) entropy is measurably higher
  // than Phase 1 (cold).  A VM's hypervisor clock is insensitive to guest
  // thermal state, so all three phases return nearly identical entropy.
  } else if (phased && iterations >= 60) {
    const coldN = Math.floor(iterations * 0.25);  // ~25% cold
    const loadN = Math.floor(iterations * 0.50);  // ~50% sustained load
    const hotN  = iterations - coldN - loadN;     // ~25% hot

    const cold = wasm.run_entropy_probe(coldN, matrixSize);
    const load = wasm.run_entropy_probe(loadN, matrixSize);
    const hot  = wasm.run_entropy_probe(hotN,  matrixSize);

    const coldTimings = Array.from(cold.timings);
    const loadTimings = Array.from(load.timings);
    const hotTimings  = Array.from(hot.timings);

    timings         = [...coldTimings, ...loadTimings, ...hotTimings];
    resolutionProbe = Array.from(cold.resolution_probe);
    checksum        = (cold.checksum + load.checksum + hot.checksum).toString();

    const { detectQuantizationEntropy } = await import('../analysis/jitter.js');
    const coldQE = detectQuantizationEntropy(coldTimings);
    const hotQE  = detectQuantizationEntropy(hotTimings);

    phases = {
      cold: { n: coldN, timings: coldTimings, qe: coldQE, mean: _mean(coldTimings) },
      load: { n: loadN, timings: loadTimings, qe: detectQuantizationEntropy(loadTimings), mean: _mean(loadTimings) },
      hot:  { n: hotN,  timings: hotTimings,  qe: hotQE,  mean: _mean(hotTimings)  },
      // The key signal: entropy growth under load.
      // Real silicon: hotQE / coldQE typically 1.05 – 1.40
      // VM:           hotQE / coldQE typically 0.95 – 1.05 (flat)
      entropyJitterRatio: coldQE > 0 ? hotQE / coldQE : 1.0,
    };
  } else {
    // Single-phase fallback (fewer iterations or phased disabled)
    const result    = wasm.run_entropy_probe(iterations, matrixSize);
    timings         = Array.from(result.timings);
    resolutionProbe = Array.from(result.resolution_probe);
    checksum        = result.checksum.toString();
  }

  // ── Timer resolution (non-adaptive path only — adaptive computes its own) ─
  if (!adaptive) {
    const resDeltas = [];
    for (let i = 1; i < resolutionProbe.length; i++) {
      const d = resolutionProbe[i] - resolutionProbe[i - 1];
      if (d > 0) resDeltas.push(d);
    }
    timerGranularityMs = resDeltas.length
      ? resDeltas.reduce((a, b) => Math.min(a, b), Infinity)
      : null;
  }

  // ── Autocorrelation at diagnostic lags ────────────────────────────────
  // Extended lags catch long-period steal-time rhythms (Xen: ~150 iters)
  const lags = [1, 2, 3, 5, 10, 25, 50];
  const autocorrelations = {};
  for (const lag of lags) {
    if (lag < timings.length) {
      autocorrelations[`lag${lag}`] = wasm.compute_autocorrelation(timings, lag);
    }
  }

  // ── Secondary probe: memory bandwidth jitter ───────────────────────────
  const memTimings = Array.from(wasm.run_memory_probe(memSizeKb, memIterations));

  return {
    timings,
    resolutionProbe,
    timerGranularityMs,
    autocorrelations,
    memTimings,
    phases,
    checksum,
    collectedAt: t_start,
    iterations: timings.length,   // actual count (adaptive may differ from requested)
    matrixSize,
    adaptive: _adaptiveInfo,      // null in non-adaptive mode
  };
}

function _mean(arr) {
  return arr.length ? arr.reduce((s, v) => s + v, 0) / arr.length : 0;
}

/**
 * @typedef {object} EntropyResult
 * @property {number[]}  timings            - per-iteration wall-clock deltas (ms)
 * @property {number[]}  resolutionProbe    - raw successive perf.now() readings
 * @property {number|null} timerGranularityMs - effective timer resolution
 * @property {object}    autocorrelations   - { lag1, lag2, lag3, lag5, lag10 }
 * @property {number[]}  memTimings         - memory-probe timings (ms)
 * @property {string}    checksum           - proof the computation ran
 * @property {number}    collectedAt        - Date.now() at probe start
 * @property {number}    iterations
 * @property {number}    matrixSize
 */

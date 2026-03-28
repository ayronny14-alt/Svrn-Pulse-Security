/**
 * @svrnsec/pulse — Adaptive Entropy Probe
 *
 * Runs the WASM probe in batches and stops early once the signal is decisive.
 *
 * Why this works:
 *   A KVM VM with QE=1.27 and lag-1 autocorr=0.67 is unambiguously a VM after
 *   just 50 iterations.  Running 200 iterations confirms what was already obvious
 *   at 50 — it adds no new information but wastes 3 seconds of user time.
 *
 *   Conversely, a physical device with healthy entropy needs more data to
 *   rule out edge cases, so it runs longer.
 *
 * Speed profile:
 *   Obvious VM  (QE < 1.5,  lag1 > 0.60)  →  stops at  50 iters  →  ~0.9s  (75% faster)
 *   Clear HW    (QE > 3.5,  lag1 < 0.10)  →  stops at ~100 iters  →  ~1.8s  (50% faster)
 *   Ambiguous   (borderline metrics)       →  runs full 200 iters  →  ~3.5s  (same)
 */

import { detectQuantizationEntropy } from '../analysis/jitter.js';

// ---------------------------------------------------------------------------
// Quick classifier (cheap, runs after every batch)
// ---------------------------------------------------------------------------

/**
 * Fast signal-quality check.  No Hurst, no thermal analysis — just the three
 * metrics that converge quickest: QE, CV, and lag-1 autocorrelation.
 *
 * @param {number[]} timings
 * @returns {{ vmConf: number, hwConf: number, qe: number, cv: number, lag1: number }}
 */
export function quickSignal(timings) {
  const n    = timings.length;
  const mean = timings.reduce((s, v) => s + v, 0) / n;
  const variance = timings.reduce((s, v) => s + (v - mean) ** 2, 0) / n;
  const cv   = mean > 0 ? Math.sqrt(variance) / mean : 0;
  const qe   = detectQuantizationEntropy(timings);

  // Pearson autocorrelation at lag-1 (O(n), fits in a single pass)
  let num = 0, da = 0, db = 0;
  for (let i = 0; i < n - 1; i++) {
    const a = timings[i]     - mean;
    const b = timings[i + 1] - mean;
    num += a * b;
    da  += a * a;
    db  += b * b;
  }
  const lag1 = Math.sqrt(da * db) < 1e-14 ? 0 : num / Math.sqrt(da * db);

  // VM confidence: each factor independently identifies the hypervisor footprint
  const vmConf = Math.min(1,
    (qe   < 1.50 ? 0.40 : qe   < 2.00 ? 0.20 : 0.0) +
    (lag1 > 0.60 ? 0.35 : lag1 > 0.40 ? 0.18 : 0.0) +
    (cv   < 0.04 ? 0.25 : cv   < 0.07 ? 0.10 : 0.0)
  );

  // HW confidence: must see all three positive signals together
  const hwConf = Math.min(1,
    (qe   > 3.50 ? 0.38 : qe   > 3.00 ? 0.22 : 0.0) +
    (Math.abs(lag1) < 0.10 ? 0.32 : Math.abs(lag1) < 0.20 ? 0.15 : 0.0) +
    (cv   > 0.10 ? 0.30 : cv   > 0.07 ? 0.14 : 0.0)
  );

  return { vmConf, hwConf, qe, cv, lag1 };
}

// ---------------------------------------------------------------------------
// collectEntropyAdaptive
// ---------------------------------------------------------------------------

/**
 * @param {object}   opts
 * @param {number}   [opts.minIterations=50]        - never stop before this
 * @param {number}   [opts.maxIterations=200]        - hard cap
 * @param {number}   [opts.batchSize=25]             - WASM call granularity
 * @param {number}   [opts.vmThreshold=0.85]         - stop early if VM confidence ≥ this
 * @param {number}   [opts.hwThreshold=0.80]         - stop early if HW confidence ≥ this
 * @param {number}   [opts.hwMinIterations=75]        - physical needs more data to confirm
 * @param {number}   [opts.matrixSize=64]
 * @param {Function} [opts.onBatch]                  - called after each batch with interim signal
 * @param {string}   [opts.wasmPath]
 * @param {Function}  wasmModule                     - pre-initialised WASM module
 * @returns {Promise<AdaptiveEntropyResult>}
 */
export async function collectEntropyAdaptive(wasmModule, opts = {}) {
  const {
    minIterations  = 50,
    maxIterations  = 200,
    batchSize      = 25,
    vmThreshold    = 0.85,
    hwThreshold    = 0.80,
    hwMinIterations = 75,
    matrixSize     = 64,
    onBatch,
  } = opts;

  const wasm       = wasmModule;
  const allTimings = [];
  const batches    = [];       // per-batch timing snapshots
  let   stoppedAt  = null;    // { reason, iterations, vmConf, hwConf }
  let   checksum   = 0;

  const t_start = Date.now();

  while (allTimings.length < maxIterations) {
    const n      = Math.min(batchSize, maxIterations - allTimings.length);
    const result = wasm.run_entropy_probe(n, matrixSize);
    const chunk  = Array.from(result.timings);

    allTimings.push(...chunk);
    checksum += result.checksum;

    const sig = quickSignal(allTimings);
    batches.push({ iterations: allTimings.length, ...sig });

    // Fire progress callback with live signal so callers can stream to UI
    if (typeof onBatch === 'function') {
      try {
        onBatch({
          iterations:   allTimings.length,
          maxIterations,
          pct:          Math.round(allTimings.length / maxIterations * 100),
          vmConf:       sig.vmConf,
          hwConf:       sig.hwConf,
          qe:           sig.qe,
          cv:           sig.cv,
          lag1:         sig.lag1,
          // Thresholds: 0.70 — high enough that a legitimate device won't be
        // shown a false early verdict from a noisy first batch.
        // 'borderline' surfaces when one axis is moderate but not decisive.
        earlyVerdict: sig.vmConf > 0.70 ? 'vm'
          : sig.hwConf > 0.70 ? 'physical'
          : (sig.vmConf > 0.45 || sig.hwConf > 0.45) ? 'borderline'
          : 'uncertain',
        });
      } catch (e) { if (typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production') console.error('[pulse] onBatch error:', e); }
    }

    // ── Early-exit checks ──────────────────────────────────────────────────
    if (allTimings.length < minIterations) continue;

    if (sig.vmConf >= vmThreshold) {
      stoppedAt = { reason: 'VM_SIGNAL_DECISIVE', vmConf: sig.vmConf, hwConf: sig.hwConf };
      break;
    }

    if (allTimings.length >= hwMinIterations && sig.hwConf >= hwThreshold) {
      stoppedAt = { reason: 'PHYSICAL_SIGNAL_DECISIVE', vmConf: sig.vmConf, hwConf: sig.hwConf };
      break;
    }
  }

  const elapsed          = Date.now() - t_start;
  const iterationsRan    = allTimings.length;
  const iterationsSaved  = maxIterations - iterationsRan;
  const speedupFactor    = maxIterations / iterationsRan;

  // ── Resolution probe using cached WASM call ────────────────────────────
  const resResult     = wasm.run_entropy_probe(1, 4); // tiny probe for resolution
  const resProbe      = Array.from(resResult.resolution_probe ?? []);

  const resDeltas = [];
  for (let i = 1; i < resProbe.length; i++) {
    const d = resProbe[i] - resProbe[i - 1];
    if (d > 0) resDeltas.push(d);
  }

  return {
    timings:          allTimings,
    iterations:       iterationsRan,
    maxIterations,
    checksum:         checksum.toString(),
    resolutionProbe:  resProbe,
    timerGranularityMs: resDeltas.length
      ? resDeltas.reduce((a, b) => Math.min(a, b), Infinity)
      : null,
    earlyExit: stoppedAt ? {
      ...stoppedAt,
      iterationsSaved,
      timeSavedMs:    Math.round(iterationsSaved * (elapsed / iterationsRan)),
      speedupFactor:  +speedupFactor.toFixed(2),
    } : null,
    batches,
    elapsedMs: elapsed,
    collectedAt: t_start,
    matrixSize,
    phased: false, // adaptive replaces phased for speed
  };
}

/**
 * @typedef {object} AdaptiveEntropyResult
 * @property {number[]}  timings
 * @property {number}    iterations         - how many actually ran
 * @property {number}    maxIterations      - cap that was set
 * @property {object|null} earlyExit        - null if ran to completion
 * @property {object[]}  batches            - per-batch signal snapshots
 * @property {number}    elapsedMs
 */

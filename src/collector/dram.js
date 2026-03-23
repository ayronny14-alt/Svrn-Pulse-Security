/**
 * @svrnsec/pulse — DRAM Refresh Cycle Detector
 *
 * DDR4 DRAM refreshes every 7.8 ms (tREFI per JEDEC JESD79-4). During a
 * refresh, the memory controller stalls all access requests for ~350 ns.
 * In a tight sequential memory access loop this appears as a periodic
 * slowdown — detectable as a ~128Hz peak in the autocorrelation of access
 * timings.
 *
 * Virtual machines do not have physical DRAM. The hypervisor's memory
 * subsystem does not reproduce the refresh cycle because:
 *   1. The guest never touches real DRAM directly — there is always a
 *      hypervisor-controlled indirection layer.
 *   2. EPT/NPT (Extended/Nested Page Tables) absorb the timing.
 *   3. The hypervisor's memory balloon driver further smooths access latency.
 *
 * What we detect
 * ──────────────
 *   refreshPeriodMs     estimated DRAM refresh period (should be ~7.8ms on real DDR4)
 *   refreshPresent      true if the ~7.8ms periodicity is statistically significant
 *   peakLag             autocorrelation lag with the highest power (units: sample index)
 *   peakPower           autocorrelation power at peakLag (0–1)
 *   verdict             'dram' | 'virtual' | 'ambiguous'
 *
 * Calibration
 * ───────────
 * We allocate a buffer large enough to exceed all CPU caches (typically
 * L3 = 8–32 MB on consumer parts). Sequential reads then go to DRAM, not
 * cache. The refresh stall is only visible when we're actually hitting DRAM —
 * a cache-resident access loop shows no refresh signal.
 *
 * Buffer size: 64 MB — comfortably above L3 on all tested platforms.
 * Sampling interval: ~1 ms per iteration (chosen to resolve 7.8ms at ≥8 pts).
 * Total probe time: ~400 ms — well within the fingerprint collection window.
 */

const DRAM_REFRESH_MS    = 7.8;   // JEDEC DDR4 nominal
const DRAM_REFRESH_SLACK = 1.5;   // ±1.5 ms acceptable range for real hardware
const BUFFER_MB          = 64;    // must exceed L3 cache
const PROBE_ITERATIONS   = 400;   // ~400 ms total

/* ─── collectDramTimings ─────────────────────────────────────────────────── */

/**
 * @param {object} [opts]
 * @param {number} [opts.iterations=400]
 * @param {number} [opts.bufferMb=64]
 * @returns {{ timings: number[], refreshPeriodMs: number|null,
 *             refreshPresent: boolean, peakLag: number, peakPower: number,
 *             verdict: string }}
 */
export function collectDramTimings(opts = {}) {
  const {
    iterations = PROBE_ITERATIONS,
    bufferMb   = BUFFER_MB,
  } = opts;

  // ── Allocate cache-busting buffer ────────────────────────────────────────
  const nElements  = (bufferMb * 1024 * 1024) / 8;  // 64-bit doubles
  let   buf;

  try {
    buf = new Float64Array(nElements);
    // Touch every cache line to ensure OS actually maps the pages
    const stride = 64 / 8; // 64-byte cache lines, 8 bytes per element
    for (let i = 0; i < nElements; i += stride) buf[i] = i;
  } catch {
    // Allocation failure (memory constrained) — cannot run this probe
    return _noSignal('buffer allocation failed');
  }

  // ── Sequential access loop ───────────────────────────────────────────────
  // Each iteration does a full sequential pass over `passElements` worth of
  // the buffer. Pass size is tuned so each iteration takes ~1 ms wall-clock,
  // giving us enough resolution to see the 7.8 ms refresh cycle.
  //
  // We start with a small pass and auto-calibrate to hit the 1 ms target.
  const passElements = _calibratePassSize(buf);

  const timings = new Float64Array(iterations);
  let   checksum = 0;

  for (let iter = 0; iter < iterations; iter++) {
    const t0 = performance.now();
    for (let i = 0; i < passElements; i++) checksum += buf[i];
    timings[iter] = performance.now() - t0;
  }

  // Prevent dead-code elimination
  if (checksum === 0) buf[0] = 1;

  // ── Autocorrelation over timings ─────────────────────────────────────────
  // The refresh stall appears as elevated autocorrelation at lag ≈ 7.8 / Δt
  // where Δt is the mean iteration time in ms.
  const meanIterMs = _mean(timings);
  if (meanIterMs <= 0) return _noSignal('zero mean iteration time');

  const targetLag  = Math.round(DRAM_REFRESH_MS / meanIterMs);
  const maxLag     = Math.min(Math.round(50 / meanIterMs), iterations >> 1);

  const ac = _autocorr(Array.from(timings), maxLag);

  // Find the peak in the range [targetLag ± slack]
  const slackLags = Math.round(DRAM_REFRESH_SLACK / meanIterMs);
  const lagLo     = Math.max(1, targetLag - slackLags);
  const lagHi     = Math.min(maxLag, targetLag + slackLags);

  let peakPower = -Infinity;
  let peakLag   = targetLag;
  for (let l = lagLo; l <= lagHi; l++) {
    if (ac[l - 1] > peakPower) {
      peakPower = ac[l - 1];
      peakLag   = l;
    }
  }

  // Baseline: average autocorrelation outside the refresh window
  const baseline = _mean(
    Array.from({ length: maxLag }, (_, i) => ac[i])
      .filter((_, i) => i + 1 < lagLo || i + 1 > lagHi)
  );

  const snr              = baseline > 0 ? peakPower / baseline : 0;
  const refreshPresent   = peakPower > 0.15 && snr > 1.8;
  const refreshPeriodMs  = refreshPresent ? peakLag * meanIterMs : null;

  const verdict =
    refreshPresent && refreshPeriodMs !== null &&
    Math.abs(refreshPeriodMs - DRAM_REFRESH_MS) < DRAM_REFRESH_SLACK
      ? 'dram'
      : peakPower < 0.05
        ? 'virtual'
        : 'ambiguous';

  return {
    timings:         Array.from(timings),
    refreshPeriodMs,
    refreshPresent,
    peakLag,
    peakPower:       +peakPower.toFixed(4),
    snr:             +snr.toFixed(2),
    meanIterMs:      +meanIterMs.toFixed(3),
    verdict,
  };
}

/* ─── helpers ────────────────────────────────────────────────────────────── */

function _noSignal(reason) {
  return {
    timings: [], refreshPeriodMs: null, refreshPresent: false,
    peakLag: 0, peakPower: 0, snr: 0, meanIterMs: 0,
    verdict: 'ambiguous', reason,
  };
}

/**
 * Run a quick calibration pass to find how many elements to read per
 * iteration so each iteration takes approximately 1 ms.
 */
function _calibratePassSize(buf) {
  const target  = 1.0; // ms
  let   n       = Math.min(100_000, buf.length);
  let   elapsed = 0;
  let   dummy   = 0;

  // Warm up
  for (let i = 0; i < n; i++) dummy += buf[i];

  // Measure
  const t0 = performance.now();
  for (let i = 0; i < n; i++) dummy += buf[i];
  elapsed = performance.now() - t0;
  if (dummy === 0) buf[0] = 1; // prevent DCE

  if (elapsed <= 0) return n;
  return Math.min(buf.length, Math.round(n * (target / elapsed)));
}

function _mean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((s, v) => s + v, 0) / arr.length;
}

function _autocorr(data, maxLag) {
  const n    = data.length;
  const mean = _mean(data);
  let   v    = 0;
  for (let i = 0; i < n; i++) v += (data[i] - mean) ** 2;
  v /= n;

  const result = new Float64Array(maxLag);
  if (v < 1e-14) return result;

  for (let lag = 1; lag <= maxLag; lag++) {
    let cov = 0;
    for (let i = 0; i < n - lag; i++) {
      cov += (data[i] - mean) * (data[i + lag] - mean);
    }
    result[lag - 1] = cov / ((n - lag) * v);
  }
  return result;
}

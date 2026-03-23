/**
 * pulse_core — pure-JavaScript probe engine
 *
 * This module ships the entropy probe as portable JS so the package works
 * out-of-the-box without a Rust toolchain.  When a compiled .wasm binary is
 * present (dropped in via `build.sh`) this file is replaced by the wasm-pack
 * output and the native engine runs instead.
 *
 * Physics model
 * ─────────────
 * Real silicon: DRAM refresh cycles, branch-predictor misses, and L3-cache
 * evictions inject sub-microsecond noise into any tight compute loop.
 * Hypervisors virtualise the TSC and smooth those interrupts out, leaving
 * a near-flat timing distribution that our QE/EJR checks catch.
 *
 * The JS loop below is a faithful port of the Rust matrix-multiply probe:
 * same work unit (N×N DGEMM-style loop), same checksum accumulation to
 * prevent dead-code elimination, same resolution micro-probe.
 */

/* ─── clock ─────────────────────────────────────────────────────────────── */

const _now = (typeof performance !== 'undefined' && typeof performance.now === 'function')
  ? () => performance.now()
  : (() => {
      // Node.js fallback: process.hrtime.bigint() → milliseconds
      const _hr = process.hrtime.bigint;
      return () => Number(_hr()) / 1_000_000;
    })();

/* ─── init (no-op for the JS engine) ───────────────────────────────────── */

/**
 * Initialise the engine.  When a real .wasm binary is supplied the wasm-pack
 * glue calls WebAssembly.instantiateStreaming here.  The JS engine is already
 * "compiled", so we return immediately.
 *
 * @param {string|URL|Request|BufferSource|WebAssembly.Module} [_source]
 * @returns {Promise<void>}
 */
export default async function init(_source) {
  // JS engine is ready synchronously — nothing to stream or compile.
}

/* ─── run_entropy_probe ─────────────────────────────────────────────────── */

/**
 * Run N iterations of a matrix-multiply work unit and record wall-clock time
 * per iteration.  The distribution of those times is what the heuristic
 * engine analyses.
 *
 * @param {number} iterations  – number of timing samples to collect
 * @param {number} matrixSize  – N for the N×N multiply (default 64)
 * @returns {{ timings: Float64Array, checksum: number, resolution_probe: Float64Array }}
 */
export function run_entropy_probe(iterations, matrixSize = 64) {
  const N = matrixSize | 0;

  // Persistent working matrices — allocated once per probe to avoid GC noise.
  const A = new Float64Array(N * N);
  const B = new Float64Array(N * N);
  const C = new Float64Array(N * N);

  // Seed matrices with pseudo-random data (deterministic per call for
  // reproducibility, but different each run due to xorshift seeding from time).
  let seed = (_now() * 1e6) | 0 || 0xdeadbeef;
  const xr  = () => { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; return (seed >>> 0) / 4294967296; };
  for (let i = 0; i < N * N; i++) { A[i] = xr(); B[i] = xr(); }

  const timings         = new Float64Array(iterations);
  const resolution_probe = new Float64Array(32);
  let   checksum        = 0;

  for (let iter = 0; iter < iterations; iter++) {
    // Zero accumulator each round (realistic cache pressure).
    C.fill(0);

    const t0 = _now();

    // N×N matrix multiply: C = A · B  (ikj loop order for cache friendliness)
    for (let i = 0; i < N; i++) {
      const rowA = i * N;
      const rowC = i * N;
      for (let k = 0; k < N; k++) {
        const aik   = A[rowA + k];
        const rowBk = k * N;
        for (let j = 0; j < N; j++) {
          C[rowC + j] += aik * B[rowBk + j];
        }
      }
    }

    const t1 = _now();
    timings[iter] = t1 - t0;

    // Accumulate one element so the compiler cannot eliminate the work.
    checksum += C[0];
  }

  // Resolution micro-probe: fire 32 back-to-back timestamps.
  // The minimum non-zero delta reveals timer granularity.
  for (let i = 0; i < resolution_probe.length; i++) {
    resolution_probe[i] = _now();
  }

  return { timings, checksum, resolution_probe };
}

/* ─── run_memory_probe ──────────────────────────────────────────────────── */

/**
 * Sequential read/write bandwidth probe over a large buffer.
 * Memory latency variance is a secondary signal (NUMA, DRAM refresh).
 *
 * @param {number} memSizeKb    – buffer size in kibibytes
 * @param {number} memIterations
 * @returns {{ timings: Float64Array, checksum: number }}
 */
export function run_memory_probe(memSizeKb = 512, memIterations = 50) {
  const len     = (memSizeKb * 1024 / 8) | 0;   // 64-bit elements
  const buf     = new Float64Array(len);
  const timings = new Float64Array(memIterations);
  let   checksum = 0;

  // Warm-up pass (fills TLB, avoids first-access bias)
  for (let i = 0; i < len; i++) buf[i] = i;

  for (let iter = 0; iter < memIterations; iter++) {
    const t0 = _now();
    // Sequential read-modify-write
    for (let i = 0; i < len; i++) buf[i] = buf[i] * 1.0000001;
    const t1 = _now();

    timings[iter] = t1 - t0;
    checksum += buf[0];
  }

  return { timings, checksum };
}

/* ─── compute_autocorrelation ───────────────────────────────────────────── */

/**
 * Pearson autocorrelation for lags 1..maxLag.
 * O(n·maxLag) — kept cheap by the adaptive early-exit cap.
 *
 * @param {ArrayLike<number>} data
 * @param {number}            maxLag
 * @returns {Float64Array}  length = maxLag, index 0 = lag-1
 */
export function compute_autocorrelation(data, maxLag) {
  const n    = data.length;
  let   mean = 0;
  for (let i = 0; i < n; i++) mean += data[i];
  mean /= n;

  let variance = 0;
  for (let i = 0; i < n; i++) variance += (data[i] - mean) ** 2;
  variance /= n;

  const result = new Float64Array(maxLag);
  if (variance < 1e-14) return result;          // degenerate — all identical

  for (let lag = 1; lag <= maxLag; lag++) {
    let cov = 0;
    for (let i = 0; i < n - lag; i++) {
      cov += (data[i] - mean) * (data[i + lag] - mean);
    }
    result[lag - 1] = cov / ((n - lag) * variance);
  }

  return result;
}

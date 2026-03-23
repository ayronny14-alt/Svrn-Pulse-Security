/**
 * @sovereign/pulse — Statistical Jitter Analysis
 *
 * Analyses the timing distribution from the entropy probe to classify
 * the host as a real consumer device or a sanitised datacenter VM.
 *
 * Core insight:
 *   Real hardware  → thermal throttling, OS context switches, DRAM refresh
 *                    cycles create a characteristic "noisy" but physically
 *                    plausible timing distribution.
 *   Datacenter VM  → hypervisor scheduler presents a nearly-flat execution
 *                    curve; thermal feedback is absent; timer may be
 *                    quantised to the host's scheduler quantum.
 */

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Full statistical analysis of a timing vector.
 *
 * @param {number[]} timings  - per-iteration millisecond deltas from WASM probe
 * @param {object}   [opts]
 * @param {object}   [opts.autocorrelations]  - pre-computed { lag1 … lag10 }
 * @returns {JitterAnalysis}
 */
export function classifyJitter(timings, opts = {}) {
  if (!timings || timings.length < 10) {
    return _insufficientData();
  }

  const stats       = computeStats(timings);
  const autocorr    = opts.autocorrelations ?? _computeLocalAutocorr(timings);
  const hurst       = computeHurst(timings);
  const quantEnt    = detectQuantizationEntropy(timings);
  const thermal     = detectThermalSignature(timings);
  const outlierRate = _outlierRate(timings, stats);

  // ── Scoring rubric ───────────────────────────────────────────────────────
  // Each criterion contributes 0–1 to a weighted sum.
  // Weights sum to 1.0; final score is in [0, 1].
  //   1.0 = almost certainly a real consumer device + real silicon
  //   0.0 = almost certainly a sanitised VM / AI instance

  const components = {};
  const flags      = [];

  // 1. Coefficient of Variation  (weight 0.25)
  //    Real hardware: CV ∈ [0.04, 0.35]
  //    VM:            CV often < 0.02 ("too flat") or > 0.5 (scheduler bursts)
  let cvScore = 0;
  if (stats.cv >= 0.04 && stats.cv <= 0.35) {
    cvScore = 1.0;
  } else if (stats.cv >= 0.02 && stats.cv < 0.04) {
    cvScore = (stats.cv - 0.02) / 0.02; // linear ramp up
    flags.push('LOW_CV_BORDERLINE');
  } else if (stats.cv > 0.35 && stats.cv < 0.5) {
    cvScore = 1.0 - (stats.cv - 0.35) / 0.15; // ramp down
    flags.push('HIGH_CV_POSSIBLE_SCHEDULER_BURST');
  } else if (stats.cv < 0.02) {
    cvScore = 0;
    flags.push('CV_TOO_FLAT_VM_INDICATOR');
  } else {
    cvScore = 0.2;
    flags.push('CV_TOO_HIGH_SCHEDULER_BURST');
  }
  components.cv = { score: cvScore, weight: 0.25, value: stats.cv };

  // 2. Autocorrelation profile  (weight 0.20)
  //    Real thermal noise → all lags near 0 (i.i.d. / Brownian)
  //    VM hypervisor scheduler → positive autocorr (periodic steal-time bursts)
  //    We use the maximum absolute autocorrelation across all measured lags
  //    to catch both lag-1 and longer-period scheduler artifacts.
  const acVals   = Object.values(autocorr).filter(v => v != null);
  const maxAbsAC = acVals.length ? Math.max(...acVals.map(Math.abs)) : 0;
  const meanAbsAC = acVals.length ? acVals.reduce((s, v) => s + Math.abs(v), 0) / acVals.length : 0;
  const acStat   = (maxAbsAC + meanAbsAC) / 2; // blend: worst + average

  let ac1Score = 0;
  if (acStat < 0.12) {
    ac1Score = 1.0;
  } else if (acStat < 0.28) {
    ac1Score = 1.0 - (acStat - 0.12) / 0.16;
    flags.push('MODERATE_AUTOCORR_POSSIBLE_SCHEDULER');
  } else {
    ac1Score = 0;
    flags.push('HIGH_AUTOCORR_VM_SCHEDULER_DETECTED');
  }
  components.autocorr = { score: ac1Score, weight: 0.20, value: acStat };

  // 3. Quantization Entropy  (weight 0.20)
  //    High entropy → timings are spread, not clustered on fixed boundaries
  //    Low entropy  → values cluster on integer-ms ticks (legacy VM timer)
  let qeScore = 0;
  if (quantEnt >= 4.5) {
    qeScore = 1.0;
  } else if (quantEnt >= 3.0) {
    qeScore = (quantEnt - 3.0) / 1.5;
  } else {
    qeScore = 0;
    flags.push('LOW_QUANTIZATION_ENTROPY_SYNTHETIC_TIMER');
  }
  components.quantization = { score: qeScore, weight: 0.20, value: quantEnt };

  // 4. Hurst Exponent  (weight 0.15)
  //    Genuine white thermal noise → H ≈ 0.5
  //    VM scheduler periodicity   → H > 0.7 (persistent / self-similar)
  //    Synthetic / replayed       → H near 0 or 1
  let hurstScore = 0;
  const hurstDev = Math.abs(hurst - 0.5);
  if (hurstDev < 0.10) {
    hurstScore = 1.0;
  } else if (hurstDev < 0.25) {
    hurstScore = 1.0 - (hurstDev - 0.10) / 0.15;
    if (hurst > 0.7) flags.push('HIGH_HURST_VM_SCHEDULER_PERIODICITY');
  } else {
    hurstScore = 0;
    if (hurst > 0.7)      flags.push('VERY_HIGH_HURST_VM');
    else if (hurst < 0.3) flags.push('VERY_LOW_HURST_ANTIPERSISTENT');
  }
  components.hurst = { score: hurstScore, weight: 0.15, value: hurst };

  // 5. Thermal signature  (weight 0.10)
  //    Real CPU under sustained load → upward drift or sawtooth (fan cycling)
  //    VM: flat timing regardless of simulated load (no thermal feedback loop)
  let thermalScore = 0;
  if (thermal.pattern === 'rising' || thermal.pattern === 'sawtooth') {
    thermalScore = 1.0;
  } else if (Math.abs(thermal.slope) > 5e-5) {
    thermalScore = 0.5; // some drift present
    flags.push('WEAK_THERMAL_SIGNATURE');
  } else {
    thermalScore = 0;
    flags.push('FLAT_THERMAL_PROFILE_VM_INDICATOR');
  }
  components.thermal = { score: thermalScore, weight: 0.10, value: thermal.slope };

  // 6. Outlier rate  (weight 0.10)
  //    Context switches on real OS → occasional timing spikes (> 3σ)
  //    VMs: far fewer OS-level interruptions visible to guest
  let outlierScore = 0;
  if (outlierRate >= 0.02 && outlierRate <= 0.15) {
    outlierScore = 1.0;
  } else if (outlierRate > 0 && outlierRate < 0.02) {
    outlierScore = outlierRate / 0.02;
    flags.push('FEW_OUTLIERS_POSSIBLY_VM');
  } else if (outlierRate > 0.15) {
    outlierScore = Math.max(0, 1.0 - (outlierRate - 0.15) / 0.15);
    flags.push('EXCESSIVE_OUTLIERS_UNSTABLE');
  }
  components.outliers = { score: outlierScore, weight: 0.10, value: outlierRate };

  // ── Weighted aggregate ────────────────────────────────────────────────────
  const score = Object.values(components)
    .reduce((sum, c) => sum + c.score * c.weight, 0);

  return {
    score: Math.max(0, Math.min(1, score)),
    flags,
    components,
    stats,
    autocorrelations: autocorr,
    hurstExponent:    hurst,
    quantizationEntropy: quantEnt,
    thermalSignature: thermal,
    outlierRate,
  };
}

// ---------------------------------------------------------------------------
// computeStats
// ---------------------------------------------------------------------------

/**
 * Descriptive statistics for a timing vector.
 * @param {number[]} arr
 * @returns {TimingStats}
 */
export function computeStats(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const n      = arr.length;
  const mean   = arr.reduce((s, v) => s + v, 0) / n;
  const varr   = arr.reduce((s, v) => s + (v - mean) ** 2, 0) / (n - 1);
  const std    = Math.sqrt(varr);

  const pct = (p) => {
    const idx = (p / 100) * (n - 1);
    const lo  = Math.floor(idx);
    const hi  = Math.ceil(idx);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
  };

  // Skewness (Fisher-Pearson)
  const skew = n < 3 ? 0 :
    arr.reduce((s, v) => s + ((v - mean) / std) ** 3, 0) *
    (n / ((n - 1) * (n - 2)));

  // Excess kurtosis
  const kurt = n < 4 ? 0 :
    (arr.reduce((s, v) => s + ((v - mean) / std) ** 4, 0) *
     (n * (n + 1)) / ((n - 1) * (n - 2) * (n - 3))) -
    (3 * (n - 1) ** 2) / ((n - 2) * (n - 3));

  return {
    n, mean, std,
    cv:       std / mean,
    min:      sorted[0],
    max:      sorted[n - 1],
    p5:       pct(5),
    p25:      pct(25),
    p50:      pct(50),
    p75:      pct(75),
    p95:      pct(95),
    p99:      pct(99),
    skewness: skew,
    kurtosis: kurt,
  };
}

/**
 * @typedef {object} TimingStats
 * @property {number} n
 * @property {number} mean
 * @property {number} std
 * @property {number} cv
 * @property {number} min
 * @property {number} max
 * @property {number} p5
 * @property {number} p25
 * @property {number} p50
 * @property {number} p75
 * @property {number} p95
 * @property {number} p99
 * @property {number} skewness
 * @property {number} kurtosis
 */

// ---------------------------------------------------------------------------
// computeHurst
// ---------------------------------------------------------------------------

/**
 * Estimates the Hurst exponent via Rescaled Range (R/S) analysis.
 * Covers 4 sub-series sizes (n/4, n/3, n/2, n) to get a log-log slope.
 *
 * H ≈ 0.5 → random walk (Brownian, thermal noise)
 * H > 0.5 → persistent (VM hypervisor periodicity)
 * H < 0.5 → anti-persistent
 *
 * @param {number[]} arr
 * @returns {number}
 */
export function computeHurst(arr) {
  const n = arr.length;
  if (n < 16) return 0.5; // not enough data

  const sizes = [
    Math.floor(n / 4),
    Math.floor(n / 3),
    Math.floor(n / 2),
    n,
  ].filter(s => s >= 8);

  const points = sizes.map(s => {
    const rs = _rescaledRange(arr.slice(0, s));
    return [Math.log(s), Math.log(rs)];
  });

  // Ordinary least squares on log-log
  const xMean = points.reduce((s, p) => s + p[0], 0) / points.length;
  const yMean = points.reduce((s, p) => s + p[1], 0) / points.length;
  let num = 0, den = 0;
  for (const [x, y] of points) {
    num += (x - xMean) * (y - yMean);
    den += (x - xMean) ** 2;
  }
  const H = den === 0 ? 0.5 : num / den;
  return Math.max(0, Math.min(1, H));
}

function _rescaledRange(arr) {
  const n    = arr.length;
  const mean = arr.reduce((s, v) => s + v, 0) / n;
  const dev  = arr.map(v => v - mean);

  // Cumulative deviation
  const cum = [];
  let acc = 0;
  for (const d of dev) { acc += d; cum.push(acc); }

  const R = Math.max(...cum) - Math.min(...cum);
  const S = Math.sqrt(arr.reduce((s, v) => s + (v - mean) ** 2, 0) / n);
  return S === 0 ? 1 : R / S;
}

// ---------------------------------------------------------------------------
// detectQuantizationEntropy
// ---------------------------------------------------------------------------

/**
 * Computes Shannon entropy of a histogram of timing values.
 * Low entropy (< 3 bits) indicates clustered / quantised timings (VM timer).
 *
 * @param {number[]} arr
 * @param {number}   [binWidthMs=0.2]
 * @returns {number}  entropy in bits
 */
export function detectQuantizationEntropy(arr, binWidthMs = 0.2) {
  if (!arr.length) return 0;
  const bins = new Map();
  for (const v of arr) {
    const bin = Math.round(v / binWidthMs);
    bins.set(bin, (bins.get(bin) ?? 0) + 1);
  }
  const n = arr.length;
  let H = 0;
  for (const count of bins.values()) {
    const p = count / n;
    H -= p * Math.log2(p);
  }
  return H;
}

// ---------------------------------------------------------------------------
// detectThermalSignature
// ---------------------------------------------------------------------------

/**
 * Analyses whether the timing series shows a thermal throttle pattern:
 * a rising trend (CPU heating up) or sawtooth (fan intervention).
 *
 * @param {number[]} arr
 * @returns {{ slope: number, pattern: 'rising'|'falling'|'sawtooth'|'flat', r2: number }}
 */
export function detectThermalSignature(arr) {
  const n    = arr.length;
  if (n < 10) return { slope: 0, pattern: 'flat', r2: 0 };

  // Linear regression (timing vs sample index)
  const xMean = (n - 1) / 2;
  const yMean = arr.reduce((s, v) => s + v, 0) / n;
  let num = 0, den = 0;
  for (let i = 0; i < n; i++) {
    num += (i - xMean) * (arr[i] - yMean);
    den += (i - xMean) ** 2;
  }
  const slope = den === 0 ? 0 : num / den;

  // R² of linear fit
  const ss_res = arr.reduce((s, v, i) => {
    const pred = yMean + slope * (i - xMean);
    return s + (v - pred) ** 2;
  }, 0);
  const ss_tot = arr.reduce((s, v) => s + (v - yMean) ** 2, 0);
  const r2 = ss_tot === 0 ? 0 : 1 - ss_res / ss_tot;

  // Sawtooth detection: look for a drop > 2σ after a rising segment
  const std  = Math.sqrt(arr.reduce((s, v) => s + (v - yMean) ** 2, 0) / n);
  let sawtoothCount = 0;
  for (let i = 1; i < n; i++) {
    if (arr[i - 1] - arr[i] > 2 * std) sawtoothCount++;
  }

  let pattern;
  if (sawtoothCount >= 2)   pattern = 'sawtooth';
  else if (slope > 5e-5)    pattern = 'rising';
  else if (slope < -5e-5)   pattern = 'falling';
  else                      pattern = 'flat';

  return { slope, pattern, r2, sawtoothCount };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _outlierRate(arr, stats) {
  const threshold = stats.mean + 3 * stats.std;
  return arr.filter(v => v > threshold).length / arr.length;
}

function _computeLocalAutocorr(arr) {
  const autocorr = {};
  for (const lag of [1, 2, 3, 5, 10]) {
    autocorr[`lag${lag}`] = _pearsonAC(arr, lag);
  }
  return autocorr;
}

function _pearsonAC(arr, lag) {
  const n = arr.length;
  if (lag >= n) return 0;
  const valid = n - lag;
  const mean  = arr.reduce((s, v) => s + v, 0) / n;
  let num = 0, da = 0, db = 0;
  for (let i = 0; i < valid; i++) {
    const a = arr[i]       - mean;
    const b = arr[i + lag] - mean;
    num += a * b;
    da  += a * a;
    db  += b * b;
  }
  const denom = Math.sqrt(da * db);
  return denom < 1e-14 ? 0 : num / denom;
}

function _insufficientData() {
  return {
    score: 0,
    flags: ['INSUFFICIENT_DATA'],
    components:          {},
    stats:               null,
    autocorrelations:    {},
    hurstExponent:       0.5,
    quantizationEntropy: 0,
    thermalSignature:    { slope: 0, pattern: 'flat', r2: 0 },
    outlierRate:         0,
  };
}

/**
 * @typedef {object} JitterAnalysis
 * @property {number}   score              - [0,1], 1 = real hardware
 * @property {string[]} flags              - diagnostic flags
 * @property {object}   components         - per-criterion scores and weights
 * @property {TimingStats} stats
 * @property {object}   autocorrelations
 * @property {number}   hurstExponent
 * @property {number}   quantizationEntropy
 * @property {object}   thermalSignature
 * @property {number}   outlierRate
 */

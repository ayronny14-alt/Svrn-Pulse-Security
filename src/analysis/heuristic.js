/**
 * @sovereign/pulse — Cross-Metric Heuristic Engine
 *
 * Instead of checking individual thresholds in isolation, this module looks
 * at the *relationships* between metrics. A sophisticated adversary can spoof
 * any single number.  Spoofing six metrics so they remain mutually consistent
 * with physical laws is exponentially harder.
 *
 * Three core insights drive this engine:
 *
 *   1. Entropy-Jitter Coherence
 *      Real silicon gets noisier as it heats up. Under sustained load, the
 *      Quantization Entropy of the timing distribution grows because thermal
 *      fluctuations add variance. A VM's hypervisor clock doesn't care about
 *      guest temperature — its entropy is flat across all load phases.
 *
 *   2. Hurst-Autocorrelation Coherence
 *      Genuine Brownian noise has Hurst ≈ 0.5 and near-zero autocorrelation
 *      at all lags. These two values are physically linked. If they diverge —
 *      high autocorrelation but Hurst near 0.5, or vice versa — the timings
 *      were generated, not measured.
 *
 *   3. CV-Entropy Coherence
 *      High variance (CV) must come from somewhere. On real hardware, high CV
 *      means the timing distribution is spread out, which also means high
 *      entropy. A VM that inflates CV without inflating entropy (e.g. by
 *      adding synthetic outliers at fixed offsets) produces a coherence gap.
 */

import { detectQuantizationEntropy } from './jitter.js';

// ---------------------------------------------------------------------------
// runHeuristicEngine
// ---------------------------------------------------------------------------

/**
 * @param {object} p
 * @param {import('./jitter.js').JitterAnalysis}  p.jitter
 * @param {object|null}                           p.phases  - from entropy collector
 * @param {object}                                p.autocorrelations
 * @returns {HeuristicReport}
 */
export function runHeuristicEngine({ jitter, phases, autocorrelations }) {
  const findings = [];
  const bonuses  = [];
  let   penalty  = 0;  // accumulated penalty [0, 1]
  let   bonus    = 0;  // accumulated bonus   [0, 1]

  const stats = jitter.stats;
  if (!stats) return _empty();

  // ── 1. Entropy-Jitter Ratio (phases required) ────────────────────────────
  let entropyJitterRatio  = null;
  let entropyJitterScore  = 0.5; // neutral if no phased data

  if (phases) {
    entropyJitterRatio = phases.entropyJitterRatio;

    if (entropyJitterRatio >= 1.08) {
      // Clear entropy growth under load — signature of real thermal feedback
      entropyJitterScore = 1.0;
      bonuses.push({
        id:     'ENTROPY_GROWS_WITH_LOAD',
        label:  'Entropy grew under load (thermal feedback confirmed)',
        detail: `ratio=${entropyJitterRatio.toFixed(3)}  cold_QE=${phases.cold.qe.toFixed(3)}  hot_QE=${phases.hot.qe.toFixed(3)}`,
        value:  0.12,
      });
      bonus += 0.12;
    } else if (entropyJitterRatio >= 1.02) {
      entropyJitterScore = 0.7;
      findings.push({
        id:     'ENTROPY_MILD_GROWTH',
        label:  'Weak entropy growth under load',
        detail: `ratio=${entropyJitterRatio.toFixed(3)}`,
        severity: 'info',
        penalty: 0,
      });
    } else if (entropyJitterRatio < 1.02 && entropyJitterRatio > 0.95) {
      // Flat entropy across phases → hypervisor clock insensitive to guest load
      entropyJitterScore = 0.2;
      findings.push({
        id:      'ENTROPY_FLAT_UNDER_LOAD',
        label:   'Entropy did not grow under load — hypervisor clock suspected',
        detail:  `ratio=${entropyJitterRatio.toFixed(3)}  (expected ≥ 1.08 for real hardware)`,
        severity: 'high',
        penalty:  0.10,
      });
      penalty += 0.10;
    } else if (entropyJitterRatio < 0.95) {
      // Entropy DECREASED — clock rounding became more aggressive under load
      entropyJitterScore = 0.0;
      findings.push({
        id:      'ENTROPY_DECREASES_UNDER_LOAD',
        label:   'Entropy shrank under load — hypervisor clock-rounding confirmed',
        detail:  `ratio=${entropyJitterRatio.toFixed(3)}  (clock rounding more aggressive at high load)`,
        severity: 'critical',
        penalty:  0.18,
      });
      penalty += 0.18;
    }

    // Phase mean drift: real CPU heats up → iterations get slower
    const coldToHotDrift = phases.hot.mean - phases.cold.mean;
    if (coldToHotDrift > 0.05) {
      bonuses.push({
        id:    'THERMAL_DRIFT_CONFIRMED',
        label: 'CPU mean timing increased from cold to hot phase (thermal drift)',
        detail: `cold=${phases.cold.mean.toFixed(3)}ms  hot=${phases.hot.mean.toFixed(3)}ms  Δ=${coldToHotDrift.toFixed(3)}ms`,
        value:  0.08,
      });
      bonus += 0.08;
    }
  }

  // ── 2. Hurst-Autocorrelation Coherence ───────────────────────────────────
  const h    = jitter.hurstExponent ?? 0.5;
  const ac1  = Math.abs(autocorrelations?.lag1  ?? 0);
  const ac5  = Math.abs(autocorrelations?.lag5  ?? 0);
  const ac50 = Math.abs(autocorrelations?.lag50 ?? 0);

  // Physical law: Brownian noise (H≈0.5) must have low autocorrelation.
  // Divergence between these two means the data wasn't generated by physics.
  const hurstExpectedAC = Math.abs(2 * h - 1); // theoretical max |autocorr| for given H
  const actualAC        = (ac1 + ac5) / 2;
  const acHurstDivergence = Math.abs(actualAC - hurstExpectedAC);

  if (acHurstDivergence > 0.35) {
    findings.push({
      id:      'HURST_AUTOCORR_INCOHERENT',
      label:   'Hurst exponent and autocorrelation are physically inconsistent',
      detail:  `H=${h.toFixed(3)}  expected_AC≈${hurstExpectedAC.toFixed(3)}  actual_AC=${actualAC.toFixed(3)}  divergence=${acHurstDivergence.toFixed(3)}`,
      severity: 'high',
      penalty:  0.12,
    });
    penalty += 0.12;
  } else if (h > 0.45 && h < 0.55 && ac1 < 0.15) {
    // Ideal Brownian + low autocorr — physically coherent
    bonuses.push({
      id:    'BROWNIAN_COHERENCE_CONFIRMED',
      label: 'Hurst ≈ 0.5 and autocorrelation near zero — genuine Brownian noise',
      detail: `H=${h.toFixed(3)}  lag1_AC=${ac1.toFixed(3)}`,
      value:  0.10,
    });
    bonus += 0.10;
  }

  // ── 3. CV-Entropy Coherence ───────────────────────────────────────────────
  // High CV should correlate with high QE. If CV is high but QE is low,
  // the variance was added artificially (fixed-offset outliers, synthetic spikes).
  const cv = stats.cv;
  const qe = jitter.quantizationEntropy;

  // Expected QE given CV, assuming roughly normal distribution
  // Normal dist with σ/μ = CV: entropy ≈ log2(σ * sqrt(2πe)) + log2(n/binWidth)
  // We use a simplified linear proxy calibrated against real benchmarks.
  const expectedQE = Math.max(0, 1.5 + cv * 16);  // empirical: CV=0.15 → QE≈3.9
  const qeDivergence = expectedQE - qe;            // positive = QE lower than expected

  if (qeDivergence > 1.8 && cv > 0.05) {
    // High variance but low entropy: synthetic outliers at fixed offsets
    findings.push({
      id:      'CV_ENTROPY_INCOHERENT',
      label:   'High CV but low entropy — variance appears synthetic (fixed-offset outliers)',
      detail:  `CV=${cv.toFixed(4)}  QE=${qe.toFixed(3)} bits  expected_QE≈${expectedQE.toFixed(3)}  gap=${qeDivergence.toFixed(3)}`,
      severity: 'high',
      penalty:  0.10,
    });
    penalty += 0.10;
  } else if (qeDivergence < 0.5 && cv > 0.08) {
    // CV and QE are coherent — timings come from a real distribution
    bonuses.push({
      id:    'CV_ENTROPY_COHERENT',
      label: 'Variance and entropy are physically coherent',
      detail: `CV=${cv.toFixed(4)}  QE=${qe.toFixed(3)}  expected≈${expectedQE.toFixed(3)}`,
      value:  0.06,
    });
    bonus += 0.06;
  }

  // ── 4. Steal-time periodicity (the "Picket Fence" detector) ─────────────
  // VM steal-time bursts create a periodic signal in the autocorrelation.
  // If lag-50 autocorrelation is significantly higher than lag-5,
  // the scheduler quantum is approximately 50× the mean iteration time.
  const picketFence = _detectPicketFence(autocorrelations);
  if (picketFence.detected) {
    findings.push({
      id:      'PICKET_FENCE_DETECTED',
      label:   `"Picket Fence" steal-time rhythm detected at lag ${picketFence.dominantLag}`,
      detail:  picketFence.detail,
      severity: 'high',
      penalty:  0.08,
    });
    penalty += 0.08;
  }

  // ── 5. Skewness-Kurtosis coherence ───────────────────────────────────────
  // Real hardware timing is right-skewed (occasional slow outliers from OS preemption).
  // VMs that add synthetic outliers at fixed offsets produce wrong skew/kurtosis.
  const skew = stats.skewness ?? 0;
  const kurt = stats.kurtosis ?? 0;

  if (skew > 0.3 && kurt > 0) {
    // Right-skewed, leptokurtic — consistent with OS preemption on real hardware
    bonuses.push({
      id:    'NATURAL_SKEW_CONFIRMED',
      label: 'Right-skewed distribution with positive kurtosis — OS preemption pattern',
      detail: `skew=${skew.toFixed(3)}  kurtosis=${kurt.toFixed(3)}`,
      value:  0.06,
    });
    bonus += 0.06;
  } else if (skew < 0 && Math.abs(kurt) > 1) {
    // Negative skew with high kurtosis: inconsistent with physical timing noise
    findings.push({
      id:      'SKEW_KURTOSIS_ANOMALY',
      label:   'Left-skewed distribution — inconsistent with natural hardware timing',
      detail:  `skew=${skew.toFixed(3)}  kurtosis=${kurt.toFixed(3)}`,
      severity: 'medium',
      penalty:  0.06,
    });
    penalty += 0.06;
  }

  // ── Physical floor protection (anti-compounding) ──────────────────────────
  // When the three PRIMARY timing metrics are clearly consistent with real
  // silicon, cap the penalty so that marginal secondary signals (weak Picket
  // Fence, mild EJR, slight skew anomaly) cannot compound into a rejection.
  //
  // Why: a modern i7 laptop running heavy browser extensions may show:
  //   EJR = 1.01  → -0.10 penalty (just under the 1.02 threshold)
  //   lag50 = 0.31 → picket fence → -0.08 penalty (background process rhythm)
  //   slight negative skew → -0.06 penalty
  //   total: -0.24, drops score from 0.73 → 0.49 → wrongly flagged as synthetic
  //
  // Solution: if ≥ 2 of the 3 primary metrics are unambiguously physical,
  // treat the device as "probably physical with some noise" and limit the
  // penalty to 0.22 (enough to lower confidence but not enough to reject).
  const clearQE   = jitter.quantizationEntropy    > 3.2;
  const clearCV   = stats.cv >= 0.05 && stats.cv <= 0.30;
  const clearLag1 = Math.abs(autocorrelations?.lag1 ?? 1) < 0.22;
  const clearPhysicalCount = [clearQE, clearCV, clearLag1].filter(Boolean).length;

  // Also check: if at least one metric is a HARD VM indicator (QE < 2.0 or
  // lag1 > 0.65), override the floor — the floor is for borderline noise, not
  // for devices that are clearly VMs on at least one axis.
  const hardVmSignal =
    jitter.quantizationEntropy < 2.0 ||
    Math.abs(autocorrelations?.lag1 ?? 0) > 0.65;

  const penaltyCap = (!hardVmSignal && clearPhysicalCount >= 2)
    ? 0.22   // physical floor: cap compounding for clearly physical devices
    : 0.60;  // default: full penalty range for ambiguous or VM-like signals

  const totalPenalty = Math.min(penaltyCap, penalty);
  const totalBonus   = Math.min(0.35, bonus);

  return {
    penalty:             totalPenalty,
    bonus:               totalBonus,
    netAdjustment:       totalBonus - totalPenalty,
    findings,
    bonuses,
    entropyJitterRatio,
    entropyJitterScore,
    picketFence,
    coherenceFlags: findings.map(f => f.id),
  };
}

/**
 * @typedef {object} HeuristicReport
 * @property {number}   penalty           - total score penalty [0, 0.60]
 * @property {number}   bonus             - total score bonus   [0, 0.35]
 * @property {number}   netAdjustment     - bonus - penalty
 * @property {object[]} findings          - detected anomalies
 * @property {object[]} bonuses           - confirmed physical properties
 * @property {number|null} entropyJitterRatio
 * @property {object}   picketFence
 * @property {string[]} coherenceFlags
 */

// ---------------------------------------------------------------------------
// Picket Fence detector
// ---------------------------------------------------------------------------

/**
 * Detects periodic steal-time bursts by finding the lag with the highest
 * autocorrelation beyond lag-5.  A strong periodic peak indicates the
 * hypervisor is scheduling the guest on a fixed quantum.
 *
 * Named "Picket Fence" because of how the timing histogram looks: dense
 * clusters at fixed intervals with empty space between them — like fence posts.
 */
function _detectPicketFence(autocorrelations) {
  const longLags = [10, 25, 50].map(l => ({
    lag:  l,
    ac:   Math.abs(autocorrelations?.[`lag${l}`] ?? 0),
  }));

  const shortBaseline = (Math.abs(autocorrelations?.lag5 ?? 0) +
                         Math.abs(autocorrelations?.lag3 ?? 0)) / 2;

  const peak = longLags.reduce((best, cur) =>
    cur.ac > best.ac ? cur : best, { lag: 0, ac: 0 });

  // "Picket fence" condition: a long-lag autocorr significantly exceeds baseline
  if (peak.ac > 0.30 && peak.ac > shortBaseline + 0.20) {
    return {
      detected:     true,
      dominantLag:  peak.lag,
      peakAC:       peak.ac,
      baseline:     shortBaseline,
      detail: `lag${peak.lag}_AC=${peak.ac.toFixed(3)}  baseline_AC=${shortBaseline.toFixed(3)}  ` +
              `estimated_quantum≈${(peak.lag * 5).toFixed(0)}ms (at 5ms/iter)`,
    };
  }

  return { detected: false, dominantLag: null, peakAC: peak.ac, baseline: shortBaseline, detail: '' };
}

function _empty() {
  return {
    penalty: 0, bonus: 0, netAdjustment: 0,
    findings: [], bonuses: [],
    entropyJitterRatio: null, entropyJitterScore: 0.5,
    picketFence: { detected: false },
    coherenceFlags: [],
  };
}

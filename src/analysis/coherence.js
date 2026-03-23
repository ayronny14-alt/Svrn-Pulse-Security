/**
 * @svrnsec/pulse — Zero-Latency Second-Stage Coherence Analysis
 *
 * Runs entirely on data already collected by the entropy probe, bio
 * collector, canvas fingerprinter, and audio analyser.
 * Adds approximately 1–3 ms of CPU time. Zero WASM, zero network.
 *
 * Architecture:
 *   Stage 1 — classifyJitter()       → rawScore  [0, 1]
 *   Stage 2 — runHeuristicEngine()   → netAdjustment  (physics coherence)
 *   Stage 3 — runCoherenceAnalysis() → THIS MODULE
 *              ↳ small score refinement  [-0.15, +0.18]
 *              ↳ dynamic threshold       [0.55, 0.67]
 *              ↳ hard override           'vm' | null
 *
 * Why a third stage?
 *   Stage 1 checks individual metrics in isolation.
 *   Stage 2 checks pairwise relationships between metrics.
 *   Stage 3 checks STRUCTURAL properties of the entire time-series and
 *   signal evolution that require the full dataset to evaluate — and that
 *   a sophisticated attacker cannot spoof without also spoofing every
 *   other correlated signal simultaneously.
 *
 * The six checks cover orthogonal signal dimensions so they are hard to
 * spoof together even if one is individually defeated:
 *
 *   1. Timing distinctness   — frequency domain (quantization density)
 *   2. AC decay shape        — temporal domain (Brownian vs harmonic)
 *   3. Chunk CV stability    — stationarity axis (thermal non-stationarity)
 *   4. Level-dependent noise — noise model axis (multiplicative vs additive)
 *   5. Batch convergence     — measurement stability (adaptive mode)
 *   6. Phase trajectory      — EJR monotonicity (thermal sequence integrity)
 *
 * Dynamic threshold:
 *   The evidence weight reflects how much data was actually collected.
 *   An early-exit proof with 50 iterations and no bio activity has far less
 *   support than a 200-iteration proof with bio, audio, and phased data.
 *   The threshold rises automatically as evidence decreases:
 *     Full evidence  → threshold 0.55  (standard)
 *     Minimal proof  → threshold 0.67  (conservative gate)
 *   This prevents low-evidence proofs from passing the same bar as full ones.
 */

// ---------------------------------------------------------------------------
// runCoherenceAnalysis
// ---------------------------------------------------------------------------

/**
 * @param {object}        p
 * @param {number[]}      p.timings   — raw timing array (already collected)
 * @param {object}        p.jitter    — JitterAnalysis from classifyJitter()
 * @param {object|null}   p.phases    — phased entropy result (optional)
 * @param {object[]|null} p.batches   — adaptive batch snapshots (optional)
 * @param {object}        p.bio       — bio snapshot
 * @param {object}        p.canvas    — canvas fingerprint
 * @param {object}        p.audio     — audio jitter result
 * @returns {CoherenceReport}
 */
export function runCoherenceAnalysis({ timings, jitter, phases, batches, bio, canvas, audio }) {
  if (!timings || timings.length < 10) {
    // Insufficient data — return a conservative threshold and no adjustments.
    return _empty(0.64);
  }

  const checks  = [];   // anomalies found (each may carry a penalty)
  const bonuses = [];   // physical properties confirmed (each carries a bonus)
  let   penalty = 0;
  let   bonus   = 0;
  let   hardOverride = null;  // 'vm' | null

  const n  = timings.length;
  const ac = jitter.autocorrelations ?? {};

  // ── Check 1: Timing Distinctness Ratio ──────────────────────────────────────
  // VM quantized timers repeat the same integer-millisecond values.
  // Real silicon at sub-ms resolution produces mostly unique values.
  //
  // Bin width: 0.2 ms (matches detectQuantizationEntropy for consistency).
  // Normalized by sample count → iteration-count-independent.
  //
  //   distinctRatio > 0.65 → sub-ms resolution confirmed → physical bonus
  //   distinctRatio < 0.30 → heavy quantization         → VM penalty
  //   distinctRatio < 0.45 at n ≥ 100                   → mild VM penalty
  {
    const bins = new Set(timings.map(t => Math.round(t / 0.2)));
    const distinctRatio = bins.size / n;

    if (n >= 50) {
      if (distinctRatio > 0.65) {
        bonuses.push({
          id:     'HIGH_TIMING_DISTINCTNESS',
          label:  'Timer produces mostly unique values — sub-ms resolution confirmed',
          detail: `ratio=${distinctRatio.toFixed(3)} (${bins.size}/${n} distinct 0.2ms bins)`,
          value:  0.06,
        });
        bonus += 0.06;

      } else if (distinctRatio < 0.30) {
        // Severely quantized — VM with integer-ms timer emulation
        checks.push({
          id:       'LOW_TIMING_DISTINCTNESS',
          label:    'Heavy timer quantization — integer-ms VM timer suspected',
          detail:   `ratio=${distinctRatio.toFixed(3)} (only ${bins.size}/${n} distinct 0.2ms bins)`,
          severity: 'high',
          penalty:  0.12,
        });
        penalty += 0.12;

      } else if (distinctRatio < 0.45 && n >= 100) {
        // At 100+ iterations we expect more spread; below 0.45 is suspicious
        checks.push({
          id:       'BORDERLINE_TIMING_DISTINCTNESS',
          label:    'Below-expected timer resolution — coarse-grained timer suspected',
          detail:   `ratio=${distinctRatio.toFixed(3)} at n=${n}`,
          severity: 'medium',
          penalty:  0.05,
        });
        penalty += 0.05;
      }
    }
  }

  // ── Check 2: Autocorrelation Decay Shape ────────────────────────────────────
  // Genuine Brownian noise decays monotonically: lag1 > lag2 > lag5 > lag10 > …
  // VM scheduler rhythms create harmonic revivals: lag25 or lag50 elevated
  // above lag10 because steal-time bursts recur at the scheduler quantum period.
  //
  // This is structurally orthogonal to the Picket Fence detector (stage 2),
  // which checks absolute magnitude — this checks the SHAPE of the decay curve.
  {
    const l1  = Math.abs(ac.lag1  ?? 0);
    const l2  = Math.abs(ac.lag2  ?? 0);
    const l3  = Math.abs(ac.lag3  ?? 0);
    const l5  = Math.abs(ac.lag5  ?? 0);
    const l10 = Math.abs(ac.lag10 ?? 0);
    const l25 = Math.abs(ac.lag25 ?? 0);
    const l50 = Math.abs(ac.lag50 ?? 0);

    // Strict Brownian decay: each successive lag is no higher than the previous
    // (+0.03 tolerance for estimation noise)
    const isBrownianDecay =
      l1  < 0.20 &&
      l2  <= l1  + 0.03 &&
      l5  <= l2  + 0.03 &&
      l10 <= l5  + 0.03 &&
      l25 <= l10 + 0.05 &&
      l50 <= l10 + 0.05;

    // Harmonic revival: a long lag significantly exceeds medium lags
    // (scheduler quantum footprint)
    const revival25 = l25 > l5 + 0.12 && l25 > 0.18;
    const revival50 = l50 > l5 + 0.12 && l50 > 0.18;

    if (isBrownianDecay && l1 < 0.15) {
      bonuses.push({
        id:     'BROWNIAN_DECAY_SHAPE',
        label:  'AC decays monotonically at all measured lags — genuine Brownian noise structure',
        detail: `lag1=${l1.toFixed(3)} lag3=${l3.toFixed(3)} lag5=${l5.toFixed(3)} lag10=${l10.toFixed(3)} lag50=${l50.toFixed(3)}`,
        value:  0.09,
      });
      bonus += 0.09;
    }

    if (revival25 || revival50) {
      const peakLag = revival25 ? 25 : 50;
      const peakVal = revival25 ? l25 : l50;
      checks.push({
        id:       'HARMONIC_AUTOCORR_REVIVAL',
        label:    `Long-lag AC revival at lag ${peakLag} — VM scheduler harmonic footprint`,
        detail:   `lag5=${l5.toFixed(3)}  lag${peakLag}=${peakVal.toFixed(3)}  Δ=${(peakVal - l5).toFixed(3)}`,
        severity: 'high',
        penalty:  0.10,
      });
      penalty += 0.10;
    }
  }

  // ── Check 3: Chunk CV Stability (temporal stationarity test) ─────────────────
  // Split the timing series into 4 equal windows and compute CV per window.
  // Real hardware: CV varies across chunks — CPU temperature changes, workload
  // varies, OS scheduling fluctuates — making the process non-stationary.
  // VM hypervisor: CV is nearly identical in every chunk because the hypervisor's
  // scheduling behaviour is constant — a stationary process.
  //
  // Metric: CV of the 4 chunk CVs (CV-of-CVs).
  //   > 0.15 → non-stationary noise → physical bonus
  //   < 0.06 → suspiciously constant → VM penalty
  if (n >= 40) {
    const chunkSize = Math.floor(n / 4);
    const chunkCVs  = [];

    for (let c = 0; c < 4; c++) {
      const chunk = timings.slice(c * chunkSize, (c + 1) * chunkSize);
      const m     = chunk.reduce((a, b) => a + b, 0) / chunk.length;
      const s     = Math.sqrt(chunk.reduce((acc, v) => acc + (v - m) ** 2, 0) / chunk.length);
      if (m > 0) chunkCVs.push(s / m);
    }

    if (chunkCVs.length === 4) {
      const cvMean  = chunkCVs.reduce((a, b) => a + b, 0) / 4;
      const cvStd   = Math.sqrt(chunkCVs.reduce((s, v) => s + (v - cvMean) ** 2, 0) / 4);
      const cvOfCVs = cvMean > 1e-9 ? cvStd / cvMean : 0;

      if (cvOfCVs > 0.15) {
        bonuses.push({
          id:     'TEMPORAL_NON_STATIONARITY',
          label:  'Noise level varies across time windows — thermal non-stationarity confirmed',
          detail: `CV-of-CVs=${cvOfCVs.toFixed(3)}  windows=[${chunkCVs.map(v => v.toFixed(3)).join(', ')}]`,
          value:  0.07,
        });
        bonus += 0.07;

      } else if (cvOfCVs < 0.06 && cvMean > 0.01) {
        checks.push({
          id:       'STATIONARY_NOISE_PROCESS',
          label:    'Noise level constant across all time windows — hypervisor stationarity suspected',
          detail:   `CV-of-CVs=${cvOfCVs.toFixed(3)}  windows=[${chunkCVs.map(v => v.toFixed(3)).join(', ')}]`,
          severity: 'high',
          penalty:  0.09,
        });
        penalty += 0.09;
      }
    }
  }

  // ── Check 4: Level-Dependent Volatility (noise model test) ──────────────────
  // Thermal noise is multiplicative: the physical process that adds jitter
  // (electron thermal motion, gate capacitance variation) scales with the
  // operating conditions that also drive longer execution times.
  // Consequence: larger timing values tend to have more incremental variance.
  // This produces a positive Pearson correlation between:
  //   — timing[i]              (level — how long that iteration took)
  //   — |timing[i+1]-timing[i]| (volatility — how much it changed)
  //
  // VM hypervisor noise is additive: a constant scheduling jitter is applied
  // regardless of the iteration's timing level → near-zero correlation.
  //
  //   r > 0.15 → multiplicative noise → physical bonus
  //   r < 0.04 at n ≥ 80 → additive noise → VM penalty
  if (n >= 30) {
    const levels = timings.slice(0, n - 1);
    const deltas = timings.slice(1).map((v, i) => Math.abs(v - timings[i]));
    const lMean  = levels.reduce((a, b) => a + b, 0) / levels.length;
    const dMean  = deltas.reduce((a, b) => a + b, 0) / deltas.length;

    let cov = 0, lVar = 0, dVar = 0;
    for (let i = 0; i < levels.length; i++) {
      const ld = levels[i] - lMean;
      const dd = deltas[i] - dMean;
      cov  += ld * dd;
      lVar += ld * ld;
      dVar += dd * dd;
    }
    const denom         = Math.sqrt(lVar * dVar);
    const levelVolCorr  = denom < 1e-14 ? 0 : cov / denom;

    if (levelVolCorr > 0.15) {
      bonuses.push({
        id:     'MULTIPLICATIVE_NOISE_MODEL',
        label:  'Timing variance scales with level — multiplicative thermal noise confirmed',
        detail: `level-volatility r=${levelVolCorr.toFixed(3)} (expected >0.15 for real silicon)`,
        value:  0.07,
      });
      bonus += 0.07;

    } else if (levelVolCorr < 0.04 && n >= 80) {
      // Enough samples to trust the estimate; near-zero = additive hypervisor noise
      checks.push({
        id:       'ADDITIVE_NOISE_MODEL',
        label:    'Timing variance independent of level — additive hypervisor noise suspected',
        detail:   `level-volatility r=${levelVolCorr.toFixed(3)} (expected >0.15 for real silicon)`,
        severity: 'medium',
        penalty:  0.07,
      });
      penalty += 0.07;
    }
  }

  // ── Check 5: Batch Convergence Variance (adaptive mode only) ─────────────────
  // In adaptive mode each batch of 25 iterations produces a vmConf estimate.
  // Real hardware: these estimates wander batch-to-batch because the underlying
  // physical source is genuinely stochastic.
  // VM hypervisor: estimates lock in immediately — deterministic scheduling means
  // each batch produces essentially the same picture.
  //
  // Most diagnostic in the ambiguous zone (vmConf 0.25–0.70) where stability
  // is suspicious.  A clearly obvious VM (vmConf 0.90 every batch) is expected
  // to be stable.  A borderline device (vmConf 0.45 across 6 identical batches)
  // is exhibiting VM-like stability despite claiming ambiguity.
  //
  // Uses only batches collected after iteration 75 to avoid early-sample noise.
  if (batches && batches.length >= 4) {
    const stableBatches = batches.filter(b => b.iterations >= 75);

    if (stableBatches.length >= 3) {
      const vmConfs = stableBatches.map(b => b.vmConf);
      const hwConfs = stableBatches.map(b => b.hwConf);
      const vmMean  = vmConfs.reduce((a, b) => a + b, 0) / vmConfs.length;
      const hwMean  = hwConfs.reduce((a, b) => a + b, 0) / hwConfs.length;
      const vmStd   = Math.sqrt(
        vmConfs.reduce((s, v) => s + (v - vmMean) ** 2, 0) / vmConfs.length
      );

      // Only meaningful in the ambiguous zone
      const isAmbiguous = vmMean > 0.25 && vmMean < 0.70 && hwMean < 0.55;

      if (isAmbiguous) {
        if (vmStd > 0.06) {
          bonuses.push({
            id:     'SIGNAL_FLUCTUATES_STOCHASTICALLY',
            label:  'Batch-by-batch signal variance confirms genuine stochastic noise source',
            detail: `vmConf σ=${vmStd.toFixed(3)} across ${stableBatches.length} stable batches (μ=${vmMean.toFixed(3)})`,
            value:  0.05,
          });
          bonus += 0.05;

        } else if (vmStd < 0.025 && stableBatches.length >= 4) {
          checks.push({
            id:       'SIGNAL_DETERMINISTICALLY_STABLE',
            label:    'Signal locked-in immediately — deterministic hypervisor suspected',
            detail:   `vmConf σ=${vmStd.toFixed(3)} across ${stableBatches.length} stable batches (μ=${vmMean.toFixed(3)})`,
            severity: 'medium',
            penalty:  0.06,
          });
          penalty += 0.06;
        }
      }
    }
  }

  // ── Check 6: Phase Entropy Trajectory ────────────────────────────────────────
  // The EJR (hot_QE / cold_QE) captures the endpoint ratio, but misses the
  // intermediate trajectory.  We additionally verify monotonic growth:
  //   cold_QE < load_QE < hot_QE
  //
  // If all three phases are available, monotonic growth is a strong bonus.
  // Non-monotonic trajectory (entropy dropped then recovered) is suspicious.
  //
  // HARD OVERRIDE: if EJR ≥ 1.08 (claims entropy grew from cold to hot)
  // but cold_QE ≥ hot_QE (entropy provably didn't grow), the proof is
  // mathematically self-contradictory → forgery attempt.
  if (phases) {
    const coldQE = phases.cold?.qe ?? null;
    const loadQE = phases.load?.qe ?? null;
    const hotQE  = phases.hot?.qe  ?? null;
    const ejr    = phases.entropyJitterRatio ?? null;

    // Mathematical contradiction: EJR = hot_QE / cold_QE, so EJR ≥ 1.08
    // implies hot_QE ≥ 1.08 × cold_QE > cold_QE.  Violation = tampered proof.
    if (ejr !== null && ejr >= 1.08 && coldQE !== null && hotQE !== null) {
      if (coldQE >= hotQE) {
        hardOverride = 'vm';
        checks.push({
          id:       'EJR_QE_CONTRADICTION',
          label:    'HARD OVERRIDE: EJR claims entropy growth but cold_QE ≥ hot_QE — mathematically impossible',
          detail:   `ejr=${ejr.toFixed(4)}  cold_QE=${coldQE.toFixed(3)}  hot_QE=${hotQE.toFixed(3)}  (ejr=hot/cold requires hot>cold)`,
          severity: 'critical',
          penalty:  0.60,  // overwhelms any bonus
        });
        penalty += 0.60;
      }
    }

    // Monotonic trajectory check (requires all three phases)
    if (!hardOverride && coldQE !== null && loadQE !== null && hotQE !== null) {
      if (coldQE < loadQE && loadQE < hotQE) {
        bonuses.push({
          id:     'MONOTONIC_ENTROPY_TRAJECTORY',
          label:  'QE increased continuously cold→load→hot — unbroken thermal feedback confirmed',
          detail: `${coldQE.toFixed(3)} → ${loadQE.toFixed(3)} → ${hotQE.toFixed(3)}`,
          value:  0.09,
        });
        bonus += 0.09;

      } else if (coldQE >= loadQE || loadQE >= hotQE) {
        // Entropy stalled or reversed mid-run — unusual for real silicon
        checks.push({
          id:       'NON_MONOTONIC_ENTROPY_TRAJECTORY',
          label:    'Entropy did not increase monotonically across load phases',
          detail:   `cold=${coldQE.toFixed(3)}  load=${loadQE.toFixed(3)}  hot=${hotQE.toFixed(3)}`,
          severity: 'medium',
          penalty:  0.06,
        });
        penalty += 0.06;
      }
    }
  }

  // ── Dynamic threshold ─────────────────────────────────────────────────────────
  // A proof built from more evidence earns a more permissive (lower) passing bar.
  // Weights:
  //   iterations (0→200): up to 0.65 of the evidence score
  //   phased collection:  +0.15 (gold standard of thermal measurement)
  //   bio activity:       +0.10 (human presence confirmed)
  //   audio available:    +0.05 (additional timing channel)
  //   canvas available:   +0.05 (hardware renderer identified)
  //
  // dynamicThreshold = 0.55 + (1 − evidenceWeight) × 0.12
  //   Full evidence  → 0.55  (standard gate)
  //   Minimal proof  → 0.67  (tightened gate for low-evidence submissions)
  const iterFraction   = Math.min(1.0, n / 200);
  const phasedBonus    = phases                  ? 0.15 : 0.0;
  const bioBonus       = bio?.hasActivity        ? 0.10 : 0.0;
  const audioBonus     = audio?.available        ? 0.05 : 0.0;
  const canvasBonus    = canvas?.available       ? 0.05 : 0.0;

  const evidenceWeight = Math.min(1.0,
    iterFraction * 0.65 + phasedBonus + bioBonus + audioBonus + canvasBonus
  );

  const dynamicThreshold = +(0.55 + (1 - evidenceWeight) * 0.12).toFixed(4);

  // ── Stage-3 caps ─────────────────────────────────────────────────────────────
  // Stage 3 is a REFINEMENT, not the primary classifier.  The caps are smaller
  // than stage 2 to prevent triple-compounding across all three stages on
  // legitimate hardware with multiple marginal-but-not-damning signals.
  const totalPenalty = Math.min(0.15, penalty);   // hard floor: stage 3 can't reject alone
  const totalBonus   = Math.min(0.18, bonus);

  return {
    penalty:          totalPenalty,
    bonus:            totalBonus,
    netAdjustment:    +(totalBonus - totalPenalty).toFixed(4),
    checks,
    bonuses,
    hardOverride,                               // 'vm' | null
    dynamicThreshold,                           // [0.55, 0.67]
    evidenceWeight:   +evidenceWeight.toFixed(4),
    coherenceFlags:   checks.map(c => c.id),
    physicalFlags:    bonuses.map(b => b.id),
  };
}

// ---------------------------------------------------------------------------
// computeServerDynamicThreshold
// ---------------------------------------------------------------------------

/**
 * Server-side recomputation of the dynamic threshold.
 * The server NEVER trusts the client's dynamicThreshold value; it recomputes
 * from known payload fields.
 *
 * @param {object} payload - validated ProofPayload
 * @returns {number} - minimum passing score for this proof [0.50, 0.62]
 */
export function computeServerDynamicThreshold(payload) {
  const entropy = payload?.signals?.entropy;
  const bio     = payload?.signals?.bio;
  const audio   = payload?.signals?.audio;
  const canvas  = payload?.signals?.canvas;

  const n            = entropy?.iterations ?? 0;
  const hasPhases    = payload?.heuristic?.entropyJitterRatio != null;
  const hasBio       = bio?.hasActivity === true;
  const hasAudio     = audio?.available === true;
  const hasCanvas    = canvas?.available === true;

  const iterFraction = Math.min(1.0, n / 200);
  const evidenceWeight = Math.min(1.0,
    iterFraction * 0.65 +
    (hasPhases ? 0.15 : 0) +
    (hasBio    ? 0.10 : 0) +
    (hasAudio  ? 0.05 : 0) +
    (hasCanvas ? 0.05 : 0)
  );

  // Server threshold: [0.50, 0.62]
  // Slightly more lenient than client [0.55, 0.67] because the server already
  // applies minJitterScore as an independent check.  The dynamic component
  // adds an ADDITIONAL evidence-proportional tightening on top.
  return +(0.50 + (1 - evidenceWeight) * 0.12).toFixed(4);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _empty(threshold) {
  return {
    penalty: 0, bonus: 0, netAdjustment: 0,
    checks: [], bonuses: [],
    hardOverride: null,
    dynamicThreshold: threshold,
    evidenceWeight: 0,
    coherenceFlags: [],
    physicalFlags:  [],
  };
}

/**
 * @typedef {object} CoherenceReport
 * @property {number}    penalty            - total score penalty [0, 0.15]
 * @property {number}    bonus              - total score bonus   [0, 0.18]
 * @property {number}    netAdjustment      - bonus − penalty  [-0.15, +0.18]
 * @property {object[]}  checks             - anomalies found (with penalty values)
 * @property {object[]}  bonuses            - physical properties confirmed
 * @property {'vm'|null} hardOverride       - overrides score when set
 * @property {number}    dynamicThreshold   - computed passing threshold [0.55, 0.67]
 * @property {number}    evidenceWeight     - how much evidence was collected [0, 1]
 * @property {string[]}  coherenceFlags     - check IDs for logging
 * @property {string[]}  physicalFlags      - bonus IDs for logging
 */

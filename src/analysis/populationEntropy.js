/**
 * @svrnsec/pulse — Population Entropy Analysis
 *
 * Server-side Sybil detector: given N engagement tokens from the same cohort
 * (e.g., all ad clicks in a 10-minute window), determine whether they
 * represent independently-operated consumer devices or a coordinated farm.
 *
 * Why per-token verification is necessary but not sufficient
 * ──────────────────────────────────────────────────────────
 * A single token from a farm device may pass every individual check:
 *   - Real hardware  ✓  (it is a real phone)
 *   - Valid idle proof ✓  (45+ seconds of forced downtime)
 *   - Plausible entropy ✓  (within normal ranges)
 *
 * But 1,000 farm devices in one warehouse share inescapable physical context:
 *   - Same ambient temperature  → correlated DRAM timing variance
 *   - Same power circuit        → near-identical ENF phase deviation
 *   - Coordinator dispatch      → rhythmic submission timestamp patterns
 *   - Same operational pattern  → homogeneous thermal transitions
 *   - Economic throughput limit → idle durations cluster at the minimum
 *
 * Population analysis exposes these systematic correlations that are
 * individually invisible but statistically unmistakable at scale.
 *
 * Statistical tests (5)
 * ─────────────────────
 *   1. Timestamp rhythm        — autocorrelation of inter-arrival times
 *   2. Entropy dispersion      — coefficient of variation across physics scores
 *   3. Thermal diversity       — Shannon entropy of thermal transition labels
 *   4. Idle duration cluster   — fraction of durations near the minimum viable
 *   5. ENF phase coherence     — variance of measured grid frequency deviations
 *
 * Scoring
 * ───────
 * Each test returns a sybilScore in [0, 100] where 100 = maximally suspicious.
 * The population sybilScore is a weighted average of the five tests.
 * An authentic cohort scores < 40; a clear farm scores > 70.
 */

// ── analysePopulation ─────────────────────────────────────────────────────────

/**
 * Analyse a cohort of parsed engagement tokens for population-level Sybil signals.
 *
 * @param {ParsedEngagementToken[]} tokens  decoded (not yet signature-verified) tokens
 * @param {object}  [opts]
 * @param {number}  [opts.minSample=5]  minimum cohort size for a meaningful verdict
 * @returns {PopulationVerdict}
 */
export function analysePopulation(tokens, opts = {}) {
  const { minSample = 5 } = opts;

  if (!Array.isArray(tokens) || tokens.length < minSample) {
    return _insufficientSample(tokens?.length ?? 0, minSample);
  }

  const rhythmResult  = testTimestampRhythm(tokens);
  const dispersion    = testEntropyDispersion(tokens);
  const thermalDiv    = testThermalDiversity(tokens);
  const idlePlaus     = testIdlePlausibility(tokens);
  const enfCoherence  = testEnfCoherence(tokens);

  // Weighted aggregate (weights reflect signal reliability and discriminative power)
  const sybilScore = Math.round(
    rhythmResult.score * 0.25 +
    dispersion.score   * 0.25 +
    thermalDiv.score   * 0.20 +
    idlePlaus.score    * 0.20 +
    enfCoherence.score * 0.10
  );

  // Confidence scales with cohort size — small cohorts can't make strong claims
  const confidence = +Math.min(1.0, tokens.length / 50).toFixed(3);

  const flags = [
    rhythmResult.score  > 60 && 'RHYTHMIC_DISPATCH',
    dispersion.score    > 60 && 'HOMOGENEOUS_HARDWARE',
    thermalDiv.score    > 60 && 'UNIFORM_THERMAL_PATTERN',
    idlePlaus.score     > 60 && 'SYNTHETIC_IDLE_CLUSTERING',
    enfCoherence.score  > 60 && 'CO_LOCATED_DEVICES',
  ].filter(Boolean);

  return {
    authentic:   sybilScore < 40,
    sybilScore,
    confidence,
    tests: {
      timestampRhythm:   rhythmResult,
      entropyDispersion: dispersion,
      thermalDiversity:  thermalDiv,
      idlePlausibility:  idlePlaus,
      enfCoherence,
    },
    flags,
    summary: _formatSummary(sybilScore, flags, tokens.length),
  };
}

// ── Test 1: Timestamp Rhythm ──────────────────────────────────────────────────

/**
 * Farm coordinators dispatch tokens in batches at scheduler-driven intervals.
 * A coordinator sending 1,000 tokens at 120-second intervals produces strong
 * positive autocorrelation in the inter-arrival time series.
 *
 * Real users click independently; their inter-arrival times are random.
 *
 * @param {ParsedEngagementToken[]} tokens
 * @returns {{ score: number, ac1: number, ac2: number, detail: string }}
 */
export function testTimestampRhythm(tokens) {
  const timestamps = tokens.map(t => t.iat).filter(Number.isFinite).sort((a, b) => a - b);
  if (timestamps.length < 4) {
    return { score: 0, ac1: 0, ac2: 0, detail: 'insufficient_samples' };
  }

  // Inter-arrival times in milliseconds
  const deltas = [];
  for (let i = 1; i < timestamps.length; i++) {
    deltas.push(timestamps[i] - timestamps[i - 1]);
  }

  const n    = deltas.length;
  const mean = _mean(deltas);
  const v0   = _variance(deltas, mean);

  // Zero-variance: perfectly uniform dispatch — maximally suspicious
  if (v0 < 1e-6) {
    return { score: 100, ac1: 1, ac2: 1, detail: 'perfectly_uniform_dispatch' };
  }

  const ac1 = _autocorrAtLag(deltas, mean, v0, 1);
  const ac2 = _autocorrAtLag(deltas, mean, v0, 2);

  // Both positive autocorrelation (rhythmic dispatch from farm coordinator) and negative autocorrelation (perfectly alternating patterns) are treated as suspicious signals.
  // Use the more suspicious of the two lags
  const signal = Math.max(Math.abs(ac1), Math.abs(ac2));

  // Threshold calibration:
  //   |ac| < 0.15  → independent (real users)
  //   |ac| > 0.40  → rhythmic (farm coordinator)
  const score = Math.min(100, Math.max(0,
    ((signal - 0.15) / (0.40 - 0.15)) * 100
  ));

  return {
    score:  Math.round(score),
    ac1:    +ac1.toFixed(3),
    ac2:    +ac2.toFixed(3),
    detail: signal > 0.40 ? 'rhythmic_dispatch_detected' : 'normal_variance',
  };
}

// ── Test 2: Entropy Dispersion ────────────────────────────────────────────────

/**
 * Real users bring diverse device histories: different ages, temperatures,
 * load profiles. Their physics scores (entropy, jitter) span a wide range.
 *
 * Farm devices in one warehouse are typically the same model, same ambient
 * temperature, running the same workload. Their scores cluster tightly.
 *
 * @param {ParsedEngagementToken[]} tokens
 * @returns {{ score: number, cv: number, mean: number, detail: string }}
 */
export function testEntropyDispersion(tokens) {
  const scores = tokens.map(t => t.hw?.ent).filter(v => v != null && Number.isFinite(v) && v > 0);
  if (scores.length < 3) {
    return { score: 0, cv: 0, mean: 0, detail: 'no_entropy_data' };
  }

  const mean   = _mean(scores);
  if (mean < 1e-9) return { score: 50, cv: 0, mean: 0, detail: 'zero_entropy_scores' };

  const stddev = Math.sqrt(_variance(scores, mean));
  const cv     = stddev / mean; // Coefficient of Variation

  // Calibration:
  //   CV > 0.12  → diverse hardware (real users)
  //   CV < 0.04  → homogeneous (farm devices)
  const score = Math.min(100, Math.max(0,
    ((0.10 - cv) / (0.10 - 0.03)) * 100
  ));

  return {
    score:  Math.round(score),
    cv:     +cv.toFixed(4),
    mean:   +mean.toFixed(3),
    detail: cv < 0.04 ? 'homogeneous_hardware_detected' : 'normal_diversity',
  };
}

// ── Test 3: Thermal Diversity ─────────────────────────────────────────────────

/**
 * Real users encounter devices in diverse thermal states throughout the day:
 * cold morning wake-ups, warm post-commute picks, hot post-gaming sessions.
 * The population distribution across transition labels should be broad.
 *
 * Farm devices maintain constant operational throughput. Their transitions
 * cluster at 'step_function' (scripted pause) or 'sustained_hot' (constant load).
 *
 * @param {ParsedEngagementToken[]} tokens
 * @returns {{ score: number, suspiciousRatio: number, distribution: object, detail: string }}
 */
export function testThermalDiversity(tokens) {
  const transitions = tokens.map(t => t.idle?.therm).filter(Boolean);
  if (transitions.length < 3) {
    return { score: 0, suspiciousRatio: 0, distribution: {}, detail: 'no_thermal_data' };
  }

  const counts = {};
  for (const t of transitions) counts[t] = (counts[t] ?? 0) + 1;
  const total = transitions.length;

  // Farm-indicator transitions
  const suspicious     = (counts.step_function ?? 0) + (counts.sustained_hot ?? 0);
  const suspiciousRatio = suspicious / total;

  // Shannon entropy of the transition label distribution
  const probs           = Object.values(counts).map(c => c / total);
  const popEntropy      = _shannonEntropy(probs);
  const maxEntropy      = Math.log2(6); // 6 possible labels

  // Combined: raw suspicious ratio + low population entropy both indicate farm
  const ratioScore   = Math.min(100, suspiciousRatio * 100);
  const entropyScore = Math.min(80, (1 - popEntropy / maxEntropy) * 80);
  const score        = Math.round(0.6 * ratioScore + 0.4 * entropyScore);

  const detail = suspiciousRatio > 0.50
    ? 'majority_farm_thermal_transitions'
    : popEntropy < maxEntropy * 0.40
      ? 'low_thermal_label_diversity'
      : 'normal_distribution';

  return {
    score,
    suspiciousRatio: +suspiciousRatio.toFixed(3),
    distribution:    Object.fromEntries(
      Object.entries(counts).map(([k, v]) => [k, +(v / total).toFixed(3)])
    ),
    detail,
  };
}

// ── Test 4: Idle Duration Plausibility ───────────────────────────────────────

/**
 * Real humans idle unpredictably: 5 minutes for a notification, an hour for
 * lunch, 8 hours overnight. The distribution is broad and roughly log-normal.
 *
 * Farm scripts, constrained by throughput targets, idle for exactly the
 * minimum duration required to pass attestation (~45–90s). The population
 * reveals a tight cluster just above the minimum viable threshold.
 *
 * @param {ParsedEngagementToken[]} tokens
 * @returns {{ score: number, clusterRatio: number, medianMs: number, detail: string }}
 */
export function testIdlePlausibility(tokens) {
  const durations = tokens.map(t => t.idle?.dMs).filter(d => d != null && d > 0);
  if (durations.length < 3) {
    return { score: 0, clusterRatio: 0, medianMs: 0, detail: 'no_idle_data' };
  }

  // The "barely made it" window: idle just long enough to pass, then immediately resume
  const CLUSTER_LO = 45_000;   // MIN_IDLE_MS
  const CLUSTER_HI = 100_000;  // 2.2× minimum — beyond this, farms lose too much throughput

  const inCluster    = durations.filter(d => d >= CLUSTER_LO && d <= CLUSTER_HI).length;
  const clusterRatio = inCluster / durations.length;

  // Low coefficient of variation = durations are suspiciously uniform
  const mean   = _mean(durations);
  const stddev = Math.sqrt(_variance(durations, mean));
  const cv     = stddev / (mean + 1);

  // Scoring: high cluster ratio + low duration CV = farm fingerprint
  const clusterScore = Math.min(70, Math.max(0, (clusterRatio - 0.40) / (0.80 - 0.40)) * 70);
  const cvScore      = Math.min(30, Math.max(0, (0.50 - cv)           / (0.50 - 0.10)) * 30);
  const score        = Math.round(clusterScore + cvScore);

  return {
    score,
    clusterRatio: +clusterRatio.toFixed(3),
    medianMs:     _median(durations),
    detail:       clusterRatio > 0.70 ? 'idle_duration_clustered_at_minimum' : 'normal_distribution',
  };
}

// ── Test 5: ENF Phase Coherence ───────────────────────────────────────────────

/**
 * All devices on the same electrical circuit share the same ENF phase.
 * A 1,000-device farm in a single warehouse shares one power feed — their
 * ENF frequency deviations are nearly identical.
 *
 * Real users across a city are on separate circuits with independent phase
 * evolution; their deviations spread naturally over a measurable range.
 *
 * @param {ParsedEngagementToken[]} tokens
 * @returns {{ score: number, phaseVariance: number|null, detail: string }}
 */
export function testEnfCoherence(tokens) {
  const deviations = tokens
    .map(t => t.hw?.enfDev)
    .filter(d => d != null && Number.isFinite(d));

  if (deviations.length < 4) {
    return { score: 0, phaseVariance: null, detail: 'enf_unavailable_or_insufficient' };
  }

  const mean     = _mean(deviations);
  const variance = _variance(deviations, mean);

  // Calibration (Hz² variance):
  //   variance > 0.0002  → diverse circuits (real users across a city)
  //   variance < 0.00002 → same rack, same feed (co-located farm)
  const score = Math.round(Math.min(100, Math.max(0,
    (1 - variance / 0.0002) * 100
  )));

  return {
    score,
    phaseVariance: +variance.toFixed(8),
    detail:        variance < 0.00002 ? 'co_located_devices_same_circuit' : 'normal_phase_spread',
  };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function _mean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((s, v) => s + v, 0) / arr.length;
}

function _variance(arr, mean) {
  if (arr.length < 2) return 0;
  return arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length;
}

function _median(arr) {
  const s   = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
}

function _autocorrAtLag(data, mean, variance, lag) {
  const n = data.length;
  if (lag >= n || variance < 1e-12) return 0;
  let cov = 0;
  for (let i = 0; i < n - lag; i++) {
    cov += (data[i] - mean) * (data[i + lag] - mean);
  }
  return cov / ((n - lag) * variance);
}

function _shannonEntropy(probs) {
  return -probs
    .filter(p => p > 0)
    .reduce((s, p) => s + p * Math.log2(p), 0);
}

function _formatSummary(score, flags, n) {
  const risk    = score >= 80 ? 'HIGH_RISK'
                : score >= 50 ? 'SUSPICIOUS'
                : score >= 30 ? 'MARGINAL'
                :               'CLEAN';
  const flagStr = flags.length ? `  flags=[${flags.join(',')}]` : '';
  return `${risk}: sybilScore=${score}/100  n=${n}${flagStr}`;
}

function _insufficientSample(n, required) {
  return {
    authentic:   true,    // default to not blocking on insufficient data
    sybilScore:  0,
    confidence:  0,
    tests:       {},
    flags:       [],
    summary:     `INSUFFICIENT_SAMPLE: ${n}/${required} tokens required for analysis`,
  };
}

// ── JSDoc types ───────────────────────────────────────────────────────────────

/**
 * @typedef {object} ParsedEngagementToken
 * @property {number}       iat          issued-at Unix ms
 * @property {object}       [idle]       idle proof summary
 * @property {number|null}  [idle.dMs]   idle duration ms
 * @property {string}       [idle.therm] thermal transition label
 * @property {object}       [hw]         hardware signal summary
 * @property {number}       [hw.ent]     normalized entropy score (0–1)
 * @property {number}       [hw.enfDev]  ENF frequency deviation (Hz)
 */

/**
 * @typedef {object} PopulationVerdict
 * @property {boolean}   authentic      true if population appears legitimate (sybilScore < 40)
 * @property {number}    sybilScore     0–100 suspicion score (higher = more suspicious)
 * @property {number}    confidence     0–1 confidence in verdict (scales with cohort size)
 * @property {object}    tests          per-test result objects
 * @property {string[]}  flags          fired detection flags
 * @property {string}    summary        one-line human-readable summary
 */

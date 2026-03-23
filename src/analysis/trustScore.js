/**
 * @svrnsec/pulse — TrustScore Engine
 *
 * Converts the raw multi-signal proof into a single 0–100 integer that
 * security teams can put in dashboards, set thresholds on, and alert from.
 *
 * Design goals
 * ────────────
 *   1. Transparent — every point can be traced to a physical measurement.
 *   2. Conservative — a missing signal lowers the score; it never inflates it.
 *   3. Hard floors — certain signals (EJR forgery, software GPU, no grid) can
 *      never be compensated by a perfect bio score. Physics overrules behaviour.
 *   4. Grade labels map to enterprise risk tiers (A/B/C/D/F).
 *
 * Signal weights
 * ──────────────
 *   Physics layer   40 pts  (EJR, Hurst coherence, CV-entropy, autocorr)
 *   ENF             20 pts  (grid signal presence and region confidence)
 *   GPU             15 pts  (thermal variance, software renderer penalty)
 *   DRAM            15 pts  (DDR4 refresh cycle detection)
 *   Bio / LLM       10 pts  (behavioral biometrics, AI agent detection)
 *
 * Hard floors
 * ───────────
 *   EJR forgery detected    → score capped at 20  (HARD_KILL)
 *   Software GPU renderer   → score capped at 45  (likely VM/container)
 *   LLM agent conf > 0.85   → score capped at 30  (AI-driven session)
 *   No bio activity + no ENF → score capped at 55 (cannot confirm human)
 */

// ---------------------------------------------------------------------------
// Grade thresholds
// ---------------------------------------------------------------------------

const GRADES = [
  { min: 90, grade: 'A', label: 'Trusted',      color: 'bgreen'   },
  { min: 75, grade: 'B', label: 'Verified',     color: 'bgreen'   },
  { min: 60, grade: 'C', label: 'Marginal',     color: 'byellow'  },
  { min: 45, grade: 'D', label: 'Suspicious',   color: 'byellow'  },
  { min:  0, grade: 'F', label: 'Blocked',      color: 'bred'     },
];

// ---------------------------------------------------------------------------
// computeTrustScore
// ---------------------------------------------------------------------------

/**
 * Compute a 0–100 TrustScore from a ProofPayload + optional extended signals.
 *
 * @param {object}  payload    - ProofPayload from buildProof()
 * @param {object}  [extended] - { enf, gpu, dram, llm } from pulse() extended
 * @returns {TrustScore}
 */
export function computeTrustScore(payload, extended = {}) {
  const signals      = payload?.signals    ?? {};
  const cls          = payload?.classification ?? {};
  const { enf, gpu, dram, llm } = extended;

  const breakdown    = {};
  const penalties    = [];
  const bonuses      = [];
  let   hardCap      = 100;

  // ── 1. Physics layer (40 pts) ─────────────────────────────────────────────
  const phys = _scorePhysics(signals.entropy, cls);
  breakdown.physics = phys;

  // Hard kill: EJR forgery
  if (cls.vmIndicators?.includes('ejr_forgery') ||
      phys.ejrForgery) {
    hardCap = Math.min(hardCap, 20);
    penalties.push({ signal: 'physics', reason: 'EJR phase trajectory forgery detected', cap: 20 });
  }

  // ── 2. ENF layer (20 pts) ─────────────────────────────────────────────────
  const enfScore = _scoreEnf(signals.enf ?? enf);
  breakdown.enf = enfScore;

  if (enfScore.isVmIndicator) {
    penalties.push({ signal: 'enf', reason: 'No grid signal — conditioned/datacenter power', cap: 70 });
    hardCap = Math.min(hardCap, 70);
  }

  // ── 3. GPU layer (15 pts) ─────────────────────────────────────────────────
  const gpuScore = _scoreGpu(signals.gpu ?? gpu);
  breakdown.gpu = gpuScore;

  if (gpuScore.isSoftware) {
    hardCap = Math.min(hardCap, 45);
    penalties.push({ signal: 'gpu', reason: 'Software renderer detected (SwiftShader/llvmpipe)', cap: 45 });
  }

  // ── 4. DRAM layer (15 pts) ────────────────────────────────────────────────
  const dramScore = _scoreDram(signals.dram ?? dram);
  breakdown.dram = dramScore;

  // ── 5. Bio / LLM layer (10 pts) ───────────────────────────────────────────
  const bioScore = _scoreBio(signals.bio, signals.llm ?? llm);
  breakdown.bio = bioScore;

  if (bioScore.aiConf > 0.85) {
    hardCap = Math.min(hardCap, 30);
    penalties.push({ signal: 'bio', reason: `AI agent detected (conf ${(bioScore.aiConf * 100).toFixed(0)}%)`, cap: 30 });
  }

  // No bio + no ENF = can't confirm human on real device
  if (!signals.bio?.hasActivity && !signals.enf?.ripplePresent) {
    hardCap = Math.min(hardCap, 55);
    penalties.push({ signal: 'bio+enf', reason: 'No bio activity and no grid signal', cap: 55 });
  }

  // ── Bonuses ───────────────────────────────────────────────────────────────
  // Temporal anchor present (ENF deviation logged → session timestampable)
  if (signals.enf?.capturedAt && signals.enf?.enfDeviation != null) {
    bonuses.push({ signal: 'enf', reason: 'Temporal fingerprint present', pts: 2 });
  }
  // Both GPU and DRAM confirmed physical
  if (gpuScore.pts >= 13 && dramScore.pts >= 12) {
    bonuses.push({ signal: 'gpu+dram', reason: 'GPU thermal + DRAM refresh both confirmed', pts: 3 });
  }

  // ── 6. Idle attestation (bonus/penalty from engagement token) ─────────────
  // The idle proof is optional — only present when createEngagementToken() is used.
  // Genuine thermal cooling proves the device was not running continuous load.
  const idleProof = extended.idle ?? payload?.signals?.idle ?? null;
  if (idleProof) {
    const { thermalTransition, coolingMonotonicity, samples } = idleProof;

    if (thermalTransition === 'hot_to_cold' || thermalTransition === 'cold') {
      bonuses.push({ signal: 'idle', reason: 'Genuine thermal cooling confirmed between interactions', pts: 5 });
      if (coolingMonotonicity >= 0.8 && samples >= 3) {
        bonuses.push({ signal: 'idle', reason: 'Smooth exponential cooling curve — consistent with Newton cooling', pts: 3 });
      }
    } else if (thermalTransition === 'cooling') {
      bonuses.push({ signal: 'idle', reason: 'Mild thermal decay during idle period', pts: 2 });
    } else if (thermalTransition === 'step_function') {
      // Abrupt variance drop: characteristic of script pause, not natural idle
      hardCap = Math.min(hardCap, 65);
      penalties.push({ signal: 'idle', reason: 'Step-function thermal transition (click farm script pause pattern)', cap: 65 });
    } else if (thermalTransition === 'sustained_hot') {
      // No cooling at all: device was under constant load throughout "idle"
      hardCap = Math.min(hardCap, 60);
      penalties.push({ signal: 'idle', reason: 'No thermal decay during idle — sustained load pattern', cap: 60 });
    }
  }

  // ── Raw score ─────────────────────────────────────────────────────────────
  const bonusPts = bonuses.reduce((s, b) => s + b.pts, 0);
  const raw = Math.min(100,
    phys.pts    +
    enfScore.pts +
    gpuScore.pts +
    dramScore.pts +
    bioScore.pts +
    bonusPts
  );

  // Apply hard cap
  const score = Math.max(0, Math.min(hardCap, raw));

  // ── Grade ─────────────────────────────────────────────────────────────────
  const gradeEntry = GRADES.find(g => score >= g.min) ?? GRADES[GRADES.length - 1];

  return {
    score,
    grade:    gradeEntry.grade,
    label:    gradeEntry.label,
    color:    gradeEntry.color,
    hardCap:  hardCap < 100 ? hardCap : null,
    breakdown,
    penalties,
    bonuses,
    // Convenience: per-layer pct (0–1)
    signals: {
      physics: +(phys.pts    / 40).toFixed(3),
      enf:     +(enfScore.pts / 20).toFixed(3),
      gpu:     +(gpuScore.pts / 15).toFixed(3),
      dram:    +(dramScore.pts / 15).toFixed(3),
      bio:     +(bioScore.pts  / 10).toFixed(3),
    },
  };
}

// ---------------------------------------------------------------------------
// Per-signal scorers
// ---------------------------------------------------------------------------

function _scorePhysics(entropy, cls) {
  let pts        = 0;
  let ejrForgery = false;

  if (!entropy) return { pts: 0, max: 40, ejrForgery, reason: 'no entropy data' };

  const jitter = cls.jitterScore ?? 0;
  const qe     = entropy.quantizationEntropy ?? 0;
  const hurst  = entropy.hurstExponent       ?? 0.5;
  const cv     = entropy.timingsCV           ?? 0;
  const lag1   = entropy.autocorr_lag1       ?? 0;

  // Jitter score (0–15 pts)
  pts += Math.round(Math.min(1, Math.max(0, jitter)) * 15);

  // QE / EJR (0–10 pts)
  if      (qe >= 4.0) pts += 10;
  else if (qe >= 3.0) pts += 8;
  else if (qe >= 2.0) pts += 5;
  else if (qe >= 1.5) pts += 2;
  else if (qe < 1.08) { ejrForgery = true; pts += 0; }

  // Hurst coherence (0–8 pts)
  const hurstDelta = Math.abs(hurst - 0.5);
  if      (hurstDelta < 0.05) pts += 8;
  else if (hurstDelta < 0.10) pts += 5;
  else if (hurstDelta < 0.20) pts += 2;

  // CV-entropy coherence (0–7 pts) — high CV must accompany high QE
  const cvOk = cv > 0.08 && qe > 2.5;
  if (cvOk)      pts += 7;
  else if (cv > 0.05 && qe > 1.8) pts += 3;

  // Autocorrelation (bonus/penalty on existing score)
  if (Math.abs(lag1) < 0.10) pts = Math.min(40, pts + 2);
  if (lag1 > 0.60)            pts = Math.max(0,  pts - 5);

  return { pts: Math.min(40, Math.max(0, pts)), max: 40, ejrForgery };
}

function _scoreEnf(enf) {
  if (!enf || enf.available === false || enf.enfAvailable === false) {
    return { pts: 8, max: 20, reason: 'ENF unavailable (no COOP+COEP)', isVmIndicator: false };
    // Unavailable ≠ VM. Give half marks — cannot confirm but cannot deny.
  }

  let pts = 0;
  const isVmIndicator = enf.isVmIndicator ?? false;

  if (!enf.ripplePresent) {
    // High sample rate + no ripple = conditioned DC power (datacenter)
    return { pts: 0, max: 20, reason: 'No grid ripple detected', isVmIndicator };
  }

  // Grid signal present
  pts += 10;

  // Region confirmed
  if (enf.gridRegion === 'americas' || enf.gridRegion === 'emea_apac') pts += 5;

  // SNR quality
  const snr = Math.max(enf.snr50hz ?? 0, enf.snr60hz ?? 0);
  if      (snr >= 5)  pts += 5;
  else if (snr >= 3)  pts += 3;
  else if (snr >= 2)  pts += 1;

  return { pts: Math.min(20, pts), max: 20, gridRegion: enf.gridRegion, snr, isVmIndicator };
}

function _scoreGpu(gpu) {
  if (!gpu || gpu.available === false || gpu.gpuPresent === false) {
    return { pts: 8, max: 15, reason: 'WebGPU unavailable', isSoftware: false };
  }

  if (gpu.isSoftware || gpu.isSoftware === true) {
    return { pts: 0, max: 15, reason: 'Software renderer', isSoftware: true };
  }

  let pts = 8; // GPU present, not software

  // Thermal growth (real GPUs warm under load)
  const growth = gpu.thermalGrowth ?? 0;
  if      (growth >= 0.05) pts += 7;
  else if (growth >= 0.02) pts += 4;
  else if (growth >= 0.01) pts += 1;

  return { pts: Math.min(15, pts), max: 15, thermalGrowth: growth, isSoftware: false };
}

function _scoreDram(dram) {
  if (!dram) return { pts: 8, max: 15, reason: 'DRAM probe unavailable' };

  if (!dram.refreshPresent) {
    return { pts: 0, max: 15, reason: 'No DRAM refresh cycle detected (virtual memory)' };
  }

  let pts = 10;

  // Refresh period accuracy (DDR4 nominal = 7.8 ms ± 1.5 ms)
  const period = dram.refreshPeriodMs ?? 0;
  if (period > 0) {
    const delta = Math.abs(period - 7.8);
    if      (delta < 0.5)  pts += 5;
    else if (delta < 1.0)  pts += 3;
    else if (delta < 1.5)  pts += 1;
  }

  // Peak power confidence
  if ((dram.peakPower ?? 0) > 0.3) pts = Math.min(15, pts + 2);

  return { pts: Math.min(15, pts), max: 15, refreshPeriodMs: period };
}

function _scoreBio(bio, llm) {
  let pts = 5; // neutral baseline when no bio activity

  const aiConf = llm?.aiConf ?? 0;

  if (!bio?.hasActivity) {
    // No interaction — can't confirm human but also can't confirm bot
    return { pts, max: 10, aiConf, reason: 'no bio activity' };
  }

  pts = 7; // bio activity present

  // High correction rate is a human signal
  const corrRate = llm?.correctionRate ?? 0.08;
  if (corrRate >= 0.05 && corrRate <= 0.20) pts += 2;

  // Rhythmicity (tremor present)
  const rhythmicity = llm?.rhythmicity ?? 0;
  if (rhythmicity > 0.3) pts += 1;

  // LLM penalty
  if      (aiConf > 0.85) pts = 0;
  else if (aiConf > 0.70) pts = Math.max(0, pts - 4);
  else if (aiConf > 0.50) pts = Math.max(0, pts - 2);

  return { pts: Math.min(10, Math.max(0, pts)), max: 10, aiConf };
}

// ---------------------------------------------------------------------------
// formatTrustScore — pretty one-liner for logs
// ---------------------------------------------------------------------------

/**
 * Returns a short human-readable summary.
 * e.g. "TrustScore 87/100  B · Verified  [physics:91% enf:80% gpu:100%]"
 */
export function formatTrustScore(ts) {
  if (!ts) return 'TrustScore N/A';
  const sigs = Object.entries(ts.signals ?? {})
    .map(([k, v]) => `${k}:${Math.round(v * 100)}%`)
    .join(' ');
  return `TrustScore ${ts.score}/100  ${ts.grade} · ${ts.label}  [${sigs}]`;
}

/**
 * @typedef {object} TrustScore
 * @property {number}   score      0–100
 * @property {string}   grade      A|B|C|D|F
 * @property {string}   label      Trusted|Verified|Marginal|Suspicious|Blocked
 * @property {string}   color      ANSI color name for terminal rendering
 * @property {number|null} hardCap applied hard cap (null if none)
 * @property {object}   breakdown  per-layer detailed scores
 * @property {object[]} penalties  hard cap reasons
 * @property {object[]} bonuses    bonus point sources
 * @property {object}   signals    per-layer 0–1 confidence values
 */

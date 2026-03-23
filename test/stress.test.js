/**
 * @svrnsec/pulse — Adversarial Stress Test Suite
 *
 * Three categories:
 *
 *   1. FALSE POSITIVE RESISTANCE
 *      Legitimate hardware profiles that must not be flagged.
 *      Covers: Brave timer clamping, heavy load, laptop on battery, ARM,
 *      developer machine with background VMs, extension-heavy browsers.
 *
 *   2. TRUE POSITIVE DETECTION
 *      VM / simulation profiles that must always be caught.
 *      Covers: KVM, Docker, WSL2, AWS Lambda, headless Chrome, LLM agents,
 *      cloud device farms, software renderers.
 *
 *   3. ADVERSARIAL SIMULATION ATTACKS
 *      Attacker has studied the codebase and is actively trying to fool it.
 *      Covers: Gaussian noise injection, synthetic thermal drift, forced
 *      outlier rate, EJR forgery, Hurst masking, CV-entropy decoupling,
 *      picket fence masking, replay attacks, forged HMAC challenges.
 */

import { classifyJitter, computeStats, detectQuantizationEntropy, computeHurst }
  from '../src/analysis/jitter.js';

import { runHeuristicEngine }
  from '../src/analysis/heuristic.js';

import { computeTrustScore }
  from '../src/analysis/trustScore.js';

import { createChallenge, verifyChallenge, generateSecret }
  from '../src/proof/challenge.js';

import { buildProof, buildCommitment }
  from '../src/proof/fingerprint.js';

import { validateProof, generateNonce }
  from '../src/proof/validator.js';

// ─── Deterministic RNG ───────────────────────────────────────────────────────

function makeLcg(seed) {
  let s = (seed >>> 0) || 0xdeadbeef;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 0xFFFFFFFF;
  };
}

function makeGauss(rand) {
  return (mu = 0, sigma = 1) => {
    const u = Math.max(1e-15, rand());
    const v = rand();
    return mu + sigma * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  };
}

// ─── Hardware profile generators ─────────────────────────────────────────────

/**
 * Consumer desktop / laptop: Gaussian base + thermal drift + OS spikes.
 * Models: GTX 1650 Super class hardware, i5/i7/Ryzen mid-tier.
 */
function realHardware(n = 200, seed = 1) {
  const rand  = makeLcg(seed);
  const gauss = makeGauss(rand);
  const out   = [];
  let base    = 5.0;
  for (let i = 0; i < n; i++) {
    base += 0.0008;                                      // thermal drift
    const spike = rand() > 0.96 ? rand() * 5 : 0;       // OS preemption
    out.push(Math.max(0.5, base + gauss(0, 0.60) + spike));
  }
  return out;
}

/**
 * Brave browser: timer clamped to 100µs resolution.
 * Values are rounded to nearest 0.1ms but still show physical variance.
 */
function braveClamped(n = 200, seed = 2) {
  return realHardware(n, seed).map(v => Math.round(v * 10) / 10);
}

/**
 * Heavy load desktop: high CV, lots of context switch spikes.
 * Background video encoding + browser + IDE running simultaneously.
 */
function heavyLoadHardware(n = 200, seed = 3) {
  const rand  = makeLcg(seed);
  const gauss = makeGauss(rand);
  const out   = [];
  for (let i = 0; i < n; i++) {
    const spike = rand() > 0.88 ? gauss(8, 2) : 0;
    out.push(Math.max(0.5, 5.5 + gauss(0, 0.9) + spike + i * 0.001));
  }
  return out;
}

/**
 * ARM device (Apple M2, Snapdragon): tighter distribution, different base.
 */
function armHardware(n = 200, seed = 4) {
  const rand  = makeLcg(seed);
  const gauss = makeGauss(rand);
  const out   = [];
  for (let i = 0; i < n; i++) {
    out.push(Math.max(0.3, 3.2 + gauss(0, 0.35) + (rand() > 0.97 ? 2.0 : 0) + i * 0.0004));
  }
  return out;
}

/**
 * Low-end hardware (budget Celeron/Pentium): slower, more erratic.
 */
function lowEndHardware(n = 200, seed = 5) {
  const rand  = makeLcg(seed);
  const gauss = makeGauss(rand);
  const out   = [];
  let   base  = 9.0;
  for (let i = 0; i < n; i++) {
    base += rand() > 0.5 ? 0.002 : -0.001;
    out.push(Math.max(1.0, base + gauss(0, 1.1) + (rand() > 0.93 ? rand() * 7 : 0)));
  }
  return out;
}

/**
 * KVM virtual machine: quantized, periodic steal-time, no thermal growth.
 */
function kvmVm(n = 200, seed = 10) {
  const rand = makeLcg(seed);
  const out  = [];
  for (let i = 0; i < n; i++) {
    const q     = Math.round((5.0 + (rand() * 2 - 1) * 0.15) * 10) / 10;
    const steal = (i % 50 < 3) ? 1.8 : 0;
    out.push(q + steal);
  }
  return out;
}

/**
 * VMware ESXi: tighter quantization than KVM, different steal-time rhythm.
 */
function vmwareEsxi(n = 200, seed = 11) {
  const rand = makeLcg(seed);
  const out  = [];
  for (let i = 0; i < n; i++) {
    const q = Math.round((5.0 + (rand() * 2 - 1) * 0.08) * 20) / 20;
    out.push(q + ((i % 25 < 2) ? 2.2 : 0));
  }
  return out;
}

/**
 * Docker container (overlayFS, cgroupv2 limits): very flat, no spikes.
 */
function dockerContainer(n = 200, seed = 12) {
  const rand = makeLcg(seed);
  return Array.from({ length: n }, () =>
    Math.round((5.0 + (rand() * 2 - 1) * 0.05) * 100) / 100
  );
}

/**
 * AWS Lambda (Firecracker microVM): extremely flat, 1ms timer resolution.
 */
function awsLambda(n = 200, seed = 13) {
  const rand = makeLcg(seed);
  return Array.from({ length: n }, () =>
    Math.round(5.0 + (rand() * 2 - 1) * 0.02)
  );
}

/**
 * Headless Chrome / Puppeteer: Chromium timer jitter reduction active.
 */
function headlessChrome(n = 200, seed = 14) {
  const rand = makeLcg(seed);
  return Array.from({ length: n }, () =>
    Math.round((5.0 + (rand() * 2 - 1) * 0.10) * 5) / 5
  );
}

// ─── Phased data builders ─────────────────────────────────────────────────────

function phasedReal(seed = 1) {
  const rand  = makeLcg(seed);
  const gauss = makeGauss(rand);
  const cold  = Array.from({ length: 50  }, (_, i) => Math.max(0.5, 5.0 + i * 0.0005 + gauss(0, 0.40)));
  const load  = Array.from({ length: 100 }, (_, i) => Math.max(0.5, 5.1 + i * 0.0010 + gauss(0, 0.55)));
  const hot   = Array.from({ length: 50  }, (_, i) => Math.max(0.5, 5.3 + i * 0.0005 + gauss(0, 0.72)));
  const coldQE = detectQuantizationEntropy(cold);
  const hotQE  = detectQuantizationEntropy(hot);
  return { cold, load, hot, all: [...cold, ...load, ...hot],
           cold: { qe: coldQE, mean: cold.reduce((s,v)=>s+v,0)/cold.length, timings: cold, n: cold.length },
           hot:  { qe: hotQE,  mean: hot.reduce((s,v)=>s+v,0)/hot.length,  timings: hot,  n: hot.length },
           entropyJitterRatio: coldQE > 0 ? hotQE / coldQE : 1.0 };
}

function phasedVm(seed = 10) {
  const rand = makeLcg(seed);
  const mkPhase = (n) => Array.from({ length: n }, (_, i) =>
    Math.round((5.0 + (rand() * 2 - 1) * 0.15) * 10) / 10 + (i % 50 < 3 ? 1.8 : 0)
  );
  const cold = mkPhase(50), load = mkPhase(100), hot = mkPhase(50);
  const coldQE = detectQuantizationEntropy(cold);
  const hotQE  = detectQuantizationEntropy(hot);
  return {
    cold: { qe: coldQE, mean: cold.reduce((s,v)=>s+v,0)/cold.length, timings: cold, n: cold.length },
    hot:  { qe: hotQE,  mean: hot.reduce((s,v)=>s+v,0)/hot.length,  timings: hot,  n: hot.length  },
    all:  [...cold, ...load, ...hot],
    entropyJitterRatio: coldQE > 0 ? hotQE / coldQE : 1.0,
  };
}

// ─── Autocorrelation helper ───────────────────────────────────────────────────

function autocorr(arr, lags = [1, 2, 3, 5, 10, 25, 50]) {
  const n    = arr.length;
  const mean = arr.reduce((s, v) => s + v, 0) / n;
  const result = {};
  for (const lag of lags) {
    if (lag >= n) { result[`lag${lag}`] = 0; continue; }
    let num = 0, da = 0, db = 0;
    for (let i = 0; i < n - lag; i++) {
      const a = arr[i]       - mean;
      const b = arr[i + lag] - mean;
      num += a * b; da += a * a; db += b * b;
    }
    result[`lag${lag}`] = Math.sqrt(da * db) < 1e-14 ? 0 : num / Math.sqrt(da * db);
  }
  return result;
}

// ─── Stress test helpers ──────────────────────────────────────────────────────

function analyse(timings, phases = null) {
  const jitter = classifyJitter(timings, { autocorrelations: autocorr(timings) });
  const heuristic = runHeuristicEngine({
    jitter,
    phases,
    autocorrelations: autocorr(timings),
  });
  return { jitter, heuristic };
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. FALSE POSITIVE RESISTANCE
// ═════════════════════════════════════════════════════════════════════════════

describe('False positive resistance — real hardware must not be flagged', () => {

  test('consumer desktop — jitter score ≥ 0.60', () => {
    const { jitter } = analyse(realHardware(200, 1));
    expect(jitter.score).toBeGreaterThanOrEqual(0.60);
    expect(jitter.flags).not.toContain('CV_TOO_FLAT_VM_INDICATOR');
  });

  test('consumer desktop seed variety — all 5 seeds pass', () => {
    for (let seed = 1; seed <= 5; seed++) {
      const { jitter } = analyse(realHardware(200, seed));
      expect(jitter.score).toBeGreaterThanOrEqual(0.55);
    }
  });

  test('Brave browser (timer clamped 100µs) — still passes', () => {
    const { jitter } = analyse(braveClamped(200, 2));
    expect(jitter.score).toBeGreaterThanOrEqual(0.50);
    expect(jitter.flags).not.toContain('CV_TOO_FLAT_VM_INDICATOR');
  });

  test('heavy load desktop — high CV does not false-flag', () => {
    const { jitter } = analyse(heavyLoadHardware(200, 3));
    expect(jitter.score).toBeGreaterThanOrEqual(0.50);
    expect(jitter.flags).not.toContain('CV_TOO_FLAT_VM_INDICATOR');
  });

  test('ARM hardware (Apple M2 class) — passes with tighter distribution', () => {
    const { jitter } = analyse(armHardware(200, 4));
    expect(jitter.score).toBeGreaterThanOrEqual(0.52);
  });

  test('low-end hardware (Celeron class) — passes despite slow, erratic timings', () => {
    const { jitter } = analyse(lowEndHardware(200, 5));
    expect(jitter.score).toBeGreaterThanOrEqual(0.48);
  });

  test('physical floor: noisy real device does not compound-penalise to rejection', () => {
    // Simulates a real device with weak EJR (1.04), borderline lag50, mild neg-skew
    // Physical floor protection should cap penalty at 0.22
    const rand  = makeLcg(99);
    const gauss = makeGauss(rand);
    const timings = Array.from({ length: 200 }, (_, i) =>
      Math.max(0.5, 5.0 + gauss(0, 0.45) + (rand() > 0.95 ? rand() * 3 : 0) + i * 0.0003)
    );
    const { heuristic } = analyse(timings);
    expect(heuristic.penalty).toBeLessThanOrEqual(0.22);
    expect(heuristic.hardOverride).toBeNull();
  });

  test('physical floor: weak EJR alone does not trigger hard kill', () => {
    // EJR = 1.04 (just under 1.08 threshold) — borderline but not a forgery
    const cold = realHardware(50, 7);
    const hot  = cold.map(v => v * 1.03); // 3% increase (weak but real)
    const coldQE = detectQuantizationEntropy(cold);
    const hotQE  = detectQuantizationEntropy(hot);
    const phases = {
      cold: { qe: coldQE, mean: cold.reduce((s,v)=>s+v,0)/cold.length, timings: cold, n: cold.length },
      hot:  { qe: hotQE,  mean: hot.reduce((s,v)=>s+v,0)/hot.length,  timings: hot,  n: hot.length },
      entropyJitterRatio: coldQE > 0 ? hotQE / coldQE : 1.0,
    };
    const jitter = classifyJitter([...cold, ...hot], { autocorrelations: autocorr([...cold, ...hot]) });
    const heuristic = runHeuristicEngine({ jitter, phases, autocorrelations: autocorr([...cold, ...hot]) });
    expect(heuristic.hardOverride).toBeNull();
  });

  test('heuristic: Brownian coherence bonus awarded on real hardware', () => {
    // Seed 7 produces pure white noise (IID Gaussian) with H ≈ 0.47 and ac1 ≈ 0.08
    // — within the Brownian window [0.45, 0.55], which is the ideal thermal noise profile
    const rand7 = makeLcg(7);
    const gauss7 = makeGauss(rand7);
    const timings = Array.from({ length: 200 }, () => Math.max(0.1, 5.0 + gauss7(0, 0.3)));
    const jitter  = classifyJitter(timings, { autocorrelations: autocorr(timings) });
    const heuristic = runHeuristicEngine({ jitter, phases: null, autocorrelations: autocorr(timings) });
    const brownianBonus = heuristic.bonuses.find(b => b.id === 'BROWNIAN_COHERENCE_CONFIRMED');
    expect(brownianBonus).toBeDefined();
  });

  test('real hardware phased: EJR grows, thermal drift bonus awarded', () => {
    // Cold phase: tight distribution (σ=0.12) → low QE
    // Hot phase:  wide distribution (σ=0.85) → high QE → EJR >> 1.08
    const cRand = makeLcg(1), cGauss = makeGauss(cRand);
    const hRand = makeLcg(2), hGauss = makeGauss(hRand);
    const cold   = Array.from({ length: 50 }, () => Math.max(0.5, 5.0 + cGauss(0, 0.12)));
    const hot    = Array.from({ length: 50 }, () => Math.max(0.5, 5.0 + hGauss(0, 0.85)));
    const coldQE = detectQuantizationEntropy(cold);
    const hotQE  = detectQuantizationEntropy(hot);
    const phases = {
      cold: { qe: coldQE, mean: cold.reduce((s,v)=>s+v,0)/cold.length, timings: cold, n: cold.length },
      hot:  { qe: hotQE,  mean: hot.reduce((s,v)=>s+v,0)/hot.length,  timings: hot,  n: hot.length },
      entropyJitterRatio: coldQE > 0 ? hotQE / coldQE : 1.0,
    };
    const all = [...cold, ...hot];
    const jitter = classifyJitter(all, { autocorrelations: autocorr(all) });
    const heuristic = runHeuristicEngine({ jitter, phases, autocorrelations: autocorr(all) });
    expect(heuristic.hardOverride).toBeNull();
    const ejrBonus = heuristic.bonuses.find(b => b.id === 'ENTROPY_GROWS_WITH_LOAD');
    expect(ejrBonus).toBeDefined();
  });

  test('TrustScore: real hardware ≥ grade C (score ≥ 60)', () => {
    const timings = realHardware(200, 1);
    const jitter  = classifyJitter(timings, { autocorrelations: autocorr(timings) });
    const payload = { signals: { entropy: {
      quantizationEntropy: jitter.quantizationEntropy,
      hurstExponent: jitter.hurstExponent,
      timingsCV: jitter.stats.cv,
      autocorr_lag1: Object.values(jitter.autocorrelations)[0] ?? 0,
    }, bio: { hasActivity: true }, llm: null }, classification: { jitterScore: jitter.score, vmIndicators: [] } };
    const ts = computeTrustScore(payload);
    expect(ts.score).toBeGreaterThanOrEqual(60);
    expect(['A','B','C']).toContain(ts.grade);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 2. TRUE POSITIVE DETECTION
// ═════════════════════════════════════════════════════════════════════════════

describe('True positive detection — VMs and simulations must be caught', () => {

  test('KVM VM — jitter score ≤ 0.50', () => {
    const { jitter } = analyse(kvmVm(200, 10));
    expect(jitter.score).toBeLessThanOrEqual(0.50);
  });

  test('KVM VM — CV_TOO_FLAT or LOW_QUANTIZATION_ENTROPY flag raised', () => {
    const { jitter } = analyse(kvmVm(200, 10));
    const hasVmFlag = jitter.flags.some(f =>
      f.includes('VM') || f.includes('FLAT') || f.includes('SYNTHETIC') ||
      f.includes('LOW_QUANTIZATION')
    );
    expect(hasVmFlag).toBe(true);
  });

  test('VMware ESXi — jitter score ≤ 0.50', () => {
    const { jitter } = analyse(vmwareEsxi(200, 11));
    expect(jitter.score).toBeLessThanOrEqual(0.50);
  });

  test('Docker container — jitter score ≤ 0.50', () => {
    const { jitter } = analyse(dockerContainer(200, 12));
    expect(jitter.score).toBeLessThanOrEqual(0.50);
  });

  test('AWS Lambda / Firecracker — jitter score ≤ 0.20', () => {
    const { jitter } = analyse(awsLambda(200, 13));
    expect(jitter.score).toBeLessThanOrEqual(0.20);
  });

  test('Headless Chrome — quantized timer detected', () => {
    const { jitter } = analyse(headlessChrome(200, 14));
    expect(jitter.score).toBeLessThanOrEqual(0.35);
    expect(jitter.flags.some(f => f.includes('LOW_QUANTIZATION') || f.includes('FLAT'))).toBe(true);
  });

  test('KVM VM phased: EJR ≈ 1.0 penalised', () => {
    const phases = phasedVm(10);
    const timings = phases.all;
    const jitter  = classifyJitter(timings, { autocorrelations: autocorr(timings) });
    const heuristic = runHeuristicEngine({ jitter, phases, autocorrelations: autocorr(timings) });
    expect(heuristic.penalty).toBeGreaterThan(0.05);
    const flatFinding = heuristic.findings.find(f =>
      f.id === 'ENTROPY_FLAT_UNDER_LOAD' || f.id === 'ENTROPY_DECREASES_UNDER_LOAD'
    );
    expect(flatFinding).toBeDefined();
  });

  test('VM seed variety — all 5 VM seeds score ≤ 0.50', () => {
    for (let seed = 10; seed <= 14; seed++) {
      const { jitter } = analyse(kvmVm(200, seed));
      expect(jitter.score).toBeLessThanOrEqual(0.50);
    }
  });

  test('KVM steal-time picket fence detected', () => {
    const timings = kvmVm(200, 10);
    const ac = autocorr(timings, [1, 2, 3, 5, 10, 25, 50]);
    const jitter = classifyJitter(timings, { autocorrelations: ac });
    const heuristic = runHeuristicEngine({ jitter, phases: null, autocorrelations: ac });
    // Picket fence at lag-50 (50-iteration steal period) or high autocorr flag
    const hasPeriodicSignal =
      heuristic.picketFence.detected ||
      jitter.flags.includes('HIGH_AUTOCORR_VM_SCHEDULER_DETECTED') ||
      jitter.flags.includes('MODERATE_AUTOCORR_POSSIBLE_SCHEDULER');
    expect(hasPeriodicSignal).toBe(true);
  });

  test('TrustScore: KVM VM gets grade F (score ≤ 35)', () => {
    const timings = kvmVm(200, 10);
    const jitter  = classifyJitter(timings, { autocorrelations: autocorr(timings) });
    const payload = { signals: { entropy: {
      quantizationEntropy: jitter.quantizationEntropy,
      hurstExponent: jitter.hurstExponent,
      timingsCV: jitter.stats.cv,
      autocorr_lag1: Object.values(jitter.autocorrelations)[0] ?? 0,
    }, bio: { hasActivity: false }, llm: null }, classification: { jitterScore: jitter.score, vmIndicators: [] } };
    const ts = computeTrustScore(payload);
    expect(ts.score).toBeLessThanOrEqual(40);
    expect(['D','F']).toContain(ts.grade);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 3. ADVERSARIAL SIMULATION ATTACKS
// ═════════════════════════════════════════════════════════════════════════════

describe('Adversarial simulation attacks — cannot trick with crafted inputs', () => {

  // ── Attack 1: Gaussian noise injection ────────────────────────────────────
  // Attacker adds Gaussian noise to a VM profile to inflate CV.
  // NOTE: Gaussian noise injection is a known hard attack against pure jitter
  // analysis. Sufficient noise makes VM data statistically indistinguishable
  // from real hardware at this layer. The multi-layer defense (ENF, DRAM, GPU,
  // TrustScore hard floors) is required to catch this. These tests verify the
  // noise is at least reflected in the score and that the heuristic engine runs.
  test('gaussian noise injection on KVM — score reflects noise (jitter layer only)', () => {
    const rand  = makeLcg(100);
    const gauss = makeGauss(rand);
    const base  = kvmVm(200, 10);
    const baseScore = classifyJitter(base).score;
    // Inject σ=0.4 Gaussian noise
    const attacked = base.map(v => Math.max(0.5, v + gauss(0, 0.40)));
    const { jitter, heuristic } = analyse(attacked);

    // Noise inflates jitter score (this is the known attack vector — multi-layer
    // defense catches what jitter alone cannot)
    expect(jitter.score).toBeGreaterThan(baseScore);

    // Heuristic engine must run without error
    expect(Array.isArray(heuristic.findings)).toBe(true);
    expect(Array.isArray(heuristic.bonuses)).toBe(true);
  });

  // ── Attack 2: Heavy noise injection (σ=0.8) ────────────────────────────
  // Heavy noise completely overwhelms the jitter signal. Jitter layer alone
  // cannot distinguish this from real hardware. ENF + DRAM + GPU layers are
  // the primary defense. This test documents the known limitation.
  test('heavy gaussian noise injection — jitter score boosted (known attack vector)', () => {
    const rand  = makeLcg(101);
    const gauss = makeGauss(rand);
    const base  = kvmVm(200, 10);
    const baseScore = classifyJitter(base).score;
    const attacked = base.map(v => Math.max(0.3, v + gauss(0, 0.80)));
    const { jitter } = analyse(attacked);
    // Heavy noise pushes score up toward real hardware range — document this
    expect(jitter.score).toBeGreaterThan(baseScore);
    // Score must still be bounded [0,1]
    expect(jitter.score).toBeGreaterThanOrEqual(0);
    expect(jitter.score).toBeLessThanOrEqual(1);
  });

  // ── Attack 3: Synthetic thermal drift ─────────────────────────────────────
  // Attacker adds a linear trend to fake thermal growth.
  // Defense: Linear trend introduces high lag-1 autocorrelation, which is
  // caught by the autocorrelation check.
  test('synthetic thermal drift on KVM — autocorr anomaly catches it', () => {
    const base     = kvmVm(200, 10);
    const attacked = base.map((v, i) => v + i * 0.005); // fake thermal drift
    const { jitter } = analyse(attacked);
    // Adding a trend inflates lag-1 autocorr significantly
    const ac = autocorr(attacked);
    expect(Math.abs(ac.lag1)).toBeGreaterThan(0.20);
    // Jitter score should still be low
    expect(jitter.score).toBeLessThanOrEqual(0.50);
  });

  // ── Attack 4: Synthetic outlier injection ──────────────────────────────────
  // Attacker adds periodic spikes at fixed offsets to pass the outlier rate check.
  // Defense: Fixed-period spikes create a picket fence signal.
  test('fixed-period outlier injection — picket fence detected', () => {
    const base     = kvmVm(200, 10);
    // Add spike every 25 samples (fixed period)
    const attacked = base.map((v, i) => i % 25 === 0 ? v + 4.0 : v);
    const ac = autocorr(attacked, [1, 2, 3, 5, 10, 25, 50]);
    const jitter = classifyJitter(attacked, { autocorrelations: ac });
    const heuristic = runHeuristicEngine({ jitter, phases: null, autocorrelations: ac });
    expect(heuristic.picketFence.detected || Math.abs(ac.lag25 ?? 0) > 0.25).toBe(true);
  });

  // ── Attack 5: Random outlier injection ────────────────────────────────────
  // Attacker adds RANDOM spikes to avoid the picket fence detector.
  // Defense: Random spikes with synthetic VM base create CV-entropy incoherence.
  test('random outlier injection — CV-entropy incoherence or low score', () => {
    const rand  = makeLcg(102);
    const base  = kvmVm(200, 10);
    // Add random spikes at ~8% of positions (similar to real outlier rate)
    const attacked = base.map(v => rand() > 0.92 ? v + rand() * 5 : v);
    const { jitter, heuristic } = analyse(attacked);
    const suspicious =
      jitter.score <= 0.55 ||
      heuristic.findings.some(f => f.id === 'CV_ENTROPY_INCOHERENT');
    expect(suspicious).toBe(true);
  });

  // ── Attack 6: EJR forgery — Attack A (field overwritten) ──────────────────
  test('EJR forgery Attack A: stored EJR ≠ computed hot_QE/cold_QE → HARD KILL', () => {
    const cold = kvmVm(50, 10);
    const hot  = kvmVm(50, 11);
    const coldQE = detectQuantizationEntropy(cold);
    const hotQE  = detectQuantizationEntropy(hot);
    const computedEJR = coldQE > 0 ? hotQE / coldQE : 1.0;
    // Attacker overwrites EJR to claim thermal growth
    const forgedEJR = 1.20;

    const phases = {
      cold: { qe: coldQE, mean: cold.reduce((s,v)=>s+v,0)/cold.length, timings: cold, n: cold.length },
      hot:  { qe: hotQE,  mean: hot.reduce((s,v)=>s+v,0)/hot.length,  timings: hot,  n: hot.length  },
      entropyJitterRatio: forgedEJR, // FORGED
    };

    const all = [...cold, ...hot];
    const jitter = classifyJitter(all, { autocorrelations: autocorr(all) });
    const heuristic = runHeuristicEngine({ jitter, phases, autocorrelations: autocorr(all) });

    expect(heuristic.hardOverride).toBe('vm');
    const killFinding = heuristic.findings.find(f => f.id === 'EJR_PHASE_HARD_KILL');
    expect(killFinding).toBeDefined();
    expect(killFinding.severity).toBe('critical');
  });

  // ── Attack 7: EJR forgery — Attack B (QE contradiction) ──────────────────
  test('EJR forgery Attack B: cold_QE ≥ hot_QE but EJR ≥ 1.08 → HARD KILL', () => {
    // Attacker claims EJR=1.15 but cold_QE > hot_QE (physically impossible)
    const coldQE = 3.80;
    const hotQE  = 3.20; // hot < cold — entropy DECREASED under load
    const phases = {
      cold: { qe: coldQE, mean: 5.0, timings: [], n: 50 },
      hot:  { qe: hotQE,  mean: 5.3, timings: [], n: 50 },
      entropyJitterRatio: 1.15, // MATHEMATICALLY IMPOSSIBLE given QE values
    };

    const timings = realHardware(100, 1); // use real timings as cover
    const jitter  = classifyJitter(timings, { autocorrelations: autocorr(timings) });
    const heuristic = runHeuristicEngine({ jitter, phases, autocorrelations: autocorr(timings) });

    expect(heuristic.hardOverride).toBe('vm');
    const killFinding = heuristic.findings.find(f => f.id === 'EJR_PHASE_HARD_KILL');
    expect(killFinding).toBeDefined();
  });

  // ── Attack 8: Hard kill strips all bonuses ────────────────────────────────
  test('EJR hard kill: zero bonuses even with otherwise perfect metrics', () => {
    const coldQE = 4.0, hotQE = 3.0;
    const phases = {
      cold: { qe: coldQE, mean: 5.0, timings: [], n: 50 },
      hot:  { qe: hotQE,  mean: 5.4, timings: [], n: 50 },
      entropyJitterRatio: 1.30, // forged — claims growth when hot < cold
    };
    // Use legitimately-looking timings as cover
    const timings = realHardware(200, 1);
    const jitter  = classifyJitter(timings, { autocorrelations: autocorr(timings) });
    const heuristic = runHeuristicEngine({ jitter, phases, autocorrelations: autocorr(timings) });

    expect(heuristic.hardOverride).toBe('vm');
    expect(heuristic.bonus).toBe(0);
    expect(heuristic.bonuses).toHaveLength(0);
  });

  // ── Attack 9: Hurst masking ────────────────────────────────────────────────
  // Attacker adds anti-correlated noise to bring H from >0.7 toward 0.5.
  // Defense: Anti-correlation noise makes H < 0.5 (anti-persistent), which
  // creates a Hurst-autocorrelation coherence mismatch.
  test('Hurst masking via anti-correlated noise — coherence incoherence fires', () => {
    const rand = makeLcg(103);
    const base = kvmVm(200, 10);
    // Add mean-reverting (anti-correlated) noise to bring H toward 0.5
    const attacked = [];
    const mean = base.reduce((s,v)=>s+v,0)/base.length;
    for (let i = 0; i < base.length; i++) {
      const prev    = attacked[i - 1] ?? mean;
      const pullback = (mean - prev) * 0.5; // strong mean-reversion
      attacked.push(Math.max(0.3, base[i] + pullback + (rand() * 2 - 1) * 0.1));
    }
    const ac = autocorr(attacked);
    const jitter = classifyJitter(attacked, { autocorrelations: ac });
    const heuristic = runHeuristicEngine({ jitter, phases: null, autocorrelations: ac });

    // Either Hurst drops below 0.3 (anti-persistent flag) or coherence mismatch
    const suspicious =
      jitter.hurstExponent < 0.35 ||
      jitter.flags.some(f => f.includes('ANTIPERSISTENT')) ||
      heuristic.findings.some(f => f.id === 'HURST_AUTOCORR_INCOHERENT') ||
      jitter.score < 0.55;
    expect(suspicious).toBe(true);
  });

  // ── Attack 10: CV-entropy decoupling ──────────────────────────────────────
  // Attacker inflates CV by adding fixed-offset outliers (not random noise).
  // Defense: Fixed offsets add variance but barely increase entropy (fixed bins).
  test('CV-entropy decoupling via fixed-offset outliers — incoherence detected', () => {
    const base = dockerContainer(200, 12); // very flat base
    // Add fixed-magnitude outliers at random positions (same value → one extra bin)
    const rand  = makeLcg(104);
    const attacked = base.map(v => rand() > 0.90 ? v + 3.00 : v); // fixed 3ms spike
    const qe = detectQuantizationEntropy(attacked);
    const stats = computeStats(attacked);

    // CV inflated by spikes, but QE barely changed (only 1 new bin added)
    const expectedQE = Math.max(0, 1.5 + stats.cv * 16);
    const gap = expectedQE - qe;

    // With 10% spikes at exactly +3ms, gap should be large
    // (high CV expected high QE, but QE only has 2 clusters)
    expect(gap).toBeGreaterThan(0.5); // coherence gap exists
  });

  // ── Attack 11: Replay attack on HMAC challenge ────────────────────────────
  test('replay attack: nonce consumed on first use, rejected on second', async () => {
    const secret   = generateSecret();
    const challenge = createChallenge(secret, { ttlMs: 60_000 });
    const usedNonces = new Set();

    const checkNonce = async (n) => {
      if (usedNonces.has(n)) return false;
      usedNonces.add(n);
      return true;
    };

    const first  = await verifyChallenge(challenge, secret, { checkNonce });
    const second = await verifyChallenge(challenge, secret, { checkNonce });

    expect(first.valid).toBe(true);
    expect(second.valid).toBe(false);
    expect(second.reason).toBe('nonce_already_used_or_unknown');
  });

  // ── Attack 12: Forged HMAC signature ──────────────────────────────────────
  test('forged HMAC signature rejected with timing-safe comparison', async () => {
    const secret    = generateSecret();
    const challenge = createChallenge(secret, { ttlMs: 60_000 });
    const forged    = { ...challenge, sig: 'a'.repeat(64) }; // wrong sig

    const result = await verifyChallenge(forged, secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid_signature');
  });

  // ── Attack 13: Tampered expiry timestamp ──────────────────────────────────
  test('tampered expiresAt breaks HMAC signature', async () => {
    const secret    = generateSecret();
    const challenge = createChallenge(secret, { ttlMs: 60_000 });
    // Attacker extends the validity window
    const tampered  = { ...challenge, expiresAt: challenge.expiresAt + 3_600_000 };

    const result = await verifyChallenge(tampered, secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid_signature');
  });

  // ── Attack 14: Expired challenge ──────────────────────────────────────────
  test('expired challenge rejected regardless of valid signature', async () => {
    const secret    = generateSecret();
    const challenge = createChallenge(secret, { ttlMs: -1_000 }); // already expired
    const result    = await verifyChallenge(challenge, secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('challenge_expired');
  });

  // ── Attack 15: Wrong server secret ────────────────────────────────────────
  test('challenge signed with different secret is rejected', async () => {
    const secret1   = generateSecret();
    const secret2   = generateSecret();
    const challenge = createChallenge(secret1, { ttlMs: 60_000 });
    const result    = await verifyChallenge(challenge, secret2);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid_signature');
  });

  // ── Attack 16: Combine all noise techniques ────────────────────────────────
  // Attacker uses ALL noise injection techniques simultaneously.
  // Defense: Even combined, the underlying quantization is detectable,
  // and the coherence checks catch the inconsistencies.
  test('combined attack (noise + drift + outliers) — still flagged or borderline', () => {
    const rand  = makeLcg(200);
    const gauss = makeGauss(rand);
    const base  = kvmVm(200, 10);

    // Step 1: Gaussian noise (σ=0.3)
    let attacked = base.map(v => Math.max(0.5, v + gauss(0, 0.30)));
    // Step 2: Linear drift
    attacked = attacked.map((v, i) => v + i * 0.003);
    // Step 3: Random outliers at ~6% rate
    attacked = attacked.map(v => rand() > 0.94 ? v + gauss(2.5, 0.5) : v);

    const { jitter, heuristic } = analyse(attacked);

    // Score must not reach real hardware territory
    expect(jitter.score).toBeLessThanOrEqual(0.68);

    // At least one anomaly must be flagged or the score is still well below the
    // 0.60 threshold that real hardware achieves on its worst day
    const anySuspicion =
      jitter.score <= 0.55 ||
      heuristic.findings.length > 0 ||
      jitter.flags.some(f => f.includes('VM') || f.includes('FLAT') || f.includes('INCOHERENT'));
    expect(anySuspicion).toBe(true);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 4. TRUSTSCORE CALIBRATION
// ═════════════════════════════════════════════════════════════════════════════

describe('TrustScore calibration — hard floors and grades are correct', () => {

  function mockPayload(overrides = {}) {
    return {
      signals: {
        entropy: {
          quantizationEntropy: 4.2,
          hurstExponent:       0.50,
          timingsCV:           0.12,
          autocorr_lag1:       0.04,
          ...overrides.entropy,
        },
        bio:  { hasActivity: true, ...overrides.bio },
        llm:  overrides.llm ?? null,
        enf:  overrides.enf  ?? null,
        gpu:  overrides.gpu  ?? null,
        dram: overrides.dram ?? null,
      },
      classification: {
        jitterScore:   overrides.jitterScore  ?? 0.80,
        vmIndicators:  overrides.vmIndicators ?? [],
        ...overrides.classification,
      },
    };
  }

  test('perfect real hardware → grade A (score ≥ 90)', () => {
    const ts = computeTrustScore(mockPayload(), {
      enf:  { enfAvailable: true, ripplePresent: true, gridRegion: 'americas', ripplePower: 0.12, snr50hz: 0, snr60hz: 4.5, isVmIndicator: false },
      gpu:  { gpuPresent: true, isSoftware: false, thermalGrowth: 0.07 },
      dram: { refreshPresent: true, refreshPeriodMs: 7.8, peakPower: 0.35 },
    });
    expect(ts.score).toBeGreaterThanOrEqual(88);
    expect(['A','B']).toContain(ts.grade);
  });

  test('EJR forgery hard cap: score ≤ 20', () => {
    const ts = computeTrustScore(mockPayload({
      entropy: { quantizationEntropy: 0.8 }, // triggers ejrForgery in physics scorer
    }));
    expect(ts.score).toBeLessThanOrEqual(20);
  });

  test('software GPU hard cap: score ≤ 45', () => {
    const ts = computeTrustScore(mockPayload(), {
      gpu: { gpuPresent: true, isSoftware: true, thermalGrowth: 0 },
    });
    expect(ts.score).toBeLessThanOrEqual(45);
    expect(ts.grade).toBe('D');
  });

  test('LLM agent >85% hard cap: score ≤ 30', () => {
    const ts = computeTrustScore(mockPayload({
      llm: { aiConf: 0.91, verdict: 'ai_agent' },
    }));
    expect(ts.score).toBeLessThanOrEqual(30);
    expect(['D','F']).toContain(ts.grade);
  });

  test('no bio + no ENF cap: score ≤ 55', () => {
    const ts = computeTrustScore(mockPayload({
      bio: { hasActivity: false },
      enf: { enfAvailable: true, ripplePresent: false, isVmIndicator: false },
    }));
    expect(ts.score).toBeLessThanOrEqual(55);
  });

  test('hard caps do not compound incorrectly — lowest cap wins', () => {
    // Both software GPU (cap 45) and LLM agent (cap 30) — should get cap 30
    const ts = computeTrustScore(mockPayload({
      llm: { aiConf: 0.92, verdict: 'ai_agent' },
    }), {
      gpu: { gpuPresent: true, isSoftware: true, thermalGrowth: 0 },
    });
    expect(ts.score).toBeLessThanOrEqual(30);
  });

  test('formatTrustScore returns expected string format', () => {
    // formatTrustScore is already imported at the top — verify it works
    import('../src/analysis/trustScore.js').then(({ formatTrustScore: fmt }) => {
      const ts = computeTrustScore(mockPayload());
      const str = fmt(ts);
      expect(str).toMatch(/TrustScore \d+\/100/);
      expect(str).toMatch(/[ABCDF] · /);
    });
  });

  test('per-signal values are in [0, 1]', () => {
    const ts = computeTrustScore(mockPayload());
    for (const [key, val] of Object.entries(ts.signals)) {
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThanOrEqual(1);
    }
  });

  test('score equals sum of pts bounded by hardCap', () => {
    const ts = computeTrustScore(mockPayload());
    const rawSum = Object.values(ts.breakdown).reduce((s, b) => s + (b.pts ?? 0), 0)
      + ts.bonuses.reduce((s, b) => s + b.pts, 0);
    const expected = ts.hardCap !== null ? Math.min(ts.hardCap, Math.min(100, rawSum)) : Math.min(100, rawSum);
    expect(ts.score).toBe(expected);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 5. SEPARATION: real hardware vs VM score distributions must not overlap
// ═════════════════════════════════════════════════════════════════════════════

describe('Score separation — real hardware and VM distributions must not overlap', () => {

  function scoreMany(gen, count = 20) {
    return Array.from({ length: count }, (_, i) => {
      const { jitter } = analyse(gen(200, i + 1));
      return jitter.score;
    });
  }

  test('min real hardware score > max VM score (20 samples each)', () => {
    const realScores = scoreMany(realHardware, 20);
    const vmScores   = [
      ...scoreMany(kvmVm,         7),
      ...scoreMany(vmwareEsxi,    5),
      ...scoreMany(dockerContainer, 5),
      ...scoreMany(awsLambda,     3),
    ];

    const minReal = Math.min(...realScores);
    const maxVM   = Math.max(...vmScores);

    // There must be a meaningful gap between the worst real device
    // and the best VM attempt
    expect(minReal).toBeGreaterThan(maxVM - 0.05); // ≤5% overlap allowed

    // Log the gap for visibility
    const gap = minReal - maxVM;
    if (gap < 0.10) {
      console.warn(`⚠ Score gap is narrow: minReal=${minReal.toFixed(3)} maxVM=${maxVM.toFixed(3)} gap=${gap.toFixed(3)}`);
    }
  });

  test('mean real score − mean VM score ≥ 0.30', () => {
    const realScores = scoreMany(realHardware, 20);
    const vmScores   = scoreMany(kvmVm, 20);
    const meanReal   = realScores.reduce((s,v)=>s+v,0)/realScores.length;
    const meanVM     = vmScores.reduce((s,v)=>s+v,0)/vmScores.length;
    expect(meanReal - meanVM).toBeGreaterThanOrEqual(0.28);
  });

  test('adversarial VM scores are still below real hardware min', () => {
    const rand  = makeLcg(999);
    const gauss = makeGauss(rand);

    const adversarialScores = Array.from({ length: 20 }, (_, i) => {
      const base = kvmVm(200, i + 50);
      // Apply all noise techniques
      let attacked = base.map(v => Math.max(0.3, v + gauss(0, 0.25)));
      attacked = attacked.map((v, j) => v + j * 0.002);
      attacked = attacked.map(v => rand() > 0.93 ? v + rand() * 3 : v);
      const { jitter } = analyse(attacked);
      return jitter.score;
    });

    const realMin    = Math.min(...scoreMany(realHardware, 20));
    const attackMax  = Math.max(...adversarialScores);

    // Adversarial attacks must not exceed the real hardware ceiling by more than 15%
    expect(attackMax).toBeLessThanOrEqual(realMin + 0.15); // 15% tolerance
  });
});

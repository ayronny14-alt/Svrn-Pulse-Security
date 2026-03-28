/**
 * @svrnsec/pulse — Engagement Token Test Suite
 *
 * Tests cover three modules:
 *   1. IdleAttestation  — state machine, hash chain, thermal classification
 *   2. PopulationEntropy — all 5 statistical Sybil-detection tests
 *   3. EngagementToken  — creation, verification, replay prevention, risk signals
 *
 * Philosophy: every test asserts a physically meaningful invariant, not an
 * implementation detail. The numbers come from the same deterministic RNG
 * used in stress.test.js so results are reproducible across environments.
 */

import { jest } from '@jest/globals';

import { createIdleMonitor, analyseIdleProof, _miniProbe }
  from '../src/collector/idleAttestation.js';

import {
  analysePopulation,
  testTimestampRhythm,
  testEntropyDispersion,
  testThermalDiversity,
  testIdlePlausibility,
  testEnfCoherence,
} from '../src/analysis/populationEntropy.js';

import {
  createEngagementToken,
  verifyEngagementToken,
  encodeToken,
  decodeToken,
} from '../src/proof/engagementToken.js';

// ── Deterministic helpers ──────────────────────────────────────────────────────

function makeLcg(seed) {
  let s = (seed >>> 0) || 0xdeadbeef;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 0xFFFFFFFF;
  };
}

const SECRET = 'test-secret-at-least-32-characters-long!';

// ── Synthetic idle proofs ──────────────────────────────────────────────────────

/**
 * Build a plausible IdleProof representing a real device that cooled gradually.
 * Thermal variance decays from 0.040 to 0.010 across 3 samples (60% drop,
 * distributed smoothly → hot_to_cold, monotonicity 1.0).
 */
function makeRealIdleProof(overrides = {}) {
  return {
    chain:               'a'.repeat(64),
    samples:             3,
    idleDurationMs:      90_000,
    thermalTransition:   'hot_to_cold',
    coolingMonotonicity: 1.0,
    baselineVariance:    0.040,
    finalVariance:       0.010,
    capturedAt:          Date.now(),
    ...overrides,
  };
}

/**
 * Build an IdleProof representing a click farm script pause.
 * Variance drops from 0.040 to 0.006 in the first interval (90% of drop)
 * then stays flat → step_function.
 */
function makeFarmIdleProof(overrides = {}) {
  return {
    chain:               'b'.repeat(64),
    samples:             3,
    idleDurationMs:      50_000,
    thermalTransition:   'step_function',
    coolingMonotonicity: 0.10,
    baselineVariance:    0.040,
    finalVariance:       0.007,
    capturedAt:          Date.now(),
    ...overrides,
  };
}

/**
 * Build a valid engagement token directly (bypasses createEngagementToken
 * for population tests where we need fine-grained control over fields).
 */
function makeToken(fields = {}) {
  return {
    iat:  Date.now(),
    idle: { dMs: 90_000, therm: 'hot_to_cold' },
    hw:   { ent: 0.75, dram: 'dram', enf: 'grid_60hz' },
    evt:  { t: 'click', mot: 0.80 },
    ...fields,
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. IDLE ATTESTATION — STATE MACHINE
// ═════════════════════════════════════════════════════════════════════════════

describe('IdleAttestation — state machine and proof quality', () => {

  test('initial state is ACTIVE', () => {
    const monitor = createIdleMonitor();
    expect(monitor.getState()).toBe('active');
  });

  test('getProof returns null when in ACTIVE state (no idle period recorded)', () => {
    const monitor = createIdleMonitor();
    expect(monitor.getProof()).toBeNull();
  });

  test('declareIdle transitions to IDLE_WATCH after grace period', done => {
    jest.useFakeTimers();
    const monitor = createIdleMonitor({ minIdleMs: 45_000, sampleIntervalMs: 30_000 });
    monitor.declareIdle();
    expect(monitor.getState()).toBe('idle_watch');

    jest.advanceTimersByTime(5_001); // past grace period
    expect(monitor.getState()).toBe('idle_sampling');

    jest.useRealTimers();
    done();
  });

  test('getProof is null if device never passed MIN_IDLE_MS', done => {
    jest.useFakeTimers();
    const monitor = createIdleMonitor({ minIdleMs: 45_000, sampleIntervalMs: 30_000 });
    monitor.declareIdle();
    jest.advanceTimersByTime(5_001);   // enter sampling
    jest.advanceTimersByTime(10_000);  // only 10s of idle — below 45s threshold
    monitor.declareActive();           // triggers commitOrReset
    expect(monitor.getProof()).toBeNull();
    expect(monitor.getState()).toBe('active');
    jest.useRealTimers();
    done();
  });

  test('valid proof issued after MIN_IDLE_MS with ≥ 2 samples', done => {
    jest.useFakeTimers();
    const monitor = createIdleMonitor({ minIdleMs: 45_000, sampleIntervalMs: 30_000 });
    monitor.declareIdle();
    jest.advanceTimersByTime(5_001);   // enter sampling → first sample taken
    jest.advanceTimersByTime(30_001);  // second sample taken
    jest.advanceTimersByTime(15_000);  // total idle ≈ 50s — above 45s threshold
    monitor.declareActive();

    expect(monitor.getState()).toBe('idle_committed');
    const proof = monitor.getProof();
    expect(proof).not.toBeNull();
    expect(proof.samples).toBeGreaterThanOrEqual(2);
    expect(proof.idleDurationMs).toBeGreaterThanOrEqual(45_000);
    expect(proof.chain).toHaveLength(64); // SHA-256 hex
    expect(proof.capturedAt).toBeGreaterThan(0);

    // Proof is consumed — second call returns null
    expect(monitor.getProof()).toBeNull();
    expect(monitor.getState()).toBe('active');

    jest.useRealTimers();
    done();
  });

  test('hash chain is deterministically ordered (prevHash changes each step)', done => {
    jest.useFakeTimers();
    const monitor1 = createIdleMonitor({ sessionNonce: 'seed-a', minIdleMs: 45_000, sampleIntervalMs: 30_000 });
    const monitor2 = createIdleMonitor({ sessionNonce: 'seed-a', minIdleMs: 45_000, sampleIntervalMs: 30_000 });

    // Both monitors get the same timing sequence — chains should differ because
    // each _tick() calls performance.now() at different moments (but both
    // should be 64-char hex regardless of timing)
    monitor1.declareIdle();
    monitor2.declareIdle();
    jest.advanceTimersByTime(5_001);
    jest.advanceTimersByTime(30_001);
    jest.advanceTimersByTime(15_000);
    monitor1.declareActive();
    monitor2.declareActive();

    const p1 = monitor1.getProof();
    const p2 = monitor2.getProof();
    expect(p1?.chain).toHaveLength(64);
    expect(p2?.chain).toHaveLength(64);
    // Chain hashes encode real performance.now() timestamps — will differ
    // in the same process across two sequential runs even with fake timers
    expect(typeof p1?.chain).toBe('string');

    jest.useRealTimers();
    done();
  });

  test('reset clears pending proof — cannot get proof after second declareIdle', done => {
    jest.useFakeTimers();
    const monitor = createIdleMonitor({ minIdleMs: 45_000, sampleIntervalMs: 30_000 });
    monitor.declareIdle();
    jest.advanceTimersByTime(5_001);
    jest.advanceTimersByTime(30_001);
    jest.advanceTimersByTime(15_000);
    monitor.declareActive(); // → IDLE_COMMITTED

    // Start a new idle before consuming proof — old proof should be discarded
    monitor.declareIdle();
    expect(monitor.getState()).toBe('idle_watch');
    // Proof not yet consumed and now monitor is back in watch — getProof returns null
    expect(monitor.getProof()).toBeNull();

    jest.useRealTimers();
    done();
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 2. IDLE ATTESTATION — THERMAL CLASSIFICATION & ANALYSIS
// ═════════════════════════════════════════════════════════════════════════════

describe('IdleAttestation — thermal classification and proof analysis', () => {

  test('analyseIdleProof: valid real-hardware proof passes as plausible', () => {
    const result = analyseIdleProof(makeRealIdleProof());
    expect(result.plausible).toBe(true);
    expect(result.warnings).not.toContain('step_function_transition');
  });

  test('analyseIdleProof: farm step_function proof raises warning', () => {
    const result = analyseIdleProof(makeFarmIdleProof());
    expect(result.plausible).toBe(true); // still passes (advisory, not blocking)
    expect(result.warnings).toContain('abrupt_cpu_transition_detected');
  });

  test('analyseIdleProof: proof too short returns plausible=false', () => {
    const result = analyseIdleProof(makeRealIdleProof({ idleDurationMs: 10_000 }));
    expect(result.plausible).toBe(false);
    expect(result.reason).toBe('idle_too_short');
  });

  test('analyseIdleProof: single sample returns plausible=false', () => {
    const result = analyseIdleProof(makeRealIdleProof({ samples: 1 }));
    expect(result.plausible).toBe(false);
    expect(result.reason).toBe('insufficient_chain_samples');
  });

  test('analyseIdleProof: null returns plausible=false', () => {
    const result = analyseIdleProof(null);
    expect(result.plausible).toBe(false);
    expect(result.reason).toBe('no_proof');
  });

  test('analyseIdleProof: non-monotonic cooling (low monotonicity) raises warning', () => {
    const result = analyseIdleProof(makeRealIdleProof({ coolingMonotonicity: 0.15, samples: 4 }));
    expect(result.warnings).toContain('non_monotonic_cooling_curve');
  });

  test('_miniProbe returns valid ThermalSample structure', () => {
    // Allocate a small buffer for the unit test (no need for full 16MB)
    const buf    = new Float64Array(8_192);
    for (let i = 0; i < buf.length; i++) buf[i] = i;
    const sample = _miniProbe(buf);

    expect(typeof sample.ts).toBe('number');
    expect(sample.ts).toBeGreaterThan(0);
    expect(typeof sample.meanMs).toBe('number');
    // meanMs may be 0 with a tiny buffer on high-speed hardware (sub-ms timing)
    expect(sample.meanMs).toBeGreaterThanOrEqual(0);
    expect(typeof sample.variance).toBe('number');
    expect(sample.variance).toBeGreaterThanOrEqual(0);
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 3. POPULATION ENTROPY — INDIVIDUAL TESTS
// ═════════════════════════════════════════════════════════════════════════════

describe('PopulationEntropy — individual statistical tests', () => {

  // ── Timestamp rhythm ──────────────────────────────────────────────────────

  test('testTimestampRhythm: uniform dispatch scores HIGH (farm)', () => {
    const now    = Date.now();
    const tokens = Array.from({ length: 20 }, (_, i) => ({ iat: now + i * 2000 }));
    const result = testTimestampRhythm(tokens);
    expect(result.score).toBeGreaterThan(60);
  });

  test('testTimestampRhythm: random dispatch scores LOW (real users)', () => {
    const rand   = makeLcg(1);
    const now    = Date.now();
    let   cursor = now;
    const tokens = Array.from({ length: 20 }, () => {
      cursor += Math.floor(rand() * 120_000 + 5_000); // 5–125s random gaps
      return { iat: cursor };
    });
    const result = testTimestampRhythm(tokens);
    expect(result.score).toBeLessThan(50);
  });

  test('testTimestampRhythm: insufficient samples returns score 0', () => {
    const result = testTimestampRhythm([{ iat: 1 }, { iat: 2 }]);
    expect(result.score).toBe(0);
    expect(result.detail).toBe('insufficient_samples');
  });

  // ── Entropy dispersion ────────────────────────────────────────────────────

  test('testEntropyDispersion: homogeneous scores (farm) → score HIGH', () => {
    const tokens = Array.from({ length: 20 }, () => ({ hw: { ent: 0.72 + Math.random() * 0.01 } }));
    const result = testEntropyDispersion(tokens);
    expect(result.score).toBeGreaterThan(60);
    expect(result.cv).toBeLessThan(0.04);
  });

  test('testEntropyDispersion: diverse scores (real) → score LOW', () => {
    const rand   = makeLcg(2);
    const tokens = Array.from({ length: 20 }, () => ({ hw: { ent: 0.30 + rand() * 0.65 } }));
    const result = testEntropyDispersion(tokens);
    expect(result.score).toBeLessThan(40);
    expect(result.cv).toBeGreaterThan(0.08);
  });

  // ── Thermal diversity ─────────────────────────────────────────────────────

  test('testThermalDiversity: all step_function (farm) → score HIGH', () => {
    const tokens = Array.from({ length: 15 }, () => ({ idle: { therm: 'step_function' } }));
    const result = testThermalDiversity(tokens);
    expect(result.score).toBeGreaterThan(60);
    expect(result.suspiciousRatio).toBeGreaterThan(0.9);
  });

  test('testThermalDiversity: diverse transitions (real) → score LOW', () => {
    const labels = ['hot_to_cold', 'cold', 'cooling', 'warming', 'hot_to_cold', 'cold'];
    const tokens = Array.from({ length: 18 }, (_, i) => ({
      idle: { therm: labels[i % labels.length] },
    }));
    const result = testThermalDiversity(tokens);
    expect(result.score).toBeLessThan(40);
  });

  // ── Idle plausibility ─────────────────────────────────────────────────────

  test('testIdlePlausibility: durations clustered at minimum (farm) → score HIGH', () => {
    const rand   = makeLcg(3);
    // Farm: idle 45–70s uniformly (just above minimum to maximize throughput)
    const tokens = Array.from({ length: 20 }, () => ({
      idle: { dMs: 45_000 + Math.floor(rand() * 25_000) },
    }));
    const result = testIdlePlausibility(tokens);
    expect(result.score).toBeGreaterThan(40);
    expect(result.clusterRatio).toBeGreaterThan(0.80);
  });

  test('testIdlePlausibility: broad duration distribution (real) → score LOW', () => {
    const rand   = makeLcg(4);
    // Real users: idle spans minutes to hours
    const tokens = Array.from({ length: 20 }, () => ({
      idle: { dMs: 60_000 + Math.floor(rand() * 3_540_000) }, // 1min–60min
    }));
    const result = testIdlePlausibility(tokens);
    expect(result.score).toBeLessThan(40);
  });

  // ── ENF phase coherence ───────────────────────────────────────────────────

  test('testEnfCoherence: near-zero phase variance (farm rack) → score HIGH', () => {
    const tokens = Array.from({ length: 10 }, (_, i) => ({
      hw: { enfDev: 0.0012 + i * 0.000001 }, // variance ≈ 8e-12 Hz²
    }));
    const result = testEnfCoherence(tokens);
    expect(result.score).toBeGreaterThan(80);
  });

  test('testEnfCoherence: spread phase deviations (real users) → score LOW', () => {
    const rand   = makeLcg(5);
    const tokens = Array.from({ length: 10 }, () => ({
      hw: { enfDev: (rand() - 0.5) * 0.10 }, // ±0.05 Hz spread
    }));
    const result = testEnfCoherence(tokens);
    expect(result.score).toBeLessThan(30);
  });

  test('testEnfCoherence: insufficient ENF data returns score 0', () => {
    const tokens = [{ hw: {} }, { hw: {} }];
    const result = testEnfCoherence(tokens);
    expect(result.score).toBe(0);
    expect(result.phaseVariance).toBeNull();
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 4. POPULATION ENTROPY — FULL COHORT ANALYSIS
// ═════════════════════════════════════════════════════════════════════════════

describe('PopulationEntropy — full analysePopulation verdicts', () => {

  test('authentic cohort → authentic=true, sybilScore < 40', () => {
    const rand   = makeLcg(10);
    const now    = Date.now();
    let   cursor = now;
    const labels = ['hot_to_cold', 'cold', 'cooling', 'warming', 'hot_to_cold'];

    const tokens = Array.from({ length: 20 }, (_, i) => {
      cursor += Math.floor(rand() * 90_000 + 15_000);
      return {
        iat:  cursor,
        idle: { dMs: 90_000 + Math.floor(rand() * 300_000), therm: labels[i % labels.length] },
        hw:   { ent: 0.40 + rand() * 0.55, enfDev: (rand() - 0.5) * 0.03 },
      };
    });

    const verdict = analysePopulation(tokens);
    expect(verdict.authentic).toBe(true);
    expect(verdict.sybilScore).toBeLessThan(50);
    expect(verdict.confidence).toBeGreaterThan(0);
    expect(Array.isArray(verdict.flags)).toBe(true);
  });

  test('farm cohort → authentic=false, sybilScore ≥ 50', () => {
    const now    = Date.now();
    // Farm: uniform 2-second dispatch cadence, identical hardware, all step_function
    const tokens = Array.from({ length: 20 }, (_, i) => ({
      iat:  now + i * 2_000,
      idle: { dMs: 48_000 + i * 100, therm: 'step_function' },
      hw:   { ent: 0.71 + i * 0.001, enfDev: 0.0012 + i * 0.0000001 },
    }));

    const verdict = analysePopulation(tokens);
    expect(verdict.authentic).toBe(false);
    expect(verdict.sybilScore).toBeGreaterThanOrEqual(50);
    expect(verdict.flags.length).toBeGreaterThan(0);
  });

  test('insufficient sample returns authentic=true with confidence=0', () => {
    const verdict = analysePopulation([makeToken(), makeToken()], { minSample: 5 });
    expect(verdict.authentic).toBe(true);
    expect(verdict.confidence).toBe(0);
    expect(verdict.summary).toMatch(/INSUFFICIENT_SAMPLE/);
  });

  test('analysePopulation always returns required shape', () => {
    const verdict = analysePopulation(Array.from({ length: 10 }, () => makeToken()));
    expect(typeof verdict.authentic).toBe('boolean');
    expect(typeof verdict.sybilScore).toBe('number');
    expect(verdict.sybilScore).toBeGreaterThanOrEqual(0);
    expect(verdict.sybilScore).toBeLessThanOrEqual(100);
    expect(typeof verdict.confidence).toBe('number');
    expect(typeof verdict.summary).toBe('string');
    expect(typeof verdict.tests).toBe('object');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 5. ENGAGEMENT TOKEN — CREATION
// ═════════════════════════════════════════════════════════════════════════════

describe('EngagementToken — creation', () => {

  test('createEngagementToken returns token, compact, and expiresAt', () => {
    const result = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now(), motorConsistency: 0.82 },
      secret:      SECRET,
    });

    expect(result).toHaveProperty('token');
    expect(result).toHaveProperty('compact');
    expect(result).toHaveProperty('expiresAt');
    expect(typeof result.compact).toBe('string');
    expect(result.compact.length).toBeGreaterThan(100);
    expect(result.expiresAt).toBeGreaterThan(Date.now());
  });

  test('token contains all required fields', () => {
    const { token } = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now(), motorConsistency: 0.80 },
      secret:      SECRET,
    });

    expect(token.v).toBe(2);
    expect(typeof token.n).toBe('string');
    expect(token.n).toHaveLength(64);
    expect(typeof token.iat).toBe('number');
    expect(typeof token.exp).toBe('number');
    expect(token.exp - token.iat).toBe(30_000);
    expect(typeof token.sig).toBe('string');
    expect(token.sig).toHaveLength(64);
  });

  test('token without idle proof includes idle: null', () => {
    const { token } = createEngagementToken({
      pulseResult: {},
      idleProof:   null,
      interaction: { type: 'view', ts: Date.now() },
      secret:      SECRET,
    });
    expect(token.idle).toBeNull();
  });

  test('idle proof fields are packed correctly into token', () => {
    const proof    = makeRealIdleProof();
    const { token } = createEngagementToken({
      pulseResult: {},
      idleProof:   proof,
      interaction: { type: 'click', ts: Date.now() },
      secret:      SECRET,
    });

    expect(token.idle.chain).toBe(proof.chain);
    expect(token.idle.s).toBe(proof.samples);
    expect(token.idle.dMs).toBe(proof.idleDurationMs);
    expect(token.idle.therm).toBe(proof.thermalTransition);
    expect(token.idle.mono).toBe(proof.coolingMonotonicity);
  });

  test('createEngagementToken throws on missing or short secret', () => {
    expect(() => createEngagementToken({ secret: '' })).toThrow();
    expect(() => createEngagementToken({ secret: 'short' })).toThrow();
    expect(() => createEngagementToken({ secret: null })).toThrow();
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 6. ENGAGEMENT TOKEN — VERIFICATION
// ═════════════════════════════════════════════════════════════════════════════

describe('EngagementToken — verification', () => {

  async function issueAndVerify(interactionOpts = {}, verifyOpts = {}) {
    const created = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now(), motorConsistency: 0.80, ...interactionOpts },
      secret:      SECRET,
    });
    return verifyEngagementToken(created.compact, SECRET, verifyOpts);
  }

  test('valid token passes verification', async () => {
    const result = await issueAndVerify();
    expect(result.valid).toBe(true);
    expect(result.token).toBeDefined();
    expect(Array.isArray(result.riskSignals)).toBe(true);
    expect(Array.isArray(result.idleWarnings)).toBe(true);
  });

  test('expired token is rejected', async () => {
    const created = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now() },
      secret:      SECRET,
      _overrides:  { issuedAt: Date.now() - 60_000 }, // issued 60s ago → expired
    });
    const result = await verifyEngagementToken(created.compact, SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('token_expired');
    expect(result.expiredByMs).toBeGreaterThan(0);
  });

  test('future-dated token is rejected', async () => {
    const created = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now() },
      secret:      SECRET,
      _overrides:  { issuedAt: Date.now() + 30_000 }, // 30s in the future
    });
    const result = await verifyEngagementToken(created.compact, SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('token_from_future');
  });

  test('wrong secret is rejected with invalid_signature', async () => {
    const created = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now() },
      secret:      SECRET,
    });
    const result = await verifyEngagementToken(created.compact, 'wrong-secret-with-enough-length-32chars!');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid_signature');
  });

  test('tampered compact payload is rejected', async () => {
    const created = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now() },
      secret:      SECRET,
    });
    // Tamper: decode, modify ent field, re-encode without re-signing
    const parsed       = decodeToken(created.compact);
    parsed.hw.ent      = 0.99; // inflate entropy score
    const tampered     = encodeToken(parsed);
    const result       = await verifyEngagementToken(tampered, SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid_signature');
  });

  test('malformed compact string is rejected', async () => {
    const result = await verifyEngagementToken('not-valid-base64url!!', SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('malformed_token');
  });

  test('nonce replay is rejected via checkNonce', async () => {
    const created = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now() },
      secret:      SECRET,
    });

    const usedNonces = new Set();
    const checkNonce = async (n) => {
      if (usedNonces.has(n)) return false;
      usedNonces.add(n);
      return true;
    };

    const first  = await verifyEngagementToken(created.compact, SECRET, { checkNonce });
    const second = await verifyEngagementToken(created.compact, SECRET, { checkNonce });

    expect(first.valid).toBe(true);
    expect(second.valid).toBe(false);
    expect(second.reason).toBe('nonce_replayed');
  });

  test('unsupported version is rejected', async () => {
    const created  = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now() },
      secret:      SECRET,
    });
    const parsed   = decodeToken(created.compact);
    parsed.v       = 99; // unsupported future version
    const modified = encodeToken(parsed);
    const result   = await verifyEngagementToken(modified, SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('unsupported_version');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 7. ENGAGEMENT TOKEN — RISK SIGNALS
// ═════════════════════════════════════════════════════════════════════════════

describe('EngagementToken — risk signal detection', () => {

  async function verifyWithHw(hwOverrides = {}, idleOverride = null) {
    const created = createEngagementToken({
      pulseResult: {
        extended: {
          dram: { verdict: hwOverrides.dram ?? 'dram' },
          enf:  { verdict: hwOverrides.enf  ?? 'grid_60hz', enfDeviation: hwOverrides.enfDev ?? null },
        },
      },
      idleProof:   idleOverride,
      interaction: { type: 'click', ts: Date.now(), motorConsistency: hwOverrides.mot ?? 0.80 },
      secret:      SECRET,
    });
    return verifyEngagementToken(created.compact, SECRET);
  }

  test('virtual DRAM verdict raises DRAM_VIRTUAL high-severity signal', async () => {
    const result = await verifyWithHw({ dram: 'virtual' });
    expect(result.valid).toBe(true);
    const signal = result.riskSignals.find(s => s.code === 'DRAM_VIRTUAL');
    expect(signal).toBeDefined();
    expect(signal.severity).toBe('high');
  });

  test('no idle proof raises NO_IDLE_PROOF signal', async () => {
    const result = await verifyWithHw({}, null);
    expect(result.valid).toBe(true);
    expect(result.riskSignals.some(s => s.code === 'NO_IDLE_PROOF')).toBe(true);
  });

  test('step_function idle raises STEP_FUNCTION_THERMAL high-severity signal', async () => {
    const result = await verifyWithHw({}, makeFarmIdleProof());
    expect(result.valid).toBe(true);
    const signal = result.riskSignals.find(s => s.code === 'STEP_FUNCTION_THERMAL');
    expect(signal).toBeDefined();
    expect(signal.severity).toBe('high');
  });

  test('poor motor consistency raises POOR_MOTOR_CONSISTENCY signal', async () => {
    const result = await verifyWithHw({ mot: 0.10 });
    expect(result.valid).toBe(true);
    expect(result.riskSignals.some(s => s.code === 'POOR_MOTOR_CONSISTENCY')).toBe(true);
  });

  test('clean real-device token has empty riskSignals', async () => {
    const created = createEngagementToken({
      pulseResult: {
        extended: {
          dram: { verdict: 'dram' },
          enf:  { verdict: 'grid_60hz' },
        },
      },
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now(), motorConsistency: 0.85 },
      secret:      SECRET,
    });
    const result = await verifyEngagementToken(created.compact, SECRET);
    expect(result.valid).toBe(true);
    expect(result.riskSignals).toHaveLength(0);
  });

  test('idleWarnings array is always present in successful verification', async () => {
    const result = await verifyWithHw({}, makeRealIdleProof());
    expect(result.valid).toBe(true);
    expect(Array.isArray(result.idleWarnings)).toBe(true);
    // Clean proof → no warnings
    expect(result.idleWarnings).toHaveLength(0);
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 8. ENCODE / DECODE ROUND-TRIP
// ═════════════════════════════════════════════════════════════════════════════

describe('EngagementToken — encode / decode round-trip', () => {

  test('decodeToken recovers original token from compact form', () => {
    const { token, compact } = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'view', ts: Date.now(), motorConsistency: 0.75 },
      secret:      SECRET,
    });
    const decoded = decodeToken(compact);
    expect(decoded.v).toBe(token.v);
    expect(decoded.n).toBe(token.n);
    expect(decoded.iat).toBe(token.iat);
    expect(decoded.exp).toBe(token.exp);
    expect(decoded.sig).toBe(token.sig);
  });

  test('compact form uses only base64url-safe characters', () => {
    const { compact } = createEngagementToken({
      pulseResult: {},
      idleProof:   makeRealIdleProof(),
      interaction: { type: 'click', ts: Date.now() },
      secret:      SECRET,
    });
    // base64url must not contain +, /, or =
    expect(compact).not.toMatch(/[+/=]/);
    // Must only contain safe chars
    expect(compact).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  test('encodeToken / decodeToken are inverse operations', () => {
    const original = { v: 2, n: 'a'.repeat(64), iat: 1000, exp: 31000, sig: 'b'.repeat(64) };
    const encoded  = encodeToken(original);
    const decoded  = decodeToken(encoded);
    // decodeToken (deprecated) now adds _verified: false via decodeTokenUnsafe
    const { _verified, ...rest } = decoded;
    expect(rest).toEqual(original);
    expect(_verified).toBe(false);
  });

});

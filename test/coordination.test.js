/**
 * @svrnsec/pulse — Coordinated Inauthentic Behavior test suite
 *
 * Tests all 5 detection layers plus the orchestrator.
 * Uses deterministic synthetic cohorts to validate scoring.
 */

import {
  testTemporalClustering,
  testFingerprintCollision,
  testDriftFingerprint,
  testMutualInformation,
  testEntropyVelocity,
  analyseCoordination,
  computeDriftRate,
} from '../src/analysis/coordinatedBehavior.js';

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers — synthetic token generators
// ═══════════════════════════════════════════════════════════════════════════════

/** Seeded PRNG for deterministic tests */
function seededRng(seed) {
  let s = seed;
  return () => { s = (s * 16807 + 0) % 2147483647; return s / 2147483647; };
}

const THERMAL_LABELS = ['hot_to_cold', 'cold', 'cooling', 'warming', 'sustained_hot', 'step_function'];

/**
 * Generate an organic-looking token cohort.
 * - Poisson-distributed timestamps
 * - High signal diversity
 * - Varied thermal labels, entropy scores, motor consistency
 */
function organicCohort(n, seed = 42) {
  const rng = seededRng(seed);
  const tokens = [];
  let ts = 1700000000000;

  for (let i = 0; i < n; i++) {
    // Poisson inter-arrival: exponential with mean 2s
    ts += Math.floor(-Math.log(1 - rng()) * 2000);

    tokens.push({
      iat: ts,
      idle: {
        therm: THERMAL_LABELS[Math.floor(rng() * 4)], // first 4 = organic
        dMs: 30 + rng() * 180, // 30–210s idle
        s: 45 + rng() * 120,
      },
      hw: {
        ent: 0.55 + rng() * 0.40, // 0.55–0.95
        dram: rng() > 0.5 ? 'physical' : 'virtual',
        enfDev: (rng() - 0.5) * 0.08, // ±0.04 Hz
      },
      evt: {
        mot: 0.5 + rng() * 0.45, // 0.50–0.95
        t: 'click',
        ts: ts + Math.floor(rng() * 500),
      },
    });
  }
  return tokens;
}

/**
 * Generate a bot farm cohort.
 * - Burst timestamps (arrive in waves from a C2 server)
 * - Low signal diversity (cloned environments)
 * - Uniform thermal label, narrow entropy range
 */
function farmCohort(n, seed = 99) {
  const rng = seededRng(seed);
  const tokens = [];
  let ts = 1700000000000;
  const farmEntropy = 0.72 + rng() * 0.03; // narrow band
  const farmMotor = 0.81 + rng() * 0.02;
  const farmEnf = 0.012; // co-located

  for (let i = 0; i < n; i++) {
    // Burst: groups of 20 arrive within 200ms, then 5s gap
    if (i % 20 === 0) ts += 5000;
    else ts += Math.floor(rng() * 200);

    tokens.push({
      iat: ts,
      idle: {
        therm: 'sustained_hot', // farm: constant load
        dMs: 58 + rng() * 4, // scripted: 58–62s
        s: 60,
      },
      hw: {
        ent: farmEntropy + rng() * 0.02, // very narrow range
        dram: 'virtual',
        enfDev: farmEnf + (rng() - 0.5) * 0.002, // tight cluster
      },
      evt: {
        mot: farmMotor + rng() * 0.02,
        t: 'click',
        ts: ts + 100,
      },
    });
  }
  return tokens;
}

/**
 * Generate device submission histories for drift testing.
 */
function organicDevices(n, seed = 42) {
  const rng = seededRng(seed);
  const devices = [];
  for (let d = 0; d < n; d++) {
    // Each device has unique drift rate: 20–100 ppm
    const driftPpm = 20 + rng() * 80;
    const driftMsPerS = driftPpm / 1000;
    const subs = [];
    let serverTs = 1700000000000 + d * 10000;
    for (let s = 0; s < 5; s++) {
      serverTs += 30000 + Math.floor(rng() * 10000); // 30–40s intervals
      const elapsed = (serverTs - 1700000000000) / 1000;
      subs.push({
        ts: serverTs + Math.floor(elapsed * driftMsPerS) + Math.floor(rng() * 5),
        serverTs,
      });
    }
    devices.push({ id: `device-${d}`, submissions: subs });
  }
  return devices;
}

function farmDevices(n, seed = 99) {
  const rng = seededRng(seed);
  const devices = [];
  // All devices share same drift rate (same hardware)
  const sharedDriftPpm = 47;
  const driftMsPerS = sharedDriftPpm / 1000;
  for (let d = 0; d < n; d++) {
    const subs = [];
    let serverTs = 1700000000000 + d * 100;
    for (let s = 0; s < 5; s++) {
      serverTs += 30000;
      const elapsed = (serverTs - 1700000000000) / 1000;
      subs.push({
        ts: serverTs + Math.floor(elapsed * driftMsPerS) + Math.floor(rng() * 2),
        serverTs,
      });
    }
    devices.push({ id: `farm-${d}`, submissions: subs });
  }
  return devices;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 1 — Temporal Clustering
// ═══════════════════════════════════════════════════════════════════════════════

describe('testTemporalClustering', () => {
  test('organic timestamps: low score', () => {
    const tokens = organicCohort(100);
    const ts = tokens.map(t => t.iat);
    const result = testTemporalClustering(ts);
    expect(result.score).toBeLessThan(40);
  });

  test('burst timestamps: high score', () => {
    const tokens = farmCohort(100);
    const ts = tokens.map(t => t.iat);
    const result = testTemporalClustering(ts);
    expect(result.score).toBeGreaterThan(50);
  });

  test('returns chi2 and burstRatio', () => {
    const tokens = organicCohort(50);
    const ts = tokens.map(t => t.iat);
    const result = testTemporalClustering(ts);
    expect(result).toHaveProperty('chi2');
    expect(result).toHaveProperty('burstRatio');
    expect(result).toHaveProperty('pBursty');
  });

  test('handles small input', () => {
    const result = testTemporalClustering([1000, 2000, 3000]);
    expect(result.score).toBe(50); // insufficient data
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 2 — Fingerprint Collision
// ═══════════════════════════════════════════════════════════════════════════════

describe('testFingerprintCollision', () => {
  test('organic cohort: high diversity, low score', () => {
    const tokens = organicCohort(200);
    const result = testFingerprintCollision(tokens);
    expect(result.uniqueRatio).toBeGreaterThan(0.15);
    expect(result.score).toBeLessThan(50);
  });

  test('farm cohort: low diversity, high score', () => {
    const tokens = farmCohort(200);
    const result = testFingerprintCollision(tokens);
    expect(result.uniqueRatio).toBeLessThan(0.10);
    expect(result.score).toBeGreaterThan(60);
  });

  test('returns uniqueCount and topCollision', () => {
    const tokens = organicCohort(50);
    const result = testFingerprintCollision(tokens);
    expect(result.uniqueCount).toBeGreaterThan(0);
    expect(result.topCollision).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 3 — Drift Fingerprinting
// ═══════════════════════════════════════════════════════════════════════════════

describe('testDriftFingerprint', () => {
  test('organic devices: diverse drift rates, low score', () => {
    const devices = organicDevices(30);
    const result = testDriftFingerprint(devices);
    expect(result.score).toBeLessThan(40);
    expect(result.totalDevices).toBe(30);
  });

  test('farm devices: convergent drift rates, elevated score', () => {
    const devices = farmDevices(30);
    const result = testDriftFingerprint(devices);
    expect(result.score).toBeGreaterThan(25);
    expect(result.clusterRatio).toBeGreaterThanOrEqual(0.25);
    // Farm devices cluster because they share hardware
    expect(result.uniqueBins).toBeLessThan(result.totalDevices / 2);
  });

  test('returns drift rate object', () => {
    const devices = organicDevices(10);
    const result = testDriftFingerprint(devices);
    expect(typeof result.driftRates).toBe('object');
    expect(Object.keys(result.driftRates).length).toBe(10);
  });

  test('handles insufficient data', () => {
    const result = testDriftFingerprint([{ id: 'a', submissions: [{ ts: 1, serverTs: 1 }] }]);
    expect(result.score).toBe(0);
  });
});

describe('computeDriftRate', () => {
  test('computes linear drift rate', () => {
    // 0.05 ms/s drift = 50 ppm
    const subs = [
      { ts: 1000000, serverTs: 1000000 },
      { ts: 1030005, serverTs: 1030000 }, // +5ms drift after 30s
      { ts: 1060010, serverTs: 1060000 }, // +10ms drift after 60s
      { ts: 1090015, serverTs: 1090000 }, // +15ms drift after 90s
    ];
    const rate = computeDriftRate(subs);
    expect(rate).toBeCloseTo(0.167, 1); // ~0.167 ms/s
  });

  test('returns null for single submission', () => {
    expect(computeDriftRate([{ ts: 100, serverTs: 100 }])).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 4 — Mutual Information
// ═══════════════════════════════════════════════════════════════════════════════

describe('testMutualInformation', () => {
  test('organic cohort: many communities, low score', () => {
    const tokens = organicCohort(100);
    const result = testMutualInformation(tokens);
    expect(result.score).toBeLessThan(50);
    expect(result.communities).toBeGreaterThan(3);
  });

  test('farm cohort: few communities, high score', () => {
    const tokens = farmCohort(100);
    const result = testMutualInformation(tokens);
    expect(result.score).toBeGreaterThan(40);
    expect(result.communityRatio).toBeGreaterThan(0.3);
  });

  test('returns modularity score', () => {
    const tokens = organicCohort(50);
    const result = testMutualInformation(tokens);
    expect(result).toHaveProperty('modularity');
    expect(result).toHaveProperty('communities');
    expect(result).toHaveProperty('largestCommunity');
  });

  test('handles small input', () => {
    const result = testMutualInformation(organicCohort(5));
    expect(result.score).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 5 — Entropy Velocity
// ═══════════════════════════════════════════════════════════════════════════════

describe('testEntropyVelocity', () => {
  test('organic cohort: healthy entropy growth', () => {
    const tokens = organicCohort(200);
    const result = testEntropyVelocity(tokens);
    expect(result.score).toBeLessThan(40);
    expect(result.velocityRatio).toBeGreaterThan(0.5);
  });

  test('farm cohort: stalled entropy growth', () => {
    const tokens = farmCohort(200);
    const result = testEntropyVelocity(tokens);
    expect(result.score).toBeGreaterThan(30);
  });

  test('returns entropy and count slices', () => {
    const tokens = organicCohort(100);
    const result = testEntropyVelocity(tokens);
    expect(result.entropySlices.length).toBe(5);
    expect(result.countSlices.length).toBe(5);
    // Cumulative counts should be increasing
    for (let i = 1; i < result.countSlices.length; i++) {
      expect(result.countSlices[i]).toBeGreaterThanOrEqual(result.countSlices[i - 1]);
    }
  });

  test('handles small input', () => {
    const result = testEntropyVelocity(organicCohort(5));
    expect(result.score).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Orchestrator
// ═══════════════════════════════════════════════════════════════════════════════

describe('analyseCoordination', () => {
  test('organic cohort: low coordination score', () => {
    const tokens = organicCohort(200);
    const result = analyseCoordination(tokens);
    expect(result.coordinationScore).toBeLessThan(45);
    expect(result.verdict).toMatch(/organic|low_coordination/);
    expect(result.tokenCount).toBe(200);
  });

  test('farm cohort: high coordination score', () => {
    const tokens = farmCohort(200);
    const result = analyseCoordination(tokens);
    expect(result.coordinationScore).toBeGreaterThan(50);
    expect(result.verdict).toMatch(/suspicious|coordinated/);
    expect(result.flags.length).toBeGreaterThan(0);
  });

  test('farm with drift data: drift layer contributes', () => {
    const tokens = farmCohort(100);
    const devices = farmDevices(30);
    const result = analyseCoordination(tokens, { devices });
    expect(result.layers.drift.score).toBeGreaterThan(0);
    expect(result.layers.drift.skipped).toBeUndefined();
  });

  test('organic with drift data: drift layer is clean', () => {
    const tokens = organicCohort(100);
    const devices = organicDevices(30);
    const result = analyseCoordination(tokens, { devices });
    expect(result.layers.drift.score).toBeLessThan(40);
  });

  test('without drift data: drift layer is skipped', () => {
    const tokens = organicCohort(100);
    const result = analyseCoordination(tokens);
    expect(result.layers.drift.skipped).toBe(true);
  });

  test('returns all 5 layer results', () => {
    const tokens = organicCohort(100);
    const result = analyseCoordination(tokens);
    expect(result.layers).toHaveProperty('temporal');
    expect(result.layers).toHaveProperty('fingerprint');
    expect(result.layers).toHaveProperty('drift');
    expect(result.layers).toHaveProperty('mutualInformation');
    expect(result.layers).toHaveProperty('entropyVelocity');
  });

  test('confidence increases with token count', () => {
    const small = analyseCoordination(organicCohort(20));
    const large = analyseCoordination(organicCohort(200));
    expect(large.confidence).toBeGreaterThan(small.confidence);
  });

  test('returns weights used', () => {
    const result = analyseCoordination(organicCohort(50));
    expect(result.weights).toHaveProperty('temporal');
    expect(result.weights).toHaveProperty('fingerprint');
    expect(result.weights).toHaveProperty('mi');
    expect(result.weights).toHaveProperty('velocity');
  });

  test('handles tiny input gracefully', () => {
    const result = analyseCoordination(organicCohort(3));
    expect(result.verdict).toBe('insufficient_data');
    expect(result.coordinationScore).toBe(0);
  });

  test('organic vs farm separation: farm scores significantly higher', () => {
    const organic = analyseCoordination(organicCohort(200));
    const farm = analyseCoordination(farmCohort(200));
    expect(farm.coordinationScore - organic.coordinationScore).toBeGreaterThan(15);
  });
});

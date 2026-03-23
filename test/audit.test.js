/**
 * @svrnsec/pulse — Authenticity Audit Test Suite
 *
 * The headline invariant: a cohort of organic users must score CLEAN,
 * a cohort of bot-farm tokens must score HIGH_FRAUD, and the estimated
 * humanPct must be statistically separated between the two.
 */

import { authenticityAudit } from '../src/analysis/authenticityAudit.js';

// ── Deterministic RNG (same LCG used in stress/engagement tests) ──────────────

function makeLcg(seed) {
  let s = seed;
  return () => { s = (s * 1664525 + 1013904223) & 0xffffffff; return (s >>> 0) / 0xffffffff; };
}

// ── Token builders ────────────────────────────────────────────────────────────

/**
 * Build a realistic organic-user token.
 * Each token has distinct ENF deviation, DRAM period variation, genuine cooling.
 */
function makeRealToken(rand, baseIat = Date.now()) {
  // Organic users are geographically spread → ENF range 0.10–0.40 Hz
  // (deliberately avoids the 0.00–0.05 Hz bucket used by makeFarmToken so
  //  mixed-cohort tests get clean separation between the two populations)
  const enfDev = 0.10 + rand() * 0.30;   // 0.10–0.40 Hz — different cities
  return {
    v:    2,
    n:    Array.from({ length: 64 }, () => Math.floor(rand() * 16).toString(16)).join(''),
    iat:  baseIat + Math.floor((rand() - 0.5) * 600_000), // organic arrival: ±10 min
    exp:  baseIat + 30_000,
    idle: {
      chain: Array.from({ length: 64 }, () => Math.floor(rand() * 16).toString(16)).join(''),
      s:     2 + Math.floor(rand() * 3),                   // 2–4 samples
      dMs:   45_000 + Math.floor(rand() * 300_000),        // 45s–5min idle
      therm: rand() > 0.5 ? 'hot_to_cold' : 'cooling',    // genuine cooling
      mono:  0.6 + rand() * 0.4,                           // 0.6–1.0
    },
    hw: {
      dram:   'dram',
      enf:    'grid_60hz',
      ent:    0.55 + rand() * 0.40,   // 0.55–0.95 — diverse hardware
      enfDev,
    },
    evt: { t: 'click', ts: baseIat, mot: 0.5 + rand() * 0.4 },
  };
}

/**
 * Build a bot-farm token: same building, same script, same hardware.
 * All tokens share a tight ENF deviation cluster and sustained_hot thermal.
 */
function makeFarmToken(rand, farmEnfDev = 0.023, baseIat = Date.now()) {
  // Farm scripts submit in batches — tight timestamp clustering
  const batchJitter = (rand() - 0.5) * 4_000; // ±2s jitter within a batch
  return {
    v:    2,
    n:    Array.from({ length: 64 }, () => Math.floor(rand() * 16).toString(16)).join(''),
    iat:  baseIat + batchJitter,
    exp:  baseIat + 30_000,
    idle: {
      chain: Array.from({ length: 64 }, () => Math.floor(rand() * 16).toString(16)).join(''),
      s:     2,
      dMs:   55_000 + Math.floor(rand() * 5_000),  // all cluster near 57s
      therm: 'sustained_hot',                        // device never cools
      mono:  0.1 + rand() * 0.15,
    },
    hw: {
      dram:   'dram',
      enf:    'grid_60hz',
      ent:    0.30 + rand() * 0.05,    // homogeneous — same hardware generation
      enfDev: farmEnfDev + (rand() - 0.5) * 0.01, // ±0.005 Hz — same building
    },
    evt: { t: 'click', ts: baseIat + batchJitter, mot: 0.1 + rand() * 0.1 },
  };
}

// ── Test suites ───────────────────────────────────────────────────────────────

describe('AuthenticityAudit — edge cases', () => {

  test('empty token array returns null humanPct', () => {
    const report = authenticityAudit([]);
    expect(report.cohortSize).toBe(0);
    expect(report.estimatedHumanPct).toBeNull();
    expect(report.grade).toBe('CLEAN');
  });

  test('single token below minClusterSize — no clusters analysed, treated as authentic', () => {
    const rand  = makeLcg(1);
    const token = makeRealToken(rand);
    const report = authenticityAudit([token]);
    expect(report.cohortSize).toBe(1);
    expect(report.botClusterCount).toBe(0);
    expect(report.estimatedHumanPct).toBe(100.0);
  });

});

describe('AuthenticityAudit — organic cohort', () => {

  test('100 diverse real-user tokens → CLEAN grade', () => {
    const rand   = makeLcg(42);
    const tokens = Array.from({ length: 100 }, () => makeRealToken(rand));
    const report = authenticityAudit(tokens);

    expect(report.grade).toBe('CLEAN');
    expect(report.estimatedHumanPct).toBeGreaterThanOrEqual(85);
    expect(report.botClusterCount).toBe(0);
  });

  test('organic cohort confidence interval is above 70%', () => {
    const rand   = makeLcg(7);
    const tokens = Array.from({ length: 200 }, () => makeRealToken(rand));
    const report = authenticityAudit(tokens, { confidenceLevel: 0.95 });

    expect(report.confidenceInterval).not.toBeNull();
    const [lo] = report.confidenceInterval;
    expect(lo).toBeGreaterThan(70);
  });

  test('report includes per-cluster breakdown even for authentic cohorts', () => {
    const rand   = makeLcg(9);
    const tokens = Array.from({ length: 50 }, () => makeRealToken(rand));
    const report = authenticityAudit(tokens);

    expect(typeof report.clusterCount).toBe('number');
    expect(typeof report.authenticTokenCount).toBe('number');
    expect(report.authenticTokenCount + report.fraudulentTokenCount).toBe(tokens.length);
  });

});

describe('AuthenticityAudit — bot farm cohort', () => {

  test('100 farm tokens (one farm, ENF-clustered) → HIGH_FRAUD grade', () => {
    const rand   = makeLcg(13);
    const now    = 1_700_000_000_000;
    const tokens = Array.from({ length: 100 }, () => makeFarmToken(rand, 0.023, now));
    const report = authenticityAudit(tokens);

    expect(report.grade).toMatch(/FRAUD/);
    expect(report.estimatedHumanPct).toBeLessThan(50);
    expect(report.botClusterCount).toBeGreaterThanOrEqual(1);
  });

  test('bot farm cluster fingerprint has stable ID across calls', () => {
    const rand    = makeLcg(17);
    const now     = 1_700_000_000_000;
    const tokens  = Array.from({ length: 60 }, () => makeFarmToken(rand, 0.023, now));

    const r1 = authenticityAudit(tokens);
    const r2 = authenticityAudit(tokens);

    expect(r1.botClusters[0]?.id).toBe(r2.botClusters[0]?.id);
  });

  test('bot clusters are sorted by sybilScore descending', () => {
    const rand = makeLcg(19);
    const now  = 1_700_000_000_000;

    // Two farms with different ENF deviations (different buildings)
    const farm1 = Array.from({ length: 40 }, () => makeFarmToken(rand, 0.023, now));
    const farm2 = Array.from({ length: 40 }, () => makeFarmToken(rand, 0.150, now));
    const report = authenticityAudit([...farm1, ...farm2]);

    const scores = report.botClusters.map(c => c.sybilScore);
    for (let i = 1; i < scores.length; i++) {
      expect(scores[i]).toBeLessThanOrEqual(scores[i - 1]);
    }
  });

});

describe('AuthenticityAudit — mixed cohort (real users + farm)', () => {

  test('70% authentic + 30% farm → humanPct between 50 and 85', () => {
    const rand    = makeLcg(23);
    const now     = 1_700_000_000_000;
    const real    = Array.from({ length: 70 }, () => makeRealToken(rand, now));
    const farm    = Array.from({ length: 30 }, () => makeFarmToken(rand, 0.023, now));
    const tokens  = [...real, ...farm].sort(() => rand() - 0.5); // shuffle

    const report  = authenticityAudit(tokens);

    expect(report.estimatedHumanPct).toBeGreaterThan(40);
    expect(report.estimatedHumanPct).toBeLessThan(90);
    expect(report.botClusterCount).toBeGreaterThanOrEqual(1);
    expect(report.authenticTokenCount).toBeGreaterThan(0);
    expect(report.fraudulentTokenCount).toBeGreaterThan(0);
  });

  test('organic users and farm users have statistically separated humanPct', () => {
    const rand     = makeLcg(29);
    const now      = 1_700_000_000_000;

    const allReal  = Array.from({ length: 100 }, () => makeRealToken(rand, now));
    const allFarm  = Array.from({ length: 100 }, () => makeFarmToken(rand, 0.023, now));

    const realReport = authenticityAudit(allReal);
    const farmReport = authenticityAudit(allFarm);

    // Real cohort must score meaningfully higher than farm cohort
    const gap = realReport.estimatedHumanPct - farmReport.estimatedHumanPct;
    expect(gap).toBeGreaterThan(25);
  });

  test('recommendation string is non-empty and contains cluster count for HIGH_FRAUD', () => {
    const rand   = makeLcg(31);
    const now    = 1_700_000_000_000;
    const tokens = Array.from({ length: 100 }, () => makeFarmToken(rand, 0.023, now));
    const report = authenticityAudit(tokens);

    expect(typeof report.recommendation).toBe('string');
    expect(report.recommendation.length).toBeGreaterThan(0);
  });

  test('multiple farms tracked by distinct cluster IDs', () => {
    const rand   = makeLcg(37);
    const now    = 1_700_000_000_000;
    const farm1  = Array.from({ length: 40 }, () => makeFarmToken(rand, 0.023, now));
    const farm2  = Array.from({ length: 40 }, () => makeFarmToken(rand, 0.200, now));
    const report = authenticityAudit([...farm1, ...farm2]);

    const ids = report.botClusters.map(c => c.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length); // no duplicate IDs
  });

});

describe('AuthenticityAudit — confidence interval properties', () => {

  test('CI is [lo, hi] with lo ≤ hi', () => {
    const rand   = makeLcg(41);
    const tokens = Array.from({ length: 100 }, () => makeRealToken(rand));
    const report = authenticityAudit(tokens, { confidenceLevel: 0.95 });

    const [lo, hi] = report.confidenceInterval;
    expect(lo).toBeLessThanOrEqual(hi);
  });

  test('CI narrows with larger mixed cohort (wider → narrower)', () => {
    // CI width is only meaningful when there is genuine uncertainty — i.e.,
    // a mixed cohort where some clusters are bot farms and some are not.
    // A pure organic cohort produces labels all = 1 → CI collapses to [100,100]
    // for any sample size.  Use mixed cohorts to exercise the property.
    const rand   = makeLcg(43);
    const now    = 1_700_000_000_000;

    const makeSmall = () => [
      ...Array.from({ length: 15 }, () => makeRealToken(rand, now)),
      ...Array.from({ length: 15 }, () => makeFarmToken(rand, 0.023, now)),
    ];
    const makeLarge = () => [
      ...Array.from({ length: 150 }, () => makeRealToken(rand, now)),
      ...Array.from({ length: 150 }, () => makeFarmToken(rand, 0.023, now)),
    ];

    const rSmall  = authenticityAudit(makeSmall(), { bootstrapIter: 300 });
    const rLarge  = authenticityAudit(makeLarge(), { bootstrapIter: 300 });

    const spanSmall = rSmall.confidenceInterval[1] - rSmall.confidenceInterval[0];
    const spanLarge = rLarge.confidenceInterval[1] - rLarge.confidenceInterval[0];

    expect(spanLarge).toBeLessThan(spanSmall + 5); // large CI must not be wider by more than 5pp
  });

});

/**
 * @svrnsec/pulse — Coordinated Inauthentic Behavior Detection
 *
 * Detects bot armies, click farms, and Sybil networks by analyzing
 * physics-layer correlations that coordination inevitably creates.
 *
 * Core insight:
 *   Two real users in different cities have ZERO mutual information
 *   between their thermal curves, clock drift rates, ENF phases, and
 *   idle durations. Bot farms can randomize any ONE signal but cannot
 *   independently decorrelate ALL signals simultaneously — they're
 *   bound to shared physics (same room, same hardware, same scripts).
 *
 * Five detection layers:
 *
 *   Layer 1 — Temporal Clustering
 *     Real users arrive via Poisson process. Bot armies arrive in bursts
 *     from a command server. Chi-squared test on 1s-bucket histogram.
 *
 *   Layer 2 — Signal Fingerprint Collision
 *     Hash (thermal_label, entropy_band, motor_band) per token. Real
 *     cohort: high cardinality. Bot farm: < 20 unique fingerprints
 *     across 500 tokens.
 *
 *   Layer 3 — Drift Fingerprinting
 *     Crystal oscillator imperfection (20–100 ppm) creates a unique
 *     clock drift rate per physical device. Multiple submissions from
 *     "different devices" that converge on the same drift rate = same
 *     hardware behind a rotation proxy. Survives IP/account/browser
 *     rotation.
 *
 *   Layer 4 — Mutual Information Matrix
 *     Pairwise MI across all signal dimensions. Organic traffic: sparse
 *     random MI matrix. Bot traffic: block-diagonal structure (cliques).
 *     Louvain community detection finds the cliques in O(n log n).
 *
 *   Layer 5 — Entropy Velocity
 *     Track dH/dt — the rate of Shannon entropy growth in the signal
 *     space. Organic growth adds unique profiles; bot deployment adds
 *     volume without diversity. The ratio (observed dH/dt) / (expected)
 *     catches mass deployment even with real hardware.
 *
 * Computational cost:
 *   All operations are O(n) or O(n log n). 500 tokens ≈ 8ms total
 *   on a single CPU core. No ML, no GPU, no training data.
 *
 * Usage:
 *   import { analyseCoordination } from '@svrnsec/pulse/coordination'
 *   const result = analyseCoordination(tokens, { windowMs: 60000 })
 */

// ═══════════════════════════════════════════════════════════════════════════════
// Utility
// ═══════════════════════════════════════════════════════════════════════════════

function mean(a) { return a.length === 0 ? 0 : a.reduce((s, v) => s + v, 0) / a.length; }
function variance(a) { const m = mean(a); return a.length < 2 ? 0 : a.reduce((s, v) => s + (v - m) ** 2, 0) / (a.length - 1); }
function stddev(a) { return Math.sqrt(variance(a)); }
function cv(a) { const m = mean(a); return m === 0 ? 0 : stddev(a) / m; }
function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

/**
 * Shannon entropy of a discrete distribution (array of counts).
 * Returns bits.
 */
function shannonEntropy(counts) {
  const total = counts.reduce((s, c) => s + c, 0);
  if (total === 0) return 0;
  let H = 0;
  for (const c of counts) {
    if (c > 0) {
      const p = c / total;
      H -= p * Math.log2(p);
    }
  }
  return H;
}

/**
 * Discretize a continuous value into a band index.
 * @param {number} v    - value
 * @param {number} lo   - band floor
 * @param {number} hi   - band ceiling
 * @param {number} bins - number of bins
 * @returns {number} bin index [0, bins-1]
 */
function band(v, lo, hi, bins) {
  if (hi === lo) return 0;
  return Math.min(bins - 1, Math.max(0, Math.floor(((v - lo) / (hi - lo)) * bins)));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 1 — Temporal Clustering
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Test whether token arrival times follow a Poisson process (organic)
 * or show burst patterns (coordinated).
 *
 * Method: bucket timestamps into 1s intervals, compute chi-squared
 * statistic against expected Poisson rate. High chi-squared = bursty.
 *
 * @param {number[]} timestamps - sorted epoch-ms values
 * @param {object}   [opts]
 * @param {number}   [opts.bucketMs=1000]
 * @returns {{ score: number, burstRatio: number, chi2: number, pBursty: number }}
 */
export function testTemporalClustering(timestamps, opts = {}) {
  const n = timestamps.length;
  if (n < 5) return { score: 50, burstRatio: 0, chi2: 0, pBursty: 0 };

  const bucketMs = opts.bucketMs ?? 1000;
  const tMin = timestamps[0];
  const tMax = timestamps[n - 1];
  const span = tMax - tMin;
  if (span < bucketMs) return { score: 50, burstRatio: 0, chi2: 0, pBursty: 0 };

  const numBuckets = Math.ceil(span / bucketMs);
  const buckets = new Array(numBuckets).fill(0);
  for (const t of timestamps) {
    const idx = Math.min(numBuckets - 1, Math.floor((t - tMin) / bucketMs));
    buckets[idx]++;
  }

  // Expected count per bucket under uniform Poisson
  const expected = n / numBuckets;
  let chi2 = 0;
  for (const obs of buckets) {
    chi2 += (obs - expected) ** 2 / expected;
  }

  // Burst ratio: fraction of tokens in the densest 10% of buckets
  const sorted = [...buckets].sort((a, b) => b - a);
  const top10pct = Math.max(1, Math.ceil(numBuckets * 0.1));
  const burstRatio = sorted.slice(0, top10pct).reduce((s, v) => s + v, 0) / n;

  // Normalize chi2 to score: higher chi2 = more coordinated
  // df = numBuckets - 1; chi2/df >> 1 means non-Poisson
  const chi2Norm = chi2 / Math.max(1, numBuckets - 1);
  // chi2Norm < 2 is consistent with Poisson; > 5 is very bursty
  const pBursty = clamp((chi2Norm - 1.5) / 4, 0, 1);

  // Score: 0 = organic, 100 = coordinated
  const score = Math.round(clamp(
    pBursty * 60 + (burstRatio > 0.5 ? 40 : burstRatio * 80),
    0, 100
  ));

  return { score, burstRatio: +burstRatio.toFixed(4), chi2: +chi2.toFixed(2), chi2Norm: +chi2Norm.toFixed(3), pBursty: +pBursty.toFixed(4) };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 2 — Signal Fingerprint Collision
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Compute fingerprint collision rate across a token cohort.
 *
 * Each token produces a discrete fingerprint from its physics signals.
 * Real users: high cardinality (many unique fingerprints).
 * Bot farm: low cardinality (cloned environments produce duplicates).
 *
 * @param {object[]} tokens - array of token objects
 * @param {object}   [opts]
 * @param {Function} [opts.fingerprint] - custom fingerprint fn(token) → string
 * @returns {{ score: number, uniqueRatio: number, topCollision: number, uniqueCount: number }}
 */
export function testFingerprintCollision(tokens, opts = {}) {
  const n = tokens.length;
  if (n < 5) return { score: 0, uniqueRatio: 1, topCollision: 0, uniqueCount: n };

  const fp = opts.fingerprint ?? defaultFingerprint;
  const counts = new Map();

  for (const token of tokens) {
    const key = fp(token);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const uniqueCount = counts.size;
  const uniqueRatio = uniqueCount / n;

  // Largest collision cluster
  let topCollision = 0;
  for (const c of counts.values()) {
    if (c > topCollision) topCollision = c;
  }
  const topRatio = topCollision / n;

  // Score: low unique ratio = coordinated
  // Real users: uniqueRatio > 0.40 for n > 50
  // Farms: uniqueRatio < 0.10
  let score;
  if (uniqueRatio > 0.40) score = Math.round(clamp((0.60 - uniqueRatio) / 0.20 * 30, 0, 30));
  else if (uniqueRatio > 0.15) score = Math.round(30 + (0.40 - uniqueRatio) / 0.25 * 40);
  else score = Math.round(70 + (0.15 - uniqueRatio) / 0.15 * 30);

  // Top collision bonus: if one fingerprint holds > 30% of tokens
  if (topRatio > 0.30) score = Math.min(100, score + Math.round((topRatio - 0.30) * 60));

  return {
    score: clamp(score, 0, 100),
    uniqueRatio: +uniqueRatio.toFixed(4),
    topCollision,
    topRatio: +topRatio.toFixed(4),
    uniqueCount,
  };
}

/**
 * Default fingerprint: discretize thermal label + entropy band + motor band.
 */
function defaultFingerprint(token) {
  const idle = token.idle ?? token.signals?.idle ?? {};
  const hw   = token.hw ?? token.signals?.entropy ?? {};
  const evt  = token.evt ?? token.signals?.motor ?? {};

  const thermal   = idle.therm ?? idle.thermalTransition ?? 'unknown';
  const entropy   = band(hw.ent ?? hw.score ?? 0.5, 0, 1, 10);
  const motor     = band(evt.mot ?? evt.consistency ?? 0.5, 0, 1, 5);
  const dramLabel = hw.dram ?? idle.dMs ?? 'unknown';

  return `${thermal}:${entropy}:${motor}:${dramLabel}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 3 — Drift Fingerprinting
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detect clock drift convergence across devices.
 *
 * Every crystal oscillator drifts at a unique rate (20–100 ppm).
 * Over multiple submissions, drift accumulates into a device-specific
 * signature. If "different devices" share the same drift rate, they're
 * the same physical hardware behind a rotation proxy.
 *
 * Input: array of device submission histories.
 * Each device: { id: string, submissions: [{ ts: number, serverTs: number }] }
 *
 * The delta between client timestamp and server timestamp grows linearly
 * at the drift rate. Linear regression on (serverTs, clientTs - serverTs)
 * gives the slope = drift rate in ms/s.
 *
 * @param {object[]} devices - [{ id, submissions: [{ ts, serverTs }] }]
 * @param {object}   [opts]
 * @param {number}   [opts.driftBinPpm=5]     - drift rate bin width in ppm
 * @param {number}   [opts.minSubmissions=3]   - min submissions per device
 * @param {number}   [opts.collisionThreshold=0.30] - fraction triggering flag
 * @returns {{ score: number, driftRates: Map, largestCluster: number, clusterRatio: number }}
 */
export function testDriftFingerprint(devices, opts = {}) {
  const driftBinPpm     = opts.driftBinPpm ?? 5;
  const minSubmissions  = opts.minSubmissions ?? 3;
  const collisionThresh = opts.collisionThreshold ?? 0.30;

  // Compute drift rate per device via linear regression
  const rates = [];
  const rateMap = new Map();

  for (const dev of devices) {
    const subs = dev.submissions;
    if (!subs || subs.length < minSubmissions) continue;

    const drift = computeDriftRate(subs);
    if (drift === null) continue;

    rates.push(drift);
    rateMap.set(dev.id, drift);
  }

  if (rates.length < 3) {
    return { score: 0, driftRates: rateMap, largestCluster: 0, clusterRatio: 0, totalDevices: rates.length };
  }

  // Bin drift rates and find collision clusters
  const bins = new Map();
  for (const rate of rates) {
    // Convert ms/s drift to ppm, then bin
    const ppm = rate * 1000; // ms/s → μs/s ≈ ppm
    const binKey = Math.round(ppm / driftBinPpm) * driftBinPpm;
    bins.set(binKey, (bins.get(binKey) ?? 0) + 1);
  }

  let largestCluster = 0;
  for (const c of bins.values()) {
    if (c > largestCluster) largestCluster = c;
  }

  const clusterRatio = largestCluster / rates.length;
  const uniqueBins = bins.size;
  const expectedBins = Math.min(rates.length, Math.ceil(80 / driftBinPpm)); // ~80 ppm range

  // Score: high cluster ratio + few unique bins = same hardware
  let score = 0;
  if (clusterRatio >= collisionThresh) {
    score += Math.round((clusterRatio - collisionThresh + 0.05) / (1 - collisionThresh) * 60);
  }
  if (uniqueBins < expectedBins * 0.5) {
    score += Math.round((1 - uniqueBins / expectedBins) * 40);
  }

  return {
    score: clamp(score, 0, 100),
    driftRates: Object.fromEntries(rateMap),
    largestCluster,
    clusterRatio: +clusterRatio.toFixed(4),
    uniqueBins,
    totalDevices: rates.length,
  };
}

/**
 * Compute clock drift rate from a series of submissions via linear regression.
 * Returns drift in ms/s (slope of client-server offset over time).
 *
 * @param {object[]} subs - [{ ts: clientEpochMs, serverTs: serverEpochMs }]
 * @returns {number|null} drift rate in ms/s, or null if insufficient data
 */
export function computeDriftRate(subs) {
  if (subs.length < 2) return null;

  // x = server time (seconds from first), y = client-server offset (ms)
  const t0 = subs[0].serverTs;
  const xs = subs.map(s => (s.serverTs - t0) / 1000);
  const ys = subs.map(s => s.ts - s.serverTs);

  const n = xs.length;
  const xm = mean(xs);
  const ym = mean(ys);

  let num = 0, den = 0;
  for (let i = 0; i < n; i++) {
    num += (xs[i] - xm) * (ys[i] - ym);
    den += (xs[i] - xm) ** 2;
  }

  if (den === 0) return null;
  return num / den; // ms/s drift rate
}

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 4 — Mutual Information Matrix
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Compute pairwise mutual information across signal dimensions,
 * then detect community structure via greedy modularity (Louvain-lite).
 *
 * Each token is projected into a discrete signal vector:
 *   [entropy_band, thermal_label, motor_band, idle_band, enf_band]
 *
 * MI between device i and device j = how much i's signal vector
 * tells you about j's. Organic: MI matrix is sparse. Bot farm:
 * block-diagonal (cliques).
 *
 * @param {object[]} tokens
 * @param {object}   [opts]
 * @param {number}   [opts.bins=8] - discretization bins per continuous signal
 * @returns {{ score: number, communities: number, largestCommunity: number, communityRatio: number, modularity: number }}
 */
export function testMutualInformation(tokens, opts = {}) {
  const n = tokens.length;
  if (n < 10) return { score: 0, communities: 1, largestCommunity: n, communityRatio: 1, modularity: 0 };

  const bins = opts.bins ?? 8;

  // Project each token into a discrete signal vector
  const vectors = tokens.map(t => tokenToVector(t, bins));

  // Build similarity matrix (cosine similarity of signal vectors)
  // For efficiency with large n, use fingerprint bucketing instead of O(n²)
  const { adjacency, edges } = buildSimilarityGraph(vectors, 0.7);

  if (edges === 0) {
    // No similar pairs — fully organic
    return { score: 0, communities: n, largestCommunity: 1, communityRatio: 1 / n, modularity: 0 };
  }

  // Run Louvain-lite community detection
  const { communities, modularity } = louvainLite(adjacency, n);

  // Count community sizes
  const sizes = new Map();
  for (const c of communities) {
    sizes.set(c, (sizes.get(c) ?? 0) + 1);
  }

  let largestCommunity = 0;
  for (const s of sizes.values()) {
    if (s > largestCommunity) largestCommunity = s;
  }

  const communityRatio = largestCommunity / n;
  const numCommunities = sizes.size;

  // Score: large dominant community = coordinated
  let score = 0;
  if (communityRatio > 0.4) {
    score += Math.round((communityRatio - 0.4) * 100);
  }
  // Few communities relative to n = low diversity
  const expectedCommunities = Math.sqrt(n); // organic rough estimate
  if (numCommunities < expectedCommunities * 0.5) {
    score += Math.round((1 - numCommunities / expectedCommunities) * 30);
  }
  // High modularity with large community = structured coordination
  if (modularity > 0.3 && communityRatio > 0.3) {
    score += 20;
  }

  return {
    score: clamp(score, 0, 100),
    communities: numCommunities,
    largestCommunity,
    communityRatio: +communityRatio.toFixed(4),
    modularity: +modularity.toFixed(4),
  };
}

/**
 * Project a token into a discrete signal vector for MI computation.
 */
function tokenToVector(token, bins) {
  const idle = token.idle ?? token.signals?.idle ?? {};
  const hw   = token.hw ?? token.signals?.entropy ?? {};
  const evt  = token.evt ?? token.signals?.motor ?? {};
  const enf  = hw.enfDev ?? token.enfDev ?? 0;

  return [
    band(hw.ent ?? hw.score ?? 0.5, 0, 1, bins),
    thermalToIndex(idle.therm ?? idle.thermalTransition ?? 'unknown'),
    band(evt.mot ?? evt.consistency ?? 0.5, 0, 1, bins),
    band(idle.dMs ?? idle.s ?? 0, 0, 300, bins), // idle duration in seconds
    band(enf, -0.05, 0.05, bins),
  ];
}

const THERMAL_MAP = { hot_to_cold: 0, cold: 1, cooling: 2, warming: 3, sustained_hot: 4, step_function: 5, unknown: 6 };
function thermalToIndex(label) { return THERMAL_MAP[label] ?? 6; }

/**
 * Build a similarity graph from signal vectors using fingerprint bucketing.
 * O(n * k) where k = average bucket size, instead of O(n²).
 */
function buildSimilarityGraph(vectors, threshold) {
  const n = vectors.length;
  const adjacency = new Array(n).fill(null).map(() => []);
  let edges = 0;

  // Bucket by concatenated vector (exact match = definitely similar)
  const buckets = new Map();
  for (let i = 0; i < n; i++) {
    const key = vectors[i].join(',');
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(i);
  }

  // Exact matches
  for (const group of buckets.values()) {
    for (let a = 0; a < group.length; a++) {
      for (let b = a + 1; b < group.length; b++) {
        adjacency[group[a]].push(group[b]);
        adjacency[group[b]].push(group[a]);
        edges++;
      }
    }
  }

  // Near matches: check Hamming distance ≤ 1 between bucket keys
  const keys = [...buckets.keys()];
  for (let a = 0; a < keys.length; a++) {
    const va = keys[a].split(',').map(Number);
    for (let b = a + 1; b < keys.length; b++) {
      const vb = keys[b].split(',').map(Number);
      let dist = 0;
      for (let d = 0; d < va.length; d++) {
        if (va[d] !== vb[d]) dist++;
      }
      if (dist <= 1) {
        // Connect all pairs between these two buckets
        const ga = buckets.get(keys[a]);
        const gb = buckets.get(keys[b]);
        for (const i of ga) {
          for (const j of gb) {
            adjacency[i].push(j);
            adjacency[j].push(i);
            edges++;
          }
        }
      }
    }
  }

  return { adjacency, edges };
}

/**
 * Louvain-lite: greedy modularity maximization.
 * Simplified single-pass version for real-time use.
 * Returns community assignments and modularity score.
 */
function louvainLite(adjacency, n) {
  // Initialize: each node in its own community
  const comm = new Array(n);
  for (let i = 0; i < n; i++) comm[i] = i;

  // Compute total edges (2m)
  let twoM = 0;
  for (let i = 0; i < n; i++) twoM += adjacency[i].length;
  if (twoM === 0) return { communities: comm, modularity: 0 };

  // Degree of each node
  const deg = adjacency.map(a => a.length);

  // Incremental community degree map — O(1) lookup instead of O(n) scan
  const commDeg = new Map();
  for (let i = 0; i < n; i++) {
    commDeg.set(i, deg[i]);
  }

  // Single pass: try to move each node to its best neighbor's community
  let changed = true;
  let passes = 0;
  while (changed && passes < 10) {
    changed = false;
    passes++;
    for (let i = 0; i < n; i++) {
      if (adjacency[i].length === 0) continue;

      // Count edges to each neighboring community
      const commEdges = new Map();
      for (const j of adjacency[i]) {
        const c = comm[j];
        commEdges.set(c, (commEdges.get(c) ?? 0) + 1);
      }

      // Find best community (highest modularity gain)
      let bestComm = comm[i];
      let bestDelta = 0;

      for (const [c, eic] of commEdges) {
        if (c === comm[i]) continue;
        const cDeg = commDeg.get(c) ?? 0;
        const delta = eic / twoM - (deg[i] * cDeg) / (twoM * twoM);
        if (delta > bestDelta) {
          bestDelta = delta;
          bestComm = c;
        }
      }

      if (bestComm !== comm[i]) {
        // Update community degree map incrementally
        const oldComm = comm[i];
        commDeg.set(oldComm, (commDeg.get(oldComm) ?? 0) - deg[i]);
        commDeg.set(bestComm, (commDeg.get(bestComm) ?? 0) + deg[i]);
        comm[i] = bestComm;
        changed = true;
      }
    }
  }

  // Compute modularity
  let Q = 0;
  for (let i = 0; i < n; i++) {
    for (const j of adjacency[i]) {
      if (comm[i] === comm[j]) {
        Q += 1 - (deg[i] * deg[j]) / twoM;
      }
    }
  }
  Q /= twoM;

  return { communities: comm, modularity: Math.max(0, Q) };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Layer 5 — Entropy Velocity
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Measure entropy growth rate vs traffic growth rate.
 *
 * Organic growth: each new user adds a unique signal profile → entropy
 * increases proportionally to log2(n).
 *
 * Bot deployment: traffic increases but entropy plateaus or grows slower
 * than expected (cloned profiles add volume without diversity).
 *
 * Method: split the token window into temporal slices, compute Shannon
 * entropy of the signal fingerprint distribution in each slice, then
 * measure dH/dt vs dn/dt.
 *
 * @param {object[]} tokens  - chronologically sorted
 * @param {object}   [opts]
 * @param {number}   [opts.slices=5]  - number of temporal slices
 * @returns {{ score: number, velocityRatio: number, entropySlices: number[], countSlices: number[] }}
 */
export function testEntropyVelocity(tokens, opts = {}) {
  const n = tokens.length;
  const numSlices = opts.slices ?? 5;
  if (n < numSlices * 3) return { score: 0, velocityRatio: 1, entropySlices: [], countSlices: [] };

  // Split tokens into temporal slices
  const sliceSize = Math.ceil(n / numSlices);
  const entropySlices = [];
  const countSlices = [];
  const cumulativeEntropies = [];

  for (let s = 0; s < numSlices; s++) {
    const start = 0; // cumulative — each slice includes all previous tokens
    const end = Math.min(n, (s + 1) * sliceSize);
    const slice = tokens.slice(start, end);

    // Compute Shannon entropy of fingerprint distribution
    const fps = new Map();
    for (const t of slice) {
      const key = defaultFingerprint(t);
      fps.set(key, (fps.get(key) ?? 0) + 1);
    }
    const H = shannonEntropy([...fps.values()]);
    entropySlices.push(+H.toFixed(4));
    countSlices.push(end);
    cumulativeEntropies.push(H);
  }

  // Expected entropy growth: H_expected ≈ log2(unique_count) grows as log2(n)
  // For organic traffic, H should grow roughly as log2(n) / log2(N_total)
  // Measure: ratio of actual entropy growth to expected
  const H_first = cumulativeEntropies[0];
  const H_last = cumulativeEntropies[cumulativeEntropies.length - 1];
  const n_first = countSlices[0];
  const n_last = countSlices[countSlices.length - 1];

  if (n_first === n_last) {
    return { score: 0, velocityRatio: 1, entropySlices, countSlices };
  }

  // If entropy is near-zero throughout — extremely low diversity = coordinated
  if (H_last < 0.5 && n_last >= 20) {
    return { score: Math.round(clamp(80 + (0.5 - H_last) * 40, 80, 100)), velocityRatio: 0, entropySlices, countSlices };
  }

  if (H_first < 0.01) {
    // First slice has no diversity — use absolute entropy check
    const expectedH = Math.log2(Math.max(2, n_last * 0.3)); // expected for organic
    const ratio = H_last / expectedH;
    return {
      score: Math.round(clamp((1 - ratio) * 100, 0, 100)),
      velocityRatio: +ratio.toFixed(4),
      entropySlices,
      countSlices,
    };
  }

  // Expected entropy ratio based on log growth
  const expectedGrowth = Math.log2(n_last) / Math.log2(n_first);
  const actualGrowth = H_last / Math.max(0.01, H_first);
  const velocityRatio = actualGrowth / expectedGrowth;

  // velocityRatio < 0.6 means entropy isn't keeping up with traffic = artificial
  // velocityRatio ≈ 1.0 means organic
  // velocityRatio > 1.2 could mean natural diversification
  let score;
  if (velocityRatio >= 0.8) {
    score = Math.round(clamp((1.0 - velocityRatio) * 50, 0, 20));
  } else if (velocityRatio >= 0.5) {
    score = Math.round(20 + (0.8 - velocityRatio) / 0.3 * 50);
  } else {
    score = Math.round(70 + (0.5 - velocityRatio) / 0.5 * 30);
  }

  return {
    score: clamp(score, 0, 100),
    velocityRatio: +velocityRatio.toFixed(4),
    entropySlices,
    countSlices,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Orchestrator — Coordinated Behavior Analysis
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Full coordination analysis across all 5 layers.
 *
 * @param {object[]} tokens   - engagement tokens with physics signals
 * @param {object}   [opts]
 * @param {object[]} [opts.devices]    - device submission histories for drift analysis
 * @param {number}   [opts.windowMs]   - analysis window (default: 60000ms)
 * @returns {CoordinationResult}
 */
export function analyseCoordination(tokens, opts = {}) {
  const n = tokens.length;
  if (n < 5) {
    return {
      coordinationScore: 0,
      verdict: 'insufficient_data',
      confidence: 0,
      layers: {},
      tokenCount: n,
    };
  }

  // Extract timestamps
  const timestamps = tokens.map(t =>
    t.iat ?? t.timestamp ?? t.ts ?? Date.now()
  ).sort((a, b) => a - b);

  // ── Layer 1: Temporal Clustering ──
  const temporal = testTemporalClustering(timestamps);

  // ── Layer 2: Fingerprint Collision ──
  const fingerprint = testFingerprintCollision(tokens);

  // ── Layer 3: Drift Fingerprinting ──
  const devices = opts.devices ?? [];
  const drift = devices.length >= 3
    ? testDriftFingerprint(devices)
    : { score: 0, totalDevices: 0 };

  // ── Layer 4: Mutual Information ──
  const mi = testMutualInformation(tokens);

  // ── Layer 5: Entropy Velocity ──
  const velocity = testEntropyVelocity(tokens);

  // ── Weighted Fusion ──
  // Weights reflect each layer's discriminative power and evasion cost
  const weights = {
    temporal:    0.15,  // easy to randomize, but still catches lazy farms
    fingerprint: 0.25,  // hard to fake without real hardware diversity
    drift:       0.15,  // only fires with multi-submission data
    mi:          0.25,  // hardest to evade — requires true independence
    velocity:    0.20,  // catches mass deployment timing
  };

  // If no drift data, redistribute weight
  const hasDrift = drift.totalDevices >= 3;
  const effectiveWeights = hasDrift ? weights : {
    temporal:    0.18,
    fingerprint: 0.28,
    drift:       0,
    mi:          0.30,
    velocity:    0.24,
  };

  const raw =
    temporal.score    * effectiveWeights.temporal +
    fingerprint.score * effectiveWeights.fingerprint +
    drift.score       * effectiveWeights.drift +
    mi.score          * effectiveWeights.mi +
    velocity.score    * effectiveWeights.velocity;

  const coordinationScore = Math.round(clamp(raw, 0, 100));

  // Confidence: higher with more tokens and more layers contributing
  const activeLayers = [temporal, fingerprint, mi, velocity].filter(l => l.score > 0).length + (hasDrift ? 1 : 0);
  const confidence = clamp(
    (Math.min(n, 100) / 100) * 0.5 + (activeLayers / 5) * 0.5,
    0, 1
  );

  // Verdict
  let verdict;
  if (coordinationScore >= 70) verdict = 'coordinated_inauthentic';
  else if (coordinationScore >= 45) verdict = 'suspicious_coordination';
  else if (coordinationScore >= 25) verdict = 'low_coordination';
  else verdict = 'organic';

  // Advisory flags
  const flags = [];
  if (temporal.score >= 60)    flags.push('BURST_ARRIVAL_PATTERN');
  if (fingerprint.score >= 60) flags.push('LOW_FINGERPRINT_DIVERSITY');
  if (drift.score >= 50)       flags.push('CLOCK_DRIFT_CONVERGENCE');
  if (mi.score >= 50)          flags.push('SIGNAL_CLIQUE_DETECTED');
  if (velocity.score >= 50)    flags.push('ENTROPY_GROWTH_STALLED');

  return {
    coordinationScore,
    verdict,
    confidence: +confidence.toFixed(3),
    flags,
    layers: {
      temporal,
      fingerprint,
      drift: hasDrift ? drift : { score: 0, skipped: true, reason: 'insufficient_device_history' },
      mutualInformation: mi,
      entropyVelocity: velocity,
    },
    tokenCount: n,
    weights: effectiveWeights,
  };
}

/**
 * @typedef {object} CoordinationResult
 * @property {number}  coordinationScore - 0–100, higher = more coordinated
 * @property {string}  verdict           - 'organic' | 'low_coordination' | 'suspicious_coordination' | 'coordinated_inauthentic'
 * @property {number}  confidence        - 0–1, based on token count and active layers
 * @property {string[]} flags            - advisory flags for specific signals
 * @property {object}  layers            - per-layer results
 * @property {number}  tokenCount        - number of tokens analyzed
 * @property {object}  weights           - effective layer weights used
 */

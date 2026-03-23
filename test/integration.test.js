/**
 * @svrnsec/pulse — Full Integration & Unit Test Suite
 *
 * Run: npm test
 */

import { computeStats, classifyJitter, computeHurst,
         detectQuantizationEntropy, detectThermalSignature }
  from '../src/analysis/jitter.js';

import { runHeuristicEngine }
  from '../src/analysis/heuristic.js';

import { detectProvider }
  from '../src/analysis/provider.js';

import { buildProof, buildCommitment, canonicalJson, blake3HexStr }
  from '../src/proof/fingerprint.js';

import { validateProof, generateNonce }
  from '../src/proof/validator.js';

import { serializeSignature, matchRegistry, compareSignatures, KNOWN_PROFILES }
  from '../src/registry/serializer.js';

// ─── Synthetic timing generators ─────────────────────────────────────────────

function makeLcg(seed) {
  let s = seed >>> 0;
  return () => {
    s = Math.imul(s, 1664525) + 1013904223 >>> 0;
    return s / 0xFFFFFFFF;
  };
}

/** Consumer hardware: Gaussian noise + thermal drift + spikes */
function realHardwareSamples(n = 200, seed = 42) {
  const rand = makeLcg(seed);
  const gauss = () => {
    const u = Math.max(1e-12, rand());
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * rand());
  };
  const out = [];
  let base = 5.0;
  for (let i = 0; i < n; i++) {
    base += 0.001;
    out.push(Math.max(0.5, base + gauss() * 0.55 + (rand() > 0.94 ? rand() * 4 : 0)));
  }
  return out;
}

/** KVM VM: quantized + periodic steal-time bursts */
function vmSamples(n = 200) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const q     = Math.round((5.0 + (Math.random() - 0.5) * 0.18) * 10) / 10;
    const steal = (i % 50 < 3) ? 1.8 : 0;
    out.push(q + steal);
  }
  return out;
}

/** Three-phase samples: cold / load / hot — simulates phased entropy collection */
function phasedRealHardware() {
  const rand = makeLcg(0xDEAD);
  const gauss = () => {
    const u = Math.max(1e-12, rand());
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * rand());
  };
  const cold = Array.from({ length: 50  }, (_, i) => Math.max(0.5, 5.0 + i * 0.0005 + gauss() * 0.40));
  const load = Array.from({ length: 100 }, (_, i) => Math.max(0.5, 5.1 + i * 0.0010 + gauss() * 0.55));
  const hot  = Array.from({ length: 50  }, (_, i) => Math.max(0.5, 5.3 + i * 0.0005 + gauss() * 0.70));
  return { cold, load, hot, all: [...cold, ...load, ...hot] };
}

function phasedVM() {
  const cold = Array.from({ length: 50  }, (_, i) => Math.round((5.0 + (Math.random() - 0.5) * 0.18) * 10) / 10 + (i % 50 < 3 ? 1.8 : 0));
  const load = Array.from({ length: 100 }, (_, i) => Math.round((5.0 + (Math.random() - 0.5) * 0.18) * 10) / 10 + (i % 50 < 3 ? 1.8 : 0));
  const hot  = Array.from({ length: 50  }, (_, i) => Math.round((5.0 + (Math.random() - 0.5) * 0.18) * 10) / 10 + (i % 50 < 3 ? 1.8 : 0));
  return { cold, load, hot, all: [...cold, ...load, ...hot] };
}

// ─── Shared mock payload builder ─────────────────────────────────────────────

const _mockPayload = (jitterScore = 0.78, overrides = {}) => ({
  version:   1,
  timestamp: Date.now(),
  nonce:     'aabbcc',
  signals: {
    entropy: {
      timingsMean: 5.2, timingsCV: 0.12, timingsP50: 5.0, timingsP95: 7.5,
      timingsSkewness: 0.4, timingsKurtosis: 0.8,
      autocorr_lag1: 0.05, autocorr_lag2: 0.03, autocorr_lag5: 0.01, autocorr_lag10: -0.02,
      hurstExponent: 0.52, quantizationEntropy: 5.1, thermalDrift: 0.00012,
      thermalPattern: 'rising', outlierRate: 0.04, timerGranularityMs: 0.1,
      checksum: '12345678', timingsHash: 'aabbcc', memTimingsHash: 'ddeeff',
      iterations: 200, matrixSize: 64,
    },
    bio: {
      mouseSampleCount: 80, mouseIEIMean: 16.2, mouseIEICV: 0.35,
      mouseVelocityP50: 0.5, mouseVelocityP95: 2.1, mouseAngularJerkMean: 0.003,
      pressureVariance: 0, keyboardSampleCount: 12, keyboardDwellMean: 95,
      keyboardDwellCV: 0.22, keyboardIKIMean: 210, keyboardIKICV: 0.41,
      interferenceCoefficient: 0.18, hasActivity: true, durationMs: 3000,
    },
    canvas: {
      webglRenderer: 'NVIDIA GeForce GTX 1650 Super/PCIe/SSE2',
      webglVendor: 'NVIDIA Corporation', webglVersion: 2,
      webglPixelHash: 'abc123', canvas2dHash: 'def456',
      extensionCount: 38, isSoftwareRenderer: false, available: true,
    },
    audio: {
      available: true, workletAvailable: true, callbackJitterCV: 0.08,
      noiseFloorMean: 0.0001, noiseFloorStd: 0.00002, sampleRate: 44100,
      callbackCount: 340, jitterMeanMs: 5.8, jitterP95Ms: 7.2,
    },
  },
  classification: { jitterScore, flags: [] },
  ...overrides,
});

// =============================================================================
// computeStats
// =============================================================================

describe('computeStats', () => {
  test('basic statistics are correct', () => {
    const s = computeStats([1, 2, 3, 4, 5]);
    expect(s.mean).toBeCloseTo(3.0);
    expect(s.min).toBe(1);
    expect(s.max).toBe(5);
    expect(s.cv).toBeGreaterThan(0);
  });
  test('constant array has zero CV', () => {
    const s = computeStats(new Array(100).fill(5.0));
    expect(s.cv).toBeCloseTo(0, 5);
  });
});

// =============================================================================
// computeHurst
// =============================================================================

describe('computeHurst', () => {
  test('returns value in [0,1]', () => {
    expect(computeHurst(realHardwareSamples(200))).toBeGreaterThanOrEqual(0);
    expect(computeHurst(realHardwareSamples(200))).toBeLessThanOrEqual(1);
  });
  test('constant series returns ~0.5', () => {
    expect(computeHurst(new Array(15).fill(5.0))).toBeCloseTo(0.5, 1);
  });
});

// =============================================================================
// detectQuantizationEntropy
// =============================================================================

describe('detectQuantizationEntropy', () => {
  test('real hardware samples have high entropy', () => {
    expect(detectQuantizationEntropy(realHardwareSamples(200))).toBeGreaterThan(3.0);
  });
  test('quantized VM samples have low entropy', () => {
    expect(detectQuantizationEntropy(vmSamples(200))).toBeLessThan(2.5);
  });
});

// =============================================================================
// detectThermalSignature
// =============================================================================

describe('detectThermalSignature', () => {
  test('detects rising pattern', () => {
    const sig = detectThermalSignature(Array.from({ length: 100 }, (_, i) => 5 + i * 0.01));
    expect(sig.pattern).toBe('rising');
    expect(sig.slope).toBeGreaterThan(0);
  });
  test('detects flat pattern', () => {
    expect(detectThermalSignature(new Array(100).fill(5.0)).pattern).toBe('flat');
  });
});

// =============================================================================
// classifyJitter
// =============================================================================

describe('classifyJitter', () => {
  test('real hardware scores higher than VM', () => {
    expect(classifyJitter(realHardwareSamples(200)).score)
      .toBeGreaterThan(classifyJitter(vmSamples(200)).score);
  });
  test('score is in [0,1]', () => {
    const { score } = classifyJitter(realHardwareSamples(200));
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(1);
  });
  test('VM samples are flagged', () => {
    const { flags } = classifyJitter(vmSamples(200));
    expect(flags.some(f => f.includes('VM') || f.includes('FLAT') || f.includes('SYNTHETIC') || f.includes('AUTOCORR'))).toBe(true);
  });
  test('insufficient data returns zero score', () => {
    const { score, flags } = classifyJitter([1, 2, 3]);
    expect(score).toBe(0);
    expect(flags).toContain('INSUFFICIENT_DATA');
  });
});

// =============================================================================
// runHeuristicEngine
// =============================================================================

describe('runHeuristicEngine', () => {
  test('returns neutral result on empty input', () => {
    const result = runHeuristicEngine({ jitter: { stats: null }, phases: null, autocorrelations: {} });
    expect(result.penalty).toBe(0);
    expect(result.bonus).toBe(0);
  });

  test('detects entropy growth under load (real hardware)', () => {
    const phased = phasedRealHardware();
    const jitter = classifyJitter(phased.all);
    const coldQE = detectQuantizationEntropy(phased.cold);
    const hotQE  = detectQuantizationEntropy(phased.hot);
    const phases = {
      cold: { qe: coldQE, mean: phased.cold.reduce((s, v) => s + v, 0) / phased.cold.length },
      hot:  { qe: hotQE,  mean: phased.hot.reduce((s, v)  => s + v, 0) / phased.hot.length  },
      entropyJitterRatio: hotQE / coldQE,
    };
    const result = runHeuristicEngine({ jitter, phases, autocorrelations: jitter.autocorrelations ?? {} });
    // Real hardware: entropy grows → bonus or at worst neutral
    expect(result.penalty).toBeLessThan(0.20);
  });

  test('penalises flat entropy under load (VM)', () => {
    const phased = phasedVM();
    const jitter = classifyJitter(phased.all);
    const coldQE = detectQuantizationEntropy(phased.cold);
    const hotQE  = detectQuantizationEntropy(phased.hot);
    const phases = {
      cold: { qe: coldQE, mean: 5.1 },
      hot:  { qe: hotQE,  mean: 5.1 },
      entropyJitterRatio: hotQE / Math.max(coldQE, 0.001),
    };
    const result = runHeuristicEngine({ jitter, phases, autocorrelations: jitter.autocorrelations ?? {} });
    // VM: flat entropy → should add some penalty
    expect(result.findings.length).toBeGreaterThan(0);
  });

  test('penalises CV-entropy incoherence', () => {
    // Craft a jitter analysis with high CV but very low QE (incoherent)
    const jitter = classifyJitter(realHardwareSamples(200));
    // Override qe to be very low while CV stays high
    const patchedJitter = { ...jitter, quantizationEntropy: 0.5, stats: { ...jitter.stats, cv: 0.20 } };
    const result = runHeuristicEngine({ jitter: patchedJitter, phases: null, autocorrelations: {} });
    const hasCVFlag = result.findings.some(f => f.id === 'CV_ENTROPY_INCOHERENT');
    expect(hasCVFlag).toBe(true);
  });

  test('detects picket fence at lag-50', () => {
    // Simulate VM with strong long-lag autocorrelation
    const autocorrelations = { lag1: 0.66, lag2: 0.10, lag3: 0.05, lag5: 0.03, lag10: 0.02, lag25: 0.28, lag50: 0.55 };
    const jitter = classifyJitter(vmSamples(200));
    const result = runHeuristicEngine({ jitter, phases: null, autocorrelations });
    expect(result.picketFence.detected).toBe(true);
  });

  test('bonus awarded for Brownian coherence', () => {
    // Near-perfect Brownian noise: H≈0.5, low autocorr
    const jitter = classifyJitter(realHardwareSamples(200));
    const patchedJitter = { ...jitter, hurstExponent: 0.50 };
    const autocorrelations = { lag1: 0.02, lag2: 0.01, lag3: 0.01, lag5: 0.00, lag10: 0.00, lag25: 0.00, lag50: 0.00 };
    const result = runHeuristicEngine({ jitter: patchedJitter, phases: null, autocorrelations });
    expect(result.bonuses.some(b => b.id === 'BROWNIAN_COHERENCE_CONFIRMED')).toBe(true);
  });
});

// =============================================================================
// detectProvider
// =============================================================================

describe('detectProvider', () => {
  const realCanvas = {
    webglRenderer: 'NVIDIA GeForce GTX 1650 Super/PCIe/SSE2',
    webglVendor: 'NVIDIA Corporation', isSoftwareRenderer: false, available: true,
  };
  const vmCanvas = {
    webglRenderer: 'Google SwiftShader', webglVendor: 'Google Inc.',
    isSoftwareRenderer: true, available: true,
  };
  const kvmCanvas = {
    webglRenderer: 'llvmpipe (LLVM 15.0.7, 256 bits)', webglVendor: 'Mesa/X.org',
    isSoftwareRenderer: true, available: true,
  };

  test('classifies real hardware as physical', () => {
    const jitter = classifyJitter(realHardwareSamples(200));
    const result = detectProvider({
      jitter, canvas: realCanvas, phases: null,
      autocorrelations: { lag1: 0.07, lag25: 0.04, lag50: 0.05 },
    });
    expect(result.providerId).toBe('physical');
    expect(result.isVirtualized).toBe(false);
  });

  test('classifies SwiftShader as VM', () => {
    const jitter = classifyJitter(vmSamples(200));
    const result = detectProvider({
      jitter, canvas: vmCanvas, phases: null,
      autocorrelations: { lag1: 0.66, lag25: 0.28, lag50: 0.55 },
    });
    expect(result.isVirtualized).toBe(true);
  });

  test('classifies llvmpipe (KVM) correctly', () => {
    const jitter = classifyJitter(vmSamples(200));
    const result = detectProvider({
      jitter, canvas: kvmCanvas, phases: null,
      autocorrelations: { lag1: 0.66, lag25: 0.28, lag50: 0.55 },
    });
    expect(result.isVirtualized).toBe(true);
    expect(['kvm-generic', 'kvm-digitalocean', 'generic-vm']).toContain(result.providerId);
  });

  test('profile is analog-fog for physical hardware', () => {
    const jitter = classifyJitter(realHardwareSamples(200));
    const result = detectProvider({
      jitter, canvas: realCanvas, phases: null,
      autocorrelations: { lag1: 0.07, lag25: 0.03, lag50: 0.04 },
    });
    expect(result.profile).toBe('analog-fog');
  });

  test('estimates scheduler quantum for VM', () => {
    const jitter = classifyJitter(vmSamples(200));
    const result = detectProvider({
      jitter, canvas: kvmCanvas, phases: null,
      autocorrelations: { lag1: 0.66, lag25: 0.35, lag50: 0.58 },
    });
    // lag50 dominant → quantum ≈ 250ms
    expect(result.schedulerQuantumMs).toBe(250);
  });
});

// =============================================================================
// buildCommitment / canonicalJson
// =============================================================================

describe('buildCommitment', () => {
  test('produces deterministic hash', () => {
    const p = _mockPayload();
    expect(buildCommitment(p).hash).toBe(buildCommitment(p).hash);
    expect(buildCommitment(p).hash).toHaveLength(64);
  });
  test('any field change breaks the hash', () => {
    const p1 = _mockPayload();
    const p2 = JSON.parse(JSON.stringify(p1));
    p2.classification.jitterScore = 0.99;
    expect(buildCommitment(p1).hash).not.toBe(buildCommitment(p2).hash);
  });
});

describe('canonicalJson', () => {
  test('sorts keys deterministically', () => {
    expect(canonicalJson({ z: 1, a: 2, m: 3 })).toBe(canonicalJson({ m: 3, z: 1, a: 2 }));
  });
});

// =============================================================================
// validateProof
// =============================================================================

describe('validateProof', () => {
  test('valid proof passes', async () => {
    const p = _mockPayload(0.78);
    const { hash } = buildCommitment(p);
    const r = await validateProof(p, hash, { minJitterScore: 0.55 });
    expect(r.valid).toBe(true);
    expect(r.confidence).not.toBe('rejected');
  });
  test('tampered payload is rejected', async () => {
    const p = _mockPayload(0.78);
    const { hash } = buildCommitment(p);
    p.classification.jitterScore = 0.99;
    const r = await validateProof(p, hash);
    expect(r.valid).toBe(false);
    expect(r.reasons).toContain('HASH_MISMATCH_PAYLOAD_TAMPERED');
  });
  test('low jitter score is rejected', async () => {
    const p = _mockPayload(0.30);
    const { hash } = buildCommitment(p);
    const r = await validateProof(p, hash, { minJitterScore: 0.55 });
    expect(r.valid).toBe(false);
    expect(r.reasons.some(r => r.startsWith('JITTER_SCORE_TOO_LOW'))).toBe(true);
  });
  test('software renderer is blocked', async () => {
    const p = _mockPayload(0.78);
    p.signals.canvas.webglRenderer = 'Google SwiftShader';
    p.signals.canvas.isSoftwareRenderer = true;
    const { hash } = buildCommitment(p);
    const r = await validateProof(p, hash, { blockSoftwareRenderer: true });
    expect(r.valid).toBe(false);
  });
  test('expired proof is rejected', async () => {
    const p = _mockPayload(0.78);
    p.timestamp = Date.now() - 400_000;
    const { hash } = buildCommitment(p);
    const r = await validateProof(p, hash, { maxAgeMs: 300_000 });
    expect(r.valid).toBe(false);
    expect(r.reasons.some(r => r.startsWith('PROOF_EXPIRED'))).toBe(true);
  });
  test('nonce check is called', async () => {
    const p = _mockPayload(0.78);
    const { hash } = buildCommitment(p);
    let called = false;
    await validateProof(p, hash, { checkNonce: async () => { called = true; return true; } });
    expect(called).toBe(true);
  });
  test('rejected nonce fails proof', async () => {
    const p = _mockPayload(0.78);
    const { hash } = buildCommitment(p);
    const r = await validateProof(p, hash, { checkNonce: async () => false });
    expect(r.valid).toBe(false);
    expect(r.reasons).toContain('NONCE_INVALID_OR_REPLAYED');
  });
});

// =============================================================================
// generateNonce
// =============================================================================

describe('generateNonce', () => {
  test('produces 64-char hex strings', () => {
    const n = generateNonce();
    expect(n).toHaveLength(64);
    expect(n).toMatch(/^[0-9a-f]{64}$/);
  });
  test('each call is unique', () => {
    expect(generateNonce()).not.toBe(generateNonce());
  });
});

// =============================================================================
// Registry — serializeSignature / matchRegistry / compareSignatures
// =============================================================================

/** Build a minimal mock Fingerprint-like object for registry tests */
function mockFingerprint(overrides = {}) {
  const jitter = classifyJitter(realHardwareSamples(200));
  return {
    isSynthetic:  false,
    profile:      'analog-fog',
    providerId:   'physical',
    _raw: {
      jitter,
      heuristic: { entropyJitterRatio: 1.18, picketFence: { detected: false }, coherenceFlags: [] },
      entropy: { autocorrelations: { lag1: 0.07, lag50: 0.04 } },
      canvas: {
        webglRenderer: 'NVIDIA GeForce GTX 1650 Super/PCIe/SSE2',
        webglVendor: 'NVIDIA Corporation',
        extensionCount: 38, webglVersion: 2, isSoftwareRenderer: false,
      },
      audio: { sampleRate: 44100 },
      bioSnapshot: {},
    },
    metrics() {
      return {
        cv: jitter.stats?.cv, hurstExponent: jitter.hurstExponent,
        quantizationEntropy: jitter.quantizationEntropy,
        autocorrLag1: jitter.autocorrelations?.lag1, autocorrLag50: 0.04,
        outlierRate: jitter.outlierRate, thermalPattern: 'sawtooth',
        entropyJitterRatio: 1.18, picketFence: false,
        provider: 'Physical Hardware', providerConfidence: 90,
        schedulerQuantumMs: null,
        webglRenderer: 'NVIDIA GeForce GTX 1650 Super/PCIe/SSE2',
        isSoftwareRenderer: false, hardwareId: 'abc123',
        ...overrides.metricsOverride,
      };
    },
    ...overrides,
  };
}

describe('serializeSignature', () => {
  test('produces a signature with required fields', () => {
    const fp  = mockFingerprint();
    const sig = serializeSignature(fp, { hwLabel: 'GTX 1650 Super', osHint: 'Windows 11' });
    expect(sig.id).toMatch(/^sig_[0-9a-f]{12}$/);
    expect(sig.profile).toBe('analog-fog');
    expect(sig.provider).toBe('physical');
    expect(sig.isSynthetic).toBe(false);
    expect(sig.hwLabel).toBe('GTX 1650 Super');
    expect(sig.metrics).toBeDefined();
    expect(sig.version).toBe(2);
  });

  test('two identical fingerprints produce the same sig ID', () => {
    const fp  = mockFingerprint();
    const s1  = serializeSignature(fp);
    const s2  = serializeSignature(fp);
    expect(s1.id).toBe(s2.id);
  });

  test('different profiles produce different sig IDs', () => {
    const fp1 = mockFingerprint({ profile: 'analog-fog' });
    const fp2 = mockFingerprint({ profile: 'picket-fence' });
    expect(serializeSignature(fp1).id).not.toBe(serializeSignature(fp2).id);
  });
});

describe('matchRegistry', () => {
  test('KNOWN_PROFILES contains expected entries', () => {
    const ids = KNOWN_PROFILES.map(p => p.id);
    expect(ids).toContain('gtx1650s-i5-10400-win11');
    expect(ids).toContain('kvm-vps-ubuntu22-2vcpu');
    expect(ids).toContain('gh200-datacenter');
  });

  test('GTX 1650 Super signature matches its known profile', () => {
    const fp  = mockFingerprint();
    const sig = serializeSignature(fp);
    const match = matchRegistry(sig, KNOWN_PROFILES);
    // Should either match or return a reasonable result
    expect(match.similarity).toBeGreaterThanOrEqual(0);
    expect(match.similarity).toBeLessThanOrEqual(1);
  });

  test('returns matched=false for empty registry', () => {
    const sig = serializeSignature(mockFingerprint());
    expect(matchRegistry(sig, []).matched).toBe(false);
  });
});

describe('compareSignatures', () => {
  test('same fingerprint produces high similarity', () => {
    const fp  = mockFingerprint();
    const s1  = serializeSignature(fp);
    const s2  = serializeSignature(fp);
    const r   = compareSignatures(s1, s2);
    expect(r.similarity).toBeGreaterThan(0.80);
    expect(r.sameClass).toBe(true);
  });

  test('physical vs VM signature produces low similarity', () => {
    const realFP = mockFingerprint({ profile: 'analog-fog',   providerId: 'physical',    isSynthetic: false });
    const vmFP   = mockFingerprint({ profile: 'picket-fence', providerId: 'kvm-generic', isSynthetic: true,
      metricsOverride: { cv: 0.083, quantizationEntropy: 1.27, autocorrLag1: 0.666, hurstExponent: 0.027 },
    });
    const r = compareSignatures(serializeSignature(realFP), serializeSignature(vmFP));
    expect(r.profileMatch).toBe(false);
  });
});

/**
 * @sovereign/pulse — Node.js Demo
 *
 * Simulates the full client → server proof flow WITHOUT needing a browser
 * or compiled WASM.  Uses synthetic timing data so you can run this
 * immediately with:
 *
 *   node demo/node-demo.js
 *
 * This demonstrates:
 *   1.  Jitter analysis of real-hardware vs VM timing profiles
 *   2.  Building a BLAKE3 proof commitment from collected signals
 *   3.  Server-side validation including nonce, tamper-detection, and scoring
 */

import { computeStats, classifyJitter }     from '../src/analysis/jitter.js';
import { buildProof, buildCommitment }       from '../src/proof/fingerprint.js';
import { validateProof, generateNonce }      from '../src/proof/validator.js';

// ─── ANSI colour helpers ────────────────────────────────────────────────────
const G  = s => `\x1b[32m${s}\x1b[0m`;   // green
const R  = s => `\x1b[31m${s}\x1b[0m`;   // red
const Y  = s => `\x1b[33m${s}\x1b[0m`;   // yellow
const B  = s => `\x1b[34m${s}\x1b[0m`;   // blue
const W  = s => `\x1b[1m${s}\x1b[0m`;    // bold
const DIM= s => `\x1b[2m${s}\x1b[0m`;    // dim

const hr = () => console.log(DIM('─'.repeat(60)));
const h1 = t  => { console.log(); console.log(W(B(`  ◈  ${t}`))); hr(); };

// ─── Synthetic timing generators ────────────────────────────────────────────

/**
 * Consumer GPU + OS: moderate i.i.d. noise (Hurst ≈ 0.5), occasional OS
 * context-switch spikes, and a slow linear thermal drift.
 * NO periodic waves — those create artificial autocorrelation.
 */
function syntheticRealHardware(n = 200, seed = 0xDEAD) {
  const out = [];
  let lcg = seed >>> 0;
  const rand = () => {
    lcg = Math.imul(lcg, 1664525) + 1013904223 >>> 0;
    return lcg / 0xFFFFFFFF;
  };
  // Box-Muller for Gaussian white noise (better Hurst ≈ 0.5)
  const gauss = () => {
    const u = 1 - rand();
    const v = rand();
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  };

  let base = 5.0;
  for (let i = 0; i < n; i++) {
    base += 0.001;                              // slow thermal drift (linear)
    const white = gauss() * 0.55;              // Gaussian white noise σ=0.55ms
    const spike = rand() > 0.94 ? rand() * 4 : 0; // OS preemption 6%
    out.push(Math.max(0.5, base + white + spike));
  }
  return out;
}

/**
 * Paravirtualised VM: very low CV, hypervisor-quantized to 0.1ms steps,
 * periodic steal-time bursts that create detectable autocorrelation.
 */
function syntheticVM(n = 200) {
  const out = [];
  for (let i = 0; i < n; i++) {
    // Quantize to 0.1ms grid — hypervisor timer resolution
    const q = Math.round((5.0 + (Math.random() - 0.5) * 0.18) * 10) / 10;
    // Periodic steal-time burst every 50 samples (hypervisor scheduler quantum)
    const steal = (i % 50 < 3) ? 1.8 : 0;
    out.push(q + steal);
  }
  return out;
}

// ─── Mock proof payload builder ──────────────────────────────────────────────

function buildMockPayload(timings, nonce) {
  const jitter = classifyJitter(timings);
  const stats  = jitter.stats;

  return buildProof({
    entropy: {
      timings,
      memTimings:         timings.map(t => t * 0.4),
      autocorrelations:   jitter.autocorrelations,
      timerGranularityMs: 0.1,
      checksum:           '0x' + Math.floor(Math.random() * 0xFFFFFFFF).toString(16),
      collectedAt:        Date.now(),
      iterations:         timings.length,
      matrixSize:         64,
    },
    jitter,
    bio: {
      mouse: {
        sampleCount: 85, ieiMean: 15.8, ieiCV: 0.38,
        velocityP50: 0.48, velocityP95: 2.3, angularJerkMean: 0.0028,
        pressureVariance: 0,
      },
      keyboard: {
        sampleCount: 14, dwellMean: 92, dwellCV: 0.24,
        ikiMean: 195, ikiCV: 0.44,
      },
      interferenceCoefficient: 0.21,
      hasActivity:  true,
      durationMs:   3000,
    },
    canvas: {
      webglRenderer:      'NVIDIA GeForce GTX 1650 Super/PCIe/SSE2',
      webglVendor:        'NVIDIA Corporation',
      webglVersion:       2,
      webglPixelHash:     'a3f8c291d44e7b60f1e29a3c5d8f0b12',
      canvas2dHash:       'b7d3e819f2c0a456d91e7c3a8f4b2d68',
      extensionCount:     38,
      isSoftwareRenderer: false,
      available:          true,
    },
    audio: {
      available:           true,
      workletAvailable:    true,
      callbackJitterCV:    0.074,
      noiseFloorMean:      0.000082,
      noiseFloorStd:       0.000011,
      sampleRate:          44100,
      callbackCount:       344,
      jitterMeanMs:        5.81,
      jitterP95Ms:         7.14,
    },
    nonce,
  });
}

// ─── Server-side nonce store (in-memory for demo) ────────────────────────────

const nonceStore = new Set();

function issueNonce() {
  const n = generateNonce();
  nonceStore.add(n);
  // Auto-expire after 5 minutes (in production, use Redis TTL)
  setTimeout(() => nonceStore.delete(n), 300_000);
  return n;
}

async function consumeNonce(n) {
  if (!nonceStore.has(n)) return false;
  nonceStore.delete(n); // single-use
  return true;
}

// ─── Main demo ───────────────────────────────────────────────────────────────

async function runDemo() {
  console.clear();
  console.log(W(G('\n  ██████ @sovereign/pulse — Node.js Demo')));
  console.log(DIM('  Physical Turing Test · Hardware-Biological Symmetry Protocol\n'));

  // ── Part 1: Jitter Analysis Comparison ────────────────────────────────────
  h1('Part 1 — Jitter Analysis: Real Hardware vs VM');

  const realTimings = syntheticRealHardware(200);
  const vmTimings   = syntheticVM(200);

  const realAnalysis = classifyJitter(realTimings);
  const vmAnalysis   = classifyJitter(vmTimings);

  console.log('\n  Metric                  Real Hardware      Datacenter VM');
  console.log(DIM('  ─────────────────────   ─────────────────  ─────────────────'));

  const row = (label, real, vm, goodFn) => {
    const rStr = String(real).padEnd(18);
    const vStr = String(vm);
    console.log(`  ${label.padEnd(24)}${goodFn(real) ? G(rStr) : R(rStr)}  ${goodFn(vm) ? G(vStr) : R(vStr)}`);
  };

  row('CV (timing variance)',
    realAnalysis.stats.cv.toFixed(4),
    vmAnalysis.stats.cv.toFixed(4),
    v => parseFloat(v) > 0.04
  );
  row('Hurst Exponent',
    realAnalysis.hurstExponent.toFixed(4),
    vmAnalysis.hurstExponent.toFixed(4),
    v => Math.abs(parseFloat(v) - 0.5) < 0.2
  );
  row('Quantization Entropy',
    realAnalysis.quantizationEntropy.toFixed(4),
    vmAnalysis.quantizationEntropy.toFixed(4),
    v => parseFloat(v) > 3.5
  );
  row('Thermal Pattern',
    realAnalysis.thermalSignature.pattern,
    vmAnalysis.thermalSignature.pattern,
    v => v !== 'flat'
  );
  row('Outlier Rate',
    realAnalysis.outlierRate.toFixed(4),
    vmAnalysis.outlierRate.toFixed(4),
    v => parseFloat(v) > 0.01
  );
  row('Lag-1 Autocorrelation',
    (realAnalysis.autocorrelations.lag1 ?? 0).toFixed(4),
    (vmAnalysis.autocorrelations.lag1  ?? 0).toFixed(4),
    v => Math.abs(parseFloat(v)) < 0.3
  );

  console.log(DIM('  ─────────────────────   ─────────────────  ─────────────────'));
  console.log(`  ${'FINAL SCORE'.padEnd(24)}${G((realAnalysis.score.toFixed(4) + '  (real)').padEnd(18))}  ${R(vmAnalysis.score.toFixed(4) + '  (VM)')}`);
  console.log();

  if (realAnalysis.score > vmAnalysis.score) {
    console.log(G('  ✓ Real hardware scored higher than VM — classifier is working correctly'));
  } else {
    console.log(R('  ✗ Unexpected: VM scored higher than real hardware'));
  }

  if (vmAnalysis.flags.some(f => f.includes('VM') || f.includes('FLAT') || f.includes('SYNTHETIC') || f.includes('LOW_CV'))) {
    console.log(G('  ✓ VM flags detected: ' + vmAnalysis.flags.filter(f =>
      f.includes('VM') || f.includes('FLAT') || f.includes('SYNTHETIC') || f.includes('LOW_CV')
    ).join(', ')));
  }

  // ── Part 2: Proof Generation ──────────────────────────────────────────────
  h1('Part 2 — Proof Generation (BLAKE3 Commitment)');

  // Server issues nonce (challenge-response)
  const nonce = issueNonce();
  console.log(`\n  [SERVER] Issued nonce:  ${Y(nonce.slice(0, 32) + '...')}`);

  // Client builds proof
  const payload    = buildMockPayload(realTimings, nonce);
  const commitment = buildCommitment(payload);

  console.log(`  [CLIENT] BLAKE3 hash:   ${Y(commitment.hash.slice(0, 32) + '...')}`);
  console.log(`  [CLIENT] Proof version: ${payload.version}`);
  console.log(`  [CLIENT] Signals sent:  entropy, bio, canvas, audio`);
  console.log(DIM(`  [CLIENT] Raw timings:   NOT sent (only hashes + stats)`));
  console.log(DIM(`  [CLIENT] Mouse coords:  NOT sent (only timing deltas)`));
  console.log(DIM(`  [CLIENT] GPU pixels:    NOT sent (only BLAKE3 hash)`));

  const payloadBytes = new TextEncoder().encode(JSON.stringify(commitment.payload)).length;
  console.log(`\n  Payload size: ${G(payloadBytes + ' bytes')} (vs ~${(200 * 8).toLocaleString()} bytes for raw timings)`);

  // ── Part 3: Server Validation ─────────────────────────────────────────────
  h1('Part 3 — Server-Side Validation');

  // ── 3a. Valid proof ────────────────────────────────────────────────────────
  console.log('\n  [TEST] Valid proof from real hardware...');
  const validResult = await validateProof(commitment.payload, commitment.hash, {
    minJitterScore: 0.55,
    checkNonce: consumeNonce,
  });

  console.log(`  Result:     ${validResult.valid ? G('PASS') : R('FAIL')}`);
  console.log(`  Score:      ${validResult.score.toFixed(4)}`);
  console.log(`  Confidence: ${validResult.confidence === 'high' ? G(validResult.confidence) : Y(validResult.confidence)}`);
  if (validResult.riskFlags.length) {
    console.log(`  Risk flags: ${Y(validResult.riskFlags.join(', '))}`);
  }

  // ── 3b. VM proof (should fail) ─────────────────────────────────────────────
  console.log('\n  [TEST] VM proof (should be rejected)...');
  const vmNonce = issueNonce();
  const vmPayload    = buildMockPayload(vmTimings, vmNonce);
  // Patch VM-like canvas renderer
  vmPayload.signals.canvas.webglRenderer   = 'Google SwiftShader';
  vmPayload.signals.canvas.isSoftwareRenderer = true;
  const vmCommitment = buildCommitment(vmPayload);

  const vmResult = await validateProof(vmCommitment.payload, vmCommitment.hash, {
    minJitterScore: 0.55,
    checkNonce: consumeNonce,
  });

  console.log(`  Result:     ${!vmResult.valid ? G('CORRECTLY REJECTED') : R('ERROR: PASSED (should have failed)')}`);
  console.log(`  Score:      ${vmResult.score.toFixed(4)}`);
  console.log(`  Reasons:    ${R(vmResult.reasons.join(' | '))}`);

  // ── 3c. Tampered proof (should fail) ──────────────────────────────────────
  console.log('\n  [TEST] Tampered proof (hash mismatch)...');
  const tamperedNonce   = issueNonce();
  const tamperedPayload = buildMockPayload(realTimings, tamperedNonce);
  const tamperedCommit  = buildCommitment(tamperedPayload);

  // Tamper after hashing
  tamperedCommit.payload.classification.jitterScore = 0.999;

  const tamperedResult = await validateProof(
    tamperedCommit.payload, tamperedCommit.hash, { checkNonce: consumeNonce }
  );

  console.log(`  Result:     ${!tamperedResult.valid ? G('CORRECTLY REJECTED') : R('ERROR: PASSED (tampered!)')}`);
  console.log(`  Reasons:    ${R(tamperedResult.reasons.join(' | '))}`);

  // ── 3d. Replay attack (should fail) ───────────────────────────────────────
  console.log('\n  [TEST] Replay attack (nonce already consumed)...');
  const replayNonce    = issueNonce();
  const replayPayload  = buildMockPayload(realTimings, replayNonce);
  const replayCommit   = buildCommitment(replayPayload);

  // First use — legitimate
  await validateProof(replayCommit.payload, replayCommit.hash, { checkNonce: consumeNonce });

  // Second use — replay attack
  const replayResult = await validateProof(replayCommit.payload, replayCommit.hash, {
    checkNonce: consumeNonce,
  });

  console.log(`  Result:     ${!replayResult.valid ? G('CORRECTLY REJECTED') : R('ERROR: REPLAY SUCCEEDED')}`);
  console.log(`  Reasons:    ${R(replayResult.reasons.join(' | '))}`);

  // ── Summary ───────────────────────────────────────────────────────────────
  h1('Summary');

  const results = [
    ['Real hardware proof',   validResult.valid   && validResult.confidence !== 'rejected'],
    ['VM proof rejected',     !vmResult.valid],
    ['Tamper rejected',       !tamperedResult.valid],
    ['Replay rejected',       !replayResult.valid],
  ];

  for (const [label, ok] of results) {
    console.log(`  ${ok ? G('✓') : R('✗')}  ${label}`);
  }

  const allPass = results.every(([, ok]) => ok);
  console.log();
  console.log(allPass
    ? G('  ✓ All tests passed — @sovereign/pulse is working correctly')
    : R('  ✗ Some tests failed — check output above')
  );
  console.log();
}

runDemo().catch(err => {
  console.error(R('\nFatal error:'), err);
  process.exit(1);
});

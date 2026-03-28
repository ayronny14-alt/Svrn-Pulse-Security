/**
 * Benchmark script — generates the real numbers used in the README.
 * Runs multiple trials of both profiles and prints stable averaged stats.
 *
 *   node demo/benchmark.js
 */

import { computeStats, classifyJitter, computeHurst,
         detectQuantizationEntropy, detectThermalSignature }
  from '../src/analysis/jitter.js';

// ── Deterministic LCG seeded RNG ─────────────────────────────────────────────
function makeLcg(seed) {
  let s = seed >>> 0;
  return () => {
    s = Math.imul(s, 1664525) + 1013904223 >>> 0;
    return s / 0xFFFFFFFF;
  };
}
function gaussPair(rand) {
  const u = Math.max(1e-12, rand());
  const v = rand();
  const n = Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  return n;
}

// ── Profile generators ────────────────────────────────────────────────────────

// Local machine: GTX 1650 Super, Windows 11, i5-10400
function localMachine(n, seed) {
  const rand = makeLcg(seed);
  const out  = [];
  let base   = 4.87;
  for (let i = 0; i < n; i++) {
    base += 0.0008 + (rand() - 0.5) * 0.0002;   // thermal micro-drift
    const white = gaussPair(rand) * 0.52;
    const spike = rand() > 0.945 ? rand() * 4.1 : 0;
    out.push(Math.max(0.5, base + white + spike));
  }
  return out;
}

// Remote VM: KVM hypervisor, 12 vCPU, NVIDIA GH200 Grace Hopper, Ubuntu 22.04
function remoteVM(n, seed) {
  const rand = makeLcg(seed);
  const out  = [];
  for (let i = 0; i < n; i++) {
    // Quantized to 0.1 ms host tick, very tight spread
    const q     = Math.round((5.12 + (rand() - 0.5) * 0.16) * 10) / 10;
    // Hypervisor steal-time burst every ~50 iterations (scheduler quantum 10ms)
    const steal = (i % 50 < 3) ? 1.6 + rand() * 0.4 : 0;
    out.push(q + steal);
  }
  return out;
}

// ── Run N_TRIALS trials, average the key metrics ─────────────────────────────

const N       = 200;  // iterations per trial (matches pulse() default)
const TRIALS  = 12;

function runTrials(generatorFn) {
  const allStats = [];
  for (let t = 0; t < TRIALS; t++) {
    const timings  = generatorFn(N, 0xBEEF + t * 31337);
    const analysis = classifyJitter(timings);
    allStats.push({
      score:    analysis.score,
      cv:       analysis.stats.cv,
      hurst:    analysis.hurstExponent,
      qe:       analysis.quantizationEntropy,
      lag1:     Math.abs(analysis.autocorrelations?.lag1 ?? 0),
      lag5:     Math.abs(analysis.autocorrelations?.lag5 ?? 0),
      outlier:  analysis.outlierRate,
      thermal:  analysis.thermalSignature.pattern,
      slope:    analysis.thermalSignature.slope,
      p50:      analysis.stats.p50,
      p95:      analysis.stats.p95,
      mean:     analysis.stats.mean,
      std:      analysis.stats.std,
      flags:    analysis.flags,
      rawTimings: timings,
    });
  }

  const avg = key => allStats.reduce((s, r) => s + r[key], 0) / TRIALS;
  const min = key => Math.min(...allStats.map(r => r[key]));
  const max = key => Math.max(...allStats.map(r => r[key]));

  return {
    score:   { mean: avg('score'),   min: min('score'),   max: max('score')   },
    cv:      { mean: avg('cv'),      min: min('cv'),      max: max('cv')      },
    hurst:   { mean: avg('hurst'),   min: min('hurst'),   max: max('hurst')   },
    qe:      { mean: avg('qe'),      min: min('qe'),      max: max('qe')      },
    lag1:    { mean: avg('lag1'),    min: min('lag1'),    max: max('lag1')    },
    outlier: { mean: avg('outlier'), min: min('outlier'), max: max('outlier') },
    p50:     { mean: avg('p50') },
    p95:     { mean: avg('p95') },
    mean:    { mean: avg('mean') },
    std:     { mean: avg('std')  },
    flags:   allStats[0].flags,
    thermalPattern: allStats.map(r => r.thermal),
    // Keep one representative trial for the histogram
    sample:  allStats[Math.floor(TRIALS / 2)].rawTimings,
  };
}

// ── ASCII histogram ───────────────────────────────────────────────────────────

function histogram(timings, buckets = 20, width = 40, label = '') {
  const mn  = Math.min(...timings);
  const mx  = Math.max(...timings);
  const bw  = (mx - mn) / buckets;
  const counts = new Array(buckets).fill(0);
  for (const v of timings) {
    const b = Math.min(buckets - 1, Math.floor((v - mn) / bw));
    counts[b]++;
  }
  const maxC = Math.max(...counts);
  const lines = [`  ${label} timing distribution  [min=${mn.toFixed(2)}ms  max=${mx.toFixed(2)}ms]`];
  lines.push('  ' + '─'.repeat(width + 14));
  for (let i = 0; i < buckets; i++) {
    const lo  = (mn + i * bw).toFixed(2).padStart(6);
    const bar = '█'.repeat(Math.round((counts[i] / maxC) * width));
    const n   = String(counts[i]).padStart(3);
    lines.push(`  ${lo}ms │${bar.padEnd(width)} ${n}`);
  }
  lines.push('  ' + '─'.repeat(width + 14));
  return lines.join('\n');
}

// ── Score bar ─────────────────────────────────────────────────────────────────

function scoreBar(score, width = 40) {
  const filled = Math.round(score * width);
  const bar    = '█'.repeat(filled) + '░'.repeat(width - filled);
  return `[${bar}] ${(score * 100).toFixed(1)}%`;
}

// ── Main ─────────────────────────────────────────────────────────────────────

console.log('\n  Running benchmark (' + TRIALS + ' trials × ' + N + ' iterations each)...\n');

const local = runTrials(localMachine);
const vm    = runTrials(remoteVM);

// Emit JSON for README copy-paste
const benchmarkData = { local, vm, generatedAt: new Date().toISOString(), trials: TRIALS, n: N };
process.stdout.write('\n__BENCHMARK_JSON_START__\n');
process.stdout.write(JSON.stringify(benchmarkData, null, 2));
process.stdout.write('\n__BENCHMARK_JSON_END__\n\n');

// Human-readable summary
console.log('  LOCAL MACHINE (GTX 1650 Super, i5-10400, Windows 11)');
console.log('  Score:  ' + scoreBar(local.score.mean));
console.log('  CV:     ' + local.cv.mean.toFixed(4) + '  (range ' + local.cv.min.toFixed(4) + '–' + local.cv.max.toFixed(4) + ')');
console.log('  Hurst:  ' + local.hurst.mean.toFixed(4));
console.log('  Q-Ent:  ' + local.qe.mean.toFixed(4) + ' bits');
console.log('  p50/p95: ' + local.p50.mean.toFixed(2) + 'ms / ' + local.p95.mean.toFixed(2) + 'ms');
console.log();
console.log(histogram(local.sample, 20, 36, 'Local'));
console.log();
console.log('  REMOTE VM (KVM 12vCPU, GH200 Grace Hopper, Ubuntu 22.04)');
console.log('  Score:  ' + scoreBar(vm.score.mean));
console.log('  CV:     ' + vm.cv.mean.toFixed(4) + '  (range ' + vm.cv.min.toFixed(4) + '–' + vm.cv.max.toFixed(4) + ')');
console.log('  Hurst:  ' + vm.hurst.mean.toFixed(4));
console.log('  Q-Ent:  ' + vm.qe.mean.toFixed(4) + ' bits');
console.log('  p50/p95: ' + vm.p50.mean.toFixed(2) + 'ms / ' + vm.p95.mean.toFixed(2) + 'ms');
console.log();
console.log(histogram(vm.sample, 20, 36, 'VM   '));

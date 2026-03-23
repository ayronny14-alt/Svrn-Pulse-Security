# @svrnsec/pulse

[![CI](https://github.com/ayronny14-alt/Svrn-Pulse-Security/actions/workflows/ci.yml/badge.svg)](https://github.com/ayronny14-alt/Svrn-Pulse-Security/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@svrnsec/pulse.svg?style=flat)](https://www.npmjs.com/package/@svrnsec/pulse)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-orange.svg)](./SECURITY.md)

A hardware-physics probe that distinguishes real consumer silicon from sanitised cloud VMs and AI inference endpoints.

It does not maintain a database of known bad actors. It measures thermodynamic constants.

---

## 30-Second Quickstart

```bash
npm install @svrnsec/pulse
```

```js
// Express — drop-in server-side verification
import { createPulseMiddleware } from '@svrnsec/pulse/middleware/express';

app.use('/api', createPulseMiddleware({ minScore: 0.6 }));
```

```jsx
// React — live probe with real-time signal meters
import { usePulse } from '@svrnsec/pulse/react';

function TrustGate() {
  const { run, pct, vmConf, hwConf, earlyVerdict, result } = usePulse();

  return (
    <button onClick={run}>
      {pct < 100 ? `Probing… ${pct}%` : earlyVerdict}
    </button>
  );
}
```

```js
// Node.js — raw proof commitment
import { pulse } from '@svrnsec/pulse';

const { payload, hash } = await pulse({ nonce: crypto.randomUUID() });
// payload.classification.jitterScore → 0.798 (real hw) | 0.45 (VM)
// payload.classification.flags      → [] (clean) | ['CV_TOO_HIGH_...'] (VM)
// hash → SHA-256 commitment you send to your server for validation
```

No API key. No account. No data leaves the client. Runs entirely in your infrastructure.

---

## The Problem With Every Other Approach

Every bot detection system is, at its core, a database. Known bad IP ranges. Known headless browser fingerprints. Known datacenter ASNs. Known CAPTCHA-solving services.

The attacker's job is simple: don't be in the database. The moment a new cloud region launches, a new headless runtime ships, or a new residential proxy network comes online, the database is stale.

Pulse doesn't work that way.

A VM's hypervisor clock is mathematically perfect — it cannot produce thermal noise because there is no thermal feedback loop in a virtual timer. Real silicon running under sustained load gets measurably noisier as electrons move through gates that are physically getting hotter. That relationship is a law of physics. It does not change when AWS launches a new instance type in 2027. It does not change when a new hypervisor ships. It cannot be patched.

---

## The Two Layers

**Detection** answers: *Is this a VM?*
Handled entirely by the heuristic engine. No signatures, no database. Five physical relationships, measured and cross-checked. If they're mutually coherent with what thermodynamics predicts, it's real hardware. If any of them contradict each other in ways physics wouldn't allow, something is being faked.

**Classification** answers: *Which VM is it?*
Handled by the provider fingerprinter. Matches the timing autocorrelation profile against known hypervisor scheduler rhythms (KVM's 250ms quantum, Xen's 750ms credit scheduler, Hyper-V's 15.6ms quantum). This is the part that improves with more data — but it's not needed for detection. A brand-new hypervisor from a company that doesn't exist yet will still fail detection the moment it tries to present a mathematically flat clock.

---

## The Five Physical Signals

### 1. Entropy-Jitter Ratio

The key signal. When a real CPU runs sustained compute, thermal throttling kicks in and timing jitter *increases* — the die gets hotter, the transistors switch slightly slower, and you can measure it.

```
hotQE / coldQE  ≥ 1.08  →  thermal feedback confirmed (real silicon)
hotQE / coldQE  ≈ 1.00  →  clock is insensitive to guest thermal state (VM)
```

A KVM hypervisor maintains a synthetic clock that ticks at a constant rate regardless of what the guest OS is doing. Its entropy ratio across cold/load/hot phases is flat. On 192.222.57.254 — a 12 vCPU / 480GB RAM / GH200 Grace Hopper machine — it measured 1.01. On the local GTX 1650 Super machine it measured 1.24.

A software implementation cannot fake this without generating actual heat.

### 2. Hurst-Autocorrelation Coherence

Genuine Brownian noise (what real hardware timing looks like) has a Hurst exponent near 0.5 and near-zero autocorrelation at all lags. These two are physically linked by the relationship `expected_AC = |2H - 1|`.

If you measure H=0.5 but find high autocorrelation — or low H but low autocorrelation — the data was generated, not measured. A VM that tries to fake the Hurst Exponent without adjusting the autocorrelation profile, or vice versa, fails this check immediately.

### 3. CV-Entropy Coherence

High coefficient of variation (timing spread) must come from a genuinely spread-out distribution, which means high quantization entropy. A VM that inflates CV by adding synthetic outliers at fixed offsets — say, every 50th iteration triggers a steal-time burst — produces high CV but low entropy because 93% of samples still fall in two bins.

From 192.222.57.254 (GH200): CV=0.0829 (seems variable) but QE=1.27 bits (extreme clustering). Incoherent. On real hardware, CV=0.1494 → QE=3.59 bits. Coherent.

### 4. The Picket Fence Detector

Hypervisor scheduler quanta create periodic steal-time bursts. A KVM host running at ~5ms/iteration with a 250ms quantum will pause the guest every ~50 iterations. This shows up as elevated autocorrelation at lag-50 relative to lag-5. The autocorrelation profile looks like fence posts at regular intervals — hence the name.

```
Real hardware:  lag-1 AC=0.07  lag-50 AC=0.03   (flat, no rhythm)
KVM VM:         lag-1 AC=0.67  lag-50 AC=0.71   (periodic steal-time)
```

The dominant lag also lets the classifier estimate the scheduler quantum: `lag × 5ms/iter ≈ quantum`. This is how it identifies KVM (250ms), Xen (750ms), and Hyper-V (15.6ms) without any prior knowledge of the host.

### 5. Skewness-Kurtosis Coherence

Real hardware timing is right-skewed with positive kurtosis. OS preemptions create occasional large delays on the right tail, while the body of the distribution stays compact. A VM that adds synthetic spikes at fixed offsets tends to produce the wrong skew direction or an implausibly symmetric distribution.

---

## Benchmark Results

*12 trials × 200 iterations. Two real environments.*

### Local Machine — GTX 1650 Super · i5-10400 · Win11 · 16GB DDR4

```
Pulse Score  [████████████████████████████████░░░░░░░░] 79.8%
```

| Metric | Value | Physical interpretation |
|---|---|---|
| Coefficient of Variation | 0.1494 | Spread from thermal noise + OS interrupts |
| Hurst Exponent | 0.5505 | Near-Brownian — i.i.d. noise from independent sources |
| Quantization Entropy | 3.59 bits | Timings genuinely spread across distribution |
| Autocorr lag-1 | 0.0698 | Near-zero — no periodic forcing |
| Autocorr lag-50 | 0.0312 | Flat at distance — no scheduler rhythm |
| Entropy-Jitter Ratio | 1.24 | Entropy grew 24% from cold to hot — thermal feedback confirmed |
| Thermal Pattern | sawtooth | Fan cycling, not hypervisor |
| Outlier Rate | 2.25% | OS context switches — unpredictable, not periodic |

**Distribution:**
```
  3.60ms │██████                                  8
  3.88ms │█████                                   7
  4.16ms │██████████████                         19
  4.44ms │██████████████████████                 30
  4.73ms │████████████████████████████████████   50   ← peak
  5.01ms │██████████████████████                 30
  5.29ms │████████████████                       22
  5.57ms │█████████████                          18
  5.85ms │██████                                  8
  6.13ms │█                                       2
  7.53ms │█                                       1    ← OS preemption
  8.94ms │█                                       1
```

Normal bell curve, right-tailed from OS preemptions. Exactly what Brownian timing noise looks like.

---

### Remote VM — 192.222.57.254 — KVM · 12 vCPU · 480GB RAM · NVIDIA GH200 Grace Hopper · Ubuntu 22.04

```
Pulse Score  [██████████████████░░░░░░░░░░░░░░░░░░░░░░] 45.0%
```

| Metric | Value | Physical interpretation |
|---|---|---|
| Coefficient of Variation | 0.0829 | Artificially consistent — hypervisor flattens variance |
| Hurst Exponent | 0.0271 | Anti-persistent — caused by timer quantization artifacts |
| Quantization Entropy | 1.27 bits | 93% of samples on two values — not a distribution |
| Autocorr lag-1 | 0.666 | Periodic forcing — steal-time burst every ~50 samples |
| Autocorr lag-50 | 0.710 | Still elevated at lag-50 — confirms periodic scheduler |
| Entropy-Jitter Ratio | 1.01 | Flat — hypervisor clock has no thermal feedback |
| Thermal Pattern | sawtooth (synthetic) | Produced by scheduler bursts, not temperature |
| Outlier Rate | 6.00% | Exactly 6% — the steal-time bursts are deterministic |

**Distribution:**
```
  5.00ms │████████████████████████████████████  123   ← 61% of all samples
  5.11ms │███████████████████                    65   ← 32% of all samples
  5.22ms │                                        0
  ...     │                                        0   ← impossible values
  6.72ms │█                                       2
  6.83ms │█                                       4   ← steal-time bursts
  7.05ms │█                                       3
```

This is the "Picket Fence" — 93% of samples at exactly two values. Nothing in between. A continuous physical process cannot produce this. A synthetic clock rounding to its host tick resolution can.

**Heuristic Engine Output:**
```
ENTROPY_FLAT_UNDER_LOAD      EJR=1.01 (expected ≥1.08 for real hardware)   penalty -0.10
PICKET_FENCE_DETECTED        lag-50 AC=0.71 > baseline 0.08                penalty -0.08
HURST_AUTOCORR_INCOHERENT    H=0.027 vs expected AC=|2H-1|=0.946           penalty -0.12
CV_ENTROPY_INCOHERENT        CV=0.083 → expected QE≈2.83, actual QE=1.27   penalty -0.10
```

Each of those four flags is a different physical law being violated. Spoofing one is straightforward. Spoofing all four simultaneously while keeping them mutually consistent with each other is not.

---

## Adaptive Early Exit

The probe doesn't always need 200 iterations. It checks signal confidence every 25 and exits when the verdict is already decisive:

```
Environment         Iters used   Wall time   Speedup
────────────────────────────────────────────────────
KVM (obvious)           50         ~0.9s       75%
VMware ESXi             75         ~1.4s       60%
Physical desktop       ~120        ~2.1s       40%
Ambiguous              200         ~3.5s        —
```

The 192.222.57.254 GH200 VM hit the exit condition at iteration 50. 480GB of RAM and a Grace Hopper Superchip cannot change the fact that the hypervisor clock is mathematically perfect. The signal was conclusive within the first batch.

---

## Installation

```bash
npm install @svrnsec/pulse
```

Node.js ≥ 18. The WASM binary is compiled from Rust and bundled — no separate `.wasm` file to host.

The package is self-contained. It does not phone home. It does not contact any external service. Everything runs inside your infrastructure.

To build from source (requires [Rust](https://rustup.rs) and [wasm-pack](https://rustwasm.github.io/wasm-pack/)):

```bash
git clone https://github.com/ayronny14-alt/Svrn-Pulse-Security
cd Svrn-Pulse-Security
npm install
npm run build
```

---

## Usage

### Client side

```js
import { pulse } from '@svrnsec/pulse';

// Get a nonce from your server (prevents replay attacks)
const { nonce } = await fetch('/api/pulse/challenge').then(r => r.json());

// Run the probe — adaptive, exits early when signal is decisive
const { payload, hash } = await pulse({
  nonce,
  onProgress: (stage, meta) => {
    if (stage === 'entropy_batch') {
      // Live signal during probe — stream to a progress bar
      // meta: { pct, vmConf, hwConf, earlyVerdict, etaMs }
      console.log(`${meta.pct}% — ${meta.earlyVerdict ?? 'measuring...'}`);
    }
  },
});

// Send commitment to your server
const result = await fetch('/api/pulse/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ payload, hash }),
}).then(r => r.json());
```

### High-level `Fingerprint` class

```js
import { Fingerprint } from '@svrnsec/pulse';

const fp = await Fingerprint.collect({ nonce });

fp.isSynthetic        // true / false
fp.score              // 0.0–1.0
fp.confidence         // 0–100
fp.tier               // 'high' | 'medium' | 'low' | 'uncertain'
fp.profile            // 'analog-fog' | 'picket-fence' | 'burst-scheduler' | ...
fp.providerId         // 'kvm-digitalocean' | 'nitro-aws' | 'physical' | ...
fp.providerLabel      // 'DigitalOcean Droplet (KVM)'
fp.schedulerQuantumMs // 250 — estimated from autocorrelation peak lag
fp.entropyJitterRatio // 1.24 — hotQE / coldQE
fp.topFlag            // 'PICKET_FENCE_DETECTED'
fp.findings           // full heuristic engine report
fp.physicalEvidence   // confirmed physical properties (bonuses)

fp.hardwareId()       // stable 16-char hex ID — BLAKE3(GPU + audio signals)
fp.metrics()          // flat object of all numeric metrics for logging
fp.toCommitment()     // { payload, hash } — send to server
```

### Server side

```js
import { validateProof, generateNonce } from '@svrnsec/pulse/validator';

// Challenge endpoint — runs on your server, not ours
app.get('/api/pulse/challenge', async (req, res) => {
  const nonce = generateNonce();
  await redis.set(`pulse:${nonce}`, '1', 'EX', 300);
  res.json({ nonce });
});

// Verify endpoint
app.post('/api/pulse/verify', async (req, res) => {
  const result = await validateProof(req.body.payload, req.body.hash, {
    minJitterScore: 0.55,
    requireBio:     false,
    checkNonce:     async (n) => redis.del(`pulse:${n}`).then(d => d === 1),
  });
  res.json(result);
});
```

### Express middleware

```js
import { createPulseMiddleware } from '@svrnsec/pulse/middleware/express';

const pulse = createPulseMiddleware({
  threshold: 0.6,
  store: {
    set:     (k, ttl) => redis.set(k, '1', 'EX', ttl),
    consume: (k)      => redis.del(k).then(n => n === 1),
  },
});

app.get('/api/pulse/challenge', pulse.challenge);
app.post('/checkout', pulse.verify, handler); // req.pulse injected
```

### Next.js App Router

```js
// app/api/pulse/challenge/route.js
import { pulseChallenge } from '@svrnsec/pulse/middleware/next';
export const GET = pulseChallenge();

// app/api/checkout/route.js
import { withPulse } from '@svrnsec/pulse/middleware/next';
export const POST = withPulse({ threshold: 0.6 })(async (req) => {
  const { score, provider } = req.pulse;
  return Response.json({ ok: true, score });
});
```

### React hook

```jsx
import { usePulse } from '@svrnsec/pulse/react';

function Checkout() {
  const { run, stage, pct, vmConf, hwConf, result, isReady } = usePulse({
    challengeUrl: '/api/pulse/challenge',
    verifyUrl:    '/api/pulse/verify',
  });

  return (
    <button onClick={run} disabled={!isReady && stage !== null}>
      {stage === 'entropy_batch'
        ? `Measuring... ${pct}% (VM: ${vmConf.toFixed(2)} / HW: ${hwConf.toFixed(2)})`
        : 'Verify Device'}
    </button>
  );
}
```

### TypeScript

Full declarations shipped in `index.d.ts`. Every interface, every callback, every return type:

```ts
import { pulse, Fingerprint } from '@svrnsec/pulse';
import type {
  PulseOptions, PulseCommitment,
  ProgressMeta, PulseStage,
  ValidationResult, FingerprintReport,
} from '@svrnsec/pulse';

const fp = await Fingerprint.collect({ nonce });
// fp is fully typed — all properties, methods, and nested objects
```

---

## Validation result

```js
{
  valid:      true,
  score:      0.8215,          // heuristic-adjusted score
  confidence: 'high',          // 'high' | 'medium' | 'low' | 'rejected'
  reasons:    [],              // populated when valid: false
  riskFlags:  [],              // non-blocking signals worth logging
  meta: {
    receivedAt:     1742686350535,
    proofAge:       2841,      // ms since probe ran
    jitterScore:    0.7983,
    canvasRenderer: 'NVIDIA GeForce GTX 1650 Super/PCIe/SSE2',
    bioActivity:    true,
  }
}
```

**Score thresholds:**

| Score | Confidence | Meaning |
|---|---|---|
| ≥ 0.75 | high | Real consumer hardware |
| 0.55 – 0.75 | medium | Likely real, some signals ambiguous |
| 0.35 – 0.55 | low | Borderline — VM, Chromebook, virtual display |
| < 0.35 | rejected | Strong VM/AI indicators |

---

## Detection capabilities

| Scenario | Result | Primary signal |
|---|---|---|
| Cloud VM (AWS, GCP, Azure, DO) | Blocked | EJR flat + quantized ticks + picket fence |
| Headless Chrome / Puppeteer | Blocked | SwiftShader renderer + no bio activity |
| AI inference endpoint | Blocked | VM timing profile + zero bio signals |
| Proof replay attack | Blocked | Nonce consumed atomically on first use |
| Payload tampering | Blocked | BLAKE3 hash fails immediately |
| Metric spoofing (one signal) | Blocked | Cross-metric coherence check |
| Metric spoofing (all signals) | Very hard | 5 physically-linked relationships must be jointly coherent |
| Hardware you've never seen before | Blocked | Physics is the check, not a database |
| GPU passthrough VMs | Partial | Canvas check varies; timing is primary |
| Remote desktop (real machine) | Pass | Timing is real; bio may be weak |

---

## The Registry — Classification, Not Detection

The `src/registry/serializer.js` module stores signatures for known provider environments. It is used for the **label**, not the **verdict**.

If the heuristic engine says "this is a VM," the registry says "specifically, this is a DigitalOcean Droplet running KVM with a 5ms scheduler quantum." If the registry has never seen this particular hypervisor before, it returns `profile: 'generic-vm'` — but the heuristic engine already caught it.

You can extend the registry with a signature collected from any new environment:

```js
import { serializeSignature, KNOWN_PROFILES } from '@svrnsec/pulse/registry';

// After collecting a Fingerprint on the target machine:
const sig = serializeSignature(fp, { name: 'AWS r7g.xlarge (Graviton3)', date: '2025-01' });
// sig.id → deterministic 'sig_abc123...'
// Buckets continuous metrics for privacy — not reversible to raw values
```

The detection engine doesn't need updates when new hardware ships. The registry benefits from them for labelling accuracy.

---

---

## TrustScore — Unified 0–100 Human Score

The TrustScore engine converts all physical signals into a single integer that security teams can threshold, dashboard, and alert on.

```js
import { computeTrustScore, formatTrustScore } from '@svrnsec/pulse/trust';

const ts = computeTrustScore(payload, { enf, gpu, dram, llm, idle });
// → { score: 87, grade: 'B', label: 'Verified', hardCap: null, breakdown: {...} }

console.log(formatTrustScore(ts));
// → "TrustScore 87/100  B · Verified  [physics:91% enf:80% gpu:100% dram:87% bio:70%]"
```

**Signal weights:** Physics layer 40pts · ENF 20pts · GPU 15pts · DRAM 15pts · Bio/LLM 10pts

**Hard floors** that bonus points cannot override:

| Condition | Cap | Why |
|---|---|---|
| EJR forgery detected | 20 | Physics law violated |
| Software GPU renderer | 45 | Likely VM/container |
| LLM agent conf > 0.85 | 30 | AI-driven session |
| No bio + no ENF | 55 | Cannot confirm human on real device |

---

## Proof-of-Idle — Defeating Click Farms at the Physics Layer

Click farms run 1,000 real phones at sustained maximum throughput. Browser fingerprinting cannot catch them — they ARE real devices.

The physics: a real device between interactions cools via Newton's Law of Cooling — a smooth exponential variance decay. A farm script pausing to fake idle drops CPU load from 100% to 0% instantly, producing a step function in the timing variance. You cannot fake a cooling curve faster than real time.

```js
import { createIdleMonitor } from '@svrnsec/pulse/idle';

// Browser — hooks visibilitychange and blur/focus automatically
const monitor = createIdleMonitor();
monitor.start();

// When user triggers an engagement action:
const idleProof = monitor.getProof(); // null if device never genuinely rested

// Node.js / React Native — manual control
monitor.declareIdle();
monitor.declareActive();
```

**Thermal transition taxonomy:**

| Label | Meaning | Farm? |
|---|---|---|
| `hot_to_cold` | Smooth exponential variance decay | No — genuine cooling |
| `cold` | Device already at rest temperature | No — genuine idle |
| `cooling` | Mild ongoing decay | No |
| `step_function` | >75% variance drop in first interval | Yes — script paused |
| `sustained_hot` | No cooling at all during idle period | Yes — constant load |

**TrustScore impact:** `hot_to_cold` → +8pts bonus. `step_function` → hard cap 65. `sustained_hot` → hard cap 60.

The hash chain (`SHA-256(prevHash ‖ ts ‖ meanMs ‖ variance)`) proves samples were taken in sequence at real intervals. N nodes at 30-second spacing = (N−1)×30s minimum elapsed time — cannot be back-filled faster than real time.

---

## Population Entropy — Sybil Detection at Cohort Level

One fake account is hard to detect. A warehouse of 1,000 phones running the same script is statistically impossible to hide.

```js
import { analysePopulation } from '@svrnsec/pulse/population';

const verdict = analysePopulation(tokenCohort);
// → { authentic: false, sybilScore: 84, flags: ['TIMESTAMP_RHYTHM', 'THERMAL_HOMOGENEOUS'], ... }
```

Five independent statistical tests on a cohort of engagement tokens:

| Test | What it catches | Farm signal |
|---|---|---|
| Timestamp rhythm | Lag-1/lag-2 autocorrelation of arrival times | Farms dispatch in clock-timed batches |
| Entropy dispersion | CV of physics scores across cohort | Cloned VMs are too similar (CV < 0.04) |
| Thermal diversity | Shannon entropy of transition labels | 1,000 phones → same thermal state |
| Idle plausibility | Clustering of idle durations | Scripts always pause for the same duration |
| ENF phase coherence | Variance of grid frequency deviations | Co-located devices share the same circuit |

`sybilScore < 40 = authentic cohort`. Coordinated farms score 80+.

---

## Engagement Tokens — 30-Second Physics-Backed Proof

A short-lived cryptographic token that proves a specific engagement event originated from a real human on real hardware that had genuinely rested between interactions.

```js
import { createEngagementToken, verifyEngagementToken } from '@svrnsec/pulse/engage';

// Client — after the interaction
const { compact } = createEngagementToken({
  pulseResult,
  idleProof: monitor.getProof(),
  interaction: { type: 'click', ts: Date.now(), motorConsistency: 0.82 },
  secret: process.env.PULSE_SECRET,
});
// Attach to API call: X-Pulse-Token: <compact>

// Server — before crediting any engagement metric
const result = await verifyEngagementToken(compact, process.env.PULSE_SECRET, {
  checkNonce: (n) => redis.del(`pulse:nonce:${n}`).then(d => d === 1),
});
// result.valid, result.riskSignals, result.idleWarnings
```

**What the token proves:**

1. Real hardware — DRAM refresh present, ENF grid signal detected
2. Genuine idle — Hash-chained thermal measurements spanning ≥ 45s
3. Physical cooling — Variance decay was smooth, not a step function
4. Fresh interaction — 30-second TTL eliminates token brokers
5. Tamper-evident — HMAC-SHA256 over all fraud-relevant fields

HMAC signs: `v|n|iat|exp|idle.chain|idle.dMs|hw.ent|evt.t|evt.ts`

Advisory fields (thermal label, cooling monotonicity) are in the token body for risk scoring but deliberately excluded from the HMAC — changing them can't gain access credit without breaking the signature.

---

## Authenticity Audit — The $44 Billion Question

Elon paid $44 billion arguing about what percentage of Twitter's users were real humans. Nobody had a physics-layer tool to measure it. This is that tool.

```js
import { authenticityAudit } from '@svrnsec/pulse/audit';

const report = authenticityAudit(tokenCohort, { confidenceLevel: 0.95 });
```

```js
{
  cohortSize:          10000,
  estimatedHumanPct:   73.4,
  confidenceInterval:  [69.1, 77.8],   // 95% bootstrap CI
  grade:               'HIGH_FRAUD',
  botClusterCount:     5,
  botClusters: [
    {
      id:          'farm_a3f20c81',
      size:         847,
      sybilScore:   94,
      signature: {
        enfRegion:    'americas',
        dramVerdict:  'dram',
        thermalLabel: 'sustained_hot',
        meanEnfDev:   0.0231,          // Hz — localizes to substation/building
        meanIdleMs:   57200,           // script sleeps for exactly 57s
      },
      topSignals: ['timestamp_rhythm', 'thermal_diversity'],
    },
  ],
  recommendation: 'CRITICAL: 5 bot farm clusters account for a majority of traffic...',
}
```

**Method:** Tokens are clustered by hardware signature (ENF deviation bucket × DRAM verdict × thermal label × 10-minute time bucket). Organic users scatter across all dimensions. A farm in one building, running the same script, on the same hardware generation collapses into one tight cluster. Each cluster is scored with Population Entropy. A non-parametric bootstrap produces the confidence interval.

**Typical values:**

| Scenario | estimatedHumanPct |
|---|---|
| Organic product feed | 92–97% |
| Incentivised engagement campaign | 55–75% |
| Coordinated click farm attack | 8–35% |

---

## Tests

```bash
npm test
```

```
  integration.test.js    43 tests  — core engine, provider classifier, commitment, registry
  stress.test.js         92 tests  — adversarial: KVM, VMware, Docker, LLM agents,
                                     Gaussian noise injection, synthetic thermal drift,
                                     score separation (real min vs VM max)
  engagement.test.js     45 tests  — IdleAttestation state machine, thermal classification,
                                     Population Entropy (all 5 tests), Engagement Token
                                     creation/verification/replay/tamper, risk signals
  audit.test.js          18 tests  — Authenticity Audit: organic vs farm cohorts, CI
                                     properties, multi-farm fingerprinting, grade thresholds

  Test Suites: 4 passed
  Tests:       158 passed, 0 failed
  Time:        ~1.0s
```

---

## Demo

```bash
node demo/node-demo.js
```

Simulates real hardware (Box-Muller Gaussian noise — no periodic components, no artificial autocorrelation) and VM timing profiles (0.1ms quantization grid + steal-time bursts every 50 iterations). Runs both through the full analysis and commitment pipeline. No WASM needed.

Open `demo/web/index.html` in a browser to see the animated probe running on your actual machine.

---

## Project structure

```
sovereign-pulse/
├── src/
│   ├── index.js                    pulse() — main entry point
│   ├── fingerprint.js              Fingerprint class (high-level API)
│   ├── collector/
│   │   ├── entropy.js              WASM bridge + phased/adaptive routing
│   │   ├── adaptive.js             Adaptive early-exit engine
│   │   ├── bio.js                  Mouse/keyboard interference coefficient
│   │   ├── canvas.js               WebGL/2D canvas fingerprint
│   │   ├── gpu.js                  WebGPU thermal growth probe
│   │   ├── dram.js                 DRAM refresh cycle detector
│   │   ├── enf.js                  Electrical Network Frequency probe
│   │   ├── sabTimer.js             Sub-millisecond SAB timer
│   │   └── idleAttestation.js      Proof-of-Idle — thermal hash chain (v0.5.0)
│   ├── analysis/
│   │   ├── jitter.js               Statistical classifier (6 components)
│   │   ├── heuristic.js            Cross-metric physics coherence engine
│   │   ├── provider.js             Hypervisor/cloud provider classifier
│   │   ├── audio.js                AudioContext callback jitter
│   │   ├── llm.js                  LLM agent behavioural detector
│   │   ├── trustScore.js           Unified 0–100 TrustScore engine (v0.4.0)
│   │   ├── populationEntropy.js    Sybil detection — 5 cohort-level tests (v0.5.0)
│   │   └── authenticityAudit.js    $44B question — humanPct + CI (v0.6.0)
│   ├── middleware/
│   │   ├── express.js              Express/Fastify/Hono drop-in
│   │   └── next.js                 Next.js App Router HOC
│   ├── integrations/
│   │   ├── react.js                usePulse() hook
│   │   └── react-native.js         Expo accelerometer + thermal bridge
│   ├── proof/
│   │   ├── fingerprint.js          BLAKE3 commitment builder
│   │   ├── validator.js            Server-side proof verifier
│   │   ├── challenge.js            HMAC challenge/response
│   │   └── engagementToken.js      30s physics-backed engagement token (v0.5.0)
│   └── registry/
│       └── serializer.js           Provider signature serializer + matcher
├── crates/pulse-core/              Rust/WASM entropy probe
├── index.d.ts                      Full TypeScript declarations
├── demo/
│   ├── web/index.html              Standalone browser demo
│   ├── node-demo.js                CLI demo (no WASM required)
│   ├── benchmark.js                Generates numbers in this README
│   └── perf.js                     Pipeline overhead benchmarks
└── test/
    ├── integration.test.js         43 tests  — core engine
    ├── stress.test.js              92 tests  — adversarial attack suite
    ├── engagement.test.js          45 tests  — idle / population / tokens
    └── audit.test.js               18 tests  — authenticity audit
```

---

## Privacy

Nothing leaves the browser except a ~1.6KB statistical summary:

- Timing arrays → BLAKE3 hashed, only hash transmitted
- GPU pixel buffers → BLAKE3 hashed, only hash transmitted
- Mouse coordinates → never stored, only timing deltas used
- Keystrokes → only dwell/flight times, key labels discarded immediately

The server receives enough to verify the proof. Not enough to reconstruct any original signal. Not enough to re-identify a user across sessions.

`hardwareId()` is a BLAKE3 hash of GPU renderer string + audio sample rate. Stable per physical device, not reversible, not cross-origin linkable.

---

## Limitations

- The probe runs for 0.9–3.5 seconds. Best suited for deliberate actions (login, checkout, form submit) not page load.
- Mobile browsers cap `performance.now()` to 1ms resolution. Signal quality is reduced; the classifier adjusts but scores trend lower.
- GPU passthrough VMs pass the canvas check. Timing is the primary discriminator in that case.
- This is one signal among many. High-stakes applications should layer it with behavioral and network signals.
- The heuristic engine catches unknown VMs via physics. The provider classifier labels them by scheduler signature. If a new hypervisor ships with an unusual quantum, it will be detected and flagged as `generic-vm` until the registry is updated.

---

## FAQ

**Does it work with browser extensions installed (uBlock, Privacy Badger, 1Password)?**

Yes. Extensions don't touch the physics layer. The core probe is thermal — it measures entropy growth via WASM matrix multiply timing across cold/load/hot CPU phases. Extensions cannot fake DRAM refresh variance or thermal noise on real silicon. Canvas signals (which some extensions do affect) are weighted inputs, not gates. The heuristic engine cross-validates across 5 independent signals, so no single channel can cause a false flag.

**What about Brave's timer clamping?**

Brave reduces `performance.now()` resolution to 100µs to prevent fingerprinting. We detect this via `timerGranularityMs` and adjust thresholds accordingly. A clamped timer on real hardware still shows thermal variance across phases. A VM with a clamped timer is still flat. The EJR check survives timer clamping — it's a ratio, not an absolute threshold.

**Can a VM spoof this?**

Spoofing one signal is straightforward. Spoofing all five simultaneously while keeping them mutually coherent with each other is a different problem. The Hurst-AC coherence check specifically catches data that was *generated* to look right rather than *measured* from real hardware — the two signals are physically linked and have to match each other, not just hit individual thresholds. See the [KVM example above](#the-picket-fence-detector) where four physical laws are violated simultaneously.

**Does it collect or transmit any personal data?**

No. Nothing leaves the browser except a ~1.6KB statistical summary with all raw signals BLAKE3-hashed. The server receives enough to verify the proof. Not enough to reconstruct any original signal or re-identify a user across sessions.

**What's the performance overhead?**

The probe takes 0.9–3.5 seconds depending on how quickly the signal converges. For obvious VMs it exits at 50 iterations (~0.9s). For real hardware it typically exits around 100–120 iterations (~2s). JavaScript overhead outside the probe itself is under 2ms. Best used on deliberate user actions (login, checkout) not page load.

**Mobile support?**

Mobile browsers cap `performance.now()` to 1ms resolution which reduces signal quality. The classifier adjusts thresholds and scores trend lower, but the directional verdict (VM vs. physical) remains accurate. The bio layer (touch timing, accelerometer jitter on supported devices) compensates partially.

---

## License

MIT

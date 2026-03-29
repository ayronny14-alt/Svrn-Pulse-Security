# @svrnsec/pulse

[![CI](https://github.com/ayronny14-alt/Svrn-Pulse-Security/actions/workflows/ci.yml/badge.svg)](https://github.com/ayronny14-alt/Svrn-Pulse-Security/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@svrnsec/pulse.svg?style=flat)](https://www.npmjs.com/package/@svrnsec/pulse)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-orange.svg)](./SECURITY.md)

Hardware-physics probe that tells real silicon apart from cloud VMs and AI inference endpoints.

No database of known bad actors. Just thermodynamics.

---

## Quickstart

```bash
npm install @svrnsec/pulse
```

```js
// Express — drop-in
import { createPulseMiddleware } from '@svrnsec/pulse/middleware/express';
app.use('/api', createPulseMiddleware({ minScore: 0.6 }));
```

```jsx
// React
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
// Node — raw proof
import { pulse } from '@svrnsec/pulse';

const { payload, hash } = await pulse({ nonce: crypto.randomUUID() });
// payload.classification.jitterScore → 0.798 (real hw) | 0.45 (VM)
// hash → BLAKE3 commitment for server-side validation
```

**Self-hosted:** No API key, no account, no data leaves the client. Runs entirely in your infra.

**Hosted API:** Zero server setup — pass `apiKey` and the SDK handles challenge/verify:

```js
const result = await pulse({ apiKey: 'sk_live_...' });
```

---

## Why this exists

Bot detection is a database problem. Known bad IPs, known headless fingerprints, known datacenter ASNs. Attacker's job: don't be in the database. New cloud region? New headless runtime? New residential proxy? Database is stale.

Pulse doesn't use a database.

A VM's hypervisor clock is mathematically perfect. It has to be — there's no thermal feedback loop in a virtual timer. Real silicon under load gets noisier because electrons move through gates that are physically heating up. That's a law of physics. Doesn't matter what hypervisor ships next year.

---

## Two layers

**Detection** — *Is this a VM?*
Five physical relationships, measured and cross-checked. If they're mutually coherent with what thermodynamics predicts, it's real. If any of them contradict each other in ways physics wouldn't allow, something's being faked. No signatures, no database.

**Classification** — *Which VM?*
Matches timing autocorrelation against known hypervisor scheduler rhythms (KVM 250ms quantum, Xen 750ms credit scheduler, Hyper-V 15.6ms). This part improves with data — but it's not needed for detection. A hypervisor that doesn't exist yet will still fail detection the moment it presents a flat clock.

---

## The five signals

### 1. Entropy-Jitter Ratio

The key one. Real CPU under sustained compute → thermal throttling → timing jitter increases. Die gets hotter, transistors switch slower, you can measure it.

```
hotQE / coldQE  ≥ 1.08  →  thermal feedback (real silicon)
hotQE / coldQE  ≈ 1.00  →  clock ignores guest thermal state (VM)
```

KVM hypervisor maintains a synthetic clock that ticks at a constant rate regardless of guest activity. On a KVM VM (12 vCPU / 480GB / GH200 Grace Hopper): EJR=1.01. On a local GTX 1650 Super: EJR=1.24.

Can't fake this without generating actual heat.

### 2. Hurst-Autocorrelation Coherence

Real Brownian noise → Hurst exponent near 0.5, near-zero autocorrelation at all lags. These are physically linked: `expected_AC = |2H - 1|`.

Measure H=0.5 but find high autocorrelation? Data was generated, not measured. A VM faking one without adjusting the other gets caught.

### 3. CV-Entropy Coherence

High coefficient of variation should come from genuinely spread-out timing, which means high quantization entropy. VMs that inflate CV by adding synthetic outliers at fixed offsets produce high CV but low entropy — 93% of samples still land in two bins.

KVM GH200: CV=0.0829 but QE=1.27 bits. Incoherent. Real hardware: CV=0.1494, QE=3.59 bits. Coherent.

### 4. Picket Fence Detector

Hypervisor scheduler quanta create periodic steal-time bursts. KVM at ~5ms/iteration with a 250ms quantum pauses the guest every ~50 iterations. Shows up as elevated autocorrelation at lag-50.

```
Real hardware:  lag-1 AC=0.07  lag-50 AC=0.03   (flat)
KVM VM:         lag-1 AC=0.67  lag-50 AC=0.71   (periodic steal-time)
```

Dominant lag also identifies the hypervisor: `lag × 5ms/iter ≈ quantum`.

### 5. Skewness-Kurtosis Coherence

Real hardware timing is right-skewed with positive kurtosis — OS preemptions create occasional large delays on the right tail. VMs adding synthetic spikes at fixed offsets tend to produce wrong skew or implausibly symmetric distributions.

---

## Benchmarks

*12 trials × 200 iterations.*

### Local — GTX 1650 Super · i5-10400 · Win11 · 16GB DDR4

```
Pulse Score  [████████████████████████████████░░░░░░░░] 79.8%
```

| Metric | Value | What it means |
|---|---|---|
| CV | 0.1494 | Spread from thermal noise + OS interrupts |
| Hurst | 0.5505 | Near-Brownian, i.i.d. noise |
| QE | 3.59 bits | Timings genuinely spread |
| AC lag-1 | 0.0698 | No periodic forcing |
| AC lag-50 | 0.0312 | No scheduler rhythm |
| EJR | 1.24 | 24% entropy growth cold→hot |
| Thermal | sawtooth | Fan cycling |
| Outlier Rate | 2.25% | OS context switches |

```
  3.60ms │██████                                  8
  4.16ms │██████████████                         19
  4.44ms │██████████████████████                 30
  4.73ms │████████████████████████████████████   50   ← peak
  5.01ms │██████████████████████                 30
  5.57ms │█████████████                          18
  7.53ms │█                                       1   ← OS preemption
```

Normal bell curve, right-tailed from preemptions.

---

### Remote VM — KVM · 12 vCPU · 480GB · GH200 Grace Hopper · Ubuntu 22.04

```
Pulse Score  [██████████████████░░░░░░░░░░░░░░░░░░░░░░] 45.0%
```

| Metric | Value | What it means |
|---|---|---|
| CV | 0.0829 | Hypervisor flattens variance |
| Hurst | 0.0271 | Anti-persistent, timer quantization |
| QE | 1.27 bits | 93% of samples on two values |
| AC lag-1 | 0.666 | Periodic steal-time |
| AC lag-50 | 0.710 | Confirms scheduler rhythm |
| EJR | 1.01 | Flat — no thermal feedback |
| Thermal | sawtooth (synthetic) | Scheduler bursts, not temperature |
| Outlier Rate | 6.00% | Deterministic steal-time |

```
  5.00ms │████████████████████████████████████  123   ← 61%
  5.11ms │███████████████████                    65   ← 32%
  5.22ms │                                        0
  ...     │                                        0   ← impossible gap
  6.72ms │█                                       2
  6.83ms │█                                       4   ← steal-time bursts
```

93% at exactly two values. Nothing in between. A continuous physical process can't produce this.

```
ENTROPY_FLAT_UNDER_LOAD      EJR=1.01 (expected ≥1.08)              -0.10
PICKET_FENCE_DETECTED        lag-50 AC=0.71 > baseline 0.08         -0.08
HURST_AUTOCORR_INCOHERENT    H=0.027 vs expected AC=0.946           -0.12
CV_ENTROPY_INCOHERENT        CV=0.083 → expected QE≈2.83, got 1.27  -0.10
```

Four different physical laws violated simultaneously. Spoofing one is easy. Spoofing all four while keeping them consistent with each other is a different problem.

---

## Adaptive early exit

Doesn't always need 200 iterations. Checks confidence every 25, exits when the verdict is decisive:

```
Environment         Iters   Time    Speedup
──────────────────────────────────────────
KVM (obvious)           50   ~0.9s    75%
VMware ESXi             75   ~1.4s    60%
Physical desktop       ~120  ~2.1s    40%
Ambiguous              200   ~3.5s     —
```

The GH200 VM — 480GB RAM, Grace Hopper Superchip — hit the exit at iteration 50. Doesn't matter. The hypervisor clock is still mathematically perfect.

---

## Install

```bash
npm install @svrnsec/pulse
```

Node 18+. WASM binary compiled from Rust and bundled. No separate `.wasm` file to host. No phone home, no external service.

Build from source (needs [Rust](https://rustup.rs) + [wasm-pack](https://rustwasm.github.io/wasm-pack/)):

```bash
git clone https://github.com/ayronny14-alt/Svrn-Pulse-Security
cd Svrn-Pulse-Security
npm install && npm run build
```

---

## Usage

### Client

```js
import { pulse } from '@svrnsec/pulse';

const { nonce } = await fetch('/api/pulse/challenge').then(r => r.json());

const { payload, hash } = await pulse({
  nonce,
  onProgress: (stage, meta) => {
    if (stage === 'entropy_batch') {
      console.log(`${meta.pct}% — ${meta.earlyVerdict ?? 'measuring...'}`);
    }
  },
});

const result = await fetch('/api/pulse/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ payload, hash }),
}).then(r => r.json());
```

### Fingerprint class

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
fp.schedulerQuantumMs // 250
fp.entropyJitterRatio // 1.24
fp.topFlag            // 'PICKET_FENCE_DETECTED'
fp.findings           // full heuristic report
fp.physicalEvidence   // confirmed physical properties

fp.hardwareId()       // stable 32-char hex — BLAKE3(GPU + audio), 128-bit
fp.metrics()          // flat object for logging
fp.toCommitment()     // { payload, hash }
```

### Server

```js
import { validateProof, generateNonce } from '@svrnsec/pulse/validator';

app.get('/api/pulse/challenge', async (req, res) => {
  const nonce = generateNonce();
  await redis.set(`pulse:${nonce}`, '1', 'EX', 300);
  res.json({ nonce });
});

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
app.post('/checkout', pulse.verify, handler);
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

Full declarations in `index.d.ts`:

```ts
import { pulse, Fingerprint } from '@svrnsec/pulse';
import type {
  PulseOptions, PulseCommitment,
  ProgressMeta, PulseStage,
  ValidationResult, FingerprintReport,
} from '@svrnsec/pulse';
```

---

## Validation result

```js
{
  valid:      true,
  score:      0.8215,
  confidence: 'high',       // 'high' | 'medium' | 'low' | 'rejected'
  reasons:    [],
  riskFlags:  [],
  meta: {
    receivedAt:     1742686350535,
    proofAge:       2841,
    jitterScore:    0.7983,
    canvasRenderer: 'NVIDIA GeForce GTX 1650 Super/PCIe/SSE2',
    bioActivity:    true,
  }
}
```

| Score | Confidence | Meaning |
|---|---|---|
| ≥ 0.75 | high | Real consumer hardware |
| 0.55 – 0.75 | medium | Likely real, some ambiguous signals |
| 0.35 – 0.55 | low | Borderline — VM, Chromebook, virtual display |
| < 0.35 | rejected | Strong VM/AI indicators |

---

## What it catches

| Scenario | Result | Why |
|---|---|---|
| Cloud VM (AWS, GCP, Azure, DO) | Blocked | Flat EJR + quantized ticks + picket fence |
| Headless Chrome / Puppeteer | Blocked | SwiftShader renderer + zero bio |
| AI inference endpoint | Blocked | VM timing + zero bio |
| Proof replay | Blocked | Nonce consumed on first use |
| Payload tamper | Blocked | BLAKE3 hash breaks |
| Single-signal spoofing | Blocked | Cross-metric coherence |
| All-signal spoofing | Very hard | 5 physically-linked relationships |
| Unknown hardware | Blocked | Physics is the check |
| GPU passthrough VM | Partial | Canvas varies; timing is primary |
| Remote desktop (real machine) | Pass | Timing is real; bio may be weak |

---

## TrustScore

Converts all signals into a single 0–100 integer.

```js
import { computeTrustScore, formatTrustScore } from '@svrnsec/pulse/trust';

const ts = computeTrustScore(payload, { enf, gpu, dram, llm, idle });
// → { score: 87, grade: 'B', label: 'Verified', hardCap: null, breakdown: {...} }

console.log(formatTrustScore(ts));
// → "TrustScore 87/100  B · Verified  [physics:91% enf:80% gpu:100% dram:87% bio:70%]"
```

**Weights:** Physics 40 · ENF 20 · GPU 15 · DRAM 15 · Bio/LLM 10

**Hard caps** (bonus points can't override these):

| Condition | Cap | |
|---|---|---|
| EJR forgery | 20 | Physics law violated |
| Software GPU | 45 | Likely VM/container |
| LLM agent conf > 0.85 | 30 | AI-driven session |
| No bio + no ENF | 55 | Can't confirm human on real device |

---

## Proof-of-Idle

Click farms run thousands of real phones at max throughput. Fingerprinting can't catch them — the devices are real.

But: a real device between interactions cools via Newton's Law — smooth exponential variance decay. A farm script pausing to fake idle drops CPU 100%→0% instantly. Step function in timing variance. Can't fake a cooling curve faster than real time.

```js
import { createIdleMonitor } from '@svrnsec/pulse/idle';

const monitor = createIdleMonitor();
monitor.start();

// On engagement:
const idleProof = monitor.getProof(); // null if device never genuinely rested
```

| Label | Meaning | Farm? |
|---|---|---|
| `hot_to_cold` | Smooth exponential decay | No |
| `cold` | Already at rest temp | No |
| `step_function` | >75% variance drop in first interval | Yes |
| `sustained_hot` | No cooling at all during idle | Yes |

Hash chain (`SHA-256(prevHash ‖ ts ‖ meanMs ‖ variance)`) proves samples were taken in sequence. N nodes at 30s spacing = (N-1)×30s minimum elapsed — can't backfill faster than real time.

---

## Population Entropy

One fake account is hard to spot. A warehouse of 1,000 phones running the same script is statistically impossible to hide.

```js
import { analysePopulation } from '@svrnsec/pulse/population';

const verdict = analysePopulation(tokenCohort);
// → { authentic: false, sybilScore: 84, flags: ['TIMESTAMP_RHYTHM', 'THERMAL_HOMOGENEOUS'] }
```

Five tests on a cohort:

| Test | What it catches |
|---|---|
| Timestamp rhythm | Clock-timed dispatch batches |
| Entropy dispersion | Cloned VMs too similar (CV < 0.04) |
| Thermal diversity | 1,000 phones, same thermal state |
| Idle plausibility | Scripts always pause for same duration |
| ENF phase coherence | Co-located devices share same circuit |

`sybilScore < 40 = authentic`. Farms hit 80+.

---

## Engagement Tokens

30-second HMAC-SHA256 token proving a specific interaction came from real hardware that genuinely rested between events.

```js
import { createEngagementToken, verifyEngagementToken } from '@svrnsec/pulse/engage';

const { compact } = createEngagementToken({
  pulseResult,
  idleProof: monitor.getProof(),
  interaction: { type: 'click', ts: Date.now(), motorConsistency: 0.82 },
  secret: process.env.PULSE_SECRET,
});
// Header: X-Pulse-Token: <compact>

const result = await verifyEngagementToken(compact, process.env.PULSE_SECRET, {
  checkNonce: (n) => redis.del(`pulse:nonce:${n}`).then(d => d === 1),
});
```

What the token binds together: real hardware (DRAM + ENF), genuine idle (hash-chained thermal measurements ≥45s), physical cooling (smooth decay, not step function), fresh interaction (30s TTL), tamper-evident (HMAC over all fraud-relevant fields).

---

## Authenticity Audit

Statistically estimates what percentage of a user cohort is human.

```js
import { authenticityAudit } from '@svrnsec/pulse/audit';

const report = authenticityAudit(tokenCohort, { confidenceLevel: 0.95 });
```

```js
{
  cohortSize:          10000,
  estimatedHumanPct:   73.4,
  confidenceInterval:  [69.1, 77.8],
  grade:               'HIGH_FRAUD',
  botClusterCount:     5,
  botClusters: [
    {
      id:        'farm_a3f20c81',
      size:       847,
      sybilScore: 94,
      signature: {
        enfRegion:    'americas',
        thermalLabel: 'sustained_hot',
        meanIdleMs:   57200,        // script sleeps exactly 57s
      },
      topSignals: ['timestamp_rhythm', 'thermal_diversity'],
    },
  ],
}
```

Tokens clustered by hardware signature (ENF × DRAM × thermal × time bucket). Organic users scatter. A farm in one building on the same hardware collapses into one tight cluster. Bootstrap CI on the human-rate estimate.

| Scenario | humanPct |
|---|---|
| Organic product feed | 92–97% |
| Incentivised campaign | 55–75% |
| Click farm attack | 8–35% |

---

## Coordinated Behavior Detection

```js
import { detectCoordinatedBehavior } from '@svrnsec/pulse/coordination';

const result = detectCoordinatedBehavior(tokenCohort);
// result.clusters, result.coordinationScore (0-100)
```

Five layers: Poisson test on arrival times, signal fingerprint collision, clock drift convergence, Louvain-lite community detection on mutual information, entropy velocity vs traffic growth.

---

## LLM Agent Detection

Catches AI-controlled browsers (AutoGPT, Playwright+LLM, browser agents) through behavioral biometrics:

```js
import { detectLlmAgent } from '@svrnsec/pulse/llm';

const result = detectLlmAgent(bioSnapshot);
// result.verdict → 'human' | 'ai_agent' | 'ambiguous'
```

Six signals: think-time distributions, mouse path smoothness (Bezier vs micro-tremor), keystroke correction rate, 8-12Hz physiological tremor, inter-event gap clustering, motor consistency.

---

## Tests

```bash
npm test
```

```
integration.test.js    43 tests  — core engine, provider classifier, commitment
stress.test.js         92 tests  — adversarial: KVM, VMware, Docker, LLM agents,
                                   noise injection, synthetic thermal drift
engagement.test.js     45 tests  — idle attestation, population entropy, tokens
audit.test.js          18 tests  — authenticity audit, multi-farm fingerprinting

4 suites, 158 tests, ~1.0s
```

---

## Project structure

```
sovereign-pulse/
├── src/
│   ├── index.js                    pulse() entry point
│   ├── fingerprint.js              Fingerprint class
│   ├── errors.js                   Error types
│   ├── collector/
│   │   ├── entropy.js              WASM bridge + phased/adaptive routing
│   │   ├── adaptive.js             Early-exit engine
│   │   ├── bio.js                  Mouse/keyboard interference
│   │   ├── canvas.js               WebGL/2D fingerprint
│   │   ├── gpu.js                  WebGPU thermal probe
│   │   ├── dram.js                 DRAM refresh detector
│   │   ├── enf.js                  Electrical Network Frequency
│   │   ├── sabTimer.js             Sub-ms SAB timer
│   │   └── idleAttestation.js      Proof-of-Idle hash chain
│   ├── analysis/
│   │   ├── jitter.js               Statistical classifier (6 components)
│   │   ├── heuristic.js            Cross-metric coherence engine
│   │   ├── provider.js             Hypervisor classifier
│   │   ├── audio.js                AudioContext jitter
│   │   ├── llm.js                  LLM agent detector
│   │   ├── trustScore.js           TrustScore engine
│   │   ├── populationEntropy.js    Sybil detection
│   │   ├── authenticityAudit.js    Cohort human-rate estimation
│   │   ├── coordinatedBehavior.js  CIB detection
│   │   └── refraction.js           Timer calibration
│   ├── middleware/
│   │   ├── express.js              Express/Fastify/Hono
│   │   └── next.js                 Next.js App Router
│   ├── integrations/
│   │   ├── react.js                usePulse()
│   │   └── react-native.js         Expo accelerometer + thermal
│   ├── proof/
│   │   ├── fingerprint.js          BLAKE3 commitment
│   │   ├── validator.js            Server-side verifier
│   │   ├── challenge.js            HMAC challenge/response
│   │   └── engagementToken.js      30s engagement token
│   └── registry/
│       └── serializer.js           Provider signature matcher
├── crates/pulse-core/              Rust/WASM entropy probe
├── server/                         Optional hosted API (Docker + Redis)
├── index.d.ts                      TypeScript declarations
├── demo/                           Browser + CLI demos
└── test/                           158 tests
```

---

## Privacy

Nothing leaves the browser except a ~1.6KB statistical summary. Timing arrays and GPU buffers are BLAKE3-hashed — only hashes transmitted. Mouse coordinates never stored, only timing deltas. Keystrokes reduced to dwell/flight times, labels discarded.

`hardwareId()` is a 128-bit BLAKE3 hash of GPU renderer + audio sample rate. Stable per device, not reversible, not cross-origin linkable.

---

## Limitations

- Probe takes 0.9–3.5s. Best for deliberate actions (login, checkout) not page load.
- Mobile browsers cap `performance.now()` to 1ms. Signal quality drops, scores trend lower, directional verdict still accurate.
- GPU passthrough VMs pass canvas check. Timing is primary.
- This is one signal. High-stakes stuff should layer it with behavioral and network analysis.
- New hypervisors get caught by physics but labelled `generic-vm` until the registry learns them.

---

## FAQ

**Browser extensions (uBlock, Privacy Badger, 1Password)?**
Don't touch the physics layer. Core probe is thermal — WASM matrix multiply timing across cold/load/hot phases. Extensions can't fake DRAM refresh variance. Canvas signals (which some extensions affect) are weighted inputs, not gates.

**Brave's timer clamping?**
Detected via `timerGranularityMs`, thresholds adjust. Clamped timer on real hardware still shows thermal variance. VM with clamped timer is still flat. EJR is a ratio, not absolute.

**Can a VM spoof this?**
One signal, sure. All five while keeping them mutually coherent? That's the hard part. Hurst-AC coherence specifically catches generated-not-measured data — the two signals are physically linked and have to match each other, not just hit thresholds individually.

**Performance overhead?**
0.9–3.5s for the probe. Obvious VMs exit at 50 iterations (~0.9s). Real hardware typically ~120 iterations (~2s). JS overhead outside the probe is under 2ms.

**Mobile?**
1ms timer cap reduces signal quality. Classifier adjusts, scores trend lower, verdict stays directional. Bio layer (touch timing, accelerometer) compensates.

---

## License

MIT

# @sovereign/pulse

A hardware-physics probe that distinguishes real consumer silicon from sanitised cloud VMs and AI inference endpoints.

It does not maintain a database of known bad actors. It measures thermodynamic constants.

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

A KVM hypervisor maintains a synthetic clock that ticks at a constant rate regardless of what the guest OS is doing. Its entropy ratio across cold/load/hot phases is flat. On 192.222.57.254 it measured 1.01. On the local GTX 1650 Super machine it measured 1.24.

A software implementation cannot fake this without generating actual heat.

### 2. Hurst-Autocorrelation Coherence

Genuine Brownian noise (what real hardware timing looks like) has a Hurst exponent near 0.5 and near-zero autocorrelation at all lags. These two are physically linked by the relationship `expected_AC = |2H - 1|`.

If you measure H=0.5 but find high autocorrelation — or low H but low autocorrelation — the data was generated, not measured. A VM that tries to fake the Hurst Exponent without adjusting the autocorrelation profile, or vice versa, fails this check immediately.

### 3. CV-Entropy Coherence

High coefficient of variation (timing spread) must come from a genuinely spread-out distribution, which means high quantization entropy. A VM that inflates CV by adding synthetic outliers at fixed offsets — say, every 50th iteration triggers a steal-time burst — produces high CV but low entropy because 93% of samples still fall in two bins.

From 192.222.57.254: CV=0.0829 (seems variable) but QE=1.27 bits (extreme clustering). Incoherent. On real hardware, CV=0.1494 → QE=3.59 bits. Coherent.

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

### Remote VM — 192.222.57.254 — KVM · 2 vCPU · 2GB · Ubuntu 22.04

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

The 192.222.57.254 VM hit the exit condition at iteration 50. The signal was conclusive within the first batch.

---

## Installation

```bash
npm install @sovereign/pulse
```

Node.js ≥ 18. The WASM binary is compiled from Rust and bundled — no separate `.wasm` file to host.

The package is self-contained. It does not phone home. It does not contact any external service. Everything runs inside your infrastructure.

To build from source (requires [Rust](https://rustup.rs) and [wasm-pack](https://rustwasm.github.io/wasm-pack/)):

```bash
git clone https://github.com/sovereign/pulse
cd sovereign-pulse
npm install
npm run build
```

---

## Usage

### Client side

```js
import { pulse } from '@sovereign/pulse';

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
import { Fingerprint } from '@sovereign/pulse';

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
import { validateProof, generateNonce } from '@sovereign/pulse/validator';

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
import { createPulseMiddleware } from '@sovereign/pulse/middleware/express';

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
import { pulseChallenge } from '@sovereign/pulse/middleware/next';
export const GET = pulseChallenge();

// app/api/checkout/route.js
import { withPulse } from '@sovereign/pulse/middleware/next';
export const POST = withPulse({ threshold: 0.6 })(async (req) => {
  const { score, provider } = req.pulse;
  return Response.json({ ok: true, score });
});
```

### React hook

```jsx
import { usePulse } from '@sovereign/pulse/react';

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
import { pulse, Fingerprint } from '@sovereign/pulse';
import type {
  PulseOptions, PulseCommitment,
  ProgressMeta, PulseStage,
  ValidationResult, FingerprintReport,
} from '@sovereign/pulse';

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
import { serializeSignature, KNOWN_PROFILES } from '@sovereign/pulse/registry';

// After collecting a Fingerprint on the target machine:
const sig = serializeSignature(fp, { name: 'AWS r7g.xlarge (Graviton3)', date: '2025-01' });
// sig.id → deterministic 'sig_abc123...'
// Buckets continuous metrics for privacy — not reversible to raw values
```

The detection engine doesn't need updates when new hardware ships. The registry benefits from them for labelling accuracy.

---

## Tests

```bash
npm test
```

```
  computeStats               ✓ basic statistics are correct
                             ✓ constant array has zero CV
  computeHurst               ✓ returns value in [0,1]
                             ✓ constant series returns ~0.5 (fallback)
  detectQuantizationEntropy  ✓ real hardware samples have high entropy
                             ✓ quantized (VM) samples have low entropy
  detectThermalSignature     ✓ detects rising pattern
                             ✓ detects flat pattern
  classifyJitter             ✓ real hardware scores higher than VM
                             ✓ score is in [0,1]
                             ✓ VM samples are flagged
                             ✓ insufficient data returns zero score with flag
  runHeuristicEngine         ✓ EJR < 1.02 triggers penalty
                             ✓ EJR ≥ 1.08 triggers bonus
                             ✓ Hurst-autocorr incoherence penalised
                             ✓ picket fence detector triggers on periodic AC
                             ✓ skewness-kurtosis bonus on right-skewed leptokurtic
                             ✓ clean metrics produce no flags
  detectProvider             ✓ KVM profile matched from autocorr signature
                             ✓ physical profile matched from analog-fog metrics
                             ✓ scheduler quantum estimated from lag-25 AC
                             ✓ Nitro identified from near-flat AC profile
                             ✓ alternatives list populated
  buildCommitment            ✓ produces deterministic hash
                             ✓ any field change breaks the hash
  canonicalJson              ✓ sorts keys deterministically
  validateProof              ✓ valid proof passes
                             ✓ tampered payload is rejected
                             ✓ low jitter score is rejected
                             ✓ software renderer is blocked
                             ✓ expired proof is rejected
                             ✓ nonce check is called
                             ✓ rejected nonce fails proof
  generateNonce              ✓ produces 64-char hex strings
                             ✓ each call is unique
  serializeSignature         ✓ produces deterministic sig_ ID
                             ✓ buckets continuous metrics for privacy
                             ✓ isSynthetic flag preserved
  matchRegistry              ✓ exact match returns similarity 1.0
                             ✓ different class returns low similarity
                             ✓ alternatives sorted by similarity
  compareSignatures          ✓ same class returns sameClass=true
                             ✓ physical vs VM returns sameClass=false

  Test Suites: 1 passed
  Tests:       43 passed, 0 failed
  Time:        0.327s
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
│   │   └── canvas.js              WebGL/2D canvas fingerprint
│   ├── analysis/
│   │   ├── jitter.js              Statistical classifier (6 components)
│   │   ├── heuristic.js           Cross-metric physics coherence engine
│   │   ├── provider.js            Hypervisor/cloud provider classifier
│   │   └── audio.js               AudioContext callback jitter
│   ├── middleware/
│   │   ├── express.js             Express/Fastify/Hono drop-in
│   │   └── next.js                Next.js App Router HOC
│   ├── integrations/
│   │   └── react.js               usePulse() hook
│   ├── proof/
│   │   ├── fingerprint.js         BLAKE3 commitment builder
│   │   └── validator.js           Server-side proof verifier
│   └── registry/
│       └── serializer.js          Provider signature serializer + matcher
├── crates/pulse-core/             Rust/WASM entropy probe
├── index.d.ts                     Full TypeScript declarations
├── demo/
│   ├── web/index.html             Standalone browser demo
│   ├── node-demo.js               CLI demo (no WASM required)
│   ├── benchmark.js               Generates numbers in this README
│   └── perf.js                    Pipeline overhead benchmarks
└── test/integration.test.js       43 tests
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

## License

MIT

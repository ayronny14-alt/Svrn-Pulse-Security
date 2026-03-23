/**
 * @svrnsec/pulse — Hypervisor & Cloud Provider Fingerprinter
 *
 * Each hypervisor has a distinct "steal-time rhythm" — a characteristic
 * pattern in how it schedules guest vCPUs on host physical cores.
 * This creates detectable signatures in the timing autocorrelation profile.
 *
 * Think of it like a heartbeat EKG:
 *   KVM      → regular 50-iteration bursts  (~250ms quantum at 5ms/iter)
 *   Xen      → longer 150-iteration bursts  (~750ms credit scheduler quantum)
 *   VMware   → irregular bursts, memory balloon noise
 *   Hyper-V  → 78-iteration bursts          (~390ms at 5ms/iter, 15.6ms quantum)
 *   Nitro    → almost none — SR-IOV passthrough is nearly invisible
 *   Physical → no rhythm at all
 *
 * Canvas renderer strings give a second, independent signal that we cross-
 * reference to increase confidence in the provider classification.
 */

// ---------------------------------------------------------------------------
// Provider profile database
// ---------------------------------------------------------------------------
// Each profile is calibrated from real benchmark data.
// Fields: lag1_range, lag50_range, qe_range, cv_range, renderer_hints

const PROVIDER_PROFILES = [
  {
    id:         'physical',
    label:      'Physical Hardware',
    profile:    'analog-fog',
    confidence: 0,  // set dynamically
    match: ({ lag1, lag50, qe, cv, entropyJitterRatio, isSoftwareRenderer }) =>
      !isSoftwareRenderer &&
      Math.abs(lag1) < 0.20 &&
      Math.abs(lag50) < 0.15 &&
      qe > 3.0 &&
      cv > 0.06 &&
      (entropyJitterRatio === null || entropyJitterRatio >= 1.02),
  },
  {
    id:         'kvm-generic',
    label:      'KVM Hypervisor (generic)',
    profile:    'picket-fence',
    match: ({ lag1, lag50, qe, cv }) =>
      lag1 > 0.40 && qe < 2.5 && cv < 0.15 && Math.abs(lag50) > 0.25,
    providerHints: ['digitalocean', 'linode', 'vultr', 'hetzner', 'ovh'],
  },
  {
    id:         'kvm-digitalocean',
    label:      'DigitalOcean Droplet (KVM)',
    profile:    'picket-fence',
    match: ({ lag1, lag50, qe, cv, rendererHints }) =>
      lag1 > 0.55 && qe < 2.0 && cv < 0.12 &&
      (rendererHints.some(r => ['llvmpipe', 'virtio', 'qxl'].includes(r)) ||
       lag50 > 0.30),
  },
  {
    id:         'kvm-aws-ec2-xen',
    label:      'AWS EC2 (Xen/older generation)',
    profile:    'picket-fence',
    // Xen credit scheduler has longer period (~150 iters)
    match: ({ lag1, lag25, lag50, qe, cv }) =>
      qe < 2.2 && cv < 0.13 &&
      lag25 > 0.20 && lag50 > 0.20 &&
      lag1 < 0.50,   // lag-1 less pronounced than KVM
  },
  {
    id:         'nitro-aws',
    label:      'AWS EC2 Nitro (near-baremetal)',
    profile:    'near-physical',
    // Nitro uses SR-IOV and dedicated hardware — steal-time is very low.
    // Looks almost physical but canvas renderer gives it away.
    match: ({ lag1, lag50, qe, cv, isSoftwareRenderer, rendererHints }) =>
      qe > 2.5 && cv > 0.05 &&
      lag1 < 0.25 && lag50 < 0.20 &&
      (isSoftwareRenderer ||
       rendererHints.some(r => r.includes('nvidia t4') || r.includes('nvidia a10'))),
  },
  {
    id:         'vmware-esxi',
    label:      'VMware ESXi',
    profile:    'burst-scheduler',
    // VMware balloon driver creates irregular memory pressure bursts
    match: ({ lag1, lag50, qe, cv, rendererHints }) =>
      qe < 2.5 &&
      (rendererHints.some(r => r.includes('vmware')) ||
       (lag1 > 0.30 && lag50 < lag1 * 0.7 && cv < 0.14)),
  },
  {
    id:         'hyperv',
    label:      'Microsoft Hyper-V',
    profile:    'picket-fence',
    // 15.6ms scheduler quantum → burst every ~78 iters
    match: ({ lag1, lag25, qe, cv, rendererHints }) =>
      qe < 2.3 &&
      (rendererHints.some(r => r.includes('microsoft basic render') || r.includes('warp')) ||
       (lag25 > 0.25 && lag1 > 0.35 && cv < 0.12)),
  },
  {
    id:         'gcp-kvm',
    label:      'Google Cloud (KVM)',
    profile:    'picket-fence',
    match: ({ lag1, lag50, qe, cv, rendererHints }) =>
      qe < 2.3 && lag1 > 0.45 &&
      (rendererHints.some(r => r.includes('swiftshader') || r.includes('google')) ||
       (lag50 > 0.28 && cv < 0.11)),
  },
  {
    id:         'gh200-datacenter',
    label:      'NVIDIA GH200 / HPC Datacenter',
    profile:    'hypervisor-flat',
    // Even with massive compute, still trapped by hypervisor clock.
    // GH200 shows near-zero Hurst (extreme quantization) + very high lag-1.
    match: ({ lag1, qe, hurst, cv, rendererHints }) =>
      (rendererHints.some(r => r.includes('gh200') || r.includes('grace hopper') ||
                                r.includes('nvidia a100') || r.includes('nvidia h100')) ||
       (hurst < 0.10 && lag1 > 0.60 && qe < 1.8 && cv < 0.10)),
  },
  {
    id:         'generic-vm',
    label:      'Virtual Machine (unclassified)',
    profile:    'picket-fence',
    match: ({ lag1, qe, cv, isSoftwareRenderer }) =>
      isSoftwareRenderer ||
      (qe < 2.0 && lag1 > 0.35) ||
      (cv < 0.02),
  },
];

// ---------------------------------------------------------------------------
// detectProvider
// ---------------------------------------------------------------------------

/**
 * Classifies the host environment based on timing + canvas signals.
 *
 * @param {object} p
 * @param {import('./jitter.js').JitterAnalysis} p.jitter
 * @param {object} p.autocorrelations           - extended lags including lag25, lag50
 * @param {import('../collector/canvas.js').CanvasFingerprint} p.canvas
 * @param {object|null} p.phases
 * @returns {ProviderResult}
 */
export function detectProvider({ jitter, autocorrelations, canvas, phases }) {
  const rendererHints = _rendererHints(canvas?.webglRenderer, canvas?.webglVendor);

  const signals = {
    lag1:               Math.abs(autocorrelations?.lag1  ?? 0),
    lag25:              Math.abs(autocorrelations?.lag25 ?? 0),
    lag50:              Math.abs(autocorrelations?.lag50 ?? 0),
    qe:                 jitter.quantizationEntropy,
    cv:                 jitter.stats?.cv ?? 0,
    hurst:              jitter.hurstExponent ?? 0.5,
    isSoftwareRenderer: canvas?.isSoftwareRenderer ?? false,
    rendererHints,
    entropyJitterRatio: phases?.entropyJitterRatio ?? null,
  };

  // Score each profile and pick the best match
  const scored = PROVIDER_PROFILES
    .filter(p => {
      try { return p.match(signals); }
      catch { return false; }
    })
    .map(p => ({
      ...p,
      // Physical hardware is the last resort; give it lower priority when
      // other profiles match so we don't misclassify VMs.
      priority: p.id === 'physical' ? 0 : 1,
    }))
    .sort((a, b) => b.priority - a.priority);

  const best = scored[0] ?? { id: 'unknown', label: 'Unknown', profile: 'unknown' };

  // Confidence: how many "VM indicator" thresholds the signals cross
  const vmIndicatorCount = [
    signals.qe < 2.5,
    signals.lag1 > 0.35,
    signals.lag50 > 0.20,
    signals.cv < 0.04,
    signals.isSoftwareRenderer,
    signals.hurst < 0.15,
    phases?.entropyJitterRatio != null && phases.entropyJitterRatio < 1.02,
  ].filter(Boolean).length;

  const isPhysical   = best.id === 'physical';
  const confidence   = isPhysical
    ? Math.max(20, 95 - vmIndicatorCount * 15)
    : Math.min(95, 40 + vmIndicatorCount * 12);

  return {
    providerId:         best.id,
    providerLabel:      best.label,
    profile:            best.profile,
    confidence,
    isVirtualized:      best.id !== 'physical',
    signals,
    alternatives:       scored.slice(1, 3).map(p => ({ id: p.id, label: p.label })),
    rendererHints,
    schedulerQuantumMs: _estimateQuantum(signals),
  };
}

/**
 * @typedef {object} ProviderResult
 * @property {string}  providerId
 * @property {string}  providerLabel
 * @property {string}  profile           'analog-fog' | 'picket-fence' | 'burst-scheduler' | 'near-physical' | 'hypervisor-flat' | 'unknown'
 * @property {number}  confidence        0–100
 * @property {boolean} isVirtualized
 * @property {object}  signals
 * @property {object[]} alternatives
 * @property {string[]} rendererHints
 * @property {number|null} schedulerQuantumMs
 */

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Extract lowercase hint tokens from WebGL renderer string for pattern matching.
 */
function _rendererHints(renderer = '', vendor = '') {
  return `${renderer} ${vendor}`.toLowerCase()
    .split(/[\s\/(),]+/)
    .filter(t => t.length > 2);
}

/**
 * Estimate the hypervisor's scheduler quantum from the dominant autocorrelation lag.
 * Returns null if the device appears to be physical.
 */
function _estimateQuantum({ lag1, lag25, lag50, qe }) {
  if (qe > 3.2) return null;  // likely physical

  // Find the dominant lag (highest absolute autocorrelation beyond lag-5)
  const lags = [
    { lag: 50, ac: lag50 },
    { lag: 25, ac: lag25 },
  ];
  const peak = lags.reduce((b, c) => c.ac > b.ac ? c : b, { lag: 0, ac: 0 });

  if (peak.ac < 0.20) return null;

  // Quantum (ms) ≈ dominant_lag × estimated_iteration_time (≈5ms)
  return peak.lag * 5;
}

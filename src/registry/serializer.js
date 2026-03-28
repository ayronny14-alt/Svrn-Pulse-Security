/**
 * @svrnsec/pulse — SVRN Registry Signature Serializer
 *
 * The registry is a crowdsourced database of device "Silicon Signatures" —
 * compact, privacy-safe profiles that characterise a device class rather than
 * an individual device.  Developers submit signatures from their test hardware
 * to help calibrate the classifier for hardware we haven't seen yet.
 *
 * A signature captures:
 *   - The statistical "shape" of the timing distribution (not raw timings)
 *   - The provider/hypervisor classification
 *   - The timing profile type (analog-fog vs picket-fence)
 *   - Hardware generation hints (GPU vendor, renderer class)
 *
 * What a signature does NOT capture:
 *   - Any individual timing values
 *   - Canvas pixel data
 *   - Mouse coordinates or keystrokes
 *   - Any user-identifiable information
 *
 * Usage:
 *   import { serializeSignature, matchRegistry, KNOWN_PROFILES } from '@svrnsec/pulse/registry';
 *
 *   const sig = serializeSignature(fingerprint);
 *   const match = matchRegistry(sig, KNOWN_PROFILES);
 *   console.log(match.name, match.similarity);
 */

import { blake3HexStr } from '../proof/fingerprint.js';

// ---------------------------------------------------------------------------
// Built-in known profiles (the baseline registry)
// ---------------------------------------------------------------------------
// These were generated from real benchmark runs.

export const KNOWN_PROFILES = [
  {
    id:       'gtx1650s-i5-10400-win11',
    name:     'GTX 1650 Super / i5-10400 / Windows 11',
    class:    'consumer-gpu-midrange',
    profile:  'analog-fog',
    provider: 'physical',
    metrics: {
      cv:      { mean: 0.1494, stddev: 0.012 },
      hurst:   { mean: 0.5505, stddev: 0.08  },
      qe:      { mean: 3.595,  stddev: 0.14  },
      lag1:    { mean: 0.0698, stddev: 0.05  },
      outlier: { mean: 0.0225, stddev: 0.006 },
      ejr:     { mean: 1.18,   stddev: 0.09  },  // entropy-jitter ratio
    },
    contributedBy: 'Aaron Miller (sovereign-pulse author)',
    date: '2026-03-22',
  },
  {
    id:       'kvm-vps-ubuntu22-2vcpu',
    name:     'KVM VM / Ubuntu 22.04 / 12 vCPU / 480GB RAM / NVIDIA GH200 Grace Hopper',
    class:    'datacenter-gpu-highend',
    profile:  'picket-fence',
    provider: 'kvm-generic',
    metrics: {
      cv:      { mean: 0.0829, stddev: 0.003 },
      hurst:   { mean: 0.0271, stddev: 0.04  },
      qe:      { mean: 1.266,  stddev: 0.05  },
      lag1:    { mean: 0.666,  stddev: 0.02  },
      outlier: { mean: 0.0600, stddev: 0.000 },  // exactly 6% every run
      ejr:     { mean: 0.98,   stddev: 0.03  },
    },
    contributedBy: 'Aaron Miller (sovereign-pulse author)',
    date: '2026-03-22',
  },
  {
    id:       'aws-t3-micro-nitro',
    name:     'AWS EC2 t3.micro (Nitro)',
    class:    'cloud-vm-nitro',
    profile:  'near-physical',
    provider: 'nitro-aws',
    metrics: {
      cv:      { mean: 0.072,  stddev: 0.015 },
      hurst:   { mean: 0.41,   stddev: 0.06  },
      qe:      { mean: 2.8,    stddev: 0.20  },
      lag1:    { mean: 0.18,   stddev: 0.06  },
      outlier: { mean: 0.015,  stddev: 0.005 },
      ejr:     { mean: 1.01,   stddev: 0.04  },
    },
    contributedBy: 'community',
    date: '2026-03-22',
  },
  {
    id:       'gh200-datacenter',
    name:     'NVIDIA GH200 Grace Hopper Superchip (Datacenter VM)',
    class:    'datacenter-gpu-highend',
    profile:  'hypervisor-flat',
    provider: 'gh200-datacenter',
    metrics: {
      cv:      { mean: 0.045,  stddev: 0.008 },
      hurst:   { mean: 0.038,  stddev: 0.02  },
      qe:      { mean: 1.05,   stddev: 0.08  },
      lag1:    { mean: 0.72,   stddev: 0.03  },
      outlier: { mean: 0.060,  stddev: 0.000 },
      ejr:     { mean: 0.97,   stddev: 0.02  },
    },
    contributedBy: 'community',
    date: '2026-03-22',
    notes: 'Even 480GB RAM + GH200 is trapped by the hypervisor clock. ' +
           'The 0.72 lag-1 autocorr is the highest we have seen — the "heartbeat" ' +
           'of a heavily-shared compute cluster.',
  },
  {
    id:       'macbook-m3-pro',
    name:     'MacBook Pro M3 / macOS Sonoma',
    class:    'consumer-arm-laptop',
    profile:  'analog-fog',
    provider: 'physical',
    metrics: {
      cv:      { mean: 0.112,  stddev: 0.018 },
      hurst:   { mean: 0.53,   stddev: 0.07  },
      qe:      { mean: 3.20,   stddev: 0.18  },
      lag1:    { mean: 0.088,  stddev: 0.04  },
      outlier: { mean: 0.018,  stddev: 0.005 },
      ejr:     { mean: 1.12,   stddev: 0.07  },
    },
    contributedBy: 'community',
    date: '2026-03-22',
    notes: 'ARM efficiency cores have different thermal characteristics. ' +
           'Lower CV than x86 at same load due to Apple Silicon power management.',
  },
];

// ---------------------------------------------------------------------------
// serializeSignature
// ---------------------------------------------------------------------------

/**
 * Compress a Fingerprint's analysis into a portable, privacy-safe signature
 * that can be submitted to the SVRN registry.
 *
 * @param {import('../fingerprint.js').Fingerprint} fingerprint
 * @param {object} [meta]           - optional metadata to include
 * @param {string} [meta.hwLabel]   - human label e.g. "RTX 4090 / i9-13900K"
 * @param {string} [meta.osHint]    - e.g. "Windows 11" (no version details needed)
 * @returns {SvrnSignature}
 */
export function serializeSignature(fingerprint, meta = {}) {
  const m   = fingerprint.metrics();
  const raw = fingerprint._raw;

  // Bucket continuous metrics into coarse bins to prevent re-identification
  const sig = {
    version:   2,
    id:        null,  // computed below
    profile:   fingerprint.profile,
    provider:  fingerprint.providerId,
    class:     _hwClass(fingerprint),
    metrics: {
      cv:      _bucket(m.cv,                  [0.02, 0.06, 0.10, 0.15, 0.25, 0.40]),
      hurst:   _bucket(m.hurstExponent,       [0.10, 0.25, 0.40, 0.55, 0.70, 0.85]),
      qe:      _bucket(m.quantizationEntropy, [1.0,  1.5,  2.0,  2.5,  3.0,  4.0, 5.0]),
      lag1:    _bucket(Math.abs(m.autocorrLag1 ?? 0), [0.10, 0.20, 0.35, 0.50, 0.65]),
      outlier: _bucket(m.outlierRate,         [0.005, 0.01, 0.03, 0.06, 0.10]),
      ejr:     _bucket(m.entropyJitterRatio ?? 1, [0.93, 0.97, 1.02, 1.08, 1.15, 1.30]),
    },
    // Renderer class (not full string — too identifying)
    rendererClass: _rendererClass(raw.canvas?.webglRenderer, raw.canvas?.isSoftwareRenderer),
    isSynthetic:   fingerprint.isSynthetic,
    // Optional contributor metadata
    hwLabel:       meta.hwLabel   ?? null,
    osHint:        meta.osHint    ?? null,
    date:          new Date().toISOString().split('T')[0],
  };

  // Deterministic signature ID from the metric buckets
  sig.id = 'sig_' + blake3HexStr(JSON.stringify(sig.metrics) + sig.profile + sig.rendererClass).slice(0, 12);

  return sig;
}

/**
 * @typedef {object} SvrnSignature
 * @property {string}  version
 * @property {string}  id           - deterministic signature hash
 * @property {string}  profile      - timing profile type
 * @property {string}  provider     - detected provider
 * @property {string}  class        - hardware class
 * @property {object}  metrics      - bucketed metric values
 * @property {string}  rendererClass
 * @property {boolean} isSynthetic
 * @property {string|null} hwLabel
 * @property {string|null} osHint
 * @property {string}  date
 */

// ---------------------------------------------------------------------------
// matchRegistry
// ---------------------------------------------------------------------------

/**
 * Find the closest known profile in the registry for a given signature.
 *
 * @param {SvrnSignature} sig
 * @param {object[]}      [registry=KNOWN_PROFILES]
 * @returns {RegistryMatch}
 */
export function matchRegistry(sig, registry = KNOWN_PROFILES) {
  if (!registry.length) return { matched: false, profile: null, similarity: 0 };

  const scored = registry.map(known => {
    const km  = known.metrics;
    const sm  = sig.metrics;

    // Z-score similarity for each metric
    const sims = [
      _metricSim(sm.cv?.mid,      km.cv?.mean,      km.cv?.stddev),
      _metricSim(sm.hurst?.mid,   km.hurst?.mean,   km.hurst?.stddev),
      _metricSim(sm.qe?.mid,      km.qe?.mean,      km.qe?.stddev),
      _metricSim(sm.lag1?.mid,    km.lag1?.mean,     km.lag1?.stddev),
      _metricSim(sm.outlier?.mid, km.outlier?.mean,  km.outlier?.stddev),
    ].filter(v => v !== null);

    const avgSim = sims.length ? sims.reduce((a, b) => a + b, 0) / sims.length : 0;

    // Profile-match bonus
    const profileMatch   = sig.profile   === known.profile   ? 0.10 : 0;
    const providerMatch  = sig.provider  === known.provider  ? 0.10 : 0;

    return {
      profile:    known,
      similarity: Math.min(1, avgSim + profileMatch + providerMatch),
    };
  }).sort((a, b) => b.similarity - a.similarity);

  const best = scored[0];

  return {
    matched:     best.similarity > 0.5,
    profile:     best.profile,
    similarity:  _round(best.similarity, 3),
    alternatives: scored.slice(1, 3).map(s => ({
      name:       s.profile.name,
      similarity: _round(s.similarity, 3),
    })),
  };
}

/**
 * @typedef {object} RegistryMatch
 * @property {boolean}  matched
 * @property {object|null} profile   - matching known profile
 * @property {number}   similarity   - 0.0 – 1.0
 * @property {object[]} alternatives
 */

// ---------------------------------------------------------------------------
// compareSignatures
// ---------------------------------------------------------------------------

/**
 * Check if two signatures are from the same device class.
 * Useful for detecting when a bot submits two proofs that should match
 * but actually come from different VMs (load-balanced bot farm).
 *
 * @param {SvrnSignature} a
 * @param {SvrnSignature} b
 * @returns {{ sameClass: boolean, similarity: number }}
 */
export function compareSignatures(a, b) {
  const keys = ['cv', 'hurst', 'qe', 'lag1', 'outlier'];
  const sims = keys.map(k => {
    const am = a.metrics[k]?.mid;
    const bm = b.metrics[k]?.mid;
    if (am == null || bm == null) return null;
    const diff = Math.abs(am - bm);
    const scale = Math.max(Math.abs(am), Math.abs(bm), 0.001);
    return Math.max(0, 1 - diff / scale);
  }).filter(v => v !== null);

  const similarity = sims.length ? sims.reduce((a, b) => a + b, 0) / sims.length : 0;

  return {
    sameClass:  similarity > 0.75 && a.profile === b.profile,
    similarity: _round(similarity, 3),
    profileMatch: a.profile === b.profile,
    providerMatch: a.provider === b.provider,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Bucket a continuous value into a range with labeled boundaries.
 * Returns { lo, hi, mid, label } — enough to compare without exact values.
 */
function _bucket(value, boundaries) {
  if (value == null || !isFinite(value)) return null;
  for (let i = 0; i < boundaries.length; i++) {
    if (value < boundaries[i]) {
      const lo  = i === 0 ? 0 : boundaries[i - 1];
      const hi  = boundaries[i];
      return { lo, hi, mid: (lo + hi) / 2, label: `${lo}–${hi}` };
    }
  }
  const lo = boundaries[boundaries.length - 1];
  return { lo, hi: lo * 2, mid: lo * 1.5, label: `>${lo}` };
}

function _metricSim(val, mean, stddev) {
  if (val == null || mean == null || !stddev) return null;
  const z = Math.abs(val - mean) / stddev;
  // Gaussian similarity: 1 at z=0, near 0 at z≥3
  return Math.exp(-0.5 * z * z);
}

function _hwClass(fingerprint) {
  if (!fingerprint.isSynthetic) {
    const r = fingerprint._raw.canvas?.webglRenderer?.toLowerCase() ?? '';
    if (r.includes('apple'))              return 'consumer-arm-laptop';
    if (r.includes('radeon'))             return 'consumer-gpu-amd';
    if (r.includes('geforce') || r.includes('nvidia')) return 'consumer-gpu-nvidia';
    if (r.includes('intel'))              return 'consumer-igpu-intel';
    return 'consumer-unknown';
  }
  const p = fingerprint.providerId;
  if (p.includes('nitro'))               return 'cloud-vm-nitro';
  if (p.includes('gh200'))               return 'datacenter-gpu-highend';
  if (p.includes('digitalocean'))        return 'cloud-vm-budget';
  if (p.includes('aws'))                 return 'cloud-vm-aws';
  if (p.includes('gcp'))                 return 'cloud-vm-gcp';
  if (p.includes('vmware'))              return 'cloud-vm-vmware';
  return 'cloud-vm-generic';
}

function _rendererClass(renderer = '', isSoftware = false) {
  if (isSoftware)                return 'software';
  const r = renderer.toLowerCase();
  if (r.includes('apple'))       return 'apple-metal';
  if (r.includes('geforce'))     return 'nvidia-consumer';
  if (r.includes('radeon'))      return 'amd-consumer';
  if (r.includes('intel'))       return 'intel-igpu';
  if (r.includes('quadro') || r.includes('tesla') || r.includes('a100') ||
      r.includes('h100') || r.includes('gh200')) return 'nvidia-datacenter';
  return 'unknown';
}

function _round(v, d) {
  if (v == null) return null;
  const f = 10 ** d;
  return Math.round(v * f) / f;
}

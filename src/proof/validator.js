/**
 * @svrnsec/pulse — Server-Side Validator
 *
 * Verifies a ProofPayload + BLAKE3 commitment received from the client.
 * This module is for NODE.JS / SERVER use only.
 */

import { blake3 }        from '@noble/hashes/blake3';
import { bytesToHex }    from '@noble/hashes/utils';
import { randomFillSync, timingSafeEqual } from 'node:crypto';
import { canonicalJson } from './fingerprint.js';
import { computeServerDynamicThreshold } from '../analysis/coherence.js';

// ---------------------------------------------------------------------------
// Known software / virtual renderer patterns
// ---------------------------------------------------------------------------
const VM_RENDERER_BLOCKLIST = [
  'llvmpipe', 'swiftshader', 'softpipe', 'mesa offscreen',
  'microsoft basic render', 'vmware svga', 'vmware', 'virtualbox',
  'parallels', 'chromium swiftshader', 'google swiftshader',
  'cirrussm', 'qxl', 'virtio', 'bochs',
  'nvidia t4', 'nvidia a10g', 'nvidia a100', 'nvidia h100',
  'nvidia h200', 'nvidia b100', 'nvidia b200', 'nvidia gh200',
  'amd instinct', 'amd mi300', 'amd mi250', 'amd mi200',
  'aws inferentia', 'aws trainium', 'google tpu',
];

// ANGLE with software backend — match only software variants, not real hardware through ANGLE
const VM_RENDERER_REGEX = [
  /angle\s*\(.*software/i,
];

// ---------------------------------------------------------------------------
// Recursive prototype pollution guard
// ---------------------------------------------------------------------------
function _checkProtoPollution(obj, depth = 0) {
  if (depth > 10 || obj === null || typeof obj !== 'object') return false;
  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (_checkProtoPollution(item, depth + 1)) return true;
    }
    return false;
  }
  if (
    Object.prototype.hasOwnProperty.call(obj, '__proto__') ||
    Object.prototype.hasOwnProperty.call(obj, 'constructor') ||
    Object.prototype.hasOwnProperty.call(obj, 'prototype')
  ) {
    return true;
  }
  for (const key of Object.keys(obj)) {
    if (typeof obj[key] === 'object' && obj[key] !== null) {
      if (_checkProtoPollution(obj[key], depth + 1)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// validateProof
// ---------------------------------------------------------------------------

/**
 * @param {import('./fingerprint.js').ProofPayload} payload
 * @param {string}  receivedHash
 * @param {object}  [opts]
 * @param {number}  [opts.minJitterScore=0.55]
 * @param {number}  [opts.maxAgeMs=300_000]
 * @param {number}  [opts.clockSkewMs=30_000]
 * @param {boolean} [opts.requireBio=false]
 * @param {boolean} [opts.blockSoftwareRenderer=true]
 * @param {Function} [opts.checkNonce]
 * @returns {Promise<ValidationResult>}
 */
export async function validateProof(payload, receivedHash, opts = {}) {
  const {
    minJitterScore        = 0.55,
    maxAgeMs              = 300_000,
    clockSkewMs           = 30_000,
    requireBio            = false,
    blockSoftwareRenderer = true,
    checkNonce            = null,
  } = opts;

  const reasons   = [];
  const riskFlags = [];
  let   valid     = true;

  // ── 0. Strict payload structure validation ────────────────────────────────
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return _reject(['INVALID_PAYLOAD_STRUCTURE']);
  }

  // Recursive prototype pollution guard — checks all nested objects
  if (_checkProtoPollution(payload)) {
    return _reject(['PROTOTYPE_POLLUTION_ATTEMPT']);
  }

  // Required top-level fields
  const REQUIRED_TOP = ['version', 'timestamp', 'nonce', 'signals', 'classification'];
  for (const field of REQUIRED_TOP) {
    if (!(field in payload)) {
      return _reject([`MISSING_REQUIRED_FIELD:${field}`]);
    }
  }

  // Type assertions
  if (typeof payload.version !== 'number')   return _reject(['INVALID_TYPE:version']);
  if (typeof payload.timestamp !== 'number') return _reject(['INVALID_TYPE:timestamp']);
  if (typeof payload.nonce !== 'string')     return _reject(['INVALID_TYPE:nonce']);
  if (typeof payload.signals !== 'object' || Array.isArray(payload.signals)) {
    return _reject(['INVALID_TYPE:signals']);
  }
  if (typeof payload.classification !== 'object' || Array.isArray(payload.classification)) {
    return _reject(['INVALID_TYPE:classification']);
  }

  const TS_MIN = 1_577_836_800_000;
  const TS_MAX = 4_102_444_800_000;
  if (payload.timestamp < TS_MIN || payload.timestamp > TS_MAX) {
    return _reject(['TIMESTAMP_OUT_OF_RANGE']);
  }

  if (payload.version !== 1) {
    return _reject(['UNSUPPORTED_PROOF_VERSION']);
  }

  // ── 1. Hash integrity (timing-safe comparison) ────────────────────────────
  if (typeof receivedHash !== 'string' || !/^[0-9a-f]{64}$/.test(receivedHash)) {
    return _reject(['INVALID_HASH_FORMAT']);
  }
  const canonical = canonicalJson(payload);
  const enc       = new TextEncoder().encode(canonical);
  const computed  = bytesToHex(blake3(enc));

  try {
    const computedBuf  = Buffer.from(computed,     'hex');
    const receivedBuf  = Buffer.from(receivedHash, 'hex');
    if (computedBuf.length !== receivedBuf.length || !timingSafeEqual(computedBuf, receivedBuf)) {
      return _reject(['HASH_MISMATCH_PAYLOAD_TAMPERED']);
    }
  } catch {
    return _reject(['HASH_MISMATCH_PAYLOAD_TAMPERED']);
  }

  // ── 2. Timestamp recency ──────────────────────────────────────────────────
  const now     = Date.now();
  const age     = now - payload.timestamp;
  if (age > maxAgeMs) {
    valid = false;
    reasons.push(`PROOF_EXPIRED: age=${Math.round(age / 1000)}s, max=${maxAgeMs / 1000}s`);
  }
  if (payload.timestamp > now + clockSkewMs) {
    valid = false;
    reasons.push('PROOF_FROM_FUTURE');
  }

  // ── 3. Nonce freshness ────────────────────────────────────────────────────
  let nonceChecked = false;
  if (checkNonce) {
    nonceChecked = true;
    const nonceOk = await checkNonce(payload.nonce);
    if (!nonceOk) {
      valid = false;
      reasons.push('NONCE_INVALID_OR_REPLAYED');
    }
  } else {
    riskFlags.push('NONCE_FRESHNESS_NOT_CHECKED');
  }

  // ── 4. Jitter score ───────────────────────────────────────────────────────
  const jitterScore = payload.classification?.jitterScore ?? 0;
  if (jitterScore < minJitterScore) {
    valid = false;
    reasons.push(`JITTER_SCORE_TOO_LOW: ${jitterScore} < ${minJitterScore}`);
  }

  // ── 4b. Dynamic threshold — server recomputes from raw signals, not client finalScore
  const serverDynamicMin = computeServerDynamicThreshold(payload);
  if (jitterScore < serverDynamicMin) {
    valid = false;
    reasons.push(
      `DYNAMIC_THRESHOLD_NOT_MET: jitterScore=${jitterScore} < ` +
      `serverMin=${serverDynamicMin} (evidenceWeight=${
        _computeEvidenceWeight(payload).toFixed(3)
      })`
    );
  }

  // Surface diagnostic flags from the client's classifier
  for (const flag of (payload.classification?.flags ?? [])) {
    if (flag.includes('VM') || flag.includes('FLAT') || flag.includes('SYNTHETIC')) {
      riskFlags.push(`CLIENT_FLAG:${flag}`);
    }
  }

  // Hard override from heuristic engine (stage 2)
  if (payload.heuristic?.hardOverride === 'vm') {
    valid = false;
    reasons.push(
      `HEURISTIC_HARD_OVERRIDE: stage-2 EJR/QE mathematical contradiction — ` +
      `${(payload.heuristic.coherenceFlags ?? []).join(', ')}`
    );
  }

  // Hard override from coherence stage (stage 3)
  if (payload.coherence?.hardOverride === 'vm') {
    valid = false;
    reasons.push(
      `COHERENCE_HARD_OVERRIDE: stage-3 analysis detected a mathematical ` +
      `impossibility — ${(payload.coherence.coherenceFlags ?? []).join(', ')}`
    );
  }

  // Surface all coherence flags for risk tracking
  for (const flag of (payload.heuristic?.coherenceFlags ?? [])) {
    riskFlags.push(`HEURISTIC:${flag}`);
  }
  for (const flag of (payload.coherence?.coherenceFlags ?? [])) {
    riskFlags.push(`COHERENCE:${flag}`);
  }

  // ── 5. Canvas / WebGL renderer check ──────────────────────────────────────
  const canvas = payload.signals?.canvas;
  if (canvas) {
    if (canvas.isSoftwareRenderer && blockSoftwareRenderer) {
      valid = false;
      reasons.push(`SOFTWARE_RENDERER_DETECTED: ${canvas.webglRenderer}`);
    }
    const rendererLc = (canvas.webglRenderer ?? '').toLowerCase();
    // Check substring patterns
    for (const pattern of VM_RENDERER_BLOCKLIST) {
      if (rendererLc.includes(pattern)) {
        valid = false;
        reasons.push(`BLOCKLISTED_RENDERER: ${canvas.webglRenderer}`);
        riskFlags.push(`RENDERER_MATCH:${pattern}`);
        break;
      }
    }
    // Check regex patterns (e.g. ANGLE software)
    for (const re of VM_RENDERER_REGEX) {
      if (re.test(rendererLc)) {
        valid = false;
        reasons.push(`BLOCKLISTED_RENDERER: ${canvas.webglRenderer}`);
        riskFlags.push('RENDERER_MATCH:angle_software');
        break;
      }
    }
    if (!canvas.available) {
      riskFlags.push('CANVAS_UNAVAILABLE');
    }
  }

  // ── 6. Bio activity ───────────────────────────────────────────────────────
  const bio = payload.signals?.bio;
  if (bio) {
    if (requireBio && !bio.hasActivity) {
      valid = false;
      reasons.push('NO_BIO_ACTIVITY_DETECTED');
    }
    if (bio.mouseSampleCount === 0 && bio.keyboardSampleCount === 0) {
      riskFlags.push('ZERO_BIO_SAMPLES');
    }
    if (bio.interferenceCoefficient < -0.3) {
      riskFlags.push('NEGATIVE_INTERFERENCE_COEFFICIENT');
    }
  }

  // ── 7. Internal consistency checks ────────────────────────────────────────
  const entropy = payload.signals?.entropy;
  if (entropy) {
    if (entropy.timingsCV < 0.01 && jitterScore > 0.7) {
      riskFlags.push('INCONSISTENCY:LOW_CV_BUT_HIGH_SCORE');
    }
    if (entropy.timerGranularityMs === 0) {
      riskFlags.push('SUSPICIOUS_ZERO_TIMER_GRANULARITY');
    }
    if (entropy.thermalPattern === 'flat' && jitterScore > 0.8) {
      riskFlags.push('INCONSISTENCY:FLAT_THERMAL_BUT_HIGH_SCORE');
    }
    if (entropy.hurstExponent != null) {
      if (entropy.hurstExponent < 0.2 || entropy.hurstExponent > 0.85) {
        riskFlags.push(`EXTREME_HURST:${entropy.hurstExponent}`);
      }
    }
  }

  // ── 7b. Cross-signal physics forgery detection ────────────────────────────
  if (entropy) {
    const cv   = entropy.timingsCV        ?? null;
    const qe   = entropy.quantizationEntropy ?? null;
    const lag1 = entropy.autocorr_lag1    ?? null;

    if (cv !== null && cv < 0.015 && jitterScore > 0.65) {
      valid = false;
      reasons.push(
        `FORGED_SIGNAL:CV_SCORE_IMPOSSIBLE cv=${cv.toFixed(5)} is hypervisor-flat ` +
        `but jitterScore=${jitterScore.toFixed(3)} claims physical hardware`
      );
    }

    if (lag1 !== null && lag1 > 0.70 && jitterScore > 0.70) {
      valid = false;
      reasons.push(
        `FORGED_SIGNAL:AUTOCORR_SCORE_IMPOSSIBLE lag1=${lag1.toFixed(3)} is VM-level ` +
        `but jitterScore=${jitterScore.toFixed(3)} claims physical hardware`
      );
    }

    if (qe !== null && qe < 2.0 && jitterScore > 0.65) {
      valid = false;
      reasons.push(
        `FORGED_SIGNAL:QE_SCORE_IMPOSSIBLE qe=${qe.toFixed(3)} bits is VM-level ` +
        `but jitterScore=${jitterScore.toFixed(3)} claims physical hardware`
      );
    }
  }

  // ── 8. Audio signal check ─────────────────────────────────────────────────
  const audio = payload.signals?.audio;
  if (audio?.available) {
    if (audio.callbackJitterCV < 0.001) {
      riskFlags.push('AUDIO_JITTER_TOO_FLAT');
    }
  }

  // ── Confidence rating ─────────────────────────────────────────────────────
  let confidence;
  if (!valid) {
    confidence = 'rejected';
  } else if (!nonceChecked) {
    // Without nonce verification, confidence cannot be higher than 'low'
    confidence = 'low';
  } else if (riskFlags.length === 0 && jitterScore >= 0.75) {
    confidence = 'high';
  } else if (riskFlags.length <= 2 && jitterScore >= 0.60) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }

  return {
    valid,
    score:      jitterScore,
    confidence,
    reasons,
    riskFlags,
    meta: {
      receivedAt:   now,
      proofAge:     age,
      jitterScore,
      canvasRenderer: canvas?.webglRenderer ?? null,
      bioActivity:    bio?.hasActivity ?? false,
    },
  };
}

/** @typedef {object} ValidationResult */

// ---------------------------------------------------------------------------
// generateNonce
// ---------------------------------------------------------------------------

export function generateNonce() {
  let buf;
  if (typeof globalThis.crypto?.getRandomValues === 'function') {
    buf = new Uint8Array(32);
    globalThis.crypto.getRandomValues(buf);
  } else {
    buf = new Uint8Array(32);
    randomFillSync(buf);
  }
  return bytesToHex(buf);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _reject(reasons) {
  return {
    valid:      false,
    score:      0,
    confidence: 'rejected',
    reasons,
    riskFlags:  [],
    meta:       {},
  };
}

function _computeEvidenceWeight(payload) {
  const n         = payload?.signals?.entropy?.iterations ?? 0;
  const hasPhases = payload?.heuristic?.entropyJitterRatio != null;
  const hasBio    = payload?.signals?.bio?.hasActivity === true;
  const hasAudio  = payload?.signals?.audio?.available === true;
  const hasCanvas = payload?.signals?.canvas?.available === true;
  return Math.min(1.0,
    Math.min(1.0, n / 200) * 0.65 +
    (hasPhases ? 0.15 : 0) +
    (hasBio    ? 0.10 : 0) +
    (hasAudio  ? 0.05 : 0) +
    (hasCanvas ? 0.05 : 0)
  );
}

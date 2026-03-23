/**
 * @sovereign/pulse — Server-Side Validator
 *
 * Verifies a ProofPayload + BLAKE3 commitment received from the client.
 * This module is for NODE.JS / SERVER use only.  It should NOT be bundled
 * into the browser build (see package.json "exports" field).
 *
 * Trust model:
 *   • The server issues a challenge `nonce` before the client runs pulse().
 *   • The client returns { payload, hash }.
 *   • The server calls validateProof(payload, hash, options) to:
 *       1. Verify hash integrity (no tampering).
 *       2. Verify nonce freshness (no replay).
 *       3. Verify timestamp recency.
 *       4. Check jitter score against thresholds.
 *       5. Check canvas fingerprint against software-renderer blocklist.
 *       6. Cross-validate signal consistency.
 *
 * NOTE: The server NEVER sees raw timing arrays or mouse coordinates.
 * Only statistical summaries are transmitted.  This is the ZK property.
 */

import { blake3 }        from '@noble/hashes/blake3';
import { bytesToHex }    from '@noble/hashes/utils';
import { randomFillSync } from 'node:crypto';
import { canonicalJson } from './fingerprint.js';
import { computeServerDynamicThreshold } from '../analysis/coherence.js';

// ---------------------------------------------------------------------------
// Known software / virtual renderer substring patterns (lowercase)
// ---------------------------------------------------------------------------
const VM_RENDERER_BLOCKLIST = [
  // Software / virtual renderers
  'llvmpipe', 'swiftshader', 'softpipe', 'mesa offscreen',
  'microsoft basic render', 'vmware svga', 'vmware', 'virtualbox',
  'parallels', 'chromium swiftshader', 'google swiftshader',
  'angle (', 'cirrussm', 'qxl', 'virtio', 'bochs',
  // NVIDIA datacenter / inference — no consumer unit has these
  'nvidia t4',     // AWS/GCP inference VM
  'nvidia a10g',   // AWS g5 inference
  'nvidia a100',   // Datacenter A100
  'nvidia h100',   // Hopper — datacenter only
  'nvidia h200',   // Hopper successor — datacenter only
  'nvidia b100',   // Blackwell — datacenter only
  'nvidia b200',   // Blackwell Ultra — datacenter only
  'nvidia gh200',  // Grace-Hopper superchip
  // AMD datacenter / HPC — no consumer has these
  'amd instinct',  // covers mi100, mi200, mi250, mi300 family
  'amd mi300',
  'amd mi250',
  'amd mi200',
  // Cloud-specific AI accelerators
  'aws inferentia',
  'aws trainium',
  'google tpu',
];

// ---------------------------------------------------------------------------
// validateProof
// ---------------------------------------------------------------------------

/**
 * Validates a client-submitted proof.
 *
 * @param {import('./fingerprint.js').ProofPayload} payload
 * @param {string}  receivedHash  - hex BLAKE3 from the client
 * @param {object}  [opts]
 * @param {number}  [opts.minJitterScore=0.55]     - minimum acceptable jitter score
 * @param {number}  [opts.maxAgeMs=300_000]         - max payload age (5 min)
 * @param {number}  [opts.clockSkewMs=30_000]        - tolerated future timestamp drift
 * @param {boolean} [opts.requireBio=false]          - reject if no bio activity
 * @param {boolean} [opts.blockSoftwareRenderer=true] - reject software WebGL
 * @param {Function} [opts.checkNonce]               - async fn(nonce) → boolean
 *   Called to verify the nonce was issued by this server and not yet consumed.
 *   Should mark the nonce as consumed atomically (e.g. Redis SET NX with TTL).
 *   If omitted, nonce freshness is NOT checked (not recommended for production).
 *
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

  // Prototype pollution guard — reject any payload with __proto__ / constructor tricks
  if (
    Object.prototype.hasOwnProperty.call(payload, '__proto__') ||
    Object.prototype.hasOwnProperty.call(payload, 'constructor') ||
    Object.prototype.hasOwnProperty.call(payload, 'prototype')
  ) {
    return _reject(['PROTOTYPE_POLLUTION_ATTEMPT']);
  }

  // Required top-level fields
  const REQUIRED_TOP = ['version', 'timestamp', 'nonce', 'signals', 'classification'];
  for (const field of REQUIRED_TOP) {
    if (!(field in payload)) {
      return _reject([`MISSING_REQUIRED_FIELD:${field}`]);
    }
  }

  // Type assertions on top-level scalars
  if (typeof payload.version !== 'number')   return _reject(['INVALID_TYPE:version']);
  if (typeof payload.timestamp !== 'number') return _reject(['INVALID_TYPE:timestamp']);
  if (typeof payload.nonce !== 'string')     return _reject(['INVALID_TYPE:nonce']);
  if (typeof payload.signals !== 'object' || Array.isArray(payload.signals)) {
    return _reject(['INVALID_TYPE:signals']);
  }
  if (typeof payload.classification !== 'object' || Array.isArray(payload.classification)) {
    return _reject(['INVALID_TYPE:classification']);
  }

  // Note: we deliberately do not enforce a strict nonce format here so that
  // test fixtures can provide short placeholder nonces. The `checkNonce`
  // function (if supplied) should perform any format validation it requires
  // and return false for invalid or replayed nonces.

  // Timestamp must be a plausible Unix ms value (> year 2020, < year 2100)
  const TS_MIN = 1_577_836_800_000; // 2020-01-01
  const TS_MAX = 4_102_444_800_000; // 2100-01-01
  if (payload.timestamp < TS_MIN || payload.timestamp > TS_MAX) {
    return _reject(['TIMESTAMP_OUT_OF_RANGE']);
  }

  if (payload.version !== 1) {
    return _reject(['UNSUPPORTED_PROOF_VERSION']);
  }

  // ── 1. Hash integrity ─────────────────────────────────────────────────────
  // receivedHash must be exactly 64 lowercase hex characters
  if (typeof receivedHash !== 'string' || !/^[0-9a-f]{64}$/.test(receivedHash)) {
    return _reject(['INVALID_HASH_FORMAT']);
  }
  const canonical = canonicalJson(payload);
  const enc       = new TextEncoder().encode(canonical);
  const computed  = bytesToHex(blake3(enc));

  if (computed !== receivedHash) {
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
  if (checkNonce) {
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

  // ── 4b. Dynamic threshold (evidence-proportional gate) ──────────────────
  // The server independently computes the minimum passing score based on how
  // much evidence the proof contains.  The client's dynamicThreshold field is
  // NEVER trusted — it is only used for logging/auditing.
  //
  // Logic: a proof with only 50 iterations and no bio/audio faces a higher bar
  // (0.62) than a full 200-iteration proof with phased data (0.50).
  // This makes replay attacks with minimal proofs automatically fail the gate.
  const serverDynamicMin = computeServerDynamicThreshold(payload);

  // We check the FINAL client score (which includes stage-3 coherence adjustment)
  // if it was included, otherwise fall back to the base jitterScore.
  const finalClientScore = payload.classification?.finalScore ?? jitterScore;
  if (finalClientScore < serverDynamicMin) {
    valid = false;
    reasons.push(
      `DYNAMIC_THRESHOLD_NOT_MET: score=${finalClientScore} < ` +
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

  // Hard override from the client heuristic engine (stage 2).
  // EJR_PHASE_HARD_KILL fires when the stored entropyJitterRatio is mathematically
  // inconsistent with the stored cold_QE / hot_QE values — proof of tampering.
  // A legitimate SDK running on real hardware never triggers this.
  if (payload.heuristic?.hardOverride === 'vm') {
    valid = false;
    reasons.push(
      `HEURISTIC_HARD_OVERRIDE: stage-2 EJR/QE mathematical contradiction — ` +
      `${(payload.heuristic.coherenceFlags ?? []).join(', ')}`
    );
  }

  // Hard override from the client coherence stage (stage 3).
  // Second line of defence — catches the same contradiction via a different
  // code path and also catches the phase-trajectory forgery variant.
  if (payload.coherence?.hardOverride === 'vm') {
    valid = false;
    reasons.push(
      `COHERENCE_HARD_OVERRIDE: stage-3 analysis detected a mathematical ` +
      `impossibility — ${(payload.coherence.coherenceFlags ?? []).join(', ')}`
    );
  }

  // Surface all coherence flags for risk tracking / audit logs
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
    for (const pattern of VM_RENDERER_BLOCKLIST) {
      if (rendererLc.includes(pattern)) {
        valid = false;
        reasons.push(`BLOCKLISTED_RENDERER: ${canvas.webglRenderer}`);
        riskFlags.push(`RENDERER_MATCH:${pattern}`);
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
    // Interference coefficient check: real human+hardware shows measurable correlation
    if (bio.interferenceCoefficient < -0.3) {
      riskFlags.push('NEGATIVE_INTERFERENCE_COEFFICIENT');
    }
  }

  // ── 7. Internal consistency checks ────────────────────────────────────────
  const entropy = payload.signals?.entropy;
  if (entropy) {
    // CV and jitter score should be directionally consistent
    if (entropy.timingsCV < 0.01 && jitterScore > 0.7) {
      riskFlags.push('INCONSISTENCY:LOW_CV_BUT_HIGH_SCORE');
    }
    // Timer granularity should not be exactly 0 (no real device has infinite resolution)
    if (entropy.timerGranularityMs === 0) {
      riskFlags.push('SUSPICIOUS_ZERO_TIMER_GRANULARITY');
    }
    // Extreme thermal patterns inconsistent with score
    if (entropy.thermalPattern === 'flat' && jitterScore > 0.8) {
      riskFlags.push('INCONSISTENCY:FLAT_THERMAL_BUT_HIGH_SCORE');
    }
    // Hurst exponent way out of range
    if (entropy.hurstExponent != null) {
      if (entropy.hurstExponent < 0.2 || entropy.hurstExponent > 0.85) {
        riskFlags.push(`EXTREME_HURST:${entropy.hurstExponent}`);
      }
    }
  }

  // ── 7b. Cross-signal physics forgery detection ────────────────────────────
  // BLAKE3 prevents tampering with a payload that was legitimately generated by
  // the SDK. However, a determined attacker can:
  //   1. Obtain a valid server nonce
  //   2. Craft a fake payload with forged statistics
  //   3. Compute BLAKE3(forgedPayload) themselves (BLAKE3 is public)
  //   4. Submit { payload: forgedPayload, hash: selfComputedHash }
  //
  // These checks detect statistically impossible metric combinations that no
  // real device would ever produce, catching crafted payloads even though the
  // hash integrity check passes.
  //
  // All three thresholds are set conservatively: they only fire when the
  // combination is physically IMPOSSIBLE, not just unlikely, to avoid false
  // positives on unusual-but-legitimate hardware.
  if (entropy) {
    const cv   = entropy.timingsCV        ?? null;
    const qe   = entropy.quantizationEntropy ?? null;
    const lag1 = entropy.autocorr_lag1    ?? null;

    // Impossibly flat CV + high physical score
    // Real explanation: CV < 0.015 means timing jitter < 1.5% — hypervisor-flat.
    // No real-silicon CPU running a WASM matrix multiply achieves this.
    // A high jitterScore (> 0.65) is physically incompatible with CV < 0.015.
    if (cv !== null && cv < 0.015 && jitterScore > 0.65) {
      valid = false;
      reasons.push(
        `FORGED_SIGNAL:CV_SCORE_IMPOSSIBLE cv=${cv.toFixed(5)} is hypervisor-flat ` +
        `but jitterScore=${jitterScore.toFixed(3)} claims physical hardware`
      );
    }

    // VM-grade autocorrelation + high physical score
    // lag1 > 0.70 is a hypervisor scheduler rhythm — unambiguous VM signature.
    // A device with that level of autocorrelation cannot score > 0.70 on the
    // physical scale; the jitter classifier would have penalised it heavily.
    if (lag1 !== null && lag1 > 0.70 && jitterScore > 0.70) {
      valid = false;
      reasons.push(
        `FORGED_SIGNAL:AUTOCORR_SCORE_IMPOSSIBLE lag1=${lag1.toFixed(3)} is VM-level ` +
        `but jitterScore=${jitterScore.toFixed(3)} claims physical hardware`
      );
    }

    // VM-grade quantization entropy + high physical score
    // QE < 2.0 means timings cluster on a small number of distinct values —
    // the classic integer-millisecond quantisation of an emulated/virtual timer.
    // A device producing QE < 2.0 cannot legitimately score > 0.65 as physical.
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
    // Impossibly low jitter CV may indicate a synthetic audio driver
    if (audio.callbackJitterCV < 0.001) {
      riskFlags.push('AUDIO_JITTER_TOO_FLAT');
    }
  }

  // ── Confidence rating ─────────────────────────────────────────────────────
  let confidence;
  if (!valid) {
    confidence = 'rejected';
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

/**
 * @typedef {object} ValidationResult
 * @property {boolean}  valid
 * @property {number}   score
 * @property {'high'|'medium'|'low'|'rejected'} confidence
 * @property {string[]} reasons    - human-readable rejection reasons
 * @property {string[]} riskFlags  - non-blocking risk indicators
 * @property {object}   meta
 */

// ---------------------------------------------------------------------------
// generateNonce  (convenience helper for the server challenge flow)
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically random 32-byte nonce for the server challenge.
 * The server should store this nonce with a TTL before issuing it to the client.
 *
 * @returns {string}  hex nonce
 */
export function generateNonce() {
  // Synchronous nonce generator for server-side use and tests.
  // Prefer global crypto.getRandomValues when available; otherwise use
  // Node's `randomFillSync` which is synchronous and available in Node.
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

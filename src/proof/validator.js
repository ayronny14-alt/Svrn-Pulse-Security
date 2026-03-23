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
import { canonicalJson } from './fingerprint.js';

// ---------------------------------------------------------------------------
// Known software / virtual renderer substring patterns (lowercase)
// ---------------------------------------------------------------------------
const VM_RENDERER_BLOCKLIST = [
  'llvmpipe', 'swiftshader', 'softpipe', 'mesa offscreen',
  'microsoft basic render', 'vmware svga', 'vmware', 'virtualbox',
  'parallels', 'chromium swiftshader', 'google swiftshader',
  'angle (', 'cirrussm', 'qxl', 'virtio', 'bochs',
  // Cloud GPU shadows
  'nvidia t4',     // AWS/GCP inference VM
  'nvidia a10g',   // AWS g5 inference
  'nvidia a100',   // Datacenter-exclusive, no consumer has these
  'nvidia h100',
  'amd instinct',
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

  // ── 0. Basic payload structure validation ─────────────────────────────────
  if (!payload || typeof payload !== 'object') {
    return _reject(['INVALID_PAYLOAD_STRUCTURE']);
  }
  if (payload.version !== 1) {
    return _reject(['UNSUPPORTED_PROOF_VERSION']);
  }

  // ── 1. Hash integrity ─────────────────────────────────────────────────────
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

  // Surface diagnostic flags from the client's classifier
  for (const flag of (payload.classification?.flags ?? [])) {
    if (flag.includes('VM') || flag.includes('FLAT') || flag.includes('SYNTHETIC')) {
      riskFlags.push(`CLIENT_FLAG:${flag}`);
    }
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
  const buf = new Uint8Array(32);
  // Node.js crypto.getRandomValues (via globalThis) or the crypto module
  if (typeof globalThis.crypto?.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(buf);
  } else {
    // Node.js < 19 fallback
    const { randomBytes } = require('node:crypto'); // eslint-disable-line
    randomBytes(32).copy(Buffer.from(buf.buffer));
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

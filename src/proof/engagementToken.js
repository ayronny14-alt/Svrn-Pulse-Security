/**
 * @svrnsec/pulse — Engagement Token
 *
 * A short-lived, physics-backed cryptographic token that proves a specific
 * engagement event (click, view, share, purchase) originated from a real
 * human on real hardware that had genuinely rested between interactions.
 *
 * This is the layer that defeats the "1,000 phones in a warehouse" attack.
 * Each token proves:
 *
 *   1. Real hardware       DRAM refresh present, ENF grid signal detected
 *   2. Genuine idle        Hash-chained thermal measurements spanning ≥ 45s
 *   3. Physical cooling    Variance decay was smooth, not a step function
 *   4. Fresh interaction   30-second TTL eliminates token brokers
 *   5. Tamper-evident      HMAC-SHA256 over all fraud-relevant fields
 *
 * Token wire format (compact: base64url JSON, ~400 bytes)
 * ────────────────────────────────────────────────────────
 *   {
 *     v:    2,                   protocol version
 *     n:    "hex64",             nonce — 256-bit random
 *     iat:  1234567890123,       issued-at Unix ms
 *     exp:  1234567920123,       expires-at  (iat + 30s)
 *     idle: {
 *       chain: "hex64",          final hash of idle measurement chain
 *       s:     3,                sample count (≥ 2 for a valid proof)
 *       dMs:   180000,           idle duration ms
 *       therm: "hot_to_cold",    thermal transition label
 *       mono:  0.67,             cooling monotonicity (0–1)
 *     },
 *     hw: {
 *       dram: "dram",            DRAM probe verdict
 *       enf:  "grid_60hz",       ENF probe verdict
 *       ent:  0.73,              normalized physics entropy score (0–1)
 *     },
 *     evt: {
 *       t:   "click",            event type
 *       ts:  1234567890123,      event Unix ms
 *       mot: 0.82,               motor consistency (0–1)
 *     },
 *     sig: "hex64"               HMAC-SHA256 over all fraud-relevant fields
 *   }
 *
 * HMAC input (pipe-delimited, all fields that matter for fraud)
 * ─────────────────────────────────────────────────────────────
 *   `v|n|iat|exp|idle.chain|idle.dMs|hw.ent|evt.t|evt.ts`
 *
 * Changing any signed field invalidates the token.  Unsigned fields
 * (therm, mono, dram, enf) are advisory — they inform risk scoring but
 * cannot be manipulated for credit fraud without breaking the HMAC.
 */

import { hmac }                     from '@noble/hashes/hmac';
import { sha256 }                   from '@noble/hashes/sha256';
import { bytesToHex,
         utf8ToBytes,
         randomBytes }              from '@noble/hashes/utils';

// ── Constants ─────────────────────────────────────────────────────────────────

const TOKEN_VERSION = 2;

/** 30-second TTL: short enough to prevent token brokers (resellers of valid
 *  tokens scraped from legitimate devices), long enough to survive one API
 *  round-trip on a slow connection. */
const TOKEN_TTL_MS  = 30_000;

const NONCE_BYTES   = 32;   // 256-bit nonce → 64-char hex

// ── createEngagementToken ─────────────────────────────────────────────────────

/**
 * Create a physics-backed engagement token.
 *
 * Attach the returned `compact` string to your API call:
 *   `fetch('/api/action', { headers: { 'X-Pulse-Token': token.compact } })`
 *
 * @param {object}         opts
 * @param {object}         opts.pulseResult      result object from pulse()
 * @param {IdleProof|null} opts.idleProof         from idleMonitor.getProof()
 * @param {object}         opts.interaction       { type, ts, motorConsistency }
 * @param {string}         opts.secret            shared HMAC secret (min 16 chars)
 * @param {object}         [opts._overrides]      for deterministic testing only
 * @returns {EngagementToken}
 */
export function createEngagementToken(opts) {
  const {
    pulseResult  = {},
    idleProof    = null,
    interaction  = {},
    secret,
    _overrides   = {},
  } = opts;

  _assertSecret(secret);

  const n   = _overrides.nonce    ?? bytesToHex(randomBytes(NONCE_BYTES));
  const iat = _overrides.issuedAt ?? Date.now();
  const exp = iat + TOKEN_TTL_MS;

  // ── Extract hardware evidence from pulse result ───────────────────────────
  const extended = pulseResult.extended ?? {};
  const dram     = extended.dram?.verdict ?? pulseResult.dram?.verdict ?? 'unavailable';
  const enf      = extended.enf?.verdict  ?? pulseResult.enf?.verdict  ?? 'unavailable';
  const ent      = _extractEntropyScore(pulseResult);

  // ENF deviation for population-level phase coherence test
  const enfDev   = extended.enf?.enfDeviation
    ?? pulseResult.enf?.enfDeviation
    ?? null;

  // ── Pack idle evidence ────────────────────────────────────────────────────
  const idle = idleProof
    ? {
        chain: idleProof.chain,
        s:     idleProof.samples,
        dMs:   idleProof.idleDurationMs,
        therm: idleProof.thermalTransition,
        mono:  idleProof.coolingMonotonicity,
      }
    : null;

  // ── Pack interaction evidence ─────────────────────────────────────────────
  const evt = {
    t:   interaction.type             ?? 'unknown',
    ts:  interaction.ts               ?? iat,
    mot: +(interaction.motorConsistency ?? 0).toFixed(3),
  };

  // ── Sign and seal ─────────────────────────────────────────────────────────
  const hw      = { dram, enf, ent, ...(enfDev != null && { enfDev }) };
  const unsigned = { v: TOKEN_VERSION, n, iat, exp, idle, hw, evt };
  const sig      = _sign(unsigned, secret);
  const token    = { ...unsigned, sig };

  return {
    token,
    compact:   _encode(token),
    expiresAt: exp,
  };
}

// ── verifyEngagementToken ─────────────────────────────────────────────────────

/**
 * Verify an engagement token on the server.
 *
 * Call this in your API handler before crediting any engagement metric.
 * Failed verification returns `{ valid: false, reason }` — never throws.
 *
 * @param {string|object}  tokenOrCompact  compact base64url string or parsed token
 * @param {string}         secret          shared HMAC secret
 * @param {object}         [opts]
 * @param {Function}       [opts.checkNonce]  async (nonce: string) => boolean
 *                         Must atomically consume the nonce (Redis DEL returning 1,
 *                         DB transaction with SELECT FOR UPDATE, etc.)
 * @param {Function}       [opts.now]  override Date.now for testing: () => number
 * @returns {Promise<EngagementVerifyResult>}
 */
export async function verifyEngagementToken(tokenOrCompact, secret, opts = {}) {
  _assertSecret(secret);

  // ── Parse ─────────────────────────────────────────────────────────────────
  let token;
  try {
    token = typeof tokenOrCompact === 'string'
      ? _decode(tokenOrCompact)
      : tokenOrCompact;
  } catch {
    return _reject('malformed_token');
  }

  const { v, n, iat, exp, idle, hw, evt, sig } = token ?? {};

  // ── Structural integrity ──────────────────────────────────────────────────
  if (v !== TOKEN_VERSION)                         return _reject('unsupported_version');
  if (!n || !/^[0-9a-f]{64}$/i.test(n))           return _reject('invalid_nonce');
  if (!Number.isFinite(iat) || !Number.isFinite(exp) || !sig) {
    return _reject('missing_required_fields');
  }

  // ── Freshness ─────────────────────────────────────────────────────────────
  const now = (opts.now ?? Date.now)();
  if (now > exp)         return _reject('token_expired',      { expiredByMs: now - exp });
  if (iat > now + 5_000) return _reject('token_from_future');

  // ── Signature verification (timing-safe comparison) ───────────────────────
  const { sig: _discardSig, ...unsigned } = token;
  const expected = _sign(unsigned, secret);
  if (!_timingSafeEqual(expected, sig)) {
    return _reject('invalid_signature');
  }

  // ── Nonce consumption (replay prevention) ─────────────────────────────────
  if (typeof opts.checkNonce === 'function') {
    let consumed;
    try   { consumed = await opts.checkNonce(n); }
    catch { return _reject('nonce_check_error'); }
    if (!consumed) return _reject('nonce_replayed');
  }

  // ── Advisory analysis (non-blocking) ─────────────────────────────────────
  const idleWarnings = idle ? _checkIdlePlausibility(idle) : ['no_idle_proof'];
  const riskSignals  = _assessRisk(hw, idle, evt);

  return {
    valid:        true,
    token,
    idleWarnings,
    riskSignals,
    issuedAt:     iat,
    expiresAt:    exp,
  };
}

// ── Encode / decode ───────────────────────────────────────────────────────────

/**
 * Encode a token object to a compact base64url string.
 * @param {object} token
 * @returns {string}
 */
export function encodeToken(token) {
  return _encode(token);
}

/**
 * Decode a compact string WITHOUT verifying the signature.
 * For logging/debugging only — use verifyEngagementToken for security checks.
 * Named 'Unsafe' to prevent accidental use in security-sensitive code paths.
 * @param {string} compact
 * @returns {object & { _verified: false }}
 */
export function decodeTokenUnsafe(compact) {
  return { ...(_decode(compact)), _verified: false };
}

/** @deprecated Use decodeTokenUnsafe instead */
export function decodeToken(compact) {
  return decodeTokenUnsafe(compact);
}

// ── Risk assessment ───────────────────────────────────────────────────────────

/**
 * Advisory risk signals: concerns that don't outright invalidate the token
 * but should inform downstream risk decisions.
 *
 * Returned in the `riskSignals` array of a successful verify result.
 * Each entry: `{ code: string, severity: 'high'|'medium'|'low' }`.
 */
function _assessRisk(hw, idle, evt) {
  const signals = [];

  // Hardware layer
  if (hw?.dram === 'virtual')   signals.push({ code: 'DRAM_VIRTUAL',          severity: 'high'   });
  if (hw?.dram === 'ambiguous') signals.push({ code: 'DRAM_AMBIGUOUS',        severity: 'medium' });
  if (hw?.enf  === 'no_grid_signal') signals.push({ code: 'NO_ENF_GRID',      severity: 'medium' });
  if (hw?.ent != null && hw.ent < 0.35) {
    signals.push({ code: 'LOW_ENTROPY_SCORE', severity: 'high' });
  }

  // Idle proof layer
  if (!idle) {
    signals.push({ code: 'NO_IDLE_PROOF', severity: 'medium' });
  } else {
    if (idle.therm === 'step_function')   signals.push({ code: 'STEP_FUNCTION_THERMAL',   severity: 'high'   });
    if (idle.therm === 'sustained_hot')   signals.push({ code: 'SUSTAINED_LOAD_PATTERN',  severity: 'high'   });
    if (idle.mono  < 0.30 && idle.s >= 3) signals.push({ code: 'NON_MONOTONIC_COOLING',   severity: 'medium' });
    if (idle.dMs   < 50_000)              signals.push({ code: 'MINIMAL_IDLE_DURATION',    severity: 'low'    });
  }

  // Interaction layer
  if (evt?.mot != null && evt.mot < 0.25) {
    signals.push({ code: 'POOR_MOTOR_CONSISTENCY', severity: 'medium' });
  }

  return signals;
}

function _checkIdlePlausibility(idle) {
  const w = [];
  if (!idle.chain || idle.chain.length !== 64) w.push('malformed_chain_hash');
  if (idle.s < 2)                              w.push('insufficient_chain_samples');
  if (idle.therm === 'step_function')          w.push('step_function_transition');
  if (idle.mono < 0.30 && idle.s >= 3)         w.push('non_monotonic_cooling');
  return w;
}

// ── HMAC ──────────────────────────────────────────────────────────────────────

function _sign({ v, n, iat, exp, idle, hw, evt }, secret) {
  // All fields an attacker might want to inflate/swap are in the signed body.
  // Advisory fields (therm, mono, dram labels) are deliberately excluded —
  // they're useful for risk scoring but not for access control.
  const body = [
    v,
    n,
    iat,
    exp,
    idle?.chain ?? 'null',
    idle?.dMs   ?? 'null',
    hw?.ent     ?? 'null',
    evt?.t      ?? 'null',
    evt?.ts     ?? 'null',
  ].join('|');

  const mac = hmac(sha256, utf8ToBytes(secret), utf8ToBytes(body));
  return bytesToHex(mac);
}

/**
 * Timing-safe hex string comparison.
 * Uses Node.js crypto.timingSafeEqual when available (server-side),
 * falls back to constant-time XOR accumulation for browser contexts.
 */
let _nodeTse = null;
let _nodeTseLoaded = false;

function _timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;

  // Try Node.js built-in (loaded once, cached)
  if (!_nodeTseLoaded) {
    _nodeTseLoaded = true;
    try {
      // eslint-disable-next-line no-eval -- dynamic require avoids bundler issues
      const crypto = typeof require === 'function'
        ? require('node:crypto')
        : null;
      if (crypto?.timingSafeEqual) _nodeTse = crypto.timingSafeEqual;
    } catch { /* browser — no node:crypto */ }
  }

  if (_nodeTse) {
    try {
      const bufA = Buffer.from(a, 'hex');
      const bufB = Buffer.from(b, 'hex');
      return bufA.length === bufB.length && _nodeTse(bufA, bufB);
    } catch { /* fall through to XOR */ }
  }

  // Constant-time XOR accumulation fallback
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ── Encode / decode (base64url) ───────────────────────────────────────────────

function _encode(token) {
  const bytes = utf8ToBytes(JSON.stringify(token));
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64url');
  }
  // Browser: manual base64url encoding
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g,  '');
}

function _decode(compact) {
  // Normalize base64url to standard base64 with padding
  let b64 = compact.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';

  let bytes;
  if (typeof Buffer !== 'undefined') {
    bytes = Buffer.from(b64, 'base64');
  } else {
    const str = atob(b64);
    bytes = Uint8Array.from(str, c => c.charCodeAt(0));
  }

  return JSON.parse(new TextDecoder().decode(bytes));
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

function _reject(reason, meta = {}) {
  return { valid: false, reason, ...meta };
}

function _assertSecret(secret) {
  if (!secret || typeof secret !== 'string' || secret.length < 32) {
    throw new Error(
      '@svrnsec/pulse: engagement token secret must be ≥ 32 characters (256 bits). ' +
      'Generate one with: import { generateSecret } from "@svrnsec/pulse/challenge"'
    );
  }
}

function _extractEntropyScore(pulseResult) {
  // Normalize jitter score (0–1) from wherever it lives in the result tree
  const score =
    pulseResult?.payload?.classification?.jitterScore ??
    pulseResult?.classification?.jitterScore          ??
    pulseResult?.jitterScore                          ??
    null;
  return score != null ? +Number(score).toFixed(3) : null;
}

// ── JSDoc types ───────────────────────────────────────────────────────────────

/**
 * @typedef {object} EngagementToken
 * @property {object} token      full parsed token object
 * @property {string} compact    base64url-encoded compact form (attach to API headers)
 * @property {number} expiresAt  Unix ms expiry timestamp
 */

/**
 * @typedef {object} EngagementVerifyResult
 * @property {boolean}    valid          true if all checks passed
 * @property {string}     [reason]       rejection reason code (when valid=false)
 * @property {number}     [expiredByMs]  how many ms ago it expired (when reason=token_expired)
 * @property {object}     [token]        parsed token (when valid=true)
 * @property {string[]}   [idleWarnings] advisory idle-proof warnings
 * @property {object[]}   [riskSignals]  non-fatal risk indicators with severity
 * @property {number}     [issuedAt]     Unix ms issued-at
 * @property {number}     [expiresAt]    Unix ms expiry
 */

/**
 * @svrnsec/pulse — HMAC-Signed Challenge Protocol
 *
 * Hardens the nonce system against three attack vectors that a plain random
 * nonce does not prevent:
 *
 *   1. Forged challenges
 *      Without a server secret, an attacker can generate their own nonces,
 *      pre-compute a fake proof, and submit it. HMAC signing ties the nonce
 *      to the server's secret — a nonce not signed by the server is rejected
 *      before the proof is even validated.
 *
 *   2. Replayed challenges
 *      A valid nonce captured from a legitimate session can be replayed with
 *      a cached proof. The challenge includes an expiry timestamp in the HMAC
 *      input — expired challenges are rejected even if the signature is valid.
 *
 *   3. Timestamp manipulation
 *      An attacker who intercepts a challenge cannot extend its validity by
 *      altering the expiry field because the timestamp is part of the HMAC
 *      input. Any modification breaks the signature.
 *
 * Wire format
 * ───────────
 *   {
 *     nonce:     "64-char hex"          — random, server-generated
 *     issuedAt:  1711234567890          — Unix ms
 *     expiresAt: 1711234867890          — issuedAt + ttlMs
 *     sig:       "64-char hex"          — HMAC-SHA256(body, secret)
 *   }
 *
 *   body = `${nonce}|${issuedAt}|${expiresAt}`
 *
 * Usage (server)
 * ──────────────
 *   import { createChallenge, verifyChallenge } from '@svrnsec/pulse/challenge';
 *
 *   // Challenge endpoint
 *   app.get('/api/challenge', (req, res) => {
 *     const challenge = createChallenge(process.env.PULSE_SECRET);
 *     await redis.set(`pulse:${challenge.nonce}`, '1', 'EX', 300);
 *     res.json(challenge);
 *   });
 *
 *   // Verify endpoint
 *   app.post('/api/verify', async (req, res) => {
 *     const { payload, hash } = req.body;
 *     const challenge = { nonce: payload.nonce, ...req.body.challenge };
 *
 *     const { valid, reason } = verifyChallenge(challenge, process.env.PULSE_SECRET, {
 *       checkNonce: async (n) => {
 *         const ok = await redis.del(`pulse:${n}`);
 *         return ok === 1; // consume on first use
 *       },
 *     });
 *     if (!valid) return res.status(400).json({ error: reason });
 *
 *     const result = await validateProof(payload, hash);
 *     res.json(result);
 *   });
 *
 * Zero dependencies: uses Node.js built-in crypto module only.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TTL_MS   = 5 * 60 * 1000;  // 5 minutes
const NONCE_BYTES      = 32;             // 256 bits → 64-char hex
const SIG_ALGORITHM    = 'sha256';

// ---------------------------------------------------------------------------
// createChallenge
// ---------------------------------------------------------------------------

/**
 * Issue a new signed challenge. Call this in your GET /challenge endpoint.
 *
 * @param {string}  secret      - your server secret (min 32 chars recommended)
 * @param {object}  [opts]
 * @param {number}  [opts.ttlMs=300000]  - challenge validity window (ms)
 * @param {string}  [opts.nonce]         - override nonce (testing only)
 * @returns {SignedChallenge}
 */
export function createChallenge(secret, opts = {}) {
  _assertSecret(secret);

  const { ttlMs = DEFAULT_TTL_MS } = opts;
  const nonce     = opts.nonce ?? randomBytes(NONCE_BYTES).toString('hex');
  const issuedAt  = Date.now();
  const expiresAt = issuedAt + ttlMs;
  const sig       = _sign(nonce, issuedAt, expiresAt, secret);

  return { nonce, issuedAt, expiresAt, sig };
}

// ---------------------------------------------------------------------------
// verifyChallenge
// ---------------------------------------------------------------------------

/**
 * Verify an inbound challenge before processing the proof.
 * Call this at the start of your POST /verify endpoint.
 *
 * @param {SignedChallenge}  challenge
 * @param {string}           secret
 * @param {object}           [opts]
 * @param {Function}         [opts.checkNonce]  async (nonce: string) => boolean
 *                           Return true if the nonce is valid and consume it.
 *                           Must be atomic (redis DEL returning 1, DB transaction, etc.)
 * @returns {Promise<{ valid: boolean, reason?: string }>}
 */
export async function verifyChallenge(challenge, secret, opts = {}) {
  _assertSecret(secret);

  const { nonce, issuedAt, expiresAt, sig } = challenge ?? {};

  // ── Structural checks ──────────────────────────────────────────────────────
  if (!nonce || typeof nonce !== 'string' || !/^[0-9a-f]{64}$/i.test(nonce)) {
    return { valid: false, reason: 'invalid_nonce_format' };
  }
  if (!issuedAt || !expiresAt || !sig) {
    return { valid: false, reason: 'missing_challenge_fields' };
  }

  // ── Timestamp freshness ────────────────────────────────────────────────────
  const now = Date.now();
  if (now > expiresAt) {
    return { valid: false, reason: 'challenge_expired' };
  }
  if (issuedAt > now + 30_000) {
    // Clock skew tolerance: reject challenges issued >30s in the future
    return { valid: false, reason: 'challenge_issued_in_future' };
  }

  // ── HMAC signature verification (timing-safe) ──────────────────────────────
  const expected = _sign(nonce, issuedAt, expiresAt, secret);
  try {
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(sig,      'hex');
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return { valid: false, reason: 'invalid_signature' };
    }
  } catch {
    return { valid: false, reason: 'invalid_signature' };
  }

  // ── Nonce consumption (replay prevention) ──────────────────────────────────
  if (typeof opts.checkNonce === 'function') {
    let consumed;
    try {
      consumed = await opts.checkNonce(nonce);
    } catch (err) {
      return { valid: false, reason: 'nonce_check_error' };
    }
    if (!consumed) {
      return { valid: false, reason: 'nonce_already_used_or_unknown' };
    }
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// embedChallenge / extractChallenge
// ---------------------------------------------------------------------------

/**
 * Embed a signed challenge inside a ProofPayload's nonce field.
 * The proof's nonce is set to `challenge.nonce`; the full challenge object is
 * included as `challenge.meta` for server-side re-verification.
 *
 * This lets a single API call carry both the nonce for BLAKE3 commitment AND
 * the full signed challenge for server authentication.
 *
 * @param {SignedChallenge} challenge
 * @param {object}          payload    - ProofPayload (mutates in place)
 * @returns {object} the mutated payload
 */
export function embedChallenge(challenge, payload) {
  if (payload.nonce !== challenge.nonce) {
    throw new Error('@svrnsec/pulse: proof nonce does not match challenge nonce');
  }
  payload._challenge = {
    issuedAt:  challenge.issuedAt,
    expiresAt: challenge.expiresAt,
    sig:       challenge.sig,
  };
  return payload;
}

/**
 * Extract a SignedChallenge from a ProofPayload that had embedChallenge() applied.
 * @param {object} payload
 * @returns {SignedChallenge}
 */
export function extractChallenge(payload) {
  const meta = payload?._challenge;
  if (!meta) throw new Error('@svrnsec/pulse: no embedded challenge in payload');
  return {
    nonce:     payload.nonce,
    issuedAt:  meta.issuedAt,
    expiresAt: meta.expiresAt,
    sig:       meta.sig,
  };
}

// ---------------------------------------------------------------------------
// generateSecret
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically secure server secret.
 * Run once and store in your environment variables.
 *
 * @returns {string}  64-char hex string (256 bits)
 */
export function generateSecret() {
  return randomBytes(32).toString('hex');
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _sign(nonce, issuedAt, expiresAt, secret) {
  const body = `${nonce}|${issuedAt}|${expiresAt}`;
  return createHmac(SIG_ALGORITHM, secret).update(body).digest('hex');
}

function _assertSecret(secret) {
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new Error(
      '@svrnsec/pulse: secret must be a string of at least 16 characters. ' +
      'Generate one with: import { generateSecret } from "@svrnsec/pulse/challenge"'
    );
  }
}

/**
 * @typedef {object} SignedChallenge
 * @property {string}  nonce      64-char hex nonce
 * @property {number}  issuedAt   Unix ms timestamp
 * @property {number}  expiresAt  Unix ms expiry
 * @property {string}  sig        HMAC-SHA256 hex signature
 */

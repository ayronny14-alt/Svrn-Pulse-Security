/**
 * @svrnsec/pulse — Express Middleware
 *
 * Drop-in middleware for Express / Fastify / Hono.
 * Handles the full challenge → verify flow in two lines of code.
 *
 * Usage:
 *
 *   import { createPulseMiddleware } from '@svrnsec/pulse/middleware/express';
 *
 *   const pulse = createPulseMiddleware({ threshold: 0.6 });
 *
 *   app.get('/api/pulse/challenge', pulse.challenge);
 *   app.post('/checkout', pulse.verify, checkoutHandler);
 *
 * With Redis (recommended for production):
 *
 *   import Redis from 'ioredis';
 *   const redis = new Redis(process.env.REDIS_URL);
 *
 *   const pulse = createPulseMiddleware({
 *     threshold: 0.6,
 *     store: {
 *       set: (k, ttl) => redis.set(k, '1', 'EX', ttl),
 *       consume: (k)  => redis.del(k).then(n => n === 1),
 *     },
 *   });
 */

import { validateProof, generateNonce } from '../proof/validator.js';

// ---------------------------------------------------------------------------
// In-memory nonce store (single-process / development only)
// ---------------------------------------------------------------------------

function createMemoryStore(ttlMs = 300_000) {
  const store = new Map();
  return {
    set(key) {
      store.set(key, Date.now() + ttlMs);
      // Lazy cleanup — don't leak memory in long-running processes
      if (store.size > 10_000) {
        const now = Date.now();
        for (const [k, exp] of store) {
          if (exp < now) store.delete(k);
        }
      }
    },
    consume(key) {
      const exp = store.get(key);
      if (!exp || Date.now() > exp) return false;
      store.delete(key);
      return true;
    },
  };
}

// ---------------------------------------------------------------------------
// createPulseMiddleware
// ---------------------------------------------------------------------------

/**
 * @param {object}   opts
 * @param {number}   [opts.threshold=0.55]          - minimum jitter score (0–1)
 * @param {number}   [opts.nonceTTL=300]             - nonce lifetime in seconds
 * @param {boolean}  [opts.requireBio=false]         - reject if no mouse/keyboard activity
 * @param {boolean}  [opts.blockSoftwareRenderer=true]
 * @param {object}   [opts.store]                    - custom nonce store (see above)
 * @param {string}   [opts.proofHeader='x-pulse-proof'] - request header name
 * @param {string}   [opts.hashHeader='x-pulse-hash']
 * @param {Function} [opts.onReject]                 - custom rejection handler
 * @param {Function} [opts.onError]                  - custom error handler
 * @returns {{ challenge: Function, verify: Function }}
 */
export function createPulseMiddleware(opts = {}) {
  const {
    threshold            = 0.55,
    nonceTTL             = 300,
    requireBio           = false,
    blockSoftwareRenderer = true,
    proofHeader          = 'x-pulse-proof',
    hashHeader           = 'x-pulse-hash',
    onReject,
    onError,
  } = opts;

  // Allow external store (Redis, etc.) or default to in-memory
  const store = opts.store ?? createMemoryStore(nonceTTL * 1000);

  // ── challenge — GET /api/pulse/challenge ──────────────────────────────────
  async function challenge(req, res) {
    try {
      const nonce = generateNonce();
      await store.set(`pulse:${nonce}`);
      res.json({ nonce, expiresIn: nonceTTL });
    } catch (err) {
      if (onError) return onError(err, req, res);
      res.status(500).json({ error: 'Failed to generate challenge' });
    }
  }

  // ── verify — middleware for protected routes ───────────────────────────────
  async function verify(req, res, next) {
    try {
      // Support both header and body delivery
      let payload, hash;
      if (req.headers[proofHeader]) {
        try   { payload = JSON.parse(req.headers[proofHeader]); }
        catch { return _reject(res, 400, 'MALFORMED_PROOF_HEADER', 'Could not parse x-pulse-proof header as JSON', onReject, req); }
        hash = req.headers[hashHeader];
      } else if (req.body?.pulsePayload) {
        payload = req.body.pulsePayload;
        hash    = req.body.pulseHash;
      } else {
        return _reject(res, 401, 'MISSING_PROOF', 'No pulse proof found in headers or body', onReject, req);
      }

      if (!hash) {
        return _reject(res, 401, 'MISSING_HASH', 'No pulse hash provided', onReject, req);
      }

      const result = await validateProof(payload, hash, {
        minJitterScore: threshold,
        requireBio,
        blockSoftwareRenderer,
        checkNonce: async (n) => store.consume(`pulse:${n}`),
      });

      if (!result.valid) {
        return _reject(res, 403, 'PROOF_INVALID', result.reasons.join('; '), onReject, req, result);
      }

      // Attach result to request for downstream handlers
      req.pulse = result;
      next();

    } catch (err) {
      if (onError) return onError(err, req, res, next);
      res.status(500).json({ error: 'Pulse verification error' });
    }
  }

  return { challenge, verify };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _reject(res, status, code, message, customHandler, req, result = {}) {
  if (customHandler) {
    return customHandler(req, res, { code, message, ...result });
  }
  res.status(status).json({ error: code, message, valid: result?.valid, reasons: result?.reasons, riskFlags: result?.riskFlags });
}

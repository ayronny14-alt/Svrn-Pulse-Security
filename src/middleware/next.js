/**
 * @sovereign/pulse — Next.js App Router Middleware
 *
 * Works with Next.js App Router (13+) and Edge Runtime.
 *
 * ── Route Handler wrapper ──────────────────────────────────────────────────
 *
 *   // app/api/checkout/route.js
 *   import { withPulse } from '@sovereign/pulse/middleware/next';
 *
 *   export const POST = withPulse({ threshold: 0.6 })(
 *     async (req) => {
 *       const { score, provider } = req.pulse;
 *       return Response.json({ ok: true, score });
 *     }
 *   );
 *
 * ── Challenge endpoint (copy-paste ready) ─────────────────────────────────
 *
 *   // app/api/pulse/challenge/route.js
 *   import { pulseChallenge } from '@sovereign/pulse/middleware/next';
 *   export const GET = pulseChallenge();
 *
 * ── Edge-compatible nonce store ────────────────────────────────────────────
 *
 *   // Uses in-memory by default.  For multi-instance deployments, provide
 *   // a KV store (Vercel KV, Cloudflare KV, Redis via fetch):
 *
 *   import { kv } from '@vercel/kv';
 *   export const POST = withPulse({
 *     threshold: 0.6,
 *     store: {
 *       set:     (k, ttl) => kv.set(k, '1', { ex: ttl }),
 *       consume: (k)      => kv.del(k).then(n => n === 1),
 *     },
 *   })(handler);
 */

import { validateProof, generateNonce } from '../proof/validator.js';

// ---------------------------------------------------------------------------
// Shared in-memory nonce store (single instance / dev only)
// ---------------------------------------------------------------------------

const _memStore = new Map();

function memoryStore(ttlSec) {
  return {
    set(key) {
      _memStore.set(key, Date.now() + ttlSec * 1000);
    },
    consume(key) {
      const exp = _memStore.get(key);
      if (!exp || Date.now() > exp) return false;
      _memStore.delete(key);
      return true;
    },
  };
}

// ---------------------------------------------------------------------------
// pulseChallenge  — GET /api/pulse/challenge
// ---------------------------------------------------------------------------

/**
 * @param {object} [opts]
 * @param {number} [opts.ttl=300]    - nonce TTL in seconds
 * @param {object} [opts.store]      - custom nonce store
 */
export function pulseChallenge(opts = {}) {
  const { ttl = 300, store } = opts;
  const _store = store ?? memoryStore(ttl);

  return async function GET() {
    const nonce = generateNonce();
    await _store.set(`pulse:${nonce}`);
    return Response.json({ nonce, expiresIn: ttl });
  };
}

// ---------------------------------------------------------------------------
// withPulse  — wraps a Next.js route handler
// ---------------------------------------------------------------------------

/**
 * @param {object}   opts
 * @param {number}   [opts.threshold=0.55]
 * @param {number}   [opts.ttl=300]               - nonce TTL
 * @param {boolean}  [opts.requireBio=false]
 * @param {boolean}  [opts.blockSoftwareRenderer=true]
 * @param {object}   [opts.store]                  - custom nonce store
 * @returns {(handler: Function) => Function}       - HOC
 */
export function withPulse(opts = {}) {
  const {
    threshold            = 0.55,
    ttl                  = 300,
    requireBio           = false,
    blockSoftwareRenderer = true,
    store,
  } = opts;

  const _store = store ?? memoryStore(ttl);

  return function wrap(handler) {
    return async function wrappedHandler(req, ...args) {
      // ── Read proof from headers (preferred) or body ──────────────────────
      const proofHeader = req.headers.get('x-pulse-proof');
      const hashHeader  = req.headers.get('x-pulse-hash');

      let payload, hash;

      if (proofHeader) {
        try   { payload = JSON.parse(proofHeader); }
        catch { return _err(400, 'MALFORMED_PROOF', 'Could not parse x-pulse-proof header'); }
        hash = hashHeader;
      } else {
        // Attempt to read from JSON body (non-streaming)
        try {
          const body = await req.clone().json();
          payload    = body.pulsePayload;
          hash       = body.pulseHash;
        } catch {}
      }

      if (!payload || !hash) {
        return _err(401, 'MISSING_PROOF',
          'Provide pulse proof via x-pulse-proof + x-pulse-hash headers, ' +
          'or pulsePayload + pulseHash in the request body.'
        );
      }

      // ── Validate ───────────────────────────────────────────────────────────
      let result;
      try {
        result = await validateProof(payload, hash, {
          minJitterScore: threshold,
          requireBio,
          blockSoftwareRenderer,
          checkNonce: async (n) => _store.consume(`pulse:${n}`),
        });
      } catch (err) {
        console.error('[pulse] validateProof error:', err);
        return _err(500, 'VALIDATION_ERROR', 'Internal error during proof validation');
      }

      if (!result.valid) {
        return Response.json(
          { error: 'PULSE_REJECTED', reasons: result.reasons, riskFlags: result.riskFlags },
          { status: 403 }
        );
      }

      // ── Attach pulse result and call the real handler ──────────────────────
      // Next.js Request is immutable so we inject via a lightweight proxy
      const enriched = new Proxy(req, {
        get(target, prop) {
          if (prop === 'pulse') return result;
          const val = target[prop];
          return typeof val === 'function' ? val.bind(target) : val;
        },
      });

      return handler(enriched, ...args);
    };
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _err(status, code, message) {
  return Response.json({ error: code, message }, { status });
}

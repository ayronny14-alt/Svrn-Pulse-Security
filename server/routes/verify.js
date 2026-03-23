// server/routes/verify.js
import { Router } from 'express';
import { nonceStore, usageStore } from '../stores.js';
import { fireWebhook } from '../webhook.js';

// validateProof is loaded lazily (pure JS, no WASM)
let _validate;
async function getValidator() {
  if (!_validate) {
    const mod = await import('../../src/proof/validator.js');
    _validate = mod.validateProof;
  }
  return _validate;
}

const router = Router();

router.post('/', async (req, res) => {
  const { payload, hash, options = {} } = req.body ?? {};

  if (!payload || !hash) {
    return res.status(400).json({
      error:   'MISSING_PROOF',
      message: 'Request body must contain { payload, hash }',
    });
  }

  try {
    const validateProof = await getValidator();

    // Security: options come from the request body (potentially client-controlled).
    // - minJitterScore: enforce a hard floor of 0.50 so callers can't disable the score gate
    // - blockSoftwareRenderer: always true — never let callers whitelist VM renderers
    // - maxAgeMs: client can tighten (lower) but not loosen beyond 5 min default
    const clientMinScore = typeof options.minJitterScore === 'number' ? options.minJitterScore : 0.55;
    const clientMaxAge   = typeof options.maxAgeMs       === 'number' ? options.maxAgeMs       : 300_000;

    const result = await validateProof(payload, hash, {
      minJitterScore:        Math.max(0.50, clientMinScore),       // floor: never below 0.50
      requireBio:            options.requireBio === true,          // opt-in only; default false
      blockSoftwareRenderer: true,                                 // always enforced server-side
      maxAgeMs:              Math.min(300_000, clientMaxAge),      // ceiling: never above 5 min
      checkNonce: async (n) => nonceStore.consume(`pulse:${n}`),
    });

    usageStore.track(req.apiKey, 'verify');

    // Structured log
    console.log(JSON.stringify({
      ts:         Date.now(),
      event:      result.valid ? 'verify.passed' : 'verify.rejected',
      key:        req.keyRecord.name,
      score:      result.score,
      confidence: result.confidence,
      reasons:    result.reasons,
      riskFlags:  result.riskFlags,
      provider:   payload?.provider?.id ?? 'unknown',
    }));

    // Fire webhook (non-blocking)
    fireWebhook(req.keyRecord, result.valid ? 'verify.passed' : 'verify.rejected', {
      score:      result.score,
      confidence: result.confidence,
      valid:      result.valid,
      reasons:    result.reasons,
      riskFlags:  result.riskFlags,
    });

    res.json(result);

  } catch (err) {
    console.error('[pulse-api] verify error:', err);
    res.status(500).json({ error: 'VERIFY_ERROR', message: 'Internal validation error' });
  }
});

export { router as verifyRouter };

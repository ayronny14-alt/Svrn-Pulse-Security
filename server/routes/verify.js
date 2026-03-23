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

    const result = await validateProof(payload, hash, {
      minJitterScore:        options.minJitterScore        ?? 0.55,
      requireBio:            options.requireBio            ?? false,
      blockSoftwareRenderer: options.blockSoftwareRenderer ?? true,
      maxAgeMs:              options.maxAgeMs              ?? 300_000,
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

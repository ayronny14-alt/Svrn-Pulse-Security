// server/routes/verify.js
import { Router } from 'express';
import { nonceStore, usageStore } from '../stores.js';
import { fireWebhook } from '../webhook.js';
import { config } from '../config.js';

// Lazy imports
let _validate, _verifyChallenge;
async function getValidator() {
  if (!_validate) {
    const mod = await import('../../src/proof/validator.js');
    _validate = mod.validateProof;
  }
  return _validate;
}
async function getChallengeVerifier() {
  if (!_verifyChallenge) {
    const mod = await import('../../src/proof/challenge.js');
    _verifyChallenge = mod.verifyChallenge;
  }
  return _verifyChallenge;
}

const router = Router();

router.post('/', async (req, res) => {
  const { payload, hash, challenge: challengeData, options = {} } = req.body ?? {};

  if (!payload || !hash) {
    return res.status(400).json({
      error:   'MISSING_PROOF',
      message: 'Request body must contain { payload, hash }',
    });
  }

  try {
    // ── Step 1: Verify HMAC-signed challenge (if provided) ────────────────
    // The challenge signature proves this nonce was issued by this server.
    // Without it, an attacker could forge arbitrary {payload, hash} pairs.
    if (challengeData) {
      const verifyChallenge = await getChallengeVerifier();
      const chalResult = await verifyChallenge(
        { nonce: payload.nonce, ...challengeData },
        config.challengeSecret,
        { checkNonce: async (n) => nonceStore.consume(`pulse:${n}`) }
      );
      if (!chalResult.valid) {
        usageStore.track(req.apiKey, 'blocked');
        return res.status(403).json({
          error:   'CHALLENGE_VERIFICATION_FAILED',
          message: `Challenge rejected: ${chalResult.reason}`,
          valid:   false,
        });
      }
    }

    // ── Step 2: Validate proof ────────────────────────────────────────────
    const validateProof = await getValidator();

    const clientMinScore = typeof options.minJitterScore === 'number' ? options.minJitterScore : 0.55;
    const clientMaxAge   = typeof options.maxAgeMs       === 'number' ? options.maxAgeMs       : 300_000;

    const result = await validateProof(payload, hash, {
      minJitterScore:        Math.max(0.55, clientMinScore),
      requireBio:            options.requireBio === true,
      blockSoftwareRenderer: true,
      maxAgeMs:              Math.min(300_000, clientMaxAge),
      // If challenge was already verified above, nonce is consumed.
      // If no challenge data, fall back to direct nonce consumption.
      checkNonce: challengeData
        ? null  // already consumed in step 1
        : async (n) => nonceStore.consume(`pulse:${n}`),
    });

    // Add risk flag if no HMAC challenge was provided
    if (!challengeData) {
      result.riskFlags = result.riskFlags ?? [];
      result.riskFlags.push('NO_HMAC_CHALLENGE_PROVIDED');
    }

    usageStore.track(req.apiKey, 'verify');

    console.log(JSON.stringify({
      ts:         Date.now(),
      event:      result.valid ? 'verify.passed' : 'verify.rejected',
      key:        req.keyRecord.name,
      score:      result.score,
      confidence: result.confidence,
      reasons:    result.reasons,
      riskFlags:  result.riskFlags,
      hmacChallenge: !!challengeData,
      provider:   payload?.provider?.id ?? 'unknown',
    }));

    fireWebhook(req.keyRecord, result.valid ? 'verify.passed' : 'verify.rejected', {
      score:      result.score,
      confidence: result.confidence,
      valid:      result.valid,
      reasons:    result.reasons,
      riskFlags:  result.riskFlags,
    });

    res.json(result);

  } catch (err) {
    console.error(JSON.stringify({ ts: Date.now(), event: 'verify.error', error: err.message }));
    res.status(500).json({ error: 'VERIFY_ERROR', message: 'Internal validation error' });
  }
});

export { router as verifyRouter };

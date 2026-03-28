// server/routes/challenge.js
import { Router }       from 'express';
import { nonceStore, usageStore } from '../stores.js';
import { config }       from '../config.js';

// HMAC-signed challenge protocol
let _createChallenge;
async function getChallengeFn() {
  if (!_createChallenge) {
    const mod = await import('../../src/proof/challenge.js');
    _createChallenge = mod.createChallenge;
  }
  return _createChallenge;
}

const router = Router();

router.get('/', async (req, res) => {
  try {
    // Check outstanding nonce cap to prevent hoarding
    const currentSize = typeof nonceStore.size === 'function'
      ? (await nonceStore.size?.() ?? nonceStore.size())
      : 0;
    if (currentSize >= config.maxNonces) {
      return res.status(429).json({
        error: 'NONCE_LIMIT_EXCEEDED',
        message: 'Too many outstanding challenges. Wait for existing ones to expire.',
      });
    }

    // Issue HMAC-signed challenge
    const createChallenge = await getChallengeFn();
    const challenge = createChallenge(config.challengeSecret, {
      ttlMs: config.nonceTtl * 1000,
    });

    // Store nonce for single-use consumption
    await nonceStore.set(`pulse:${challenge.nonce}`);
    usageStore.track(req.apiKey, 'challenge');

    console.log(JSON.stringify({
      ts:      Date.now(),
      event:   'challenge.issued',
      key:     req.keyRecord.name,
      tier:    req.keyRecord.tier,
      nonce:   challenge.nonce.slice(0, 8) + '...',
      signed:  true,
    }));

    res.json({
      nonce:     challenge.nonce,
      issuedAt:  challenge.issuedAt,
      expiresAt: challenge.expiresAt,
      sig:       challenge.sig,
      expiresIn: config.nonceTtl,
    });
  } catch (err) {
    console.error(JSON.stringify({ ts: Date.now(), event: 'challenge.error', error: err.message }));
    res.status(500).json({ error: 'CHALLENGE_ERROR', message: 'Failed to issue challenge' });
  }
});

export { router as challengeRouter };

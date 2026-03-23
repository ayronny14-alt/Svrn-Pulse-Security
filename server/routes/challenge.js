// server/routes/challenge.js
import { Router }       from 'express';
import { randomBytes }  from 'node:crypto';
import { nonceStore, usageStore } from '../stores.js';
import { config }       from '../config.js';

const router = Router();

router.get('/', async (req, res) => {
  try {
    const nonce = randomBytes(32).toString('hex');
    await nonceStore.set(`pulse:${nonce}`);
    usageStore.track(req.apiKey, 'challenge');

    // Structured request log
    console.log(JSON.stringify({
      ts:      Date.now(),
      event:   'challenge.issued',
      key:     req.keyRecord.name,
      tier:    req.keyRecord.tier,
      nonce:   nonce.slice(0, 8) + '...',
    }));

    res.json({
      nonce,
      expiresIn: config.nonceTtl,
    });
  } catch (err) {
    console.error('[pulse-api] challenge error:', err);
    res.status(500).json({ error: 'CHALLENGE_ERROR', message: 'Failed to issue challenge' });
  }
});

export { router as challengeRouter };

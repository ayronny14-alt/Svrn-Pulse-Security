// server/routes/health.js
import { Router } from 'express';
import { nonceStore, usageStore } from '../stores.js';

const router = Router();

router.get('/', (req, res) => {
  res.json({
    status:   'ok',
    version:  '1.0.0',
    uptime:   Math.floor(process.uptime()),
    nonces:   nonceStore.size(),
    ts:       Date.now(),
  });
});

export { router as healthRouter };

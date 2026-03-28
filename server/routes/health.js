// server/routes/health.js
import { Router } from 'express';

const router = Router();

router.get('/', (req, res) => {
  res.json({
    status:   'ok',
    version:  '1.0.0',
    uptime:   Math.floor(process.uptime()),
    ts:       Date.now(),
  });
});

export { router as healthRouter };

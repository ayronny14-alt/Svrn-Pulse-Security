// server/routes/health.js
import { Router } from 'express';
import { nonceStore } from '../stores.js';

const router = Router();

// Basic liveness probe — always responds if the process is up
router.get('/', (req, res) => {
  res.json({
    status:   'ok',
    version:  '1.0.0',
    uptime:   Math.floor(process.uptime()),
    ts:       Date.now(),
  });
});

// Readiness probe — checks backing services (Redis, etc.)
// Use this for load balancer health checks
router.get('/ready', async (req, res) => {
  const checks = { process: true };

  // Check Redis if the nonce store has a ready() method
  if (typeof nonceStore.ready === 'function') {
    try {
      checks.redis = await nonceStore.ready();
    } catch {
      checks.redis = false;
    }
  }

  const allReady = Object.values(checks).every(Boolean);

  res.status(allReady ? 200 : 503).json({
    status:  allReady ? 'ready' : 'degraded',
    checks,
    ts:      Date.now(),
  });
});

export { router as healthRouter };

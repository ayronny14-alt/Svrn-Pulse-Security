// server/routes/stats.js
import { Router } from 'express';
import { usageStore } from '../stores.js';

const router = Router();

router.get('/', (req, res) => {
  const stats = usageStore.stats(req.apiKey);
  res.json({
    key:   req.keyRecord.name,
    tier:  req.keyRecord.tier,
    usage: stats,
  });
});

export { router as statsRouter };

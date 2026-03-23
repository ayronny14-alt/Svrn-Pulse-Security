// server/middleware/rateLimit.js
import { usageStore } from '../stores.js';

// Tier rate limits (requests per minute)
const TIER_LIMITS = {
  starter:    60,
  growth:     600,
  enterprise: 6000,
};

export function rateLimitMiddleware(req, res, next) {
  const { keyRecord, apiKey } = req;
  const limitPerMin = keyRecord.rateLimit
    ?? TIER_LIMITS[keyRecord.tier]
    ?? TIER_LIMITS.starter;

  const allowed = usageStore.check(apiKey, limitPerMin);
  if (!allowed) {
    usageStore.track(apiKey, 'blocked');
    return res.status(429).json({
      error: 'RATE_LIMIT_EXCEEDED',
      message: `Rate limit exceeded for tier '${keyRecord.tier}'. Limit: ${limitPerMin} req/min.`,
      retryAfter: 60,
    });
  }

  next();
}

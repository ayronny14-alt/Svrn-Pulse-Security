// server/middleware/auth.js
import { timingSafeEqual } from 'node:crypto';
import { config } from '../config.js';

/**
 * Timing-safe API key lookup.
 * Iterates all keys and uses timingSafeEqual to prevent timing side-channels.
 */
function _safeKeyLookup(incomingKey) {
  const incomingBuf = Buffer.from(incomingKey, 'utf8');
  for (const [storedKey, record] of config.apiKeys) {
    const storedBuf = Buffer.from(storedKey, 'utf8');
    if (
      storedBuf.length === incomingBuf.length &&
      timingSafeEqual(storedBuf, incomingBuf)
    ) {
      return record;
    }
  }
  return null;
}

export function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] ?? '';
  const key = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : req.headers['x-api-key'];

  if (!key) {
    return res.status(401).json({
      error: 'MISSING_API_KEY',
      message: 'Provide your API key via Authorization: Bearer sk_live_... or X-Api-Key header',
    });
  }

  const keyRecord = _safeKeyLookup(key);
  if (!keyRecord) {
    return res.status(401).json({
      error: 'INVALID_API_KEY',
      message: 'API key not recognised',
    });
  }

  req.apiKey     = key;
  req.keyRecord  = keyRecord;
  next();
}

// server/middleware/auth.js
import { config } from '../config.js';

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

  const keyRecord = config.apiKeys.get(key);
  if (!keyRecord) {
    return res.status(401).json({
      error: 'INVALID_API_KEY',
      message: 'API key not recognised',
    });
  }

  // Attach key metadata to request for downstream use
  req.apiKey     = key;
  req.keyRecord  = keyRecord;
  next();
}

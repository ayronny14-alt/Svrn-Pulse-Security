// server/stores.js
// Singleton store instances — imported by both index.js and route/middleware files.

import { createNonceStore } from './store/nonceStore.js';
import { createUsageStore } from './store/usageStore.js';
import { config } from './config.js';

// ── Nonce store: Redis when available, in-memory fallback ─────────────────────
let nonceStore;

if (config.redisUrl) {
  try {
    const { createRedisNonceStore } = await import('./store/redisNonceStore.js');
    nonceStore = await createRedisNonceStore(config.redisUrl, config.nonceTtl);
    console.log(JSON.stringify({ event: 'store.redis_connected', url: config.redisUrl.replace(/\/\/.*@/, '//***@') }));
  } catch (err) {
    console.error(JSON.stringify({ event: 'store.redis_failed', error: err.message }));
    console.warn('[pulse-api] Falling back to in-memory nonce store. Multi-instance deployments will NOT work.');
    nonceStore = createNonceStore(config.nonceTtl);
  }
} else {
  nonceStore = createNonceStore(config.nonceTtl);
}

export { nonceStore };
export const usageStore = createUsageStore(60_000); // 1-min sliding window

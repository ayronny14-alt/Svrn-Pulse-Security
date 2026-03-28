// server/store/redisNonceStore.js
// Redis-backed nonce store for multi-instance deployments.
// Uses atomic SET NX + DEL for replay prevention.

import { createClient } from 'redis';

/**
 * Create a Redis-backed nonce store.
 * Interface matches createNonceStore() from nonceStore.js.
 *
 * @param {string} redisUrl  — e.g. 'redis://localhost:6379'
 * @param {number} ttlSec    — nonce TTL in seconds
 * @returns {Promise<{ set, consume, size, ready, quit }>}
 */
export async function createRedisNonceStore(redisUrl, ttlSec = 300) {
  const client = createClient({ url: redisUrl });

  client.on('error', (err) => {
    console.error(JSON.stringify({
      ts:    Date.now(),
      event: 'redis.error',
      error: err.message,
    }));
  });

  await client.connect();

  return {
    async set(key) {
      // SET with EX for automatic expiry — NX not needed here (key is fresh random)
      await client.set(key, '1', { EX: ttlSec });
    },

    async consume(key) {
      // Atomic: DEL returns the number of keys deleted.
      // If 1 → nonce existed and was consumed. If 0 → already used or expired.
      const deleted = await client.del(key);
      return deleted === 1;
    },

    async size() {
      // Approximate — counts all keys matching the pulse nonce pattern
      const keys = await client.keys('pulse:*');
      return keys.length;
    },

    async ready() {
      try {
        await client.ping();
        return true;
      } catch {
        return false;
      }
    },

    async quit() {
      await client.quit();
    },
  };
}

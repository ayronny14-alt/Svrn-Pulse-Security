// server/store/nonceStore.js
// In-memory nonce store with periodic expiry cleanup.
// For multi-instance production: replace with Redis (same interface).

export function createNonceStore(ttlSec = 300) {
  const store = new Map(); // key → expiresAt

  // Periodic cleanup every 30 seconds instead of inline-on-threshold
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [k, exp] of store) {
      if (exp < now) store.delete(k);
    }
  }, 30_000);
  // Allow the process to exit even if cleanup is pending
  if (cleanupInterval.unref) cleanupInterval.unref();

  return {
    set(key) {
      store.set(key, Date.now() + ttlSec * 1000);
    },
    consume(key) {
      const exp = store.get(key);
      if (!exp || Date.now() > exp) return false;
      // Atomic check-and-delete: single synchronous block in Node.js
      store.delete(key);
      return true;
    },
    size() {
      return store.size;
    },
  };
}

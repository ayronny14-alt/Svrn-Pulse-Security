// server/store/nonceStore.js
// In-memory nonce store with lazy expiry cleanup.
// For multi-instance production: replace with Redis (same interface).

const _store = new Map(); // key → expiresAt

export function createNonceStore(ttlSec = 300) {
  return {
    set(key) {
      _store.set(key, Date.now() + ttlSec * 1000);
      // Lazy cleanup when store grows large
      if (_store.size > 50_000) {
        const now = Date.now();
        for (const [k, exp] of _store) {
          if (exp < now) _store.delete(k);
        }
      }
    },
    consume(key) {
      const exp = _store.get(key);
      if (!exp || Date.now() > exp) return false;
      _store.delete(key);
      return true;
    },
    size() {
      return _store.size;
    },
  };
}

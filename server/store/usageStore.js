// server/store/usageStore.js
// Sliding window rate limiter and usage counter.
// Each key tracks: total requests, requests in current window, window start time.

const _windows  = new Map(); // key → { count, windowStart }
const _totals   = new Map(); // key → { challenge, verify, blocked }

export function createUsageStore(windowMs = 60_000) {
  return {
    // Returns true if the request is allowed (within rate limit)
    check(apiKey, limitPerMin) {
      const now = Date.now();
      let w = _windows.get(apiKey);
      if (!w || now - w.windowStart > windowMs) {
        w = { count: 0, windowStart: now };
        _windows.set(apiKey, w);
      }
      if (w.count >= limitPerMin) return false;
      w.count++;
      return true;
    },

    track(apiKey, type) {
      let t = _totals.get(apiKey) ?? { challenge: 0, verify: 0, blocked: 0 };
      t[type] = (t[type] ?? 0) + 1;
      _totals.set(apiKey, t);
    },

    stats(apiKey) {
      return _totals.get(apiKey) ?? { challenge: 0, verify: 0, blocked: 0 };
    },

    allStats() {
      const out = {};
      for (const [k, v] of _totals) out[k] = v;
      return out;
    },
  };
}

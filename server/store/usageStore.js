// server/store/usageStore.js
// Sliding window rate limiter and usage counter.

const VALID_TYPES = new Set(['challenge', 'verify', 'blocked']);

export function createUsageStore(windowMs = 60_000) {
  const windows = new Map(); // key → { count, windowStart }
  const totals  = new Map(); // key → { challenge, verify, blocked }

  return {
    check(apiKey, limitPerMin) {
      const now = Date.now();
      let w = windows.get(apiKey);
      if (!w || now - w.windowStart > windowMs) {
        w = { count: 0, windowStart: now };
        windows.set(apiKey, w);
      }
      if (w.count >= limitPerMin) return false;
      w.count++;
      return true;
    },

    /** Cost-weighted check for challenge vs verify separation */
    checkWeighted(apiKey, limitPerMin, cost = 1) {
      const now = Date.now();
      let w = windows.get(apiKey);
      if (!w || now - w.windowStart > windowMs) {
        w = { count: 0, windowStart: now };
        windows.set(apiKey, w);
      }
      if (w.count + cost > limitPerMin) return false;
      w.count += cost;
      return true;
    },

    track(apiKey, type) {
      if (!VALID_TYPES.has(type)) {
        throw new Error(`[pulse-api] Invalid usage type: "${type}". Expected one of: ${[...VALID_TYPES].join(', ')}`);
      }
      let t = totals.get(apiKey) ?? { challenge: 0, verify: 0, blocked: 0 };
      t[type] += 1;
      totals.set(apiKey, t);
    },

    stats(apiKey) {
      return totals.get(apiKey) ?? { challenge: 0, verify: 0, blocked: 0 };
    },

    allStats() {
      const out = {};
      for (const [k, v] of totals) out[k] = v;
      return out;
    },
  };
}

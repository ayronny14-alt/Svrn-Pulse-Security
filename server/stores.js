// server/stores.js
// Singleton store instances — imported by both index.js and route/middleware files.
// Keeping these separate breaks the circular dependency that would occur if routes
// imported their stores from index.js (which imports the routes).

import { createNonceStore } from './store/nonceStore.js';
import { createUsageStore } from './store/usageStore.js';
import { config } from './config.js';

export const nonceStore = createNonceStore(config.nonceTtl);
export const usageStore = createUsageStore(60_000); // 1-min sliding window

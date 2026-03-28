// server/index.js
import express from 'express';
import cors    from 'cors';
import { config }             from './config.js';
import { nonceStore, usageStore } from './stores.js';  // singleton instances
import { authMiddleware }    from './middleware/auth.js';
import { rateLimitMiddleware } from './middleware/rateLimit.js';
import { challengeRouter }   from './routes/challenge.js';
import { verifyRouter }      from './routes/verify.js';
import { statsRouter }       from './routes/stats.js';
import { healthRouter }      from './routes/health.js';

// Re-export for any code that still needs direct access
export { nonceStore, usageStore };

// ── Express app ───────────────────────────────────────────────────────────
const app = express();

app.use(cors({
  origin: config.corsOrigins === '*' ? true : config.corsOrigins.split(',').map(s => s.trim()),
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Api-Key'],
}));

// ── Security headers ───────────────────────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
  res.removeHeader('X-Powered-By');
  next();
});

app.use(express.json({ limit: '64kb' }));

// ── Public routes ─────────────────────────────────────────────────────────
app.use('/health', healthRouter);

// ── Protected routes (auth + rate limit) ─────────────────────────────────
const v1 = express.Router();
v1.use(authMiddleware);
v1.use(rateLimitMiddleware);
v1.use('/challenge', challengeRouter);
v1.use('/verify',    verifyRouter);
v1.use('/stats',     statsRouter);
app.use('/v1', v1);

// ── 404 catch-all ─────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'NOT_FOUND', message: `${req.method} ${req.path} not found` });
});

// ── Global error handler ─────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[pulse-api] unhandled error:', err);
  res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Unexpected server error' });
});

// ── Boot ──────────────────────────────────────────────────────────────────
const server = app.listen(config.port, () => {
  console.log(JSON.stringify({
    event:   'server.started',
    port:    config.port,
    env:     config.nodeEnv,
    nonceTtl: config.nonceTtl,
  }));
});

// ── Graceful shutdown ─────────────────────────────────────────────────────
function shutdown(signal) {
  console.log(`[pulse-api] ${signal} received — shutting down gracefully`);
  server.close(() => {
    console.log('[pulse-api] HTTP server closed');
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 10_000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

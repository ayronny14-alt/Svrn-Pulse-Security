// server/config.js
import 'dotenv/config';

const raw = JSON.parse(process.env.PULSE_API_KEYS ?? '[]');
if (!Array.isArray(raw) || raw.length === 0) {
  console.warn('[pulse-api] WARNING: No API keys configured. Set PULSE_API_KEYS in .env');
}

export const config = Object.freeze({
  port:          parseInt(process.env.PORT ?? '3001', 10),
  nodeEnv:       process.env.NODE_ENV ?? 'development',
  redisUrl:      process.env.REDIS_URL ?? null,
  nonceTtl:      parseInt(process.env.NONCE_TTL ?? '300', 10),
  webhookSecret: process.env.WEBHOOK_SECRET ?? 'change-me',
  corsOrigins:   process.env.CORS_ORIGINS ?? '*',
  apiKeys:       new Map(raw.map(k => [k.key, k])),
});

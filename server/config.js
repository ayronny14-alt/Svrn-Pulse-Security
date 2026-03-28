// server/config.js
import 'dotenv/config';

let raw;
try {
  raw = JSON.parse(process.env.PULSE_API_KEYS ?? '[]');
} catch {
  throw new Error('[pulse-api] PULSE_API_KEYS is not valid JSON. Check your environment configuration.');
}

if (!Array.isArray(raw) || raw.length === 0) {
  console.warn('[pulse-api] WARNING: No API keys configured. Set PULSE_API_KEYS in .env');
}

// Validate webhook URLs at startup — reject private IPs and non-https schemes
function _validateWebhookUrl(url, keyName) {
  if (!url) return null;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`[pulse-api] Invalid webhookUrl for key "${keyName}": ${url}`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(`[pulse-api] webhookUrl must use https: for key "${keyName}": ${url}`);
  }
  const host = parsed.hostname;
  if (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host.startsWith('10.') ||
    host.startsWith('192.168.') ||
    host.startsWith('172.') ||
    host === '169.254.169.254' ||
    host.endsWith('.internal') ||
    host.endsWith('.local')
  ) {
    throw new Error(`[pulse-api] webhookUrl must not target private/internal addresses for key "${keyName}": ${url}`);
  }
  return url;
}

// Validate each key's webhookUrl at startup
for (const k of raw) {
  if (k.webhookUrl) {
    _validateWebhookUrl(k.webhookUrl, k.name ?? k.key?.slice(0, 8));
  }
}

const webhookSecret = process.env.WEBHOOK_SECRET ?? null;
const nodeEnv = process.env.NODE_ENV ?? 'development';

if (nodeEnv === 'production' && (!webhookSecret || webhookSecret === 'change-me')) {
  throw new Error('[pulse-api] WEBHOOK_SECRET must be set to a strong random value in production');
}

const corsOrigins = process.env.CORS_ORIGINS ?? '*';
if (nodeEnv === 'production' && corsOrigins === '*') {
  console.warn('[pulse-api] WARNING: CORS is set to "*" in production. Consider restricting to specific origins.');
}

export const config = Object.freeze({
  port:          parseInt(process.env.PORT ?? '3001', 10),
  nodeEnv,
  redisUrl:      process.env.REDIS_URL ?? null,
  nonceTtl:      parseInt(process.env.NONCE_TTL ?? '300', 10),
  webhookSecret: webhookSecret ?? 'change-me',
  corsOrigins,
  apiKeys:       new Map(raw.map(k => [k.key, k])),
});

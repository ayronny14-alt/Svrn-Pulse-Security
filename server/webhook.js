// server/webhook.js
import { createHmac } from 'node:crypto';
import { config } from './config.js';

/**
 * Fire a webhook to the API key's configured webhookUrl.
 * Signed with HMAC-SHA256 so the receiver can verify authenticity.
 * Non-blocking — errors are logged but never bubble up to the request.
 */
export async function fireWebhook(keyRecord, event, payload) {
  const url = keyRecord.webhookUrl;
  if (!url) return;

  const body      = JSON.stringify({ event, ...payload, ts: Date.now() });
  const signature = createHmac('sha256', config.webhookSecret)
    .update(body)
    .digest('hex');

  try {
    const res = await fetch(url, {
      method:  'POST',
      headers: {
        'Content-Type':        'application/json',
        'X-Pulse-Signature':   `sha256=${signature}`,
        'X-Pulse-Event':       event,
      },
      body,
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) {
      console.warn(`[pulse-api] webhook to ${url} returned ${res.status}`);
    }
  } catch (err) {
    console.error(`[pulse-api] webhook to ${url} failed:`, err.message);
  }
}

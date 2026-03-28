// server/webhook.js
import { createHmac } from 'node:crypto';
import { config } from './config.js';

/**
 * Fire a webhook to the API key's configured webhookUrl.
 * Signed with HMAC-SHA256 so the receiver can verify authenticity.
 * Non-blocking — errors are logged as structured JSON for audit trail.
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
      console.error(JSON.stringify({
        ts:      Date.now(),
        event:   'webhook.delivery_failed',
        url,
        status:  res.status,
        key:     keyRecord.name,
        reason:  `HTTP ${res.status}`,
      }));
    }
  } catch (err) {
    console.error(JSON.stringify({
      ts:      Date.now(),
      event:   'webhook.delivery_error',
      url,
      key:     keyRecord.name,
      error:   err.message,
    }));
  }
}

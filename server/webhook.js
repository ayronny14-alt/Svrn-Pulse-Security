// server/webhook.js
import { createHmac } from 'node:crypto';
import { config } from './config.js';

const MAX_RETRIES     = 3;
const RETRY_DELAYS_MS = [1_000, 3_000, 10_000]; // exponential-ish backoff

/**
 * Fire a webhook with retry and exponential backoff.
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

  const headers = {
    'Content-Type':        'application/json',
    'X-Pulse-Signature':   `sha256=${signature}`,
    'X-Pulse-Event':       event,
  };

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const res = await fetch(url, {
        method:  'POST',
        headers,
        body,
        signal: AbortSignal.timeout(5_000),
      });

      if (res.ok) return; // success

      // 4xx = client error, don't retry (except 429)
      if (res.status >= 400 && res.status < 500 && res.status !== 429) {
        console.error(JSON.stringify({
          ts:      Date.now(),
          event:   'webhook.delivery_failed',
          url,
          status:  res.status,
          key:     keyRecord.name,
          attempt: attempt + 1,
          final:   true,
          reason:  `HTTP ${res.status} (not retryable)`,
        }));
        return;
      }

      // 5xx or 429 — log and retry
      console.warn(JSON.stringify({
        ts:      Date.now(),
        event:   'webhook.retry',
        url,
        status:  res.status,
        key:     keyRecord.name,
        attempt: attempt + 1,
      }));

    } catch (err) {
      console.warn(JSON.stringify({
        ts:      Date.now(),
        event:   'webhook.retry',
        url,
        key:     keyRecord.name,
        attempt: attempt + 1,
        error:   err.message,
      }));
    }

    // Wait before retry (skip delay on last attempt)
    if (attempt < MAX_RETRIES) {
      await new Promise(r => setTimeout(r, RETRY_DELAYS_MS[attempt] ?? 10_000));
    }
  }

  // All retries exhausted — dead letter log
  console.error(JSON.stringify({
    ts:      Date.now(),
    event:   'webhook.dead_letter',
    url,
    key:     keyRecord.name,
    eventType: event,
    payload: payload,
    reason:  `Failed after ${MAX_RETRIES + 1} attempts`,
  }));
}

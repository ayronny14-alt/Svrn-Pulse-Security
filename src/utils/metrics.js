/**
 * @svrnsec/pulse — Metrics & Observability
 *
 * Prometheus/OpenTelemetry compatible metrics for monitoring
 * Pulse verification rates, scores, and latency.
 */

import client from 'prom-client';

export class PulseMetrics {
  constructor(opts = {}) {
    this._prefix = opts.prefix || 'svrnsec_pulse_';
    this._registry = opts.registry || client.register;

    // Pulse verification events
    this.verifications = new client.Counter({
      name: `${this._prefix}verifications_total`,
      help: 'Total number of Pulse verifications processed',
      labelNames: ['verdict', 'version'],
      registers: [this._registry]
    });

    // Score distribution
    this.scores = new client.Histogram({
      name: `${this._prefix}score_distribution`,
      help: 'Distribution of Pulse trust scores (0.0 - 1.0)',
      buckets: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
      registers: [this._registry]
    });

    // Latency of verification
    this.latency = new client.Summary({
      name: `${this._prefix}verification_latency_ms`,
      help: 'Latency of Pulse payload verification in milliseconds',
      registers: [this._registry]
    });

    // Component scores (jitter, audio, etc)
    this.componentScores = new client.Gauge({
      name: `${this._prefix}component_score`,
      help: 'Average score for individual Pulse signals',
      labelNames: ['component'],
      registers: [this._registry]
    });
  }

  record(result) {
    this.verifications.inc({ 
      verdict: result.verdict, 
      version: result.version || 'v0.9' 
    });
    
    this.scores.observe(result.score);
    
    if (result.duration) {
      this.latency.observe(result.duration);
    }

    if (result.components) {
      for (const [name, comp] of Object.entries(result.components)) {
        this.componentScores.set({ component: name }, comp.score);
      }
    }
  }

  getMetrics() {
    return this._registry.metrics();
  }

  get contentType() {
    return this._registry.contentType;
  }
}

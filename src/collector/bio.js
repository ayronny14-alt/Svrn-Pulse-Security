/**
 * @svrnsec/pulse — Bio-Binding Layer
 */

import { mean, variance, cv, percentile } from '../utils/stats.js';

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------
const MAX_EVENTS     = 500; // rolling buffer cap
const MAX_KEY_STATES = 50;  // cap on simultaneous tracked key states

// ---------------------------------------------------------------------------
// BioCollector class
// ---------------------------------------------------------------------------
export class BioCollector {
  constructor() {
    this._mouseEvents  = []; // { t: DOMHighResTimeStamp, dx, dy }
    this._keyEvents    = []; // { t, type: 'down'|'up', dwell: ms|null }
    this._lastKey      = {}; // keyCode → { downAt: t }
    this._lastMouse    = null; // { t, x, y }
    this._startTime    = null;
    this._active       = false;

    // Bound handlers (needed for removeEventListener)
    this._onMouseMove  = this._onMouseMove.bind(this);
    this._onKeyDown    = this._onKeyDown.bind(this);
    this._onKeyUp      = this._onKeyUp.bind(this);
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────

  start() {
    if (this._active) return;
    this._active    = true;
    this._startTime = performance.now();

    if (typeof window !== 'undefined') {
      window.addEventListener('pointermove', this._onMouseMove, { passive: true });
      window.addEventListener('keydown',     this._onKeyDown,   { passive: true });
      window.addEventListener('keyup',       this._onKeyUp,     { passive: true });
    }
  }

  stop() {
    if (!this._active) return;
    this._active = false;

    if (typeof window !== 'undefined') {
      window.removeEventListener('pointermove', this._onMouseMove);
      window.removeEventListener('keydown',     this._onKeyDown);
      window.removeEventListener('keyup',       this._onKeyUp);
    }

    this._lastMouse = null;
  }

  // ── Event handlers ────────────────────────────────────────────────────────

  _onMouseMove(e) {
    if (!this._active) return;
    const t   = e.timeStamp ?? performance.now();
    const cur = { t, x: e.clientX, y: e.clientY };

    if (this._lastMouse) {
      const dt = t - this._lastMouse.t;
      const dx = cur.x - this._lastMouse.x;
      const dy = cur.y - this._lastMouse.y;
      // Only store the delta, not absolute position (privacy)
      if (this._mouseEvents.length < MAX_EVENTS) {
        this._mouseEvents.push({ t, dt, dx, dy,
          pressure: e.pressure ?? 0,
          pointerType: e.pointerType ?? 'mouse' });
      }
    }
    this._lastMouse = cur;
  }

  _onKeyDown(e) {
    if (!this._active) return;
    const t = e.timeStamp ?? performance.now();
    // Store timestamp keyed by code (NOT key label)
    this._lastKey[e.code] = { downAt: t };
    // Prevent unbounded growth if keys are held without keyup
    if (Object.keys(this._lastKey).length > MAX_KEY_STATES) {
      const oldest = Object.entries(this._lastKey)
        .sort((a, b) => a[1].downAt - b[1].downAt)[0];
      if (oldest) delete this._lastKey[oldest[0]];
    }
  }

  _onKeyUp(e) {
    if (!this._active) return;
    const t   = e.timeStamp ?? performance.now();
    const rec = this._lastKey[e.code];
    const dwell = rec ? (t - rec.downAt) : null;
    delete this._lastKey[e.code];

    if (this._keyEvents.length < MAX_EVENTS) {
      // Only dwell time; key identity NOT stored.
      this._keyEvents.push({ t, dwell });
    }
  }

  // ── snapshot ─────────────────────────────────────────────────────────────

  /**
   * Returns a privacy-preserving statistical snapshot of collected bio signals.
   * Raw events are summarised; nothing identifiable is included in the output.
   *
   * @param {number[]} computationTimings  - entropy probe timing array
   * @returns {BioSnapshot}
   */
  snapshot(computationTimings = []) {
    const now = performance.now();
    const durationMs = this._startTime != null ? (now - this._startTime) : 0;

    // ── Mouse statistics ────────────────────────────────────────────────
    const iei         = this._mouseEvents.map(e => e.dt);
    const velocities  = this._mouseEvents.map(e =>
      e.dt > 0 ? Math.hypot(e.dx, e.dy) / e.dt : 0
    );
    const pressure    = this._mouseEvents.map(e => e.pressure);
    const angJerk     = _computeAngularJerk(this._mouseEvents);

    const mouseStats = {
      sampleCount:      iei.length,
      ieiMean:          mean(iei),
      ieiCV:            cv(iei),
      velocityP50:      percentile(velocities, 50),
      velocityP95:      percentile(velocities, 95),
      angularJerkMean:  mean(angJerk),
      pressureVariance: variance(pressure),
    };

    // ── Keyboard statistics ───────────────────────────────────────────────
    const dwellTimes = this._keyEvents.filter(e => e.dwell != null).map(e => e.dwell);
    const iki = [];
    for (let i = 1; i < this._keyEvents.length; i++) {
      iki.push(this._keyEvents[i].t - this._keyEvents[i - 1].t);
    }

    const keyStats = {
      sampleCount:   dwellTimes.length,
      dwellMean:     mean(dwellTimes),
      dwellCV:       cv(dwellTimes),
      ikiMean:       mean(iki),
      ikiCV:         cv(iki),
    };

    // ── Interference Coefficient ──────────────────────────────────────────
    // Cross-correlate input event density with computation timing deviations.
    // A real human on real hardware creates measurable CPU-scheduling pressure
    // that perturbs the entropy probe's timing.
    const interferenceCoefficient = _computeInterference(
      this._mouseEvents,
      this._keyEvents,
      computationTimings,
    );

    return {
      mouse:                   mouseStats,
      keyboard:                keyStats,
      interferenceCoefficient,
      durationMs,
      hasActivity:             iei.length > 5 || dwellTimes.length > 2,
    };
  }
}

/**
 * @typedef {object} BioSnapshot
 * @property {object}  mouse
 * @property {object}  keyboard
 * @property {number}  interferenceCoefficient  – [−1, 1]; higher = more human
 * @property {number}  durationMs
 * @property {boolean} hasActivity
 */

// ---------------------------------------------------------------------------
// Statistical helpers (private)
// ---------------------------------------------------------------------------

const _mean = mean;

/** Angular jerk: second derivative of movement direction (radians / s²) */
function _computeAngularJerk(events) {
  if (events.length < 3) return [];
  const angles = [];
  for (let i = 0; i < events.length; i++) {
    const { dx, dy } = events[i];
    angles.push(Math.atan2(dy, dx));
  }
  const d1 = [];
  for (let i = 1; i < angles.length; i++) {
    const dt = events[i].dt || 1;
    d1.push((angles[i] - angles[i - 1]) / dt);
  }
  const d2 = [];
  for (let i = 1; i < d1.length; i++) {
    const dt = events[i].dt || 1;
    d2.push(Math.abs((d1[i] - d1[i - 1]) / dt));
  }
  return d2;
}

/**
 * Interference Coefficient
 *
 * For each computation sample, check whether an input event occurred within
 * ±16 ms (one animation frame).  Build two parallel series:
 *   X[i] = 1 if input near sample i, else 0
 *   Y[i] = deviation of timing[i] from mean timing
 * Return the Pearson correlation between X and Y.
 * A real human on real hardware produces positive correlation (input events
 * cause measurable CPU scheduling perturbations).
 */
function _computeInterference(mouseEvents, keyEvents, timings) {
  if (!timings.length) return 0;

  const allInputTimes = [
    ...mouseEvents.map(e => e.t),
    ...keyEvents.map(e => e.t),
  ].sort((a, b) => a - b);

  if (!allInputTimes.length) return 0;

  const WINDOW_MS = 16;
  const meanTiming = _mean(timings);

  // Note: timing alignment is approximate; probe start timestamp would improve accuracy
  // We need absolute timestamps for the probe samples.
  // We don't have them directly – use relative index spacing as a proxy.
  // The entropy probe runs for ~(mean * n) ms starting at collectedAt.
  // This is a statistical approximation; the exact alignment improves
  // when callers pass `collectedAt` from the entropy result.
  // For now we distribute samples evenly across the collection window.
  const first = allInputTimes[0];
  const last  = allInputTimes[allInputTimes.length - 1];
  const span  = Math.max(last - first, 1);

  const X = timings.map((_, i) => {
    const tSample = first + (i / timings.length) * span;
    return allInputTimes.some(t => Math.abs(t - tSample) < WINDOW_MS) ? 1 : 0;
  });

  const Y = timings.map(t => t - meanTiming);

  return _pearson(X, Y);
}

function _pearson(X, Y) {
  const n   = X.length;
  if (n < 2) return 0;
  const mx  = _mean(X);
  const my  = _mean(Y);
  let num = 0, da = 0, db = 0;
  for (let i = 0; i < n; i++) {
    const a = X[i] - mx;
    const b = Y[i] - my;
    num += a * b;
    da  += a * a;
    db  += b * b;
  }
  const denom = Math.sqrt(da * db);
  return denom < 1e-14 ? 0 : num / denom;
}

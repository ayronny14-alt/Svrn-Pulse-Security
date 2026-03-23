/**
 * @sovereign/pulse — AudioContext Oscillator Jitter
 *
 * Measures the scheduling jitter of the browser's audio pipeline.
 * Real audio hardware callbacks are driven by a hardware interrupt (IRQ)
 * from the sound card; the timing reflects the actual interrupt latency
 * of the physical device.  VM audio drivers (if present at all) are
 * emulated and show either unrealistically low jitter or burst-mode
 * scheduling artefacts that are statistically distinguishable.
 */

/**
 * @param {object} [opts]
 * @param {number} [opts.durationMs=2000]  - how long to collect audio callbacks
 * @param {number} [opts.bufferSize=256]   - ScriptProcessorNode buffer size
 * @returns {Promise<AudioJitter>}
 */
export async function collectAudioJitter(opts = {}) {
  const { durationMs = 2000, bufferSize = 256 } = opts;

  const base = {
    available:         false,
    workletAvailable:  false,
    callbackJitterCV:  0,
    noiseFloorMean:    0,
    sampleRate:        0,
    callbackCount:     0,
    jitterTimings:     [],
  };

  if (typeof AudioContext === 'undefined' && typeof webkitAudioContext === 'undefined') {
    return base; // Node.js / server environment
  }

  let ctx;
  try {
    ctx = new (window.AudioContext || window.webkitAudioContext)();
  } catch (_) {
    return base;
  }

  // Some browsers require a user gesture before AudioContext can run.
  if (ctx.state === 'suspended') {
    try {
      await ctx.resume();
    } catch (_) {
      await ctx.close().catch(() => {});
      return base;
    }
  }

  const sampleRate       = ctx.sampleRate;
  const expectedInterval = (bufferSize / sampleRate) * 1000; // ms per callback

  const jitterTimings = []; // absolute AudioContext.currentTime at each callback
  const callbackDeltas = [];

  const result = await new Promise((resolve) => {
    // ── AudioWorklet (preferred — runs on dedicated real-time thread) ──────
    const useWorklet = typeof AudioWorkletNode !== 'undefined';
    base.workletAvailable = useWorklet;

    if (useWorklet) {
      // Inline worklet: send currentTime back via MessagePort every buffer
      const workletCode = `
        class PulseProbe extends AudioWorkletProcessor {
          process(inputs, outputs) {
            this.port.postMessage({ t: currentTime });
            // Pass-through silence
            for (const out of outputs)
              for (const ch of out) ch.fill(0);
            return true;
          }
        }
        registerProcessor('pulse-probe', PulseProbe);
      `;
      const blob    = new Blob([workletCode], { type: 'application/javascript' });
      const blobUrl = URL.createObjectURL(blob);

      ctx.audioWorklet.addModule(blobUrl).then(() => {
        const node = new AudioWorkletNode(ctx, 'pulse-probe');
        node.port.onmessage = (e) => {
          jitterTimings.push(e.data.t * 1000); // convert to ms
        };
        node.connect(ctx.destination);

        setTimeout(async () => {
          node.disconnect();
          URL.revokeObjectURL(blobUrl);
          resolve(node);
        }, durationMs);
      }).catch(() => {
        URL.revokeObjectURL(blobUrl);
        _fallbackScriptProcessor(ctx, bufferSize, durationMs, jitterTimings, resolve);
      });

    } else {
      _fallbackScriptProcessor(ctx, bufferSize, durationMs, jitterTimings, resolve);
    }
  });

  // ── Compute deltas between successive callback times ────────────────────
  for (let i = 1; i < jitterTimings.length; i++) {
    callbackDeltas.push(jitterTimings[i] - jitterTimings[i - 1]);
  }

  // ── Noise floor via AnalyserNode ─────────────────────────────────────────
  // Feed a silent oscillator through an analyser; the FFT magnitude at silence
  // reveals the hardware's thermal noise floor (varies per ADC/DAC chipset).
  const noiseFloor = await _measureNoiseFloor(ctx);

  await ctx.close().catch(() => {});

  // ── Statistics ────────────────────────────────────────────────────────────
  const mean = callbackDeltas.length
    ? callbackDeltas.reduce((s, v) => s + v, 0) / callbackDeltas.length
    : 0;
  const variance = callbackDeltas.length > 1
    ? callbackDeltas.reduce((s, v) => s + (v - mean) ** 2, 0) / (callbackDeltas.length - 1)
    : 0;
  const jitterCV = mean > 0 ? Math.sqrt(variance) / mean : 0;

  return {
    available:         true,
    workletAvailable:  base.workletAvailable,
    callbackJitterCV:  jitterCV,
    noiseFloorMean:    noiseFloor.mean,
    noiseFloorStd:     noiseFloor.std,
    sampleRate,
    callbackCount:     jitterTimings.length,
    expectedIntervalMs: expectedInterval,
    // Only include summary stats, not raw timings (privacy / size)
    jitterMeanMs:      mean,
    jitterP95Ms:       _percentile(callbackDeltas, 95),
  };
}

/**
 * @typedef {object} AudioJitter
 * @property {boolean} available
 * @property {boolean} workletAvailable
 * @property {number}  callbackJitterCV
 * @property {number}  noiseFloorMean
 * @property {number}  sampleRate
 * @property {number}  callbackCount
 */

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _fallbackScriptProcessor(ctx, bufferSize, durationMs, jitterTimings, resolve) {
  // ScriptProcessorNode is deprecated but universally supported.
  const proc = ctx.createScriptProcessor(bufferSize, 1, 1);
  proc.onaudioprocess = () => {
    jitterTimings.push(ctx.currentTime * 1000);
  };
  // Connect to keep the graph alive
  const osc = ctx.createOscillator();
  osc.frequency.value = 1; // sub-audible
  osc.connect(proc);
  proc.connect(ctx.destination);
  osc.start();

  setTimeout(() => {
    osc.stop();
    osc.disconnect();
    proc.disconnect();
    resolve(proc);
  }, durationMs);
}

async function _measureNoiseFloor(ctx) {
  try {
    const analyser = ctx.createAnalyser();
    analyser.fftSize = 256;
    analyser.connect(ctx.destination);

    // Silent source
    const buf  = ctx.createBuffer(1, ctx.sampleRate * 0.1, ctx.sampleRate);
    const src  = ctx.createBufferSource();
    src.buffer = buf;
    src.connect(analyser);
    src.start();

    await new Promise(r => setTimeout(r, 150));

    const data = new Float32Array(analyser.frequencyBinCount);
    analyser.getFloatFrequencyData(data);
    analyser.disconnect();

    // Limit to 32 bins to keep the payload small
    const trimmed = Array.from(data.slice(0, 32)).map(v =>
      isFinite(v) ? Math.pow(10, v / 20) : 0 // dB → linear
    );
    const mean = trimmed.reduce((s, v) => s + v, 0) / trimmed.length;
    const std  = Math.sqrt(
      trimmed.reduce((s, v) => s + (v - mean) ** 2, 0) / trimmed.length
    );
    return { mean, std };
  } catch (_) {
    return { mean: 0, std: 0 };
  }
}

function _percentile(arr, p) {
  if (!arr.length) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx    = (p / 100) * (sorted.length - 1);
  const lo     = Math.floor(idx);
  const hi     = Math.ceil(idx);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

/**
 * @svrnsec/pulse
 *
 * Physical Turing Test — distinguishes a real consumer device with a human
 * operator from a sanitised Datacenter VM / AI Instance.
 *
 * Usage (client-side):
 *
 *   import { pulse } from '@svrnsec/pulse';
 *
 *   // 1. Get a server-issued nonce (prevents replay attacks)
 *   const { nonce } = await fetch('/api/pulse-challenge').then(r => r.json());
 *
 *   // 2. Run the probe (takes ~3-5 seconds)
 *   const { payload, hash } = await pulse({ nonce });
 *
 *   // 3. Send to your server
 *   const verdict = await fetch('/api/pulse-verify', {
 *     method: 'POST',
 *     body: JSON.stringify({ payload, hash }),
 *   }).then(r => r.json());
 *
 * Usage (server-side):
 *
 *   import { validateProof, generateNonce } from '@svrnsec/pulse/validator';
 *
 *   // Challenge endpoint
 *   app.get('/api/pulse-challenge', (req, res) => {
 *     const nonce = generateNonce();
 *     await redis.set(`pulse:nonce:${nonce}`, '1', 'EX', 300); // 5-min TTL
 *     res.json({ nonce });
 *   });
 *
 *   // Verify endpoint
 *   app.post('/api/pulse-verify', async (req, res) => {
 *     const { payload, hash } = req.body;
 *     const result = await validateProof(payload, hash, {
 *       checkNonce: async (n) => {
 *         const ok = await redis.del(`pulse:nonce:${n}`);
 *         return ok === 1; // true only if nonce existed and was consumed
 *       },
 *     });
 *     res.json(result);
 *   });
 */

import { collectEntropy }           from './collector/entropy.js';
import { BioCollector }             from './collector/bio.js';
import { collectCanvasFingerprint } from './collector/canvas.js';
import { collectAudioJitter }       from './analysis/audio.js';
import { classifyJitter }           from './analysis/jitter.js';
import { buildProof, buildCommitment } from './proof/fingerprint.js';
import { collectGpuEntropy }        from './collector/gpu.js';
import { collectDramTimings }       from './collector/dram.js';
import { collectEnfTimings }        from './collector/enf.js';
import { detectLlmAgent }       from './analysis/llm.js';
import { notifyOnExit }             from './update-notifier.js';
import { CONFIG }                   from './config.js';

// Register background update check — fires once at process startup.
// Shows a styled notification box after the process exits if a newer version
// is available. No-op in browser environments and non-TTY outputs.
notifyOnExit();

// ---------------------------------------------------------------------------
// Hosted API mode — pulse({ apiKey }) with zero server setup
// ---------------------------------------------------------------------------

/**
 * Run pulse() against the sovereign hosted API.
 * Fetches nonce, runs probe locally (WASM still on device), submits proof.
 *
 * @param {object} opts  — same as pulse(), plus apiKey + apiUrl
 * @returns {Promise<{ payload, hash, result }>}
 */
async function _pulseHosted(opts) {
  const {
    apiKey,
    apiUrl            = 'https://api.sovereign.dev',
    iterations        = 200,
    matrixSize        = 64,
    bioWindowMs       = 3_000,
    phased            = true,
    adaptive          = true,
    adaptiveThreshold = 0.85,
    requireBio        = false,
    wasmPath,
    onProgress,
    verifyOptions     = {},
  } = opts;

  // 1. Fetch nonce from hosted challenge endpoint
  const challengeRes = await fetch(`${apiUrl}/v1/challenge`, {
    headers: { 'Authorization': `Bearer ${apiKey}` },
  });
  if (!challengeRes.ok) {
    const body = await challengeRes.json().catch(() => ({}));
    throw new Error(`[pulse] Challenge failed (${challengeRes.status}): ${body.message ?? 'unknown error'}`);
  }
  const { nonce } = await challengeRes.json();

  // 2. Run the local probe (WASM, bio, canvas, audio — all on device)
  const commitment = await _runProbe({
    nonce, iterations, matrixSize, bioWindowMs,
    phased, adaptive, adaptiveThreshold, requireBio,
    wasmPath, onProgress,
  });

  // 3. Submit proof to hosted verify endpoint
  const verifyRes = await fetch(`${apiUrl}/v1/verify`, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      payload: commitment.payload,
      hash:    commitment.hash,
      options: verifyOptions,
    }),
  });

  const result = await verifyRes.json();

  // Return commitment + server result for convenience
  return { ...commitment, result };
}

// ---------------------------------------------------------------------------
// pulse()  — main entry point
// ---------------------------------------------------------------------------

const _pulseHistory = [];

/**
 * Run the full @svrnsec/pulse probe and return a signed commitment.
 *
 * Two modes:
 *   - pulse({ nonce })     — self-hosted (you manage the nonce server)
 *   - pulse({ apiKey })    — hosted API (zero server setup required)
 *
 * @param {PulseOptions} opts
 * @returns {Promise<PulseCommitment>}
 */
export async function pulse(opts = {}) {
  // ── Client-side rate limiting ──────────────────────────────────────────────
  const now = Date.now();
  const windowMs = 60_000;
  const maxPerWindow = CONFIG.rateLimit.maxPulsesPerMin;
  
  // Clean old entries
  while (_pulseHistory.length > 0 && _pulseHistory[0] < now - windowMs) {
    _pulseHistory.shift();
  }

  if (_pulseHistory.length >= maxPerWindow) {
    throw new Error(`@svrnsec/pulse: Rate limit exceeded (${maxPerWindow} pulses per minute). Please wait before trying again.`);
  }
  _pulseHistory.push(now);

  // ── Hosted API mode ────────────────────────────────────────────────────────
  if (opts.apiKey) {
    return _pulseHosted(opts);
  }

  // ── Self-hosted mode ───────────────────────────────────────────────────────
  const { nonce } = opts;
  if (!nonce || typeof nonce !== 'string') {
    throw new Error(
      '@svrnsec/pulse: opts.nonce is required (self-hosted), or pass opts.apiKey for zero-config hosted mode.'
    );
  }

  return _runProbe(opts);
}

/**
 * Internal probe runner — shared between self-hosted and hosted API modes.
 * @private
 */
async function _runProbe(opts) {
  const {
    nonce,
    timeout           = 8_000,
    iterations        = 200,
    matrixSize        = 64,
    bioWindowMs       = 3_000,
    phased            = true,
    adaptive          = true,
    adaptiveThreshold = 0.85,
    requireBio        = false,
    wasmPath,
    onProgress,
  } = opts;

  _emit(onProgress, 'start');

  // ── Phase 1: Start bio collector immediately (collects events over time) ──
  const bio = new BioCollector();
  bio.start();

  // ── Phase 2: Parallel collection ──────────────────────────────────────────
  const raceTimeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('pulse() timed out')), timeout)
  );

  let entropyResult, canvasResult, audioResult;

  try {
    [entropyResult, canvasResult, audioResult] = await Promise.race([
      Promise.all([
        collectEntropy({
          iterations, matrixSize, phased, adaptive, adaptiveThreshold, wasmPath,
          onBatch: (meta) => _emit(onProgress, 'entropy_batch', meta),
        }).then(r => { _emit(onProgress, 'entropy_done'); return r; }),
        collectCanvasFingerprint()
          .then(r => { _emit(onProgress, 'canvas_done'); return r; }),
        collectAudioJitter({ durationMs: Math.min(bioWindowMs, 2_000) })
          .then(r => { _emit(onProgress, 'audio_done'); return r; }),
      ]),
      raceTimeout,
    ]);
  } catch (err) {
    bio.stop();
    throw err;
  }

  // ── Phase 3: Bio snapshot ─────────────────────────────────────────────────
  const bioElapsed = Date.now() - entropyResult.collectedAt;
  const bioRemain  = Math.max(0, bioWindowMs - bioElapsed);
  if (bioRemain > 0) await _sleep(bioRemain);

  bio.stop();
  const bioSnapshot = bio.snapshot(entropyResult.timings);

  if (requireBio && !bioSnapshot.hasActivity) {
    throw new Error('@svrnsec/pulse: no bio activity detected (requireBio=true)');
  }

  _emit(onProgress, 'bio_done');

  // ── Phase 4: Extended signal collection (non-blocking, best-effort) ───────
  // ENF, GPU, DRAM, and LLM detectors run in parallel after the core probe.
  // Each gracefully returns a null/unavailable result if the environment does
  // not support it (e.g. no WebGPU, no SharedArrayBuffer, no bio events).
  const [enfResult, gpuResult, dramResult, llmResult] = await Promise.all([
    collectEnfTimings().catch(() => null),
    collectGpuEntropy().catch(() => null),
    Promise.resolve(collectDramTimings()).catch(() => null),
    Promise.resolve(detectLlmAgent(bioSnapshot)).catch(() => null),
  ]);

  _emit(onProgress, 'extended_done', {
    enf:  enfResult?.verdict,
    gpu:  gpuResult?.verdict,
    dram: dramResult?.verdict,
    llm:  llmResult?.aiConf,
  });

  // ── Phase 5: Jitter analysis ───────────────────────────────────────────────
  const jitterAnalysis = classifyJitter(entropyResult.timings, {
    autocorrelations: entropyResult.autocorrelations,
  });

  _emit(onProgress, 'analysis_done');

  // ── Phase 6: Build proof & commitment ─────────────────────────────────────
  const payload    = buildProof({
    entropy: entropyResult,
    jitter:  jitterAnalysis,
    bio:     bioSnapshot,
    canvas:  canvasResult,
    audio:   audioResult,
    enf:     enfResult,
    gpu:     gpuResult,
    dram:    dramResult,
    llm:     llmResult,
    nonce,
  });

  const commitment = buildCommitment(payload);

  _emit(onProgress, 'complete', {
    score:      jitterAnalysis.score,
    confidence: _scoreToLabel(jitterAnalysis.score),
    flags:      jitterAnalysis.flags,
    enf:        enfResult?.verdict,
    gpu:        gpuResult?.verdict,
    dram:       dramResult?.verdict,
    llmConf:    llmResult?.aiConf ?? null,
  });

  return { ...commitment, extended: { enf: enfResult, gpu: gpuResult, dram: dramResult, llm: llmResult } };
}

/**
 * @typedef {object} PulseOptions
 * @property {string}   nonce          - server-issued challenge nonce (required)
 * @property {number}   [timeout=6000] - max ms before throwing
 * @property {number}   [iterations=200]
 * @property {number}   [matrixSize=64]
 * @property {number}   [bioWindowMs=3000]
 * @property {boolean}  [requireBio=false]
 * @property {string}   [wasmPath]     - custom WASM binary URL/path
 * @property {Function} [onProgress]   - callback(stage, meta?) for progress events
 */

/**
 * @typedef {object} PulseCommitment
 * @property {import('./proof/fingerprint.js').ProofPayload} payload
 * @property {string} hash  - hex BLAKE3 commitment
 */

// ---------------------------------------------------------------------------
// Re-exports for convenience
// ---------------------------------------------------------------------------

// High-level developer API (the easiest way to use this package)
export { Fingerprint }         from './fingerprint.js';

// Analysis modules for advanced / custom integrations
export { runHeuristicEngine }  from './analysis/heuristic.js';
export { detectProvider }      from './analysis/provider.js';

// Server-side validation
export { generateNonce }       from './proof/validator.js';
export { validateProof }       from './proof/validator.js';

// Extended signal collectors (also available as named sub-path exports)
export { collectGpuEntropy }   from './collector/gpu.js';
export { collectDramTimings }  from './collector/dram.js';
export { collectEnfTimings }   from './collector/enf.js';
export { detectLlmAgent }  from './analysis/llm.js';

// Terminal utilities — pretty probe results in Node.js server contexts
export { renderProbeResult, renderError, renderInlineUpdateHint } from './terminal.js';

// Structured error codes
export { PulseErrorCode } from './errors.js';

// Version introspection
export { CURRENT_VERSION, checkForUpdate } from './update-notifier.js';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function _emit(fn, stage, meta = {}) {
  if (typeof fn === 'function') {
    try { fn(stage, meta); } catch (_) {}
  }
}

function _scoreToLabel(score) {
  if (score >= 0.75) return 'high';
  if (score >= 0.55) return 'medium';
  if (score >= 0.35) return 'low';
  return 'rejected';
}

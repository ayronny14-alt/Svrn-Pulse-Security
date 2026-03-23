/**
 * @sovereign/pulse — Hardware Fingerprint & Proof Builder
 *
 * Assembles all collected signals into a canonical ProofPayload, then
 * produces a BLAKE3 commitment: BLAKE3(canonicalJSON(payload)).
 *
 * The commitment is what gets sent to the server.  The server recomputes
 * the hash from the payload to detect tampering.  Raw timing arrays and
 * pixel buffers are NOT included — only statistical summaries.
 *
 * Zero-Knowledge property: the server learns only that the device passes
 * statistical thresholds.  It never sees raw hardware telemetry.
 */

import { blake3 } from '@noble/hashes/blake3';
import { bytesToHex } from '@noble/hashes/utils';

// ---------------------------------------------------------------------------
// BLAKE3 helpers (re-exported for use by canvas.js etc.)
// ---------------------------------------------------------------------------

/**
 * Compute BLAKE3 of a Uint8Array and return hex string.
 * @param {Uint8Array} data
 * @returns {string}
 */
export function blake3Hex(data) {
  return bytesToHex(blake3(data));
}

/**
 * Compute BLAKE3 of a UTF-8 string and return hex string.
 * @param {string} str
 * @returns {string}
 */
export function blake3HexStr(str) {
  return blake3Hex(new TextEncoder().encode(str));
}

// ---------------------------------------------------------------------------
// buildProof
// ---------------------------------------------------------------------------

/**
 * Assembles a ProofPayload from all collected signals.
 * This is the canonical structure that gets hashed into the commitment.
 *
 * @param {object} p
 * @param {import('../collector/entropy.js').EntropyResult}  p.entropy
 * @param {import('../analysis/jitter.js').JitterAnalysis}   p.jitter
 * @param {import('../collector/bio.js').BioSnapshot}         p.bio
 * @param {import('../collector/canvas.js').CanvasFingerprint} p.canvas
 * @param {import('../analysis/audio.js').AudioJitter}         p.audio
 * @param {string}  p.nonce    – server-issued challenge nonce (hex)
 * @returns {ProofPayload}
 */
export function buildProof({ entropy, jitter, bio, canvas, audio, enf, gpu, dram, llm, nonce }) {
  if (!nonce || typeof nonce !== 'string') {
    throw new Error('@svrnsec/pulse: nonce is required for anti-replay protection');
  }

  // Hash the raw timing arrays IN-BROWSER so we can prove their integrity
  // without transmitting the raw data.
  const timingsHash = blake3HexStr(JSON.stringify(entropy.timings));
  const memHash     = blake3HexStr(JSON.stringify(entropy.memTimings));

  const payload = {
    version:   1,
    timestamp: entropy.collectedAt,
    nonce,

    signals: {
      // ── Entropy probe ───────────────────────────────────────────────────
      entropy: {
        timingsMean:          _round(jitter.stats?.mean,        4),
        timingsCV:            _round(jitter.stats?.cv,          4),
        timingsP50:           _round(jitter.stats?.p50,         4),
        timingsP95:           _round(jitter.stats?.p95,         4),
        timingsSkewness:      _round(jitter.stats?.skewness,    4),
        timingsKurtosis:      _round(jitter.stats?.kurtosis,    4),
        autocorr_lag1:        _round(jitter.autocorrelations?.lag1, 4),
        autocorr_lag2:        _round(jitter.autocorrelations?.lag2, 4),
        autocorr_lag5:        _round(jitter.autocorrelations?.lag5, 4),
        autocorr_lag10:       _round(jitter.autocorrelations?.lag10, 4),
        hurstExponent:        _round(jitter.hurstExponent,      4),
        quantizationEntropy:  _round(jitter.quantizationEntropy, 4),
        thermalDrift:         _round(jitter.thermalSignature?.slope, 8),
        thermalPattern:       jitter.thermalSignature?.pattern ?? 'unknown',
        outlierRate:          _round(jitter.outlierRate,        4),
        timerGranularityMs:   _round(entropy.timerGranularityMs, 6),
        checksum:             entropy.checksum, // proves computation ran
        timingsHash,          // proves timing array integrity
        memTimingsHash:       memHash,
        iterations:           entropy.iterations,
        matrixSize:           entropy.matrixSize,
      },

      // ── Bio signals ─────────────────────────────────────────────────────
      bio: {
        mouseSampleCount:     bio.mouse.sampleCount,
        mouseIEIMean:         _round(bio.mouse.ieiMean,         3),
        mouseIEICV:           _round(bio.mouse.ieiCV,           4),
        mouseVelocityP50:     _round(bio.mouse.velocityP50,     3),
        mouseVelocityP95:     _round(bio.mouse.velocityP95,     3),
        mouseAngularJerkMean: _round(bio.mouse.angularJerkMean, 4),
        pressureVariance:     _round(bio.mouse.pressureVariance, 6),
        keyboardSampleCount:  bio.keyboard.sampleCount,
        keyboardDwellMean:    _round(bio.keyboard.dwellMean,    3),
        keyboardDwellCV:      _round(bio.keyboard.dwellCV,      4),
        keyboardIKIMean:      _round(bio.keyboard.ikiMean,      3),
        keyboardIKICV:        _round(bio.keyboard.ikiCV,        4),
        interferenceCoefficient: _round(bio.interferenceCoefficient, 4),
        hasActivity:          bio.hasActivity,
        durationMs:           _round(bio.durationMs,            1),
      },

      // ── Canvas fingerprint ───────────────────────────────────────────────
      canvas: {
        webglRenderer:        canvas.webglRenderer,
        webglVendor:          canvas.webglVendor,
        webglVersion:         canvas.webglVersion,
        webglPixelHash:       canvas.webglPixelHash,
        canvas2dHash:         canvas.canvas2dHash,
        extensionCount:       canvas.extensionCount,
        isSoftwareRenderer:   canvas.isSoftwareRenderer,
        available:            canvas.available,
      },

      // ── Audio jitter ─────────────────────────────────────────────────────
      audio: {
        available:            audio.available,
        workletAvailable:     audio.workletAvailable,
        callbackJitterCV:     _round(audio.callbackJitterCV,    4),
        noiseFloorMean:       _round(audio.noiseFloorMean,      6),
        noiseFloorStd:        _round(audio.noiseFloorStd,       6),
        sampleRate:           audio.sampleRate,
        callbackCount:        audio.callbackCount,
        jitterMeanMs:         _round(audio.jitterMeanMs,        4),
        jitterP95Ms:          _round(audio.jitterP95Ms,         4),
      },

      // ── Electrical Network Frequency ─────────────────────────────────────
      enf: enf ? {
        available:       enf.enfAvailable,
        ripplePresent:   enf.ripplePresent,
        gridFrequency:   enf.gridFrequency,
        gridRegion:      enf.gridRegion,
        ripplePower:     _round(enf.ripplePower,    4),
        enfDeviation:    _round(enf.enfDeviation,   3),
        snr50hz:         _round(enf.snr50hz,        2),
        snr60hz:         _round(enf.snr60hz,        2),
        sampleRateHz:    _round(enf.sampleRateHz,   1),
        verdict:         enf.verdict,
        isVmIndicator:   enf.isVmIndicator,
        capturedAt:      enf.temporalAnchor?.capturedAt ?? null,
      } : null,

      // ── WebGPU thermal variance ───────────────────────────────────────────
      gpu: gpu ? {
        available:       gpu.gpuPresent,
        isSoftware:      gpu.isSoftware,
        vendorString:    gpu.vendorString,
        dispatchCV:      _round(gpu.dispatchCV,     4),
        thermalGrowth:   _round(gpu.thermalGrowth,  4),
        verdict:         gpu.verdict,
      } : null,

      // ── DRAM refresh cycle ────────────────────────────────────────────────
      dram: dram ? {
        refreshPresent:  dram.refreshPresent,
        refreshPeriodMs: _round(dram.refreshPeriodMs, 2),
        peakPower:       _round(dram.peakPower,        4),
        verdict:         dram.verdict,
      } : null,

      // ── LLM / AI agent behavioral fingerprint ────────────────────────────
      llm: llm ? {
        aiConf:             _round(llm.aiConf,            3),
        thinkTimePattern:   llm.thinkTimePattern,
        correctionRate:     _round(llm.correctionRate,    3),
        rhythmicity:        _round(llm.rhythmicity,       3),
        pauseDistribution:  llm.pauseDistribution,
        verdict:            llm.verdict,
        matchedModel:       llm.matchedModel ?? null,
      } : null,
    },

    // Top-level classification summary — all signal layers combined
    classification: {
      jitterScore:    _round(jitter.score, 4),
      flags:          jitter.flags ?? [],
      enfVerdict:     enf?.verdict  ?? 'unavailable',
      gpuVerdict:     gpu?.verdict  ?? 'unavailable',
      dramVerdict:    dram?.verdict ?? 'unavailable',
      llmVerdict:     llm?.verdict  ?? 'unavailable',
      // Combined VM confidence: any hard signal raises this
      vmIndicators: [
        enf?.isVmIndicator  ? 'enf_no_grid'     : null,
        gpu?.isSoftware     ? 'gpu_software'     : null,
        dram?.verdict === 'virtual' ? 'dram_no_refresh' : null,
        llm?.aiConf > 0.7   ? 'llm_agent'        : null,
      ].filter(Boolean),
    },
  };

  return payload;
}

/**
 * @typedef {object} ProofPayload
 * @property {number}  version
 * @property {number}  timestamp
 * @property {string}  nonce
 * @property {object}  signals
 * @property {object}  classification
 */

// ---------------------------------------------------------------------------
// buildCommitment
// ---------------------------------------------------------------------------

/**
 * Hashes a ProofPayload into a BLAKE3 commitment.
 * Uses a deterministic canonical JSON serialiser (sorted keys) to ensure
 * byte-identical output across JS engines.
 *
 * @param {ProofPayload} payload
 * @returns {{ payload: ProofPayload, hash: string }}
 */
export function buildCommitment(payload) {
  const canonical = canonicalJson(payload);
  const hash      = blake3HexStr(canonical);
  return { payload, hash };
}

// ---------------------------------------------------------------------------
// canonicalJson
//
// JSON.stringify with sorted keys — ensures the hash is engine-independent.
// Numbers are serialised with fixed precision to avoid cross-platform float
// formatting differences.
// ---------------------------------------------------------------------------

export function canonicalJson(obj) {
  return JSON.stringify(obj, _replacer, 0);
}

function _replacer(key, value) {
  // Sort object keys deterministically
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const sorted = {};
    for (const k of Object.keys(value).sort()) {
      sorted[k] = value[k];
    }
    return sorted;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Internal utilities
// ---------------------------------------------------------------------------

function _round(v, decimals) {
  if (v == null || !isFinite(v)) return null;
  const factor = 10 ** decimals;
  return Math.round(v * factor) / factor;
}

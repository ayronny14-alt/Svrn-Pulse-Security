/**
 * @svrnsec/pulse — High-Level Fingerprint Class
 *
 * The developer-facing API.  Instead of forcing devs to understand Hurst
 * Exponents and Quantization Entropy, they get a Fingerprint object with
 * plain-language properties and one critical boolean: isSynthetic.
 *
 * Usage:
 *
 *   import { Fingerprint } from '@svrnsec/pulse';
 *
 *   const fp = await Fingerprint.collect({ nonce });
 *
 *   if (fp.isSynthetic) {
 *     console.log(`Blocked: ${fp.providerLabel} detected (${fp.confidence}% confidence)`);
 *     console.log(`Profile: ${fp.profile}`);        // 'picket-fence'
 *     console.log(`Reason: ${fp.topFlag}`);          // 'LOW_QE + HIGH_LAG1_AUTOCORR'
 *   } else {
 *     console.log(`Verified: ${fp.hardwareId()}`);
 *     console.log(`Score: ${fp.score}`);             // 0.0 – 1.0
 *   }
 *
 *   // Always send to server for final validation:
 *   const { payload, hash } = fp.toCommitment();
 */

import { collectEntropy }           from './collector/entropy.js';
import { BioCollector }             from './collector/bio.js';
import { collectCanvasFingerprint } from './collector/canvas.js';
import { collectAudioJitter }       from './analysis/audio.js';
import { classifyJitter }           from './analysis/jitter.js';
import { runHeuristicEngine }       from './analysis/heuristic.js';
import { runCoherenceAnalysis }     from './analysis/coherence.js';
import { detectProvider }           from './analysis/provider.js';
import { buildProof, buildCommitment, blake3HexStr } from './proof/fingerprint.js';

// ---------------------------------------------------------------------------
// Fingerprint class
// ---------------------------------------------------------------------------

export class Fingerprint {
  /** @private */
  constructor(raw) {
    this._raw        = raw;         // full internal data
    this._commitment = null;        // lazy-built on first toCommitment() call
  }

  // ── Static factory ────────────────────────────────────────────────────────

  /**
   * Collect all hardware signals and return a Fingerprint instance.
   *
   * @param {object}   opts
   * @param {string}   opts.nonce          - server-issued challenge nonce (required)
   * @param {number}   [opts.iterations=200]
   * @param {number}   [opts.bioWindowMs=3000]
   * @param {boolean}  [opts.phased=true]  - run cold/load/hot phases
   * @param {Function} [opts.onProgress]   - (stage: string) => void
   * @param {string}   [opts.wasmPath]
   * @returns {Promise<Fingerprint>}
   */
  static async collect(opts = {}) {
    const {
      nonce,
      iterations        = 200,
      bioWindowMs       = 3000,
      phased            = true,
      adaptive          = true,
      adaptiveThreshold = 0.85,
      onProgress,
      wasmPath,
    } = opts;

    if (!nonce) throw new Error('Fingerprint.collect() requires opts.nonce');

    const emit = (stage, meta) => { try { onProgress?.(stage, meta); } catch {} };

    emit('start');

    // ── Parallel collection ────────────────────────────────────────────────
    const bio = new BioCollector();
    bio.start();

    const [entropy, canvas, audio] = await Promise.all([
      collectEntropy({
        iterations, phased, adaptive, adaptiveThreshold, wasmPath,
        onBatch: (meta) => emit('entropy_batch', meta),
      }).then(r => { emit('entropy_done'); return r; }),
      collectCanvasFingerprint()
        .then(r => { emit('canvas_done'); return r; }),
      collectAudioJitter({ durationMs: Math.min(bioWindowMs, 2000) })
        .then(r => { emit('audio_done'); return r; }),
    ]);

    // Wait out the bio window
    const elapsed = Date.now() - entropy.collectedAt;
    const remain  = Math.max(0, bioWindowMs - elapsed);
    if (remain > 0) await new Promise(r => setTimeout(r, remain));

    bio.stop();
    const bioSnapshot = bio.snapshot(entropy.timings);
    emit('bio_done');

    // ── Analysis pipeline ─────────────────────────────────────────────────
    const jitter    = classifyJitter(entropy.timings, { autocorrelations: entropy.autocorrelations });
    const heuristic = runHeuristicEngine({ jitter, phases: entropy.phases, autocorrelations: entropy.autocorrelations });
    const provider  = detectProvider({ jitter, autocorrelations: entropy.autocorrelations, canvas, phases: entropy.phases });

    // ── Three-stage scoring pipeline ──────────────────────────────────────
    // Stage 1: base jitter score from timing distribution analysis
    const rawScore  = jitter.score;
    // Stage 2: heuristic cross-metric coherence adjustment
    const adjScore  = Math.max(0, Math.min(1, rawScore + heuristic.netAdjustment));
    // Stage 3: zero-latency structural coherence analysis on already-collected data
    const coherence = runCoherenceAnalysis({
      timings:  entropy.timings,
      jitter,
      phases:   entropy.phases  ?? null,
      batches:  entropy.batches ?? null,
      bio:      bioSnapshot,
      canvas,
      audio,
    });
    // Final score: stage-2 adjusted score refined by stage-3 coherence
    const finalScore = Math.max(0, Math.min(1, adjScore + coherence.netAdjustment));

    emit('analysis_done');

    // ── Build commitment ──────────────────────────────────────────────────
    const payload    = buildProof({ entropy, jitter, bio: bioSnapshot, canvas, audio, nonce });
    // Inject heuristic + provider into proof payload for server-side reference
    payload.heuristic = {
      penalty:            heuristic.penalty,
      bonus:              heuristic.bonus,
      entropyJitterRatio: heuristic.entropyJitterRatio,
      picketFence:        heuristic.picketFence.detected,
      coherenceFlags:     heuristic.coherenceFlags,
      hardOverride:       heuristic.hardOverride,  // 'vm' | null
    };
    payload.provider = {
      id:               provider.providerId,
      label:            provider.providerLabel,
      profile:          provider.profile,
      confidence:       provider.confidence,
      schedulerQuantum: provider.schedulerQuantumMs,
    };
    // Stage-3 coherence summary (server uses these for logging + dynamic threshold)
    payload.coherence = {
      netAdjustment:    coherence.netAdjustment,
      dynamicThreshold: coherence.dynamicThreshold,
      evidenceWeight:   coherence.evidenceWeight,
      coherenceFlags:   coherence.coherenceFlags,
      physicalFlags:    coherence.physicalFlags,
      hardOverride:     coherence.hardOverride,
    };
    payload.classification.adjustedScore  = _round(adjScore,    4);
    payload.classification.finalScore     = _round(finalScore,  4);
    payload.classification.dynamicThreshold = coherence.dynamicThreshold;

    const commitment = buildCommitment(payload);
    emit('complete');

    return new Fingerprint({
      entropy, canvas, audio,
      bioSnapshot, jitter, heuristic, coherence, provider,
      rawScore, adjScore, finalScore,
      nonce, commitment,
    });
  }

  // ── Primary API ────────────────────────────────────────────────────────────

  /**
   * True if the device is likely a VM, AI inference endpoint, or sanitised
   * cloud environment.  Uses the adjusted score (base + heuristic bonuses/penalties).
   * @type {boolean}
   */
  get isSynthetic() {
    // Stage-2 hard kill: EJR/QE mathematical contradiction detected in the
    // heuristic engine before any bonuses could accumulate.
    if (this._raw.heuristic.hardOverride === 'vm') return true;
    // Stage-3 hard kill: EJR/QE contradiction or phase forgery detected in
    // the coherence analyser (second line of defence).
    if (this._raw.coherence.hardOverride === 'vm') return true;
    // Normal path: final score vs dynamic threshold.
    return this._raw.finalScore < this._raw.coherence.dynamicThreshold;
  }

  /**
   * Confidence in the isSynthetic verdict, 0–100.
   * @type {number}
   */
  get confidence() {
    const s = this._raw.finalScore;
    const t = this._raw.coherence.dynamicThreshold;
    // Map distance from threshold to confidence percentage.
    // At the threshold: 0% confident. Far above/below: approaching 100%.
    const distance = Math.abs(s - t);
    return Math.min(100, Math.round(distance * 500));
  }

  /**
   * Normalised score [0.0, 1.0].  Higher = more physical.
   * This is the FINAL score after all three analysis stages.
   * @type {number}
   */
  get score() {
    return _round(this._raw.finalScore, 4);
  }

  /**
   * The dynamic passing threshold for this proof [0.55, 0.67].
   * Reflects how much evidence was collected — a full-evidence proof has a
   * lower (more permissive) threshold; a minimal-evidence proof has a higher
   * (more conservative) threshold.
   * @type {number}
   */
  get threshold() {
    return this._raw.coherence.dynamicThreshold;
  }

  /**
   * How much evidence was collected [0, 1].
   * 1.0 = 200 iterations + phased + bio + audio + canvas
   * 0.0 = minimal proof
   * @type {number}
   */
  get evidenceWeight() {
    return this._raw.coherence.evidenceWeight;
  }

  /**
   * Human-readable confidence tier.
   * @type {'high'|'medium'|'low'|'uncertain'}
   */
  get tier() {
    const c = this.confidence;
    if (c >= 70) return 'high';
    if (c >= 40) return 'medium';
    if (c >= 20) return 'low';
    return 'uncertain';
  }

  /**
   * Detected timing profile name.
   *   'analog-fog'      → real hardware, natural Brownian noise
   *   'picket-fence'    → VM steal-time bursts at regular intervals
   *   'burst-scheduler' → irregular VM scheduling (VMware-style)
   *   'hypervisor-flat' → flat timing, hypervisor completely irons out noise
   *   'near-physical'   → hard to classify (Nitro, GPU passthrough)
   *   'unknown'
   * @type {string}
   */
  get profile() {
    return this._raw.provider.profile;
  }

  /**
   * Detected cloud provider / hypervisor.
   * @type {string}  e.g. 'kvm-digitalocean', 'nitro-aws', 'physical', 'generic-vm'
   */
  get providerId() {
    return this._raw.provider.providerId;
  }

  /**
   * Human-readable provider label.
   * @type {string}  e.g. 'DigitalOcean Droplet (KVM)', 'Physical Hardware'
   */
  get providerLabel() {
    return this._raw.provider.providerLabel;
  }

  /**
   * Estimated hypervisor scheduler quantum in milliseconds.
   * Null if the device appears to be physical.
   * @type {number|null}
   */
  get schedulerQuantumMs() {
    return this._raw.provider.schedulerQuantumMs;
  }

  /**
   * Entropy-Jitter Ratio — the key signal distinguishing real silicon from VMs.
   * Values ≥ 1.08 confirm thermal feedback (real hardware).
   * Values near 1.0 indicate a hypervisor clock (VM).
   * Null if phased collection was not run.
   * @type {number|null}
   */
  get entropyJitterRatio() {
    return this._raw.heuristic.entropyJitterRatio;
  }

  /**
   * The most diagnostic flag from the heuristic engine.
   * @type {string}
   */
  get topFlag() {
    const flags = [
      ...this._raw.heuristic.findings.map(f => f.id),
      ...this._raw.jitter.flags,
    ];
    return flags[0] ?? 'NONE';
  }

  /**
   * All flags from both the base classifier and heuristic engine.
   * @type {string[]}
   */
  get flags() {
    return [
      ...this._raw.heuristic.coherenceFlags,
      ...this._raw.jitter.flags,
    ];
  }

  /**
   * Summary of heuristic findings with human-readable labels.
   * @type {Array<{id, label, severity, detail}>}
   */
  get findings() {
    return this._raw.heuristic.findings;
  }

  /**
   * Confirmed physical properties (positive evidence for real hardware).
   * @type {Array<{id, label, detail}>}
   */
  get physicalEvidence() {
    return this._raw.heuristic.bonuses;
  }

  // ── Hardware ID ────────────────────────────────────────────────────────────

  /**
   * A stable, privacy-preserving hardware identifier derived from the GPU
   * canvas fingerprint, audio sample rate, and WebGL extension set.
   *
   * Properties:
   *   - Stable: same device → same ID across sessions
   *   - Not uniquely identifying: changes if GPU or driver changes
   *   - Not reversible: BLAKE3 hash, cannot recover original signals
   *   - Not a tracking cookie: no PII, no cross-origin data
   *
   * @returns {string}  32-character hex ID (128-bit collision resistance)
   */
  hardwareId() {
    const { canvas, audio } = this._raw;
    const components = [
      canvas?.webglRenderer ?? '',
      canvas?.webglVendor   ?? '',
      canvas?.extensionCount?.toString() ?? '',
      audio?.sampleRate?.toString() ?? '',
      canvas?.webglVersion?.toString() ?? '',
    ].join('|');
    return blake3HexStr(components).slice(0, 32);
  }

  // ── Diagnostic data ────────────────────────────────────────────────────────

  /**
   * Key metrics summary — useful for logging and debugging.
   * @returns {object}
   */
  metrics() {
    const { jitter, heuristic, coherence, provider } = this._raw;
    return {
      // ── Final verdict ──────────────────────────────────────────────────
      score:                this.score,           // final (stage 3)
      threshold:            this.threshold,       // dynamic passing bar
      evidenceWeight:       this.evidenceWeight,
      isSynthetic:          this.isSynthetic,
      // ── Score pipeline breakdown ───────────────────────────────────────
      rawScore:             _round(this._raw.rawScore, 4),       // stage 1
      adjustedScore:        _round(this._raw.adjScore, 4),       // stage 2
      finalScore:           _round(this._raw.finalScore, 4),     // stage 3
      heuristicAdjustment:  _round(heuristic.netAdjustment, 4),
      coherenceAdjustment:  _round(coherence.netAdjustment, 4),
      // ── Timing signals ─────────────────────────────────────────────────
      cv:                   _round(jitter.stats?.cv, 4),
      hurstExponent:        _round(jitter.hurstExponent, 4),
      quantizationEntropy:  _round(jitter.quantizationEntropy, 4),
      autocorrLag1:         _round(jitter.autocorrelations?.lag1, 4),
      autocorrLag50:        _round(this._raw.entropy.autocorrelations?.lag50, 4),
      outlierRate:          _round(jitter.outlierRate, 4),
      thermalPattern:       jitter.thermalSignature?.pattern,
      entropyJitterRatio:   _round(heuristic.entropyJitterRatio, 4),
      picketFence:          heuristic.picketFence.detected,
      // ── Coherence signals ──────────────────────────────────────────────
      coherenceFlags:       coherence.coherenceFlags,
      physicalFlags:        coherence.physicalFlags,
      hardOverride:         coherence.hardOverride,
      // ── Provider ───────────────────────────────────────────────────────
      provider:             provider.providerLabel,
      providerConfidence:   provider.confidence,
      schedulerQuantumMs:   provider.schedulerQuantumMs,
      // ── Hardware ───────────────────────────────────────────────────────
      webglRenderer:        this._raw.canvas?.webglRenderer,
      isSoftwareRenderer:   this._raw.canvas?.isSoftwareRenderer,
      hardwareId:           this.hardwareId(),
    };
  }

  /**
   * Full diagnostic report for debugging / integration testing.
   * @returns {object}
   */
  report() {
    const { coherence } = this._raw;
    return {
      verdict: {
        isSynthetic:      this.isSynthetic,
        score:            this.score,
        threshold:        this.threshold,
        confidence:       this.confidence,
        tier:             this.tier,
        profile:          this.profile,
        provider:         this.providerLabel,
        topFlag:          this.topFlag,
        hardOverride:     coherence.hardOverride,
        evidenceWeight:   this.evidenceWeight,
      },
      pipeline: {
        rawScore:             _round(this._raw.rawScore,    4),
        adjustedScore:        _round(this._raw.adjScore,    4),
        finalScore:           _round(this._raw.finalScore,  4),
        heuristicAdjustment:  _round(this._raw.heuristic.netAdjustment, 4),
        coherenceAdjustment:  _round(coherence.netAdjustment, 4),
        dynamicThreshold:     coherence.dynamicThreshold,
      },
      metrics:          this.metrics(),
      findings:         this.findings,
      physicalEvidence: this.physicalEvidence,
      coherenceChecks:  coherence.checks,
      coherenceBonuses: coherence.bonuses,
      phases:           this._raw.entropy.phases ? {
        cold: { qe: _round(this._raw.entropy.phases.cold.qe, 4), mean: _round(this._raw.entropy.phases.cold.mean, 4) },
        hot:  { qe: _round(this._raw.entropy.phases.hot.qe,  4), mean: _round(this._raw.entropy.phases.hot.mean,  4) },
        entropyJitterRatio: _round(this._raw.entropy.phases.entropyJitterRatio, 4),
      } : null,
    };
  }

  // ── Proof commitment ───────────────────────────────────────────────────────

  /**
   * Returns the BLAKE3 commitment to send to the server for validation.
   * @returns {{ payload: object, hash: string }}
   */
  toCommitment() {
    return this._raw.commitment;
  }

  // ── String representations ─────────────────────────────────────────────────

  toString() {
    const icon = this.isSynthetic ? '🚩' : '✅';
    const verb = this.isSynthetic ? 'Synthetic' : 'Physical';
    return `${icon} ${verb} | ${this.providerLabel} | score=${this.score} | conf=${this.confidence}% | profile=${this.profile}`;
  }

  toJSON() {
    return this.report();
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _round(v, d) {
  if (v == null || !isFinite(v)) return null;
  const f = 10 ** d;
  return Math.round(v * f) / f;
}

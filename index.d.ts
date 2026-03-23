/**
 * @svrnsec/pulse — TypeScript Declarations
 */

// =============================================================================
// Core pulse() API
// =============================================================================

export interface PulseOptions {
  /**
   * Server-issued challenge nonce — required in self-hosted mode.
   * Omit when using apiKey (hosted API fetches its own nonce).
   */
  nonce?: string;
  /**
   * Sovereign hosted API key — enables zero-config mode.
   * When set, pulse() handles challenge + verify automatically.
   * Get a key at https://sovereign.dev
   */
  apiKey?: string;
  /** Hosted API base URL. Default: 'https://api.sovereign.dev' */
  apiUrl?: string;
  /** Options forwarded to the hosted verify endpoint (minJitterScore, requireBio, etc.) */
  verifyOptions?: Partial<ValidateOptions>;
  /** Number of WASM matrix-multiply iterations. Default: 200 */
  iterations?: number;
  /** How long to listen for mouse/keyboard bio signals (ms). Default: 3000 */
  bioWindowMs?: number;
  /** Run cold/load/hot phases for entropy-jitter ratio. Default: true */
  phased?: boolean;
  /** Use adaptive early exit (faster for obvious VMs). Default: true */
  adaptive?: boolean;
  /** Stop early if VM/HW signal reaches this confidence. Default: 0.85 */
  adaptiveThreshold?: number;
  /** Custom WASM binary URL/path (optional). */
  wasmPath?: string;
  /** Progress callback — called at each pipeline stage. */
  onProgress?: (stage: PulseStage, meta?: ProgressMeta) => void;
}

export type PulseStage =
  | 'start'
  | 'entropy_batch'
  | 'entropy_done'
  | 'canvas_done'
  | 'audio_done'
  | 'bio_done'
  | 'analysis_done'
  | 'complete';

export interface ProgressMeta {
  /** Current iteration count (during adaptive probe). */
  iterations?: number;
  /** Max iterations configured. */
  maxIterations?: number;
  /** Percentage complete (0–100). */
  pct?: number;
  /** Preliminary verdict from adaptive probe. */
  earlyVerdict?: 'vm' | 'physical' | 'borderline' | 'uncertain';
  /** Estimated milliseconds remaining. */
  etaMs?: number;
  /** Current VM confidence (0–1). */
  vmConf?: number;
  /** Current physical hardware confidence (0–1). */
  hwConf?: number;
}

export interface PulseCommitment {
  /** Statistical summary payload (~1.6KB). Send this to your server. */
  payload: ProofPayload;
  /** BLAKE3 hex hash of the canonical payload. */
  hash: string;
  /**
   * Server validation result — only present when using apiKey (hosted mode).
   * Undefined in self-hosted mode; validate server-side with validateProof().
   */
  result?: ValidationResult;
}

export function pulse(opts: PulseOptions): Promise<PulseCommitment>;

// =============================================================================
// React Hook (import from '@svrnsec/pulse/react')
// =============================================================================

export interface UsePulseOptions {
  /** Sovereign hosted API key. Handles nonce + verify automatically. */
  apiKey?: string;
  /** Hosted API base URL. Default: 'https://api.sovereign.dev' */
  apiUrl?: string;
  /** Self-hosted challenge endpoint URL. */
  challengeUrl?: string;
  /** Self-hosted verify endpoint URL. */
  verifyUrl?: string;
  /** Number of WASM matrix-multiply iterations. Default: 200 */
  iterations?: number;
  /** Bio collection window in milliseconds. Default: 3000 */
  bioWindowMs?: number;
  /** Enable adaptive early exit. Default: true */
  adaptive?: boolean;
  /** Run immediately on mount. Default: false */
  autoRun?: boolean;
  /** Called when proof + result are ready. */
  onResult?: (result: ValidationResult | null, commitment: PulseCommitment) => void;
  /** Called on error. */
  onError?: (error: Error) => void;
}

export interface UsePulseReturn {
  /** Trigger the probe manually. */
  run: () => Promise<void>;
  /** Reset all state back to idle. */
  reset: () => void;
  /** Current pipeline stage. */
  stage: PulseStage | null;
  /** Probe progress 0–100. */
  pct: number;
  /** Live VM confidence 0–1 (updates during entropy_batch stages). */
  vmConf: number;
  /** Live HW confidence 0–1. */
  hwConf: number;
  /** Preliminary verdict from adaptive probe, or null if still uncertain. */
  earlyVerdict: 'vm' | 'physical' | 'borderline' | 'uncertain' | null;
  /** The BLAKE3 commitment. Available after probe completes. */
  proof: PulseCommitment | null;
  /** Server validation result. Available after verify completes (hosted/verifyUrl mode). */
  result: ValidationResult | null;
  /** True while probe is in progress. */
  isRunning: boolean;
  /** True when probe has completed (pass or fail). */
  isReady: boolean;
  /** Any error thrown during the probe. */
  error: Error | null;
}

/** React hook — import from '@svrnsec/pulse/react' */
export declare function usePulse(opts?: UsePulseOptions): UsePulseReturn;

// =============================================================================
// Fingerprint class (high-level API)
// =============================================================================

export class Fingerprint {
  /** Collect all hardware signals and return a Fingerprint instance. */
  static collect(opts: PulseOptions): Promise<Fingerprint>;

  /** True if the device is likely a VM, AI endpoint, or sanitised cloud env. */
  readonly isSynthetic: boolean;

  /** Confidence in the isSynthetic verdict (0–100). */
  readonly confidence: number;

  /**
   * Final normalised score [0.0, 1.0] after all three analysis stages.
   * Higher = more physical.
   */
  readonly score: number;

  /**
   * Dynamic passing threshold for this specific proof [0.55, 0.67].
   * Lower when more evidence was collected; higher for minimal-evidence proofs.
   */
  readonly threshold: number;

  /**
   * Evidence weight [0, 1] — reflects how much data was collected.
   * 1.0 = 200 iterations + phased + bio + audio + canvas
   */
  readonly evidenceWeight: number;

  /** Confidence tier. */
  readonly tier: 'high' | 'medium' | 'low' | 'uncertain';

  /**
   * Timing profile of the device.
   * - `'analog-fog'`      — real hardware, natural Brownian noise
   * - `'picket-fence'`    — VM steal-time bursts at regular intervals
   * - `'burst-scheduler'` — irregular VM scheduling (VMware-style)
   * - `'hypervisor-flat'` — completely flat (heavy datacenter VM)
   * - `'near-physical'`   — ambiguous (Nitro, GPU passthrough)
   */
  readonly profile: 'analog-fog' | 'picket-fence' | 'burst-scheduler' | 'hypervisor-flat' | 'near-physical' | 'unknown';

  /** Detected cloud provider / hypervisor identifier. */
  readonly providerId: string;

  /** Human-readable provider label (e.g. "DigitalOcean Droplet (KVM)"). */
  readonly providerLabel: string;

  /**
   * Estimated hypervisor scheduler quantum in milliseconds.
   * `null` if the device appears to be physical hardware.
   */
  readonly schedulerQuantumMs: number | null;

  /**
   * Entropy-Jitter Ratio — key signal for real silicon vs VM.
   * - ≥ 1.08 → thermal feedback confirmed (real hardware)
   * - ~1.00  → hypervisor clock (VM)
   * - `null` → phased collection not run
   */
  readonly entropyJitterRatio: number | null;

  /** Top diagnostic flag from the heuristic engine. */
  readonly topFlag: string;

  /** All diagnostic flags. */
  readonly flags: string[];

  /** Heuristic engine findings with severity labels. */
  readonly findings: HeuristicFinding[];

  /** Confirmed physical properties (positive evidence). */
  readonly physicalEvidence: PhysicalEvidence[];

  /**
   * Stable, privacy-safe 16-char hex hardware identifier.
   * Stable per device, changes if GPU/driver changes, not reversible.
   */
  hardwareId(): string;

  /** Key metrics summary for logging / debugging. */
  metrics(): FingerprintMetrics;

  /** Full diagnostic report. */
  report(): FingerprintReport;

  /** Returns the BLAKE3 commitment to send to your server. */
  toCommitment(): PulseCommitment;

  toString(): string;
  toJSON(): FingerprintReport;
}

export interface HeuristicFinding {
  id: string;
  label: string;
  severity: 'critical' | 'high' | 'medium' | 'info';
  detail: string;
  penalty: number;
}

export interface PhysicalEvidence {
  id: string;
  label: string;
  detail: string;
  value: number;
}

export interface FingerprintMetrics {
  // Final verdict
  score: number;           // stage-3 final score
  threshold: number;       // dynamic passing threshold [0.55, 0.67]
  evidenceWeight: number;  // how much evidence was collected [0, 1]
  isSynthetic: boolean;
  // Score pipeline
  rawScore: number;
  adjustedScore: number;
  finalScore: number;
  heuristicAdjustment: number;
  coherenceAdjustment: number;
  // Timing signals
  cv: number | null;
  hurstExponent: number | null;
  quantizationEntropy: number | null;
  autocorrLag1: number | null;
  autocorrLag50: number | null;
  outlierRate: number | null;
  thermalPattern: string | null;
  entropyJitterRatio: number | null;
  picketFence: boolean;
  // Coherence signals
  coherenceFlags: string[];
  physicalFlags: string[];
  hardOverride: 'vm' | null;
  // Provider
  provider: string;
  providerConfidence: number;
  schedulerQuantumMs: number | null;
  // Hardware
  webglRenderer: string | null;
  isSoftwareRenderer: boolean;
  hardwareId: string;
}

export interface FingerprintReport {
  verdict: {
    isSynthetic: boolean;
    score: number;
    threshold: number;
    confidence: number;
    tier: string;
    profile: string;
    provider: string;
    topFlag: string;
    hardOverride: 'vm' | null;
    evidenceWeight: number;
  };
  pipeline: {
    rawScore: number;
    adjustedScore: number;
    finalScore: number;
    heuristicAdjustment: number;
    coherenceAdjustment: number;
    dynamicThreshold: number;
  };
  metrics: FingerprintMetrics;
  findings: HeuristicFinding[];
  physicalEvidence: PhysicalEvidence[];
  coherenceChecks: CoherenceCheck[];
  coherenceBonuses: CoherenceBonus[];
  phases: PhaseReport | null;
}

export interface PhaseReport {
  cold: { qe: number; mean: number };
  hot:  { qe: number; mean: number };
  entropyJitterRatio: number;
}

// =============================================================================
// Server-side validation
// =============================================================================

export interface ValidateOptions {
  /** Minimum jitter score [0–1]. Default: 0.55 */
  minJitterScore?: number;
  /** Max proof age in milliseconds. Default: 300000 (5 min) */
  maxAgeMs?: number;
  /** Tolerated future clock skew. Default: 30000 */
  clockSkewMs?: number;
  /** Reject proofs with no bio activity. Default: false */
  requireBio?: boolean;
  /** Reject software WebGL renderers. Default: true */
  blockSoftwareRenderer?: boolean;
  /**
   * Async nonce validator — must mark nonce as consumed atomically.
   * Returns true if nonce is valid and unused.
   */
  checkNonce?: (nonce: string) => Promise<boolean>;
}

export interface ValidationResult {
  valid: boolean;
  score: number;
  confidence: 'high' | 'medium' | 'low' | 'rejected';
  reasons: string[];
  riskFlags: string[];
  meta: {
    receivedAt: number;
    proofAge: number;
    jitterScore: number;
    canvasRenderer: string | null;
    bioActivity: boolean;
  };
}

export function validateProof(
  payload: ProofPayload,
  hash: string,
  opts?: ValidateOptions
): Promise<ValidationResult>;

export function generateNonce(): string;

// =============================================================================
// Heuristic engine (advanced)
// =============================================================================

export interface HeuristicReport {
  penalty: number;
  bonus: number;
  netAdjustment: number;
  findings: HeuristicFinding[];
  bonuses: PhysicalEvidence[];
  entropyJitterRatio: number | null;
  entropyJitterScore: number;
  /**
   * Set to 'vm' when a mathematical impossibility is detected in the phase data,
   * specifically when the stored EJR value contradicts the stored QE values.
   * This is a hard kill — isSynthetic returns true regardless of all other scores.
   */
  hardOverride: 'vm' | null;
  picketFence: {
    detected: boolean;
    dominantLag: number | null;
    peakAC: number;
    baseline: number;
    detail: string;
  };
  coherenceFlags: string[];
}

export function runHeuristicEngine(opts: {
  jitter: JitterAnalysis;
  phases: PhasedData | null;
  autocorrelations: Record<string, number>;
}): HeuristicReport;

// =============================================================================
// Provider detection (advanced)
// =============================================================================

export interface ProviderResult {
  providerId: string;
  providerLabel: string;
  profile: string;
  confidence: number;
  isVirtualized: boolean;
  signals: Record<string, number | boolean | string[]>;
  alternatives: Array<{ id: string; label: string }>;
  rendererHints: string[];
  schedulerQuantumMs: number | null;
}

export function detectProvider(opts: {
  jitter: JitterAnalysis;
  autocorrelations: Record<string, number>;
  canvas: CanvasFingerprint | null;
  phases: PhasedData | null;
}): ProviderResult;

// =============================================================================
// Proof payload structure
// =============================================================================

export interface ProofPayload {
  version: number;
  timestamp: number;
  nonce: string;
  signals: {
    entropy: Record<string, number | string | null>;
    bio: Record<string, number | boolean | null>;
    canvas: {
      webglRenderer: string | null;
      webglVendor: string | null;
      webglVersion: 1 | 2 | null;
      webglPixelHash: string | null;
      canvas2dHash: string | null;
      extensionCount: number;
      isSoftwareRenderer: boolean;
      available: boolean;
    };
    audio: Record<string, number | boolean | null>;
  };
  classification: {
    jitterScore: number;
    adjustedScore?: number;
    finalScore?: number;
    dynamicThreshold?: number;
    flags: string[];
  };
  heuristic?: Record<string, unknown>;
  provider?: {
    id: string;
    label: string;
    profile: string;
    confidence: number;
    schedulerQuantum: number | null;
  };
  coherence?: {
    netAdjustment: number;
    dynamicThreshold: number;
    evidenceWeight: number;
    coherenceFlags: string[];
    physicalFlags: string[];
    hardOverride: 'vm' | null;
  };
}

// =============================================================================
// Coherence analysis (stage 3)
// =============================================================================

export interface CoherenceCheck {
  id: string;
  label: string;
  severity: 'critical' | 'high' | 'medium' | 'info';
  detail: string;
  penalty: number;
}

export interface CoherenceBonus {
  id: string;
  label: string;
  detail: string;
  value: number;
}

export interface CoherenceReport {
  penalty: number;
  bonus: number;
  netAdjustment: number;
  checks: CoherenceCheck[];
  bonuses: CoherenceBonus[];
  hardOverride: 'vm' | null;
  /** Dynamic threshold [0.55, 0.67] — lower when more evidence collected. */
  dynamicThreshold: number;
  /** Evidence weight [0, 1] */
  evidenceWeight: number;
  coherenceFlags: string[];
  physicalFlags: string[];
}

export function runCoherenceAnalysis(opts: {
  timings: number[];
  jitter: JitterAnalysis;
  phases?: PhasedData | null;
  batches?: object[] | null;
  bio?: object;
  canvas?: CanvasFingerprint | null;
  audio?: object;
}): CoherenceReport;

export function computeServerDynamicThreshold(payload: ProofPayload): number;

// =============================================================================
// Internal types (exported for advanced consumers)
// =============================================================================

export interface JitterAnalysis {
  score: number;
  flags: string[];
  stats: TimingStats | null;
  autocorrelations: Record<string, number>;
  hurstExponent: number;
  quantizationEntropy: number;
  thermalSignature: { slope: number; pattern: string; r2: number };
  outlierRate: number;
}

export interface TimingStats {
  n: number; mean: number; std: number; cv: number;
  min: number; max: number;
  p5: number; p25: number; p50: number; p75: number; p95: number; p99: number;
  skewness: number; kurtosis: number;
}

export interface CanvasFingerprint {
  webglRenderer: string | null;
  webglVendor: string | null;
  webglVersion: 1 | 2 | null;
  webglPixelHash: string | null;
  canvas2dHash: string | null;
  extensionCount: number;
  extensions: string[];
  isSoftwareRenderer: boolean;
  available: boolean;
}

export interface PhasedData {
  cold: { qe: number; mean: number };
  load: { qe: number; mean: number };
  hot:  { qe: number; mean: number };
  entropyJitterRatio: number;
}

// =============================================================================
// SVRN Registry
// =============================================================================

export interface SvrnSignature {
  version: number;
  id: string;
  profile: string;
  provider: string;
  class: string;
  metrics: Record<string, { lo: number; hi: number; mid: number; label: string } | null>;
  rendererClass: string;
  isSynthetic: boolean;
  hwLabel: string | null;
  osHint: string | null;
  date: string;
}

export interface RegistryMatch {
  matched: boolean;
  profile: object | null;
  similarity: number;
  alternatives: Array<{ name: string; similarity: number }>;
}

export interface SignatureComparison {
  sameClass: boolean;
  similarity: number;
  profileMatch: boolean;
  providerMatch: boolean;
}

// =============================================================================
// Extended Signal Layer Types
// =============================================================================

// ── ENF (Electrical Network Frequency) ───────────────────────────────────────

export interface EnfResult {
  enfAvailable: boolean;
  ripplePresent: boolean;
  gridFrequency: 50 | 60 | null;
  gridRegion: 'americas' | 'emea_apac' | 'unknown';
  ripplePower: number;
  snr50hz: number;
  snr60hz: number;
  enfDeviation: number | null;
  sampleRateHz: number;
  resolutionUs: number;
  verdict: 'grid_60hz' | 'grid_50hz' | 'no_grid_signal' | 'grid_detected_region_unknown' | 'unavailable';
  isVmIndicator: boolean;
  temporalAnchor: {
    nominalHz: number;
    measuredRippleHz: number;
    capturedAt: number;
    gridHz: number;
  } | null;
  reason?: string;
}

export declare function collectEnfTimings(opts?: { iterations?: number }): Promise<EnfResult>;

// ── WebGPU Thermal Variance ───────────────────────────────────────────────────

export interface GpuEntropyResult {
  gpuPresent: boolean;
  isSoftware: boolean;
  vendorString: string | null;
  dispatchCV: number;
  thermalGrowth: number;
  verdict: 'real_gpu' | 'software_renderer' | 'no_webgpu' | 'ambiguous';
}

export declare function collectGpuEntropy(opts?: object): Promise<GpuEntropyResult>;

// ── DRAM Refresh Cycle ────────────────────────────────────────────────────────

export interface DramResult {
  timings: number[];
  refreshPeriodMs: number | null;
  refreshPresent: boolean;
  peakLag: number;
  peakPower: number;
  verdict: 'dram' | 'virtual' | 'ambiguous';
}

export declare function collectDramTimings(opts?: { iterations?: number; bufferMb?: number }): DramResult;

// ── LLM / AI Agent Behavioral Fingerprint ─────────────────────────────────────

export interface LlmResult {
  aiConf: number;
  thinkTimePattern: 'llm_latency_peak' | 'human_pareto' | 'unknown';
  correctionRate: number;
  rhythmicity: number;
  pauseDistribution: 'uniform' | 'pareto' | 'unknown';
  verdict: 'ai_agent' | 'human' | 'insufficient_data';
  matchedModel: string | null;
}

export declare function detectLlmAgent(bioSnapshot: object): LlmResult;

// ── SAB Microsecond Timer ─────────────────────────────────────────────────────

export interface SabTimerResult {
  isClamped: boolean;
  clampAmountUs: number;
  resolutionUs: number;
}

export declare function isSabAvailable(): boolean;
export declare function collectHighResTimings(opts?: { iterations?: number; matrixSize?: number }): {
  timings: number[];
  resolutionUs: number;
};

// =============================================================================
// Terminal / DX Utilities
// =============================================================================

export declare function renderProbeResult(opts: {
  payload: ProofPayload;
  hash: string;
  result?: ValidationResult;
  enf?: EnfResult | null;
  gpu?: GpuEntropyResult | null;
  dram?: DramResult | null;
  llm?: LlmResult | null;
  elapsedMs?: number;
}): void;

export declare function renderError(err: Error | string): void;
export declare function renderInlineUpdateHint(latest: string): void;

// =============================================================================
// Version / Update Notifier
// =============================================================================

export declare const CURRENT_VERSION: string;

export declare function checkForUpdate(opts?: {
  silent?: boolean;
  pkg?: string;
}): Promise<{ current: string; latest: string | null; updateAvailable: boolean }>;

export declare function notifyOnExit(opts?: { pkg?: string }): void;

// =============================================================================
// Extended PulseCommitment (includes extended signal layer results)
// =============================================================================

export interface ExtendedPulseCommitment extends PulseCommitment {
  extended: {
    enf:  EnfResult  | null;
    gpu:  GpuEntropyResult | null;
    dram: DramResult | null;
    llm:  LlmResult  | null;
  };
}

// =============================================================================
// TrustScore
// =============================================================================

export interface TrustScoreBreakdown {
  pts: number;
  max: number;
  [key: string]: unknown;
}

export interface TrustScorePenalty {
  signal: string;
  reason: string;
  cap: number;
}

export interface TrustScoreBonus {
  signal: string;
  reason: string;
  pts: number;
}

export interface TrustScore {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  label: 'Trusted' | 'Verified' | 'Marginal' | 'Suspicious' | 'Blocked';
  color: string;
  hardCap: number | null;
  breakdown: {
    physics: TrustScoreBreakdown;
    enf:     TrustScoreBreakdown;
    gpu:     TrustScoreBreakdown;
    dram:    TrustScoreBreakdown;
    bio:     TrustScoreBreakdown;
  };
  penalties: TrustScorePenalty[];
  bonuses:   TrustScoreBonus[];
  signals: {
    physics: number;
    enf:     number;
    gpu:     number;
    dram:    number;
    bio:     number;
  };
}

export declare function computeTrustScore(
  payload: ProofPayload,
  extended?: { enf?: EnfResult; gpu?: GpuEntropyResult; dram?: DramResult; llm?: LlmResult }
): TrustScore;

export declare function formatTrustScore(ts: TrustScore): string;

// =============================================================================
// HMAC-Signed Challenge
// =============================================================================

export interface SignedChallenge {
  nonce:     string;
  issuedAt:  number;
  expiresAt: number;
  sig:       string;
}

export interface ChallengeVerifyResult {
  valid:   boolean;
  reason?: string;
}

export declare function createChallenge(
  secret: string,
  opts?: { ttlMs?: number; nonce?: string }
): SignedChallenge;

export declare function verifyChallenge(
  challenge: SignedChallenge,
  secret: string,
  opts?: { checkNonce?: (nonce: string) => Promise<boolean> }
): Promise<ChallengeVerifyResult>;

export declare function embedChallenge(challenge: SignedChallenge, payload: ProofPayload): ProofPayload;
export declare function extractChallenge(payload: ProofPayload): SignedChallenge;
export declare function generateSecret(): string;

// =============================================================================
// React Native Hook
// =============================================================================

export interface TremorResult {
  tremorPresent: boolean;
  tremorPower:   number;
  rmsNoise:      number;
  sampleRate:    number;
  gyroNoise:     number;
  isStatic:      boolean;
}

export interface TouchAnalysis {
  humanConf:    number;
  dwellMean:    number;
  dwellCV:      number;
  sampleCount:  number;
}

export interface UsePulseNativeOptions {
  challengeUrl?: string;
  verifyUrl?:    string;
  apiKey?:       string;
  sensorMs?:     number;
  autoRun?:      boolean;
  onResult?:     (trustScore: TrustScore, proof: object) => void;
  onError?:      (error: Error) => void;
}

export interface UsePulseNativeReturn {
  run:         () => Promise<void>;
  reset:       () => void;
  isRunning:   boolean;
  stage:       string | null;
  pct:         number;
  trustScore:  TrustScore | null;
  tremor:      TremorResult | null;
  touches:     TouchAnalysis | null;
  proof:       object | null;
  error:       Error | null;
  panHandlers: object | null;
}

export declare function usePulseNative(opts?: UsePulseNativeOptions): UsePulseNativeReturn;

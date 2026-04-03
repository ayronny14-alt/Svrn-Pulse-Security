/**
 * @svrnsec/pulse — Centralised Configuration & Thresholds
 */

export const CONFIG = {
  // Jitter Analysis
  jitter: {
    minCV: 0.04,
    maxCV: 0.35,
    minQE: 4.5,
    hurstIdeal: 0.5,
    hurstDevTolerance: 0.15,
    weightCV: 0.25,
    weightAutocorr: 0.20,
    weightQuantization: 0.20,
    weightHurst: 0.15,
    weightThermal: 0.10,
    weightOutliers: 0.10,
  },

  // Audio Fingerprinting
  audio: {
    minJitterCV: 0.05,
    maxFFTVariance: 50.0,
  },

  // LLM / Behavioral
  llm: {
    entropyThreshold: 0.8,
    coherenceThreshold: 0.7,
  },

  // Trust Scoring
  trust: {
    passingScore: 0.7,
    suspiciousScore: 0.4,
  },

  // Rate Limiting (Client-side)
  rateLimit: {
    maxPulsesPerMin: 10,
  }
};

export default CONFIG;

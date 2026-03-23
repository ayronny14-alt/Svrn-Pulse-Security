/**
 * @svrnsec/pulse — Refraction test suite
 *
 * Tests the environment-adaptive threshold calibration system.
 * Verifies that the same raw signal values produce correct pass/fail
 * verdicts under different timer grain profiles.
 */

import { jest } from '@jest/globals';
import {
  calibrate,
  calibrateSync,
  getProfile,
  resetProfile,
  scoreSignal,
  scoreJitter,
  getThresholds,
  detectEnvironment,
  probeTimerResolution,
  hasHrtime,
  ENV,
  PROFILES,
} from '../src/analysis/refraction.js';

beforeEach(() => {
  resetProfile();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Environment detection
// ═══════════════════════════════════════════════════════════════════════════════

describe('detectEnvironment', () => {
  test('detects Node.js in test runner', () => {
    expect(detectEnvironment()).toBe(ENV.NODE);
  });

  test('ENV enum is frozen', () => {
    expect(Object.isFrozen(ENV)).toBe(true);
    expect(ENV.NODE).toBe('node');
    expect(ENV.BROWSER).toBe('browser');
    expect(ENV.WORKER).toBe('worker');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Timer resolution probe
// ═══════════════════════════════════════════════════════════════════════════════

describe('probeTimerResolution', () => {
  test('returns valid resolution object', () => {
    const r = probeTimerResolution(100);
    expect(r).toHaveProperty('resolutionUs');
    expect(r).toHaveProperty('minDeltaMs');
    expect(r).toHaveProperty('medDeltaMs');
    expect(r).toHaveProperty('uniqueRatio');
    expect(r).toHaveProperty('grain');
    expect(r).toHaveProperty('samples');
    expect(typeof r.resolutionUs).toBe('number');
    expect(r.resolutionUs).toBeGreaterThan(0);
    expect(r.samples).toBeGreaterThan(0);
  });

  test('grain is a known value', () => {
    const r = probeTimerResolution(100);
    expect(['nanosecond', 'fine', 'clamped', 'coarse']).toContain(r.grain);
  });

  test('unique ratio is between 0 and 1', () => {
    const r = probeTimerResolution(100);
    expect(r.uniqueRatio).toBeGreaterThanOrEqual(0);
    expect(r.uniqueRatio).toBeLessThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Calibration
// ═══════════════════════════════════════════════════════════════════════════════

describe('calibrate', () => {
  test('async calibration returns frozen profile', async () => {
    const p = await calibrate();
    expect(Object.isFrozen(p)).toBe(true);
    expect(p).toHaveProperty('env');
    expect(p).toHaveProperty('timer');
    expect(p).toHaveProperty('grain');
    expect(p).toHaveProperty('hrtime');
    expect(p).toHaveProperty('thresholds');
    expect(p).toHaveProperty('label');
    expect(p).toHaveProperty('calibratedAt');
  });

  test('caches result on second call', async () => {
    const p1 = await calibrate();
    const p2 = await calibrate();
    expect(p1).toBe(p2);
  });

  test('force re-calibrates', async () => {
    const p1 = await calibrate();
    const p2 = await calibrate({ force: true });
    expect(p2.calibratedAt).toBeGreaterThanOrEqual(p1.calibratedAt);
  });

  test('sync calibration works', () => {
    const p = calibrateSync();
    expect(p).toHaveProperty('grain');
    expect(p).toHaveProperty('thresholds');
  });

  test('getProfile returns null before calibration', () => {
    expect(getProfile()).toBeNull();
  });

  test('getProfile returns profile after calibration', () => {
    calibrateSync();
    expect(getProfile()).not.toBeNull();
  });

  test('Node.js with hrtime uses nanosecond profile', async () => {
    const p = await calibrate();
    expect(p.env).toBe('node');
    expect(p.hrtime).toBe(true);
    expect(p.grain).toBe('nanosecond');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Profile thresholds
// ═══════════════════════════════════════════════════════════════════════════════

describe('PROFILES', () => {
  test('all four grain profiles exist', () => {
    expect(PROFILES).toHaveProperty('nanosecond');
    expect(PROFILES).toHaveProperty('fine');
    expect(PROFILES).toHaveProperty('clamped');
    expect(PROFILES).toHaveProperty('coarse');
  });

  test('each profile has all required signal keys', () => {
    const requiredKeys = ['cv', 'hurst', 'ac', 'qe', 'uvr', 'dram'];
    for (const [name, profile] of Object.entries(PROFILES)) {
      for (const key of requiredKeys) {
        expect(profile).toHaveProperty(key);
      }
    }
  });

  test('browser thresholds are wider than node thresholds', () => {
    const node = PROFILES.nanosecond;
    const browser = PROFILES.clamped;

    // CV ceiling is higher in browser
    expect(browser.cv.ceil).toBeGreaterThan(node.cv.ceil);
    // Hurst ceiling is higher in browser
    expect(browser.hurst.ceil).toBeGreaterThan(node.hurst.ceil);
    // AC pass threshold is higher in browser
    expect(browser.ac.pass).toBeGreaterThan(node.ac.pass);
    // QE pass threshold is lower in browser
    expect(browser.qe.pass).toBeLessThan(node.qe.pass);
    // UVR pass threshold is lower in browser
    expect(browser.uvr.pass).toBeLessThan(node.uvr.pass);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Signal scoring
// ═══════════════════════════════════════════════════════════════════════════════

describe('scoreSignal', () => {
  // Calibrate as Node.js (nanosecond profile) for deterministic tests
  beforeEach(() => calibrateSync());

  describe('CV scoring', () => {
    test('real hardware CV passes (0.15)', () => {
      const r = scoreSignal('cv', 0.15);
      expect(r.pass).toBe(true);
      expect(r.score).toBe(1);
      expect(r.flag).toBeNull();
    });

    test('hypervisor-flat CV fails (0.01)', () => {
      const r = scoreSignal('cv', 0.01);
      expect(r.pass).toBe(false);
      expect(r.flag).toBe('CV_FLAT_HYPERVISOR');
    });

    test('high burst CV gets lower score (0.60)', () => {
      const r = scoreSignal('cv', 0.60);
      expect(r.pass).toBe(false);
      expect(r.flag).toBe('CV_HIGH_BURST');
    });
  });

  describe('Hurst scoring', () => {
    test('anti-persistent H passes (0.40)', () => {
      const r = scoreSignal('hurst', 0.40);
      expect(r.pass).toBe(true);
      expect(r.score).toBe(1);
    });

    test('persistent H fails in Node profile (0.65)', () => {
      const r = scoreSignal('hurst', 0.65);
      expect(r.pass).toBe(false);
      expect(r.flag).toBe('HURST_PERSISTENT_VM');
    });
  });

  describe('AC scoring', () => {
    test('low AC passes (0.10)', () => {
      const r = scoreSignal('ac', 0.10);
      expect(r.pass).toBe(true);
      expect(r.score).toBe(1);
    });

    test('high AC fails (0.55)', () => {
      const r = scoreSignal('ac', 0.55);
      expect(r.pass).toBe(false);
    });
  });

  describe('QE scoring', () => {
    test('high QE passes (4.0)', () => {
      const r = scoreSignal('qe', 4.0);
      expect(r.pass).toBe(true);
    });

    test('low QE fails (0.5)', () => {
      const r = scoreSignal('qe', 0.5);
      expect(r.pass).toBe(false);
      expect(r.flag).toBe('QE_QUANTIZED');
    });
  });

  describe('UVR scoring', () => {
    test('high UVR passes (0.75)', () => {
      const r = scoreSignal('uvr', 0.75);
      expect(r.pass).toBe(true);
    });

    test('low UVR fails (0.10)', () => {
      const r = scoreSignal('uvr', 0.10);
      expect(r.pass).toBe(false);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Refraction-aware scoring adapts to profile
// ═══════════════════════════════════════════════════════════════════════════════

describe('cross-profile scoring', () => {
  test('browser-typical values pass under clamped profile but fail under nanosecond', () => {
    // Values typical of real hardware in a browser
    const browserStats = { cv: 0.77, hurst: 0.68, ac1: 0.45, qe: 1.6, uvr: 0.20 };

    // Force nanosecond profile — these values should fail
    resetProfile();
    // Manually set cached profile by calibrating (Node.js = nanosecond)
    calibrateSync();
    const nodeResult = scoreJitter(browserStats);

    // Now score the same values against clamped thresholds directly
    // by checking individual signals against clamped profile
    const clamped = PROFILES.clamped;

    // CV 0.77: fails nanosecond (ceil 0.35), passes clamped (ceil 0.90)
    expect(nodeResult.signals.cv.pass).toBe(false);
    expect(0.77 <= clamped.cv.ceil && 0.77 >= clamped.cv.floor).toBe(true);

    // Hurst 0.68: fails nanosecond (ceil 0.55), passes clamped (ceil 0.82)
    expect(nodeResult.signals.hurst.pass).toBe(false);
    expect(0.68 <= clamped.hurst.ceil && 0.68 >= clamped.hurst.floor).toBe(true);

    // AC 0.45: fails nanosecond (pass 0.20), passes clamped (pass 0.50)
    expect(nodeResult.signals.ac.pass).toBe(false);
    expect(0.45 < clamped.ac.pass).toBe(true);
  });

  test('VM-typical values fail under all profiles', () => {
    // Values typical of a VM — flat CV, persistent Hurst, periodic AC
    const vmStats = { cv: 0.004, hurst: 0.93, ac1: 0.76, qe: 0.2, uvr: 0.02 };

    for (const [name, profile] of Object.entries(PROFILES)) {
      expect(vmStats.cv).toBeLessThan(profile.cv.floor);
      expect(vmStats.hurst).toBeGreaterThan(profile.hurst.vmCeil);
      expect(vmStats.ac1).toBeGreaterThanOrEqual(profile.ac.fail);
      expect(vmStats.qe).toBeLessThan(profile.qe.warn);
      expect(vmStats.uvr).toBeLessThan(profile.uvr.warn);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Composite scoring
// ═══════════════════════════════════════════════════════════════════════════════

describe('scoreJitter', () => {
  test('real hardware in Node.js scores high', () => {
    calibrateSync();
    const result = scoreJitter({ cv: 0.15, hurst: 0.40, ac1: 0.08, qe: 4.5, uvr: 0.80 });
    expect(result.score).toBeGreaterThan(0.90);
    expect(result.flags).toHaveLength(0);
    expect(result.grain).toBe('nanosecond');
  });

  test('VM in Node.js scores low', () => {
    calibrateSync();
    const result = scoreJitter({ cv: 0.008, hurst: 0.88, ac1: 0.65, qe: 0.4, uvr: 0.05 });
    expect(result.score).toBeLessThan(0.35);
    expect(result.flags.length).toBeGreaterThan(3);
  });

  test('returns profile label and grain', () => {
    calibrateSync();
    const result = scoreJitter({ cv: 0.15, hurst: 0.40, ac1: 0.08, qe: 4.5, uvr: 0.80 });
    expect(result.profile).toContain('High-resolution');
    expect(result.grain).toBe('nanosecond');
  });

  test('auto-calibrates if not yet calibrated', () => {
    // No calibrateSync() call — should auto-calibrate
    const result = scoreJitter({ cv: 0.15, hurst: 0.40, ac1: 0.08, qe: 4.5, uvr: 0.80 });
    expect(result.grain).toBeDefined();
    expect(getProfile()).not.toBeNull();
  });

  test('score is bounded [0.01, 0.99]', () => {
    calibrateSync();
    const perfect = scoreJitter({ cv: 0.15, hurst: 0.40, ac1: 0.05, qe: 5.0, uvr: 0.95 });
    const terrible = scoreJitter({ cv: 0.001, hurst: 0.95, ac1: 0.80, qe: 0.1, uvr: 0.01 });
    expect(perfect.score).toBeLessThanOrEqual(0.99);
    expect(terrible.score).toBeGreaterThanOrEqual(0.01);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// getThresholds
// ═══════════════════════════════════════════════════════════════════════════════

describe('getThresholds', () => {
  test('returns clamped profile when not calibrated (safe default)', () => {
    const t = getThresholds('cv');
    // Should match clamped profile since no calibration
    expect(t.ceil).toBe(PROFILES.clamped.cv.ceil);
  });

  test('returns calibrated profile after calibration', () => {
    calibrateSync();
    const t = getThresholds('cv');
    // In Node.js, should match nanosecond profile
    expect(t.ceil).toBe(PROFILES.nanosecond.cv.ceil);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// hasHrtime
// ═══════════════════════════════════════════════════════════════════════════════

describe('hasHrtime', () => {
  test('returns true in Node.js', () => {
    expect(hasHrtime()).toBe(true);
  });
});

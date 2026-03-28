/**
 * @svrnsec/pulse — React Native Hook
 *
 * Runs the Physical Turing Test on iOS and Android.
 *
 * Mobile adds two signals that desktop cannot provide:
 *
 *   1. Accelerometer micro-tremor (8–12 Hz physiological band)
 *      Human hands shake at 8–12 Hz involuntarily. This appears as a
 *      continuous low-amplitude signal in the accelerometer. Emulators
 *      (Android Emulator, iOS Simulator, any cloud device farm) have
 *      zero or perfectly smooth accelerometer output. Real devices on
 *      a desk still show ~0.002g RMS noise from building vibration and
 *      HDD/fan resonance transmitted through the surface.
 *
 *   2. Touch event temporal fingerprint
 *      Human touch-down → touch-up durations follow a log-normal
 *      distribution (mean ~120ms, CV ~0.4). Automated taps from
 *      Appium, UIAutomator, XCUITest, or an LLM agent are either
 *      instantaneous (0ms dwell) or at a fixed scripted duration.
 *
 *   3. Gyroscope micro-rotation
 *      Real hands holding a phone produce sub-degree rotation noise
 *      at 0–5 Hz. An emulator or a phone in a robot testing rig has
 *      near-zero gyroscope variance.
 *
 * Peer dependencies (install separately):
 *   expo-sensors           (Accelerometer, Gyroscope)
 *   react-native           (Platform, PanResponder)
 *
 * Both expo-sensors (Expo managed/bare workflow) and react-native are
 * already in every React Native project — this hook adds zero new deps.
 *
 * Usage:
 *   import { usePulseNative } from '@svrnsec/pulse/react-native';
 *
 *   function CheckoutScreen() {
 *     const { run, isRunning, trustScore, verdict } = usePulseNative({
 *       challengeUrl: '/api/challenge',
 *       verifyUrl:    '/api/verify',
 *     });
 *
 *     useEffect(() => { run(); }, []);
 *
 *     if (trustScore) {
 *       return <Text>TrustScore: {trustScore.score}/100 ({trustScore.grade})</Text>;
 *     }
 *   }
 */

import { useState, useEffect, useRef, useCallback } from 'react';

/* ─── Platform detection ─────────────────────────────────────────────────── */

function _getPlatform() {
  try {
    const { Platform } = require('react-native');
    return Platform.OS; // 'ios' | 'android' | 'web'
  } catch {
    return 'unknown';
  }
}

/* ─── Sensor collector ───────────────────────────────────────────────────── */

/**
 * Collect accelerometer + gyroscope samples for tremor analysis.
 * Returns a promise that resolves after `durationMs`.
 *
 * @param {number} durationMs
 * @returns {Promise<{ accel: number[][], gyro: number[][] }>}
 *          accel[i] = [x, y, z] in g
 *          gyro[i]  = [x, y, z] in rad/s
 */
async function _collectSensors(durationMs = 3000) {
  const accel = [];
  const gyro  = [];

  try {
    const { Accelerometer, Gyroscope } = require('expo-sensors');

    Accelerometer.setUpdateInterval(10); // 100 Hz
    Gyroscope.setUpdateInterval(10);

    const accelSub = Accelerometer.addListener(({ x, y, z }) => accel.push([x, y, z]));
    const gyroSub  = Gyroscope.addListener(({ x, y, z })      => gyro.push([x, y, z]));

    try {
      await new Promise(r => setTimeout(r, durationMs));
    } finally {
      accelSub.remove();
      gyroSub.remove();
    }
  } catch {
    // expo-sensors not available — return empty arrays
  }

  return { accel, gyro };
}

/* ─── Touch collector ────────────────────────────────────────────────────── */

/**
 * Returns a PanResponder that records touch dwell times and velocities.
 * Attach to the root view of the screen being probed.
 */
function _createTouchResponder(touchLog) {
  try {
    const { PanResponder } = require('react-native');
    let downAt = 0;

    return PanResponder.create({
      onStartShouldSetPanResponder: () => false, // observe only, don't capture
      onMoveShouldSetPanResponder:  () => false,
      onPanResponderGrant: () => { downAt = Date.now(); },
      onPanResponderRelease: (_, gs) => {
        const dwell = Date.now() - downAt;
        touchLog.push({
          dwell,
          vx: gs.vx,
          vy: gs.vy,
          dx: gs.dx,
          dy: gs.dy,
          t:  downAt,
        });
      },
    });
  } catch {
    return null;
  }
}

/* ─── Signal analysis ────────────────────────────────────────────────────── */

/**
 * Analyse accelerometer data for physiological micro-tremor (8–12 Hz).
 * Uses a simple DFT over the Z-axis (gravity-compensated).
 *
 * @param {number[][]} accel  array of [x, y, z] samples at ~100 Hz
 * @returns {{ tremorPresent: boolean, tremorPower: number, rmsNoise: number, sampleRate: number }}
 */
function _analyseTremor(accel) {
  if (accel.length < 64) {
    return { tremorPresent: false, tremorPower: 0, rmsNoise: 0, sampleRate: 0 };
  }

  const n          = accel.length;
  const sampleRate = 100; // Hz (we set updateInterval to 10ms)

  // Use magnitude (removes orientation dependency)
  const mag = accel.map(([x, y, z]) => Math.sqrt(x*x + y*y + z*z));

  // Remove gravity (DC offset) via moving average
  const windowSize = Math.round(sampleRate * 0.5); // 0.5s window
  const detrended  = mag.map((v, i) => {
    const lo = Math.max(0, i - windowSize);
    const hi = Math.min(n - 1, i + windowSize);
    let sum = 0;
    for (let j = lo; j <= hi; j++) sum += mag[j];
    return v - sum / (hi - lo + 1);
  });

  // RMS noise (total signal energy)
  const rmsNoise = Math.sqrt(detrended.reduce((s, v) => s + v * v, 0) / n);

  // DFT: look for power in 8–12 Hz band
  const loHz = 8, hiHz = 12;
  let tremorPower = 0, totalPower = 0;

  for (let k = 1; k < Math.floor(n / 2); k++) {
    const freq = k * sampleRate / n;
    let re = 0, im = 0;
    for (let t = 0; t < n; t++) {
      const angle = 2 * Math.PI * k * t / n;
      re += detrended[t] * Math.cos(angle);
      im -= detrended[t] * Math.sin(angle);
    }
    const power = (re * re + im * im) / (n * n);
    totalPower += power;
    if (freq >= loHz && freq <= hiHz) tremorPower += power;
  }

  const tremorRatio   = totalPower > 0 ? tremorPower / totalPower : 0;
  const tremorPresent = tremorRatio > 0.12 && rmsNoise > 0.001;

  return { tremorPresent, tremorPower: +tremorRatio.toFixed(4), rmsNoise: +rmsNoise.toFixed(6), sampleRate };
}

/**
 * Analyse touch events for human vs automated patterns.
 * @param {{ dwell: number }[]} touchLog
 * @returns {{ humanConf: number, dwellMean: number, dwellCV: number, sampleCount: number }}
 */
function _analyseTouches(touchLog) {
  if (touchLog.length < 3) {
    return { humanConf: 0.5, dwellMean: 0, dwellCV: 0, sampleCount: touchLog.length };
  }

  const dwells = touchLog.map(t => t.dwell).filter(d => d > 0 && d < 2000);
  if (dwells.length < 2) return { humanConf: 0.5, dwellMean: 0, dwellCV: 0, sampleCount: 0 };

  const mean = dwells.reduce((s, v) => s + v, 0) / dwells.length;
  const std  = Math.sqrt(dwells.reduce((s, v) => s + (v - mean) ** 2, 0) / dwells.length);
  const cv   = mean > 0 ? std / mean : 0;

  // Human: mean 80–250ms, CV 0.25–0.65 (log-normal distribution)
  // Bot:   mean ~0ms or fixed (CV near 0)
  let humanConf = 0;
  if (mean >= 50  && mean <= 300) humanConf += 0.35;
  if (cv   >= 0.2 && cv   <= 0.7) humanConf += 0.35;
  if (dwells.length >= 5)          humanConf += 0.20;
  if (mean >= 80  && mean <= 200)  humanConf += 0.10;

  return { humanConf: Math.min(1, humanConf), dwellMean: +mean.toFixed(1), dwellCV: +cv.toFixed(3), sampleCount: dwells.length };
}

/**
 * Analyse gyroscope for micro-rotation noise.
 * @param {number[][]} gyro
 * @returns {{ gyroNoise: number, isStatic: boolean }}
 */
function _analyseGyro(gyro) {
  if (gyro.length < 10) return { gyroNoise: 0, isStatic: true };

  const mags = gyro.map(([x, y, z]) => Math.sqrt(x*x + y*y + z*z));
  const mean = mags.reduce((s, v) => s + v, 0) / mags.length;
  const rms  = Math.sqrt(mags.reduce((s, v) => s + v * v, 0) / mags.length);

  return {
    gyroNoise:  +rms.toFixed(6),
    isStatic:   rms < 0.005, // rad/s — emulator threshold
    sampleCount: gyro.length,
  };
}

/* ─── usePulseNative ─────────────────────────────────────────────────────── */

/**
 * React Native hook for the Physical Turing Test.
 *
 * @param {object}  opts
 * @param {string}  [opts.challengeUrl]   - GET endpoint that returns { nonce, ...challenge }
 * @param {string}  [opts.verifyUrl]      - POST endpoint that accepts { payload, hash }
 * @param {string}  [opts.apiKey]         - hosted API key (alternative to self-hosted URLs)
 * @param {number}  [opts.sensorMs=3000]  - how long to sample sensors
 * @param {boolean} [opts.autoRun=false]  - start probe immediately on mount
 * @param {Function}[opts.onResult]       - callback(trustScore, proof)
 * @param {Function}[opts.onError]        - callback(error)
 *
 * @returns {{
 *   run:         () => Promise<void>
 *   reset:       () => void
 *   isRunning:   boolean
 *   stage:       string|null
 *   pct:         number        0–100 progress
 *   trustScore:  TrustScore|null
 *   tremor:      object|null   accelerometer analysis
 *   touches:     object|null   touch analysis
 *   proof:       object|null   { payload, hash }
 *   error:       Error|null
 *   panHandlers: object|null   attach to <View> for touch collection
 * }}
 */
export function usePulseNative(opts = {}) {
  const {
    challengeUrl,
    verifyUrl,
    apiKey,
    sensorMs    = 3_000,
    autoRun     = false,
    onResult,
    onError,
  } = opts;

  const [stage,      setStage]      = useState(null);
  const [pct,        setPct]        = useState(0);
  const [isRunning,  setIsRunning]  = useState(false);
  const [trustScore, setTrustScore] = useState(null);
  const [tremor,     setTremor]     = useState(null);
  const [touches,    setTouches]    = useState(null);
  const [proof,      setProof]      = useState(null);
  const [error,      setError]      = useState(null);

  const touchLog     = useRef([]);
  const panResponder = useRef(null);

  // Initialise touch responder once
  useEffect(() => {
    panResponder.current = _createTouchResponder(touchLog.current);
  }, []);

  const reset = useCallback(() => {
    setStage(null); setPct(0); setIsRunning(false);
    setTrustScore(null); setTremor(null); setTouches(null);
    setProof(null); setError(null);
    touchLog.current = [];
  }, []);

  const run = useCallback(async () => {
    if (isRunning) return;

    reset();
    setIsRunning(true);

    try {
      const platform = _getPlatform();

      // ── 1. Fetch challenge ──────────────────────────────────────────────
      setStage('challenge'); setPct(5);
      let nonce, challengeMeta;

      if (apiKey) {
        const res = await fetch('https://api.svrnsec.com/v1/challenge', {
          headers: { Authorization: `Bearer ${apiKey}` },
        });
        const body = await res.json();
        nonce         = body.nonce;
        challengeMeta = body;
      } else if (challengeUrl) {
        const res = await fetch(challengeUrl);
        const body = await res.json();
        nonce         = body.nonce;
        challengeMeta = body;
      } else {
        // Offline self-test — generate a local nonce (no server verification)
        const arr = new Uint8Array(32);
        crypto.getRandomValues(arr);
        nonce = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
      }

      // ── 2. Sensor collection (runs in parallel with entropy) ────────────
      setStage('sensors'); setPct(15);

      const [sensorData] = await Promise.all([
        _collectSensors(sensorMs),
      ]);

      setPct(60);

      // ── 3. Analyse sensors ──────────────────────────────────────────────
      setStage('analysis'); setPct(70);

      const tremorResult = _analyseTremor(sensorData.accel);
      const gyroResult   = _analyseGyro(sensorData.gyro);
      const touchResult  = _analyseTouches(touchLog.current);

      setTremor({ ...tremorResult, ...gyroResult });
      setTouches(touchResult);
      setPct(80);

      // ── 4. Build mobile proof ───────────────────────────────────────────
      setStage('proof'); setPct(85);

      const mobileSignals = {
        platform,
        tremor:    tremorResult,
        gyro:      gyroResult,
        touch:     touchResult,
        sensorMs,
        collectedAt: Date.now(),
      };

      // Compute mobile TrustScore from sensor signals
      const { computeTrustScore } = await import('../analysis/trustScore.js');

      // Build a synthetic payload for TrustScore computation
      const syntheticPayload = {
        signals: {
          // Encode tremor as a jitter proxy
          entropy: {
            quantizationEntropy: tremorResult.tremorPresent ? 3.5 : 1.2,
            hurstExponent:       0.52,
            timingsCV:           tremorResult.rmsNoise * 50,
            autocorr_lag1:       tremorResult.tremorPresent ? 0.05 : 0.45,
          },
          bio: { hasActivity: touchResult.sampleCount > 0 },
          llm: {
            aiConf:          1 - touchResult.humanConf,
            correctionRate:  0.08, // mobile doesn't have keyboard
            rhythmicity:     tremorResult.tremorPower,
          },
        },
        classification: {
          jitterScore: tremorResult.tremorPresent ? 0.75 : 0.25,
          vmIndicators: [
            !tremorResult.tremorPresent && sensorData.accel.length > 50 ? 'no_tremor' : null,
            gyroResult.isStatic && sensorData.gyro.length > 10 ? 'static_gyro' : null,
          ].filter(Boolean),
        },
      };

      const ts = computeTrustScore(syntheticPayload);
      setTrustScore(ts);
      setPct(90);

      // ── 5. Build and optionally verify proof ────────────────────────────
      setStage('verify'); setPct(95);

      const proofData = {
        nonce,
        platform,
        signals: mobileSignals,
        trustScore: ts,
        challenge: challengeMeta,
      };

      setProof(proofData);

      if (verifyUrl && (challengeUrl || apiKey)) {
        const vRes = await fetch(verifyUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
          },
          body: JSON.stringify(proofData),
        });
        if (!vRes.ok) throw new Error('Verify failed: ' + vRes.status);
        const result = await vRes.json();
        proofData.result = result;
        setProof(proofData);
      }

      setPct(100);
      setStage('complete');
      onResult?.(ts, proofData);

    } catch (err) {
      setError(err);
      setStage('error');
      onError?.(err);
    } finally {
      setIsRunning(false);
    }
  }, [isRunning, apiKey, challengeUrl, verifyUrl, sensorMs, onResult, onError, reset]);

  useEffect(() => {
    if (autoRun) run();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    run,
    reset,
    isRunning,
    stage,
    pct,
    trustScore,
    tremor,
    touches,
    proof,
    error,
    // Spread onto your root <View> to collect touch events
    panHandlers: panResponder.current?.panHandlers ?? null,
  };
}

/* ─── Named exports for individual signal access ─────────────────────────── */

export { _analyseTremor  as analyseTremor  };
export { _analyseTouches as analyseTouches };
export { _analyseGyro    as analyseGyro    };
export { _collectSensors as collectSensors };

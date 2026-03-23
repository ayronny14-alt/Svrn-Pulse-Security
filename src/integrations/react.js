/**
 * @svrnsec/pulse — React Hook
 *
 * import { usePulse } from '@svrnsec/pulse/react';
 *
 * const {
 *   run, reset,
 *   stage, pct, vmConf, hwConf, earlyVerdict,
 *   proof, result,
 *   isRunning, isReady, error,
 * } = usePulse({ apiKey: 'sk_live_...' });
 *
 * // Or self-hosted:
 * const { run, proof, result } = usePulse({
 *   challengeUrl: '/api/pulse/challenge',
 *   verifyUrl:    '/api/pulse/verify',
 * });
 */

import { useState, useCallback, useRef } from 'react';

// Lazy import — only loaded in browser, allows tree-shaking in SSR builds
let _pulseModule = null;
async function getPulse() {
  if (!_pulseModule) {
    _pulseModule = await import('../index.js');
  }
  return _pulseModule.pulse;
}

/**
 * @param {object}   opts
 * @param {string}   [opts.apiKey]         - hosted API key (zero-config)
 * @param {string}   [opts.apiUrl]         - hosted API base URL (default: https://api.sovereign.dev)
 * @param {string}   [opts.challengeUrl]   - self-hosted challenge endpoint
 * @param {string}   [opts.verifyUrl]      - self-hosted verify endpoint
 * @param {number}   [opts.iterations=200]
 * @param {number}   [opts.bioWindowMs=3000]
 * @param {boolean}  [opts.adaptive=true]
 * @param {boolean}  [opts.autoRun=false]  - run immediately on mount
 * @param {Function} [opts.onResult]       - callback when result is ready
 * @param {Function} [opts.onError]        - callback on error
 */
export function usePulse(opts = {}) {
  const {
    apiKey,
    apiUrl        = 'https://api.sovereign.dev',
    challengeUrl,
    verifyUrl,
    iterations    = 200,
    bioWindowMs   = 3000,
    adaptive      = true,
    autoRun       = false,
    onResult,
    onError,
  } = opts;

  // ── State ────────────────────────────────────────────────────────────────
  const [stage,        setStage]       = useState(null);
  const [pct,          setPct]         = useState(0);
  const [vmConf,       setVmConf]      = useState(0);
  const [hwConf,       setHwConf]      = useState(0);
  const [earlyVerdict, setEarlyVerdict]= useState(null);
  const [proof,        setProof]       = useState(null);
  const [result,       setResult]      = useState(null);
  const [isRunning,    setIsRunning]   = useState(false);
  const [error,        setError]       = useState(null);

  const abortRef = useRef(null);
  const hasAutoRun = useRef(false);

  // ── run() ────────────────────────────────────────────────────────────────
  const run = useCallback(async () => {
    if (isRunning) return;

    // Reset
    setStage(null); setPct(0); setVmConf(0); setHwConf(0);
    setEarlyVerdict(null); setProof(null); setResult(null);
    setError(null); setIsRunning(true);

    try {
      // 1. Resolve nonce
      let nonce;
      if (apiKey) {
        const res = await fetch(`${apiUrl}/v1/challenge`, {
          headers: { 'Authorization': `Bearer ${apiKey}` },
        });
        if (!res.ok) throw new Error(`Challenge failed: ${res.status}`);
        ({ nonce } = await res.json());
      } else if (challengeUrl) {
        const res = await fetch(challengeUrl);
        if (!res.ok) throw new Error(`Challenge failed: ${res.status}`);
        ({ nonce } = await res.json());
      } else {
        throw new Error(
          'usePulse requires either apiKey or challengeUrl. ' +
          'Pass apiKey for the hosted API, or challengeUrl + verifyUrl for self-hosted.'
        );
      }

      // 2. Run the probe
      const pulse = await getPulse();
      const commitment = await pulse({
        nonce,
        iterations,
        bioWindowMs,
        adaptive,
        onProgress: (s, meta = {}) => {
          setStage(s);
          if (s === 'entropy_batch' && meta) {
            if (meta.pct         != null) setPct(meta.pct);
            if (meta.vmConf      != null) setVmConf(meta.vmConf);
            if (meta.hwConf      != null) setHwConf(meta.hwConf);
            if (meta.earlyVerdict != null) setEarlyVerdict(meta.earlyVerdict);
          }
        },
      });

      setProof(commitment);
      setPct(100);

      // 3. Verify (hosted or self-hosted)
      if (apiKey || verifyUrl) {
        const url     = apiKey ? `${apiUrl}/v1/verify` : verifyUrl;
        const headers = {
          'Content-Type': 'application/json',
          ...(apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {}),
        };

        const res = await fetch(url, {
          method:  'POST',
          headers,
          body:    JSON.stringify({ payload: commitment.payload, hash: commitment.hash }),
        });
        const verifyResult = await res.json();
        setResult(verifyResult);
        onResult?.(verifyResult, commitment);
      } else {
        onResult?.(null, commitment);
      }

    } catch (err) {
      setError(err);
      onError?.(err);
    } finally {
      setIsRunning(false);
    }
  }, [isRunning, apiKey, apiUrl, challengeUrl, verifyUrl, iterations, bioWindowMs, adaptive, onResult, onError]);

  // ── reset() ──────────────────────────────────────────────────────────────
  const reset = useCallback(() => {
    setStage(null); setPct(0); setVmConf(0); setHwConf(0);
    setEarlyVerdict(null); setProof(null); setResult(null);
    setIsRunning(false); setError(null);
  }, []);

  // ── autoRun on mount ──────────────────────────────────────────────────────
  // Note: We use a ref to avoid triggering on every render.
  // Consumers should wrap in useEffect if they need SSR safety:
  // useEffect(() => { if (autoRun) run(); }, []);
  if (autoRun && !hasAutoRun.current && typeof window !== 'undefined') {
    hasAutoRun.current = true;
    // Defer to next microtask so hook state is initialised
    Promise.resolve().then(run);
  }

  return {
    // Actions
    run,
    reset,
    // Live probe state
    stage,
    pct,
    vmConf,
    hwConf,
    earlyVerdict,
    // Results
    proof,
    result,
    // Status
    isRunning,
    isReady: !isRunning && (proof != null || error != null),
    error,
  };
}

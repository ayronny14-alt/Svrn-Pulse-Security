/**
 * svrnsec-pulse scan
 *
 * Runs the full probe locally (Node.js JS engine, no browser required),
 * computes the TrustScore, and renders a pretty result card.
 *
 * Options:
 *   --json        output raw JSON instead of the visual card
 *   --iterations  override probe iteration count (default 200)
 *   --no-banner   suppress the banner
 */

import { generateNonce }        from '../../proof/validator.js';
import { computeTrustScore, formatTrustScore } from '../../analysis/trustScore.js';
import { collectDramTimings }   from '../../collector/dram.js';
import { collectEnfTimings }    from '../../collector/enf.js';
import { renderProbeResult }    from '../../terminal.js';
import { CURRENT_VERSION }      from '../../update-notifier.js';

// ANSI helpers (inlined — no dep on terminal.js palette export)
const isTTY = () => process.stderr.isTTY && !process.env.NO_COLOR;
const A = { reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m', gray:'\x1b[90m',
  bwhite:'\x1b[97m', bmagenta:'\x1b[95m', bcyan:'\x1b[96m', bgreen:'\x1b[92m',
  byellow:'\x1b[93m', bred:'\x1b[91m' };
const c   = (code, s) => isTTY() ? `${code}${s}${A.reset}` : s;
const dim = (s) => c(A.dim,      s);
const mag = (s) => c(A.bmagenta, s);
const wh  = (s) => c(A.bwhite,   s);
const cy  = (s) => c(A.bcyan,    s);
const gr  = (s) => c(A.bgreen,   s);
const ye  = (s) => c(A.byellow,  s);
const re  = (s) => c(A.bred,     s);
const gy  = (s) => c(A.gray,     s);
const bd  = (s) => c(A.bold,     s);

function bar(pct, w = 24) {
  const f = Math.round(Math.min(1, pct) * w);
  const fill = isTTY() ? `\x1b[92m${'█'.repeat(f)}\x1b[0m` : '█'.repeat(f);
  const void_ = gy('░'.repeat(w - f));
  return fill + void_;
}

function spinner(ms = 80) {
  if (!isTTY()) return { stop: () => {} };
  const frames = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
  let i = 0;
  const iv = setInterval(() => {
    process.stderr.write(`\r  ${gy(frames[i++ % frames.length])}  `);
  }, ms);
  return { stop: (msg = '') => { clearInterval(iv); process.stderr.write(`\r  ${msg}\n`); } };
}

export async function runScan(args) {
  const jsonMode   = args.has('json') || args.has('j');
  const iterations = parseInt(args.get('iterations', '200'), 10);
  const noBanner   = args.has('no-banner');

  if (!noBanner && isTTY()) {
    process.stderr.write(
      '\n' +
      gy('  ┌─────────────────────────────────────────────┐') + '\n' +
      gy('  │') + `  ${mag('SVRN')}${wh(':PULSE')}  ${gy('scan')}   ` +
        gy('Physical Turing Test  │') + '\n' +
      gy('  │') + `  ${gy(`v${CURRENT_VERSION}`)}   ` +
        cy('https://github.com/ayronny14-alt/Svrn-Pulse-Security') + `  ` +
        gy('│') + '\n' +
      gy('  └─────────────────────────────────────────────┘') + '\n\n'
    );
  }

  const t0    = Date.now();
  const nonce = generateNonce();

  // ── Entropy probe ─────────────────────────────────────────────────────────
  if (isTTY() && !jsonMode) {
    process.stderr.write(gy('  Probing entropy') + ' ');
  }

  const { collectEntropy } = await import('../../collector/entropy.js');
  const spin = spinner();

  let entropy;
  try {
    entropy = await collectEntropy({
      iterations,
      phased:   true,
      adaptive: true,
      onBatch: (meta) => {
        if (isTTY() && !jsonMode) {
          spin.stop(
            `${bar(meta.pct / 100, 20)}  ${gy(meta.pct + '%')}  ` +
            `vm:${(meta.vmConf * 100).toFixed(0)}%  hw:${(meta.hwConf * 100).toFixed(0)}%`
          );
        }
      },
    });
    spin.stop(gr('✓ entropy collected'));
  } catch (err) {
    spin.stop(re('✗ entropy probe failed: ' + err.message));
    process.exit(1);
  }

  // ── Extended signals ──────────────────────────────────────────────────────
  if (isTTY() && !jsonMode) process.stderr.write('\n');

  const [enf, dram] = await Promise.allSettled([
    collectEnfTimings(),
    Promise.resolve(collectDramTimings()),
  ]).then(results => results.map(r => r.status === 'fulfilled' ? r.value : null));

  // ── Analysis ──────────────────────────────────────────────────────────────
  const { classifyJitter }     = await import('../../analysis/jitter.js');
  const { buildProof, buildCommitment } = await import('../../proof/fingerprint.js');

  // Minimal bio stub for non-browser context
  const bioStub = {
    mouse:    { sampleCount:0,ieiMean:0,ieiCV:0,velocityP50:0,velocityP95:0,angularJerkMean:0,pressureVariance:0 },
    keyboard: { sampleCount:0,dwellMean:0,dwellCV:0,ikiMean:0,ikiCV:0 },
    interferenceCoefficient: 0,
    hasActivity: false,
    durationMs: 0,
  };

  const canvasStub = {
    webglRenderer:null,webglVendor:null,webglVersion:null,
    webglPixelHash:null,canvas2dHash:null,extensionCount:0,
    isSoftwareRenderer:false,available:false,
  };

  const audioStub = {
    available:false,workletAvailable:false,callbackJitterCV:0,
    noiseFloorMean:0,noiseFloorStd:0,sampleRate:0,callbackCount:0,
    jitterMeanMs:0,jitterP95Ms:0,
  };

  const jitter  = classifyJitter(entropy.timings, { autocorrelations: entropy.autocorrelations });
  const payload = buildProof({ entropy, jitter, bio: bioStub, canvas: canvasStub, audio: audioStub, enf, dram, nonce });
  const { hash } = buildCommitment(payload);

  const ts      = computeTrustScore(payload, { enf, dram });
  const elapsed = Date.now() - t0;

  // ── Output ────────────────────────────────────────────────────────────────
  if (jsonMode) {
    process.stdout.write(JSON.stringify({ payload, hash, trustScore: ts, elapsed }, null, 2) + '\n');
    return;
  }

  // Pretty result card
  renderProbeResult({ payload, hash, enf, dram, elapsedMs: elapsed });

  // TrustScore panel
  const gradeColor = ts.score >= 75 ? A.bgreen : ts.score >= 45 ? A.byellow : A.bred;
  const W = 54;
  const vb = gy('│');

  process.stderr.write(gy('╭' + '─'.repeat(W + 2) + '╮') + '\n');
  process.stderr.write(`${vb}  ${bd('TRUST SCORE')}${' '.repeat(W - 9)}  ${vb}\n`);
  process.stderr.write(gy('├' + '─'.repeat(W + 2) + '┤') + '\n');
  process.stderr.write(`${vb}  ${' '.repeat(Math.floor((W - 8) / 2))}${c(gradeColor + A.bold, `${ts.score} / 100`)}${' '.repeat(Math.ceil((W - 8) / 2))}  ${vb}\n`);
  process.stderr.write(`${vb}  ${' '.repeat(Math.floor((W - ts.grade.length - ts.label.length - 3) / 2))}${c(gradeColor, ts.grade)} · ${c(gradeColor, ts.label)}${' '.repeat(Math.ceil((W - ts.grade.length - ts.label.length - 3) / 2))}  ${vb}\n`);
  process.stderr.write(`${vb}  ${' '.repeat(W)}  ${vb}\n`);

  // Per-signal bars
  const layers = [
    ['Physics', ts.signals.physics, ts.breakdown.physics?.pts, 40],
    ['ENF',     ts.signals.enf,     ts.breakdown.enf?.pts,     20],
    ['GPU',     ts.signals.gpu,     ts.breakdown.gpu?.pts,     15],
    ['DRAM',    ts.signals.dram,    ts.breakdown.dram?.pts,    15],
    ['Bio/LLM', ts.signals.bio,     ts.breakdown.bio?.pts,     10],
  ];

  for (const [name, pct, pts, max] of layers) {
    const lbl  = gy(name.padEnd(10));
    const b    = bar(pct ?? 0, 24);
    const ptsS = `${pts ?? 0}/${max}`.padStart(6);
    process.stderr.write(`${vb}  ${lbl}  ${b}  ${gy(ptsS)}  ${vb}\n`);
  }

  if (ts.penalties.length > 0) {
    process.stderr.write(`${vb}  ${' '.repeat(W)}  ${vb}\n`);
    for (const p of ts.penalties) {
      const msg = ye('⚠ ') + gy(p.reason.slice(0, W - 4));
      process.stderr.write(`${vb}  ${msg}${' '.repeat(Math.max(0, W - 2 - msg.replace(/\x1b\[[0-9;]*m/g,''). length))}  ${vb}\n`);
    }
  }

  process.stderr.write(`${vb}  ${' '.repeat(W)}  ${vb}\n`);
  process.stderr.write(`${vb}  ${gy('BLAKE3  ' + hash.slice(0, 40) + '…')}${' '.repeat(W - 48)}  ${vb}\n`);
  process.stderr.write(`${vb}  ${gy(`elapsed  ${(elapsed/1000).toFixed(2)}s`)}${' '.repeat(W - 14)}  ${vb}\n`);
  process.stderr.write(gy('╰' + '─'.repeat(W + 2) + '╯') + '\n\n');
}

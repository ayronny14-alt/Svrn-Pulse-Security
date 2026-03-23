/**
 * @svrnsec/pulse — Terminal Result Renderer
 *
 * Pretty-prints probe results to the terminal for Node.js server usage.
 * Used by middleware and the CLI so developers see clean, actionable output
 * during integration and debugging — not raw JSON.
 *
 * Zero dependencies. Pure ANSI escape codes.
 * Automatically disabled when stdout is not a TTY or NO_COLOR is set.
 */

/* ─── TTY guard ──────────────────────────────────────────────────────────── */

const isTTY = () =>
  typeof process !== 'undefined' &&
  process.stderr?.isTTY === true &&
  process.env?.NO_COLOR == null;

const c = isTTY;

/* ─── ANSI color palette ─────────────────────────────────────────────────── */

const A = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  // foreground — normal
  red:     '\x1b[31m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  blue:    '\x1b[34m',
  magenta: '\x1b[35m',
  cyan:    '\x1b[36m',
  white:   '\x1b[37m',
  gray:    '\x1b[90m',
  // foreground — bright
  bred:    '\x1b[91m',
  bgreen:  '\x1b[92m',
  byellow: '\x1b[93m',
  bblue:   '\x1b[94m',
  bmagenta:'\x1b[95m',
  bcyan:   '\x1b[96m',
  bwhite:  '\x1b[97m',
};

const paint = (code, s) => c() ? `${code}${s}${A.reset}` : s;
const dim   = (s) => paint(A.dim,     s);
const bold  = (s) => paint(A.bold,    s);
const gray  = (s) => paint(A.gray,    s);
const cyan  = (s) => paint(A.cyan,    s);
const green = (s) => paint(A.bgreen,  s);
const red   = (s) => paint(A.bred,    s);
const yel   = (s) => paint(A.byellow, s);
const mag   = (s) => paint(A.bmagenta,s);
const wh    = (s) => paint(A.bwhite,  s);

function stripAnsi(s) {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}
const visLen = (s) => stripAnsi(s).length;

/* ─── bar renderer ───────────────────────────────────────────────────────── */

/**
 * Render a horizontal progress / confidence bar.
 * @param {number}  pct      0–1
 * @param {number}  width    character width of the bar
 * @param {string}  fillCode ANSI color code for filled blocks
 */
function bar(pct, width = 20, fillCode = A.bgreen) {
  const filled = Math.round(Math.min(1, Math.max(0, pct)) * width);
  const empty  = width - filled;
  const fill   = c() ? `${fillCode}${'█'.repeat(filled)}${A.reset}` : '█'.repeat(filled);
  const void_  = gray('░'.repeat(empty));
  return fill + void_;
}

/* ─── verdict badge ──────────────────────────────────────────────────────── */

function verdictBadge(result) {
  if (!result) return gray('  PENDING   ');
  const { valid, score, confidence } = result;

  if (valid && confidence === 'high')   return green('  ✓ PASS     ');
  if (valid && confidence === 'medium') return yel('  ⚠ PASS     ');
  if (!valid && score < 0.3)            return red('  ✗ BLOCKED  ');
  return yel('  ⚠ REVIEW  ');
}

/* ─── renderProbeResult ──────────────────────────────────────────────────── */

/**
 * Print a formatted probe result card to stderr.
 *
 * @param {object} opts
 * @param {object}  opts.payload          - ProofPayload from pulse()
 * @param {string}  opts.hash             - BLAKE3 hex commitment
 * @param {object}  [opts.result]         - ValidationResult (server-side verify)
 * @param {object}  [opts.enf]            - EnfResult if available
 * @param {object}  [opts.gpu]            - GpuEntropyResult if available
 * @param {object}  [opts.dram]           - DramResult if available
 * @param {object}  [opts.llm]            - LlmResult if available
 * @param {number}  [opts.elapsedMs]      - total probe time
 */
export function renderProbeResult({ payload, hash, result, enf, gpu, dram, llm, elapsedMs }) {
  if (!c()) return;

  const W    = 54;
  const hr   = gray('─'.repeat(W));
  const vbar = gray('│');

  const row = (label, value, valueColor = A.bwhite) => {
    const lbl  = gray(label.padEnd(24));
    const val  = c() ? `${valueColor}${value}${A.reset}` : String(value);
    const line = `  ${lbl}${val}`;
    const pad  = ' '.repeat(Math.max(0, W - visLen(line) - 2));
    process.stderr.write(`${vbar}${line}${pad}  ${vbar}\n`);
  };

  const blank = () => {
    process.stderr.write(`${vbar}${' '.repeat(W + 2)}${vbar}\n`);
  };

  const section = (title) => {
    const t   = `  ${bold(title)}`;
    const pad = ' '.repeat(Math.max(0, W - visLen(t) - 2));
    process.stderr.write(`${vbar}${t}${pad}  ${vbar}\n`);
  };

  const badge = verdictBadge(result);
  const hashShort = hash ? hash.slice(0, 16) + '…' : 'pending';
  const elapsed   = elapsedMs ? `${(elapsedMs / 1000).toFixed(2)}s` : '—';

  const sigs = payload?.signals ?? {};
  const cls  = payload?.classification ?? {};
  const jScore = cls.jitterScore ?? 0;

  // ── Physics signals ──────────────────────────────────────────────────────
  const qe        = sigs.entropy?.quantizationEntropy ?? 0;
  const hurst     = sigs.entropy?.hurstExponent ?? 0;
  const cv        = sigs.entropy?.timingsCV ?? 0;
  const ejrClass  = qe >= 1.08 ? A.bgreen : qe >= 0.95 ? A.byellow : A.bred;
  const hwConf    = result?.confidence === 'high' ? 1.0 : result?.confidence === 'medium' ? 0.65 : 0.3;
  const vmConf    = 1 - hwConf;

  // ── ENF signals ──────────────────────────────────────────────────────────
  const enfRegion = enf?.gridRegion === 'americas' ? '60 Hz  Americas'
    : enf?.gridRegion === 'emea_apac'              ? '50 Hz  EMEA/APAC'
    : enf?.enfAvailable === false                  ? 'unavailable'
    : '—';
  const enfColor = enf?.ripplePresent ? A.bgreen : enf?.enfAvailable === false ? A.gray : A.byellow;

  // ── GPU signals ──────────────────────────────────────────────────────────
  const gpuStr    = gpu?.gpuPresent
    ? (gpu.isSoftware ? red('Software renderer') : green(gpu.vendorString ?? 'GPU detected'))
    : gray('unavailable');

  // ── DRAM signals ─────────────────────────────────────────────────────────
  const dramStr   = dram?.refreshPresent
    ? green(`${(dram.refreshPeriodMs ?? 0).toFixed(1)} ms  (DDR4 JEDEC ✓)`)
    : dram ? red('No refresh cycle (VM)') : gray('unavailable');

  // ── LLM signals ──────────────────────────────────────────────────────────
  const llmStr    = llm
    ? (llm.aiConf > 0.7 ? red(`AI agent  ${(llm.aiConf * 100).toFixed(0)}%`) : green(`Human  ${((1 - llm.aiConf) * 100).toFixed(0)}%`))
    : gray('no bio data');

  // ── Render ───────────────────────────────────────────────────────────────
  const topTitle  = `  ${mag('SVRN')}${wh(':PULSE')}  ${badge}`;
  const topPad    = ' '.repeat(Math.max(0, W - visLen(topTitle) - 2));
  const topBorder = gray('╭' + '─'.repeat(W + 2) + '╮');
  const botBorder = gray('╰' + '─'.repeat(W + 2) + '╯');

  process.stderr.write('\n');
  process.stderr.write(topBorder + '\n');
  process.stderr.write(`${vbar}${topTitle}${topPad}  ${vbar}\n`);
  process.stderr.write(gray('├' + '─'.repeat(W + 2) + '┤') + '\n');
  blank();

  section('PHYSICS LAYER');
  blank();
  row('Jitter score',     (jScore * 100).toFixed(1) + '%',    jScore > 0.7 ? A.bgreen : jScore > 0.45 ? A.byellow : A.bred);
  row('QE (entropy)',     qe.toFixed(3),                       ejrClass);
  row('Hurst exponent',   hurst.toFixed(4),                    Math.abs(hurst - 0.5) < 0.1 ? A.bgreen : A.byellow);
  row('Timing CV',        cv.toFixed(4),                       cv > 0.08 ? A.bgreen : A.byellow);
  row('Timer granularity',`${((sigs.entropy?.timerGranularityMs ?? 0) * 1000).toFixed(1)} µs`, A.bcyan);
  blank();

  const hwBar = bar(hwConf, 18, A.bgreen);
  const vmBar = bar(vmConf, 18, A.bred);
  row('HW confidence',    hwBar + '  ' + (hwConf * 100).toFixed(0) + '%');
  row('VM confidence',    vmBar + '  ' + (vmConf * 100).toFixed(0) + '%');

  blank();
  process.stderr.write(gray('├' + '─'.repeat(W + 2) + '┤') + '\n');
  blank();

  section('SIGNAL LAYERS');
  blank();
  row('Grid (ENF)',        enfRegion,   enfColor);
  process.stderr.write(`${vbar}  ${gray('GPU (thermal)')}${' '.repeat(10)}${gpuStr}  ${vbar}\n`);
  process.stderr.write(`${vbar}  ${gray('DRAM refresh')} ${' '.repeat(11)}${dramStr}  ${vbar}\n`);
  process.stderr.write(`${vbar}  ${gray('Behavioral (LLM)')}${' '.repeat(7)}${llmStr}  ${vbar}\n`);

  blank();
  process.stderr.write(gray('├' + '─'.repeat(W + 2) + '┤') + '\n');
  blank();

  section('PROOF');
  blank();
  row('BLAKE3',           hashShort,   A.bcyan);
  row('Nonce',            (payload?.nonce ?? '').slice(0, 16) + '…', A.gray);
  row('Elapsed',          elapsed,     A.gray);
  if (result) {
    row('Server verdict', result.valid ? 'valid' : 'rejected', result.valid ? A.bgreen : A.bred);
    row('Score',          ((result.score ?? 0) * 100).toFixed(1) + '%', A.bwhite);
    if ((result.riskFlags ?? []).length > 0) {
      blank();
      row('Risk flags', result.riskFlags.join(', '), A.byellow);
    }
  }
  blank();
  process.stderr.write(botBorder + '\n\n');
}

/* ─── renderError ────────────────────────────────────────────────────────── */

/**
 * Print a formatted error card for pulse() failures.
 * @param {Error|string} err
 */
export function renderError(err) {
  if (!c()) return;
  const msg  = err?.message ?? String(err);
  const W    = 54;
  const vbar = gray('│');

  process.stderr.write('\n');
  process.stderr.write(red('╭' + '─'.repeat(W + 2) + '╮') + '\n');
  process.stderr.write(`${red('│')}  ${red('✗')} ${bold('SVRN:PULSE — probe failed')}${' '.repeat(Math.max(0, W - 28))}  ${red('│')}\n`);
  process.stderr.write(red('├' + '─'.repeat(W + 2) + '┤') + '\n');
  process.stderr.write(`${vbar}  ${gray(msg.slice(0, W - 2).padEnd(W))}  ${vbar}\n`);
  process.stderr.write(red('╰' + '─'.repeat(W + 2) + '╯') + '\n\n');
}

/* ─── renderUpdateBanner ─────────────────────────────────────────────────── */

/**
 * Render a simple one-line update available hint inline (used by middleware).
 * @param {string} latest
 */
export function renderInlineUpdateHint(latest) {
  if (!c()) return;
  process.stderr.write(
    gray('  ╴╴╴  ') +
    yel('update available ') +
    gray(latest) +
    '  ' + cyan('npm i @svrnsec/pulse@latest') +
    gray('  ╴╴╴') +
    '\n'
  );
}

/**
 * @svrnsec/pulse — Update Notifier
 *
 * Checks the npm registry for a newer version and prints a styled terminal
 * notice when one is available. Non-blocking — the check runs in the
 * background and only displays if a newer version is found before the
 * process exits.
 *
 * Zero dependencies. Pure Node.js https module.
 * Silent in browser environments and when stdout is not a TTY.
 */

import { createRequire } from 'module';

/* ─── version from package.json ─────────────────────────────────────────── */

let _currentVersion = '0.0.0';
try {
  const require = createRequire(import.meta.url);
  _currentVersion = require('../package.json').version;
} catch {}

export const CURRENT_VERSION = _currentVersion;

/* ─── ANSI helpers ───────────────────────────────────────────────────────── */

const isTTY   = () =>
  typeof process !== 'undefined' &&
  process.stdout?.isTTY === true &&
  process.env?.NO_COLOR == null &&
  process.env?.PULSE_NO_UPDATE == null;

const isNode  = () => typeof process !== 'undefined' && typeof window === 'undefined';

const C = {
  reset:     '\x1b[0m',
  bold:      '\x1b[1m',
  dim:       '\x1b[2m',
  // foreground
  black:     '\x1b[30m',
  red:       '\x1b[31m',
  green:     '\x1b[32m',
  yellow:    '\x1b[33m',
  blue:      '\x1b[34m',
  magenta:   '\x1b[35m',
  cyan:      '\x1b[36m',
  white:     '\x1b[37m',
  // bright foreground
  bgray:     '\x1b[90m',
  bred:      '\x1b[91m',
  bgreen:    '\x1b[92m',
  byellow:   '\x1b[93m',
  bblue:     '\x1b[94m',
  bmagenta:  '\x1b[95m',
  bcyan:     '\x1b[96m',
  bwhite:    '\x1b[97m',
  // background
  bgBlack:   '\x1b[40m',
  bgYellow:  '\x1b[43m',
  bgBlue:    '\x1b[44m',
  bgCyan:    '\x1b[46m',
};

const c  = isTTY;
const ft = (code, s) => c() ? `${code}${s}${C.reset}` : s;

/* ─── box renderer ───────────────────────────────────────────────────────── */

/**
 * Render a bordered notification box to stderr.
 * Uses box-drawing characters and ANSI colors when the terminal supports them.
 */
function _box(lines, opts = {}) {
  const { borderColor = C.yellow, titleColor = C.bwhite } = opts;
  const pad   = 2;
  const width = Math.max(...lines.map(l => _visLen(l))) + pad * 2;
  const hr    = '─'.repeat(width);
  const bc    = (s) => c() ? `${borderColor}${s}${C.reset}` : s;

  const out = [
    bc(`╭${hr}╮`),
    ...lines.map(l => {
      const vis  = _visLen(l);
      const fill = ' '.repeat(Math.max(0, width - vis - pad * 2));
      return bc('│') + ' '.repeat(pad) + (c() ? l : _stripAnsi(l)) + fill + ' '.repeat(pad) + bc('│');
    }),
    bc(`╰${hr}╯`),
  ];

  process.stderr.write('\n' + out.join('\n') + '\n\n');
}

/* ─── version comparison ─────────────────────────────────────────────────── */

function _semverGt(a, b) {
  const pa = a.replace(/[^0-9.]/g, '').split('.').map(Number);
  const pb = b.replace(/[^0-9.]/g, '').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const da = pa[i] ?? 0, db = pb[i] ?? 0;
    if (da > db) return true;
    if (da < db) return false;
  }
  return false;
}

/* ─── registry fetch ─────────────────────────────────────────────────────── */

async function _fetchLatest(pkg) {
  return new Promise((resolve) => {
    let resolved = false;
    const done = (v) => { if (!resolved) { resolved = true; resolve(v); } };

    const timeout = setTimeout(() => done(null), 3_000);

    try {
      const https = require('https');
      const req   = https.get(
        `https://registry.npmjs.org/${encodeURIComponent(pkg)}/latest`,
        { headers: { 'Accept': 'application/json', 'User-Agent': `${pkg}/${_currentVersion}` } },
        (res) => {
          let body = '';
          res.setEncoding('utf8');
          res.on('data', d => body += d);
          res.on('end', () => {
            clearTimeout(timeout);
            try { done(JSON.parse(body).version ?? null); } catch { done(null); }
          });
        }
      );
      req.on('error', () => { clearTimeout(timeout); done(null); });
      req.end();
    } catch {
      clearTimeout(timeout);
      done(null);
    }
  });
}

// Lazy require for Node.js https module (avoids bundler issues)
let _httpsReq = null;
function require(m) {
  if (typeof globalThis.require === 'function') return globalThis.require(m);
  // CJS interop — only used server-side
  if (typeof process !== 'undefined') {
    const mod = process.mainModule?.require ?? (() => null);
    return mod(m);
  }
  return null;
}

/* ─── checkForUpdate ─────────────────────────────────────────────────────── */

/**
 * Check npm for a newer version of @svrnsec/pulse.
 * Call once at process startup — the result is shown before process exit
 * (or immediately if already resolved).
 *
 * @param {object} [opts]
 * @param {boolean} [opts.silent=false]  suppress output even when update exists
 * @param {string}  [opts.pkg='@svrnsec/pulse']
 * @returns {Promise<{ current: string, latest: string|null, updateAvailable: boolean }>}
 */
export async function checkForUpdate(opts = {}) {
  const { silent = false, pkg = '@svrnsec/pulse' } = opts;

  if (!isNode()) return { current: _currentVersion, latest: null, updateAvailable: false };

  const latest = await _fetchLatest(pkg);
  const updateAvailable = latest != null && _semverGt(latest, _currentVersion);

  if (updateAvailable && !silent && isTTY()) {
    _showUpdateBox(_currentVersion, latest, pkg);
  }

  return { current: _currentVersion, latest, updateAvailable };
}

/* ─── notifyOnExit ───────────────────────────────────────────────────────── */

let _notifyRegistered = false;

/**
 * Register a one-time process 'exit' listener that prints the update notice
 * after your application's own output has finished. This is the least
 * intrusive way to show the notification.
 *
 * Called automatically by the package initialiser — you do not need to call
 * this manually unless you want to control the timing.
 *
 * @param {object} [opts]
 * @param {string} [opts.pkg='@svrnsec/pulse']
 */
export function notifyOnExit(opts = {}) {
  if (!isNode() || _notifyRegistered) return;
  _notifyRegistered = true;

  const pkg = opts.pkg ?? '@svrnsec/pulse';
  let _latest = null;

  // Start the background check immediately
  _fetchLatest(pkg).then(v => { _latest = v; }).catch(() => {});

  // Show the box just before the process exits (after all user output)
  process.on('exit', () => {
    if (_latest && _semverGt(_latest, _currentVersion) && isTTY()) {
      _showUpdateBox(_currentVersion, _latest, pkg);
    }
  });
}

/* ─── banner ─────────────────────────────────────────────────────────────── */

/**
 * Print the @svrnsec/pulse ASCII banner to stderr.
 * Called once at package initialisation in Node.js environments.
 */
export function printBanner() {
  if (!isNode() || !isTTY()) return;

  const v   = ft(C.bgray, `v${_currentVersion}`);
  const tag = ft(C.bmagenta + C.bold, 'SVRN');
  const pkg = ft(C.bwhite  + C.bold, ':PULSE');

  process.stderr.write(
    '\n' +
    ft(C.bgray, '  ┌─────────────────────────────────────┐') + '\n' +
    ft(C.bgray, '  │') + `  ${tag}${pkg}  ` + ft(C.bgray, '─  Physical Turing Test  │') + '\n' +
    ft(C.bgray, '  │') + `  ${ft(C.bgray, 'Hardware-Biological Symmetry Protocol')}  ` + ft(C.bgray, '│') + '\n' +
    ft(C.bgray, '  │') + `  ${ft(C.bcyan, 'npm i @svrnsec/pulse')}  ${' '.repeat(16)}${v}  ` + ft(C.bgray, '│') + '\n' +
    ft(C.bgray, '  └─────────────────────────────────────┘') + '\n\n'
  );
}

/* ─── _showUpdateBox ─────────────────────────────────────────────────────── */

function _showUpdateBox(current, latest, pkg) {
  const arrow  = ft(C.bgray, '→');
  const oldV   = ft(C.bred,    current);
  const newV   = ft(C.bgreen + C.bold, latest);
  const cmd    = ft(C.bcyan + C.bold, `npm i ${pkg}@latest`);
  const notice = ft(C.byellow + C.bold, '  UPDATE AVAILABLE  ');

  _box([
    notice,
    '',
    `  ${oldV}  ${arrow}  ${newV}`,
    '',
    `  Run:  ${cmd}`,
    '',
    ft(C.bgray, `  Changelog: https://github.com/ayronny14-alt/Svrn-Pulse-Security/releases`),
  ], { borderColor: C.byellow });
}

/* ─── ANSI utilities ─────────────────────────────────────────────────────── */

// Measure visible length of string (strip ANSI escape codes)
function _visLen(s) {
  return _stripAnsi(s).length;
}

function _stripAnsi(s) {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

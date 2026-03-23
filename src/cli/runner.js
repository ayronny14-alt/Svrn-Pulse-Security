/**
 * @svrnsec/pulse CLI — main entry point
 *
 * Commands:
 *   scan              run the full probe locally
 *   challenge         generate a signed challenge nonce
 *   version           show version and check for updates
 *   help              show this help text
 */

import { parseArgs }      from './args.js';
import { printBanner, checkForUpdate, CURRENT_VERSION } from '../update-notifier.js';

const isTTY = () => process.stderr.isTTY && !process.env.NO_COLOR;
const A = { reset:'\x1b[0m', gray:'\x1b[90m', bcyan:'\x1b[96m',
  bwhite:'\x1b[97m', bmagenta:'\x1b[95m', bgreen:'\x1b[92m', byellow:'\x1b[93m' };
const c  = (code, s) => isTTY() ? `${code}${s}${A.reset}` : s;
const gy = (s) => c(A.gray, s);
const cy = (s) => c(A.bcyan, s);
const wh = (s) => c(A.bwhite, s);
const gr = (s) => c(A.bgreen, s);
const ye = (s) => c(A.byellow, s);
const mg = (s) => c(A.bmagenta, s);

function help() {
  process.stderr.write(`
${mg('SVRN')}${wh(':PULSE')}  ${gy(`v${CURRENT_VERSION}`)}  ${gy('Physical Turing Test')}

${wh('Usage')}
  ${cy('npx svrnsec-pulse')} ${gy('<command>')} ${gy('[options]')}

${wh('Commands')}
  ${cy('scan')}         Run the full probe locally and show a TrustScore
  ${cy('challenge')}    Generate a signed HMAC challenge nonce
  ${cy('version')}      Show version and check for updates
  ${cy('help')}         Show this help text

${wh('Scan options')}
  ${gy('--json')}         Output raw JSON (pipe-friendly)
  ${gy('--iterations')}   Override probe iteration count ${gy('(default: 200)')}
  ${gy('--no-banner')}    Suppress the banner

${wh('Challenge options')}
  ${gy('--secret')}       Server secret for HMAC signing ${gy('(or set PULSE_SECRET env)')}
  ${gy('--ttl')}          Challenge TTL in seconds ${gy('(default: 300)')}
  ${gy('--json')}         Output raw JSON

${wh('Examples')}
  ${gy('$')} ${cy('npx svrnsec-pulse scan')}
  ${gy('$')} ${cy('npx svrnsec-pulse scan --json | jq .trustScore.score')}
  ${gy('$')} ${cy('npx svrnsec-pulse challenge --secret $PULSE_SECRET')}
  ${gy('$')} ${cy('PULSE_SECRET=mysecret npx svrnsec-pulse challenge --json')}

${wh('Environment')}
  ${gy('PULSE_SECRET')}    Default server secret for challenge signing
  ${gy('NO_COLOR')}        Disable ANSI colors
  ${gy('PULSE_NO_UPDATE')} Disable update notifications

${gy('  Docs: https://github.com/ayronny14-alt/Svrn-Pulse-Security#readme')}
`);
}

async function cmdChallenge(args) {
  const secret = args.get('secret') ?? process.env.PULSE_SECRET;
  if (!secret) {
    process.stderr.write(
      ye('⚠ ') + 'No secret provided.\n' +
      gy('  Pass --secret <value> or set PULSE_SECRET env var.\n') +
      gy('  Generate one: ') + cy('npx svrnsec-pulse challenge --generate-secret\n')
    );
    process.exit(1);
  }

  if (args.has('generate-secret')) {
    const { generateSecret } = await import('../proof/challenge.js');
    const s = generateSecret();
    if (args.has('json')) {
      process.stdout.write(JSON.stringify({ secret: s }) + '\n');
    } else {
      process.stderr.write(gr('Generated secret (store in env):\n'));
      process.stdout.write(s + '\n');
    }
    return;
  }

  const { createChallenge } = await import('../proof/challenge.js');
  const ttlMs = (parseInt(args.get('ttl', '300'), 10) || 300) * 1000;
  const challenge = createChallenge(secret, { ttlMs });

  if (args.has('json')) {
    process.stdout.write(JSON.stringify(challenge, null, 2) + '\n');
  } else {
    process.stderr.write('\n');
    process.stderr.write(gy('  nonce      ') + wh(challenge.nonce) + '\n');
    process.stderr.write(gy('  issuedAt   ') + gy(new Date(challenge.issuedAt).toISOString()) + '\n');
    process.stderr.write(gy('  expiresAt  ') + gy(new Date(challenge.expiresAt).toISOString()) + '\n');
    process.stderr.write(gy('  sig        ') + cy(challenge.sig) + '\n\n');
  }
}

async function cmdVersion(args) {
  if (args.has('json')) {
    const { latest, updateAvailable } = await checkForUpdate({ silent: true });
    process.stdout.write(JSON.stringify({ version: CURRENT_VERSION, latest, updateAvailable }) + '\n');
    return;
  }

  process.stderr.write(`\n${mg('SVRN')}${wh(':PULSE')}  ${gy('v' + CURRENT_VERSION)}\n\n`);
  const { latest, updateAvailable } = await checkForUpdate({ silent: true });
  if (updateAvailable) {
    process.stderr.write(ye(`  Update available: ${latest}\n`));
    process.stderr.write(gy(`  Run: `) + cy('npm i @svrnsec/pulse@latest') + '\n');
  } else if (latest) {
    process.stderr.write(gr('  Up to date.\n'));
  }
  process.stderr.write('\n');
}

export async function run(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const cmd  = args.command ?? 'help';

  try {
    switch (cmd) {
      case 'scan': {
        const { runScan } = await import('./commands/scan.js');
        await runScan(args);
        break;
      }
      case 'challenge':
      case 'ch':
        await cmdChallenge(args);
        break;
      case 'version':
      case '-v':
      case '--version':
        await cmdVersion(args);
        break;
      case 'help':
      case '-h':
      case '--help':
        help();
        break;
      default:
        process.stderr.write(ye(`Unknown command: ${cmd}\n`));
        help();
        process.exit(1);
    }
  } catch (err) {
    process.stderr.write(
      c(A.bmagenta + '\x1b[1m', 'SVRN:PULSE error') + '\n' +
      gy(err.message) + '\n'
    );
    if (process.env.DEBUG) process.stderr.write(err.stack + '\n');
    process.exit(1);
  }
}

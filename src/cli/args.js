/**
 * Minimal argument parser — zero dependencies.
 * Supports: flags (--flag), options (--key value), positional args.
 */
export function parseArgs(argv = process.argv.slice(2)) {
  const flags   = new Set();
  const opts    = {};
  const pos     = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        opts[key] = next;
        i++;
      } else {
        flags.add(key);
      }
    } else if (arg.startsWith('-') && arg.length === 2) {
      flags.add(arg.slice(1));
    } else {
      pos.push(arg);
    }
  }

  return {
    command: pos[0] ?? null,
    positional: pos.slice(1),
    flags,
    opts,
    has: (f) => flags.has(f),
    get: (k, def) => opts[k] ?? def,
  };
}

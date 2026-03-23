import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import wasm     from '@rollup/plugin-wasm';

// inlineDynamicImports bundles everything into a single output file.
// This sidesteps chunk-splitting for the dynamic `import('../analysis/jitter.js')`
// inside the phased entropy path, and lets the wasm plugin inline the .wasm
// binary as base64 without a separate asset file.

export default [
  // ESM build — browsers and modern Node.js (type: "module")
  {
    input:   'src/index.js',
    output: {
      file:                 'dist/pulse.esm.js',
      format:               'es',
      sourcemap:            true,
      inlineDynamicImports: true,
    },
    plugins: [
      wasm(),
      resolve({ browser: true }),
      commonjs(),
    ],
    external: [],
  },

  // CJS build — older Node.js / require() interop
  {
    input:   'src/index.js',
    output: {
      file:                 'dist/pulse.cjs.js',
      format:               'cjs',
      exports:              'named',
      sourcemap:            true,
      inlineDynamicImports: true,
    },
    plugins: [
      wasm(),
      resolve({ browser: false, preferBuiltins: true }),
      commonjs(),
    ],
    external: ['node:crypto'],
  },
];

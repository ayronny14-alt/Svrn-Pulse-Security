import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import wasm     from '@rollup/plugin-wasm';

// The WASM binary is inlined as base64 so the final bundle is a single file.
// This avoids CORS issues and separate .wasm asset fetching.

export default [
  // ESM build (for browsers and modern Node.js)
  {
    input:   'src/index.js',
    output: {
      file:   'dist/pulse.esm.js',
      format: 'es',
      sourcemap: true,
    },
    plugins: [
      wasm(), // inlines .wasm as base64
      resolve({ browser: true }),
      commonjs(),
    ],
    external: [],
  },

  // CJS build (for older Node.js / require() usage)
  {
    input:   'src/index.js',
    output: {
      file:      'dist/pulse.cjs.js',
      format:    'cjs',
      exports:   'named',
      sourcemap: true,
    },
    plugins: [
      wasm(),
      resolve({ browser: false, preferBuiltins: true }),
      commonjs(),
    ],
    external: ['node:crypto'],
  },
];

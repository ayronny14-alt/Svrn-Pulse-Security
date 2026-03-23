#!/usr/bin/env bash
# ============================================================
# @sovereign/pulse — WASM build script
# ============================================================
set -euo pipefail

# ── Preflight checks ─────────────────────────────────────────
echo "🔍  Checking toolchain..."

if ! command -v wasm-pack &> /dev/null; then
  echo "❌  wasm-pack not found."
  echo "    Install it with: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
  echo "    Or: cargo install wasm-pack"
  exit 1
fi

if ! command -v cargo &> /dev/null; then
  echo "❌  Rust/Cargo not found."
  echo "    Install from: https://rustup.rs/"
  exit 1
fi

echo "✅  wasm-pack: $(wasm-pack --version)"
echo "✅  cargo:     $(cargo --version)"

# ── Build WASM ────────────────────────────────────────────────
echo ""
echo "⚙️   Building WASM core (pulse-core)..."

wasm-pack build crates/pulse-core \
  --target web \
  --out-dir ../../pkg \
  --release \
  --no-typescript  # we'll hand-write the types

# Fix: wasm-pack places output relative to crate dir; move it to project root
# (The --out-dir above is relative to the crate, so it lands at project root/pkg already)

if [ ! -f "pkg/pulse_core_bg.wasm" ]; then
  echo "❌  WASM binary not found at pkg/pulse_core_bg.wasm"
  exit 1
fi

WASM_SIZE=$(du -sh pkg/pulse_core_bg.wasm | cut -f1)
echo "✅  WASM binary built: pkg/pulse_core_bg.wasm (${WASM_SIZE})"

# ── Optimize WASM binary (optional but recommended) ──────────
if command -v wasm-opt &> /dev/null; then
  echo "🔧  Optimising WASM with wasm-opt..."
  wasm-opt -O3 -o pkg/pulse_core_bg.wasm pkg/pulse_core_bg.wasm
  echo "✅  wasm-opt done"
else
  echo "ℹ️   wasm-opt not found (optional). Install binaryen for smaller binary."
fi

# ── Bundle JS ─────────────────────────────────────────────────
echo ""
echo "📦  Bundling JavaScript..."

if [ ! -f "node_modules/.bin/rollup" ]; then
  echo "⚙️   Installing npm dependencies..."
  npm install
fi

npm run build:js

echo ""
echo "📊  Build artifacts:"
ls -lh dist/ 2>/dev/null || echo "  (dist/ not yet created)"
ls -lh pkg/pulse_core_bg.wasm

echo ""
echo "✅  @sovereign/pulse build complete!"

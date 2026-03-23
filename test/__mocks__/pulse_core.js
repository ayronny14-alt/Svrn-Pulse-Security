// Mock WASM module for Jest (no browser context available)
export default async function init() {}
export function run_entropy_probe() { return { timings: [], resolution_probe: [], checksum: 0 }; }
export function run_memory_probe() { return []; }
export function compute_autocorrelation() { return 0; }

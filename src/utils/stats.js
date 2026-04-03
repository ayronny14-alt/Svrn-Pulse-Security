/**
 * @svrnsec/pulse — Shared Statistical Utilities
 */

export function mean(arr) {
  const n = arr.length;
  if (n === 0) return 0;
  return arr.reduce((s, v) => s + v, 0) / n;
}

export function variance(arr, isSample = true) {
  const n = arr.length;
  if (n < 2) return 0;
  const m = mean(arr);
  const sumSq = arr.reduce((s, v) => s + (v - m) ** 2, 0);
  return sumSq / (isSample ? n - 1 : n);
}

export function stdDev(arr, isSample = true) {
  return Math.sqrt(variance(arr, isSample));
}

export function cv(arr) {
  const m = mean(arr);
  if (m === 0) return 0;
  return stdDev(arr) / m;
}

export function median(arr) {
  if (arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 
    ? sorted[mid] 
    : (sorted[mid - 1] + sorted[mid]) / 2;
}

export function percentile(arr, p) {
  const n = arr.length;
  if (n === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = (p / 100) * (n - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

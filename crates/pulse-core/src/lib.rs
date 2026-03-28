use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// External JS binding: high-resolution timer
// In browsers and Node.js ≥ 16, `performance.now()` is globally available.
// ---------------------------------------------------------------------------
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn perf_now() -> f64;
}

// ---------------------------------------------------------------------------
// ProbeResult – returned to JavaScript after the entropy probe
// ---------------------------------------------------------------------------
#[wasm_bindgen]
pub struct ProbeResult {
    timings: Vec<f64>,
    resolution_probe: Vec<f64>,
    checksum: f64,
}

#[wasm_bindgen]
impl ProbeResult {
    /// Millisecond delta for each matrix-multiply iteration.
    #[wasm_bindgen(getter)]
    pub fn timings(&self) -> Vec<f64> {
        self.timings.clone()
    }

    /// 200 rapid successive `performance.now()` readings with no work in between.
    /// Used to detect timer quantization / clamping (VM vs. real HW).
    #[wasm_bindgen(getter)]
    pub fn resolution_probe(&self) -> Vec<f64> {
        self.resolution_probe.clone()
    }

    /// XOR-folded checksum of the result matrix.
    /// Proves the computation was NOT dead-code-eliminated by the JS/WASM optimizer.
    #[wasm_bindgen(getter)]
    pub fn checksum(&self) -> f64 {
        self.checksum
    }
}

// ---------------------------------------------------------------------------
// LCG pseudo-random number generator (deterministic seeding, not crypto)
// ---------------------------------------------------------------------------
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed ^ 0xDEAD_BEEF_CAFE_BABE)
    }
    fn next_f64(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // Map upper 53 bits to [0, 1)
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

// ---------------------------------------------------------------------------
// run_entropy_probe
//
// Executes `iterations` rounds of a branch-heavy, cache-thrashing N×N matrix
// multiply and records wall-clock time of each round via performance.now().
//
// The multiply is intentionally NAIVE (triple-loop, no SIMD/BLAS) so that
// timing is dominated by memory latency and CPU frequency variation rather
// than pure arithmetic throughput.  The non-linear branches defeat the branch
// predictor and increase execution-time variance on real hardware.
// ---------------------------------------------------------------------------
#[wasm_bindgen]
pub fn run_entropy_probe(iterations: u32, matrix_size: u32) -> ProbeResult {
    let n = matrix_size as usize;
    let total = n * n;

    // Seed matrices with LCG values so the compiler can't constant-fold them.
    let mut rng = Lcg::new((perf_now() * 1e6) as u64 | 0xDEAD);
    let mut a: Vec<f64> = (0..total).map(|_| rng.next_f64()).collect();
    let mut b: Vec<f64> = (0..total).map(|_| rng.next_f64()).collect();
    let mut c = vec![0f64; total];

    let mut timings = Vec::with_capacity(iterations as usize);
    let mut checksum = 0f64;

    for iter in 0..iterations as usize {
        let t0 = perf_now();

        // --- Branch-heavy non-linear matrix multiply ---
        for i in 0..n {
            for j in 0..n {
                let mut acc = 0f64;
                for k in 0..n {
                    let v = a[i * n + k] * b[k * n + j];
                    // Four-way non-linear branch: stresses branch predictor
                    // and creates data-dependent execution paths.
                    acc += if v > 0.75 {
                        v * v - 0.001          // quadratic path
                    } else if v > 0.5 {
                        v.sqrt() + 0.001       // sqrt path  (slow on many µarchs)
                    } else if v > 0.25 {
                        1.0 - v * v * 2.0      // negated quadratic
                    } else {
                        v * 3.14159265358979   // multiply by π  (random-ish)
                    };
                }
                c[i * n + j] = acc;
            }
        }

        let t1 = perf_now();
        timings.push(t1 - t0);

        // Mutate A from C so the compiler cannot hoist the loop body.
        // Use diagonal element of the current iteration's "generation".
        let diag = iter % n;
        a[diag * n + diag] = (c[diag * n + diag] * 1e-4).sin();

        // Accumulate checksum (prevents dead-code elimination of C).
        checksum += c[iter % total];
    }

    // --- Resolution probe: 200 rapid timer readings with no work ---
    let mut resolution_probe = Vec::with_capacity(200);
    for _ in 0..200 {
        resolution_probe.push(perf_now());
    }

    ProbeResult {
        timings,
        resolution_probe,
        checksum,
    }
}

// ---------------------------------------------------------------------------
// run_memory_probe
//
// Strided memory access over a large buffer.  Hits every cache level and DRAM.
// Returns per-iteration timings (same structure as entropy probe).
// Used as a secondary signal: VMs often show suspiciously stable memory latency
// because the hypervisor pins guest memory to NUMA-local pages.
// ---------------------------------------------------------------------------
#[wasm_bindgen]
pub fn run_memory_probe(size_kb: u32, iterations: u32) -> Vec<f64> {
    let len = (size_kb as usize * 1024) / 8; // number of f64 elements
    let mut buf: Vec<f64> = (0..len).map(|i| i as f64 * 1e-9).collect();

    // Stride = 8 cache lines (64 bytes each) = 512 bytes → 64 f64 elements.
    // This pattern forces TLB misses and DRAM row activation on large buffers.
    let stride = 64usize;
    let mut timings = Vec::with_capacity(iterations as usize);
    let mut acc = 0f64;

    for _ in 0..iterations {
        let t0 = perf_now();
        let mut j = 0usize;
        while j < len {
            acc += buf[j];
            buf[j] = acc * (1.0 - 1e-9); // write-back prevents read-only optimization
            j += stride;
        }
        // Prevent acc from being optimized away
        if acc < f64::MIN_POSITIVE {
            buf[0] = acc;
        }
        timings.push(perf_now() - t0);
    }

    timings
}

// ---------------------------------------------------------------------------
// compute_autocorrelation (WASM-side)
//
// Computes Pearson autocorrelation at the requested lag.
// Kept in Rust because it requires O(n) work and is called multiple times.
// ---------------------------------------------------------------------------
#[wasm_bindgen]
pub fn compute_autocorrelation(samples: &[f64], lag: usize) -> f64 {
    let n = samples.len();
    if lag >= n {
        return 0.0;
    }
    let valid = n - lag;
    let mean: f64 = samples.iter().sum::<f64>() / n as f64;

    let (mut num, mut den_a, mut den_b) = (0f64, 0f64, 0f64);
    for i in 0..valid {
        let a = samples[i] - mean;
        let b = samples[i + lag] - mean;
        num += a * b;
        den_a += a * a;
        den_b += b * b;
    }
    let denom = (den_a * den_b).sqrt();
    if denom < 1e-14 {
        0.0
    } else {
        num / denom
    }
}

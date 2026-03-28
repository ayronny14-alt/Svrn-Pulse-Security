/**
 * @svrnsec/pulse — WebGPU Thermal Variance Probe
 *
 * Runs a compute shader on the GPU and measures dispatch timing variance.
 *
 * Why this works
 * ──────────────
 * Real consumer GPUs (GTX 1650, RX 6600, M2 GPU) have thermal noise in shader
 * execution timing that increases under sustained load — the same thermodynamic
 * principle as the CPU probe but in silicon designed for parallel throughput.
 *
 * Cloud VMs with software GPU emulation (SwiftShader, llvmpipe, Mesa's softpipe)
 * execute shaders on the CPU and produce near-deterministic timing — flat CV,
 * no thermal growth across phases, no dispatch jitter.
 *
 * VMs with GPU passthrough (rare in practice, requires dedicated hardware) pass
 * this check — which is correct, they have real GPU silicon.
 *
 * Signals
 * ───────
 *   gpuPresent      false = WebGPU absent = software renderer = high VM probability
 *   isSoftware      true  = SwiftShader/llvmpipe detected by adapter info
 *   dispatchCV      coefficient of variation across dispatch timings
 *   thermalGrowth   (hotDispatchMean - coldDispatchMean) / coldDispatchMean
 *   vendorString    GPU vendor from adapter info (Intel, NVIDIA, AMD, Apple, etc.)
 */

/* ─── WebGPU availability ────────────────────────────────────────────────── */

function isWebGPUAvailable() {
  return typeof navigator !== 'undefined' && 'gpu' in navigator;
}

/* ─── Software renderer detection ───────────────────────────────────────── */

const SOFTWARE_RENDERER_PATTERNS = [
  /swiftshader/i,
  /llvmpipe/i,
  /softpipe/i,
  /microsoft basic render/i,
  /angle \(.*software/i,
  /cpu/i,
];

function detectSoftwareRenderer(adapterInfo) {
  const desc = [
    adapterInfo?.vendor   ?? '',
    adapterInfo?.device   ?? '',
    adapterInfo?.description ?? '',
    adapterInfo?.architecture ?? '',
  ].join(' ');

  return SOFTWARE_RENDERER_PATTERNS.some(p => p.test(desc));
}

/* ─── Compute shader ─────────────────────────────────────────────────────── */

// A compute workload that is trivially parallelisable but forces the GPU to
// actually execute — matrix-multiply on 64 × 64 tiles across 256 workgroups.
// Light enough that it doesn't block UI; heavy enough to generate thermal signal.
const SHADER_SRC = /* wgsl */ `
  struct Matrix {
    values: array<f32, 4096>,  // 64x64
  };

  @group(0) @binding(0) var<storage, read>       matA : Matrix;
  @group(0) @binding(1) var<storage, read>       matB : Matrix;
  @group(0) @binding(2) var<storage, read_write> matC : Matrix;

  @compute @workgroup_size(8, 8)
  fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x;
    let col = gid.y;
    if (row >= 64u || col >= 64u) { return; }

    var acc: f32 = 0.0;
    for (var k = 0u; k < 64u; k++) {
      acc += matA.values[row * 64u + k] * matB.values[k * 64u + col];
    }
    matC.values[row * 64u + col] = acc;
  }
`;

/* ─── collectGpuEntropy ─────────────────────────────────────────────────── */

/**
 * @param {object}  [opts]
 * @param {number}  [opts.iterations=60]      – dispatch rounds per phase
 * @param {boolean} [opts.phased=true]         – cold / load / hot phases
 * @param {number}  [opts.timeoutMs=8000]      – hard abort if GPU stalls
 * @returns {Promise<GpuEntropyResult>}
 */
export async function collectGpuEntropy(opts = {}) {
  const { iterations = 60, phased = true, timeoutMs = 8000 } = opts;

  if (!isWebGPUAvailable()) {
    return _noGpu('WebGPU not available in this environment');
  }

  let adapter, device;
  try {
    adapter = await Promise.race([
      navigator.gpu.requestAdapter({ powerPreference: 'high-performance' }),
      _timeout(timeoutMs, 'requestAdapter timed out'),
    ]);
    if (!adapter) return _noGpu('No WebGPU adapter found');

    device = await Promise.race([
      adapter.requestDevice(),
      _timeout(timeoutMs, 'requestDevice timed out'),
    ]);
  } catch (err) {
    return _noGpu(`WebGPU init failed: ${err.message}`);
  }

  const adapterInfo = adapter.info ?? {};
  const isSoftware  = detectSoftwareRenderer(adapterInfo);

  device.lost.then(info => console.warn('[pulse] GPU device lost:', info.message));

  // Compile the shader module once
  const shaderModule = device.createShaderModule({ code: SHADER_SRC });

  // Create persistent GPU buffers (64×64 float32 = 16 KB each)
  const bufSize = 4096 * 4; // 4096 floats × 4 bytes
  const bufA = _createBuffer(device, bufSize, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST);
  const bufB = _createBuffer(device, bufSize, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST);
  const bufC = _createBuffer(device, bufSize, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC);

  try {
    // Seed with random data
    const matData = new Float32Array(4096).map(() => Math.random());
    device.queue.writeBuffer(bufA, 0, matData);
    device.queue.writeBuffer(bufB, 0, matData);

    const pipeline = device.createComputePipeline({
      layout: 'auto',
      compute: { module: shaderModule, entryPoint: 'main' },
    });

    const bindGroup = device.createBindGroup({
      layout: pipeline.getBindGroupLayout(0),
      entries: [
        { binding: 0, resource: { buffer: bufA } },
        { binding: 1, resource: { buffer: bufB } },
        { binding: 2, resource: { buffer: bufC } },
      ],
    });

    // ── Probe ──────────────────────────────────────────────────────────────
    async function runPhase(n) {
      const timings = [];
      for (let i = 0; i < n; i++) {
        const t0 = performance.now();
        const encoder = device.createCommandEncoder();
        const pass    = encoder.beginComputePass();
        pass.setPipeline(pipeline);
        pass.setBindGroup(0, bindGroup);
        pass.dispatchWorkgroups(8, 8); // 64 workgroups total
        pass.end();
        device.queue.submit([encoder.finish()]);
        await device.queue.onSubmittedWorkDone();
        const t1 = performance.now();
        timings.push(t1 - t0);
      }
      return timings;
    }

    let coldTimings, loadTimings, hotTimings;

    if (phased) {
      coldTimings = await runPhase(Math.floor(iterations * 0.25));
      loadTimings = await runPhase(Math.floor(iterations * 0.50));
      hotTimings  = await runPhase(iterations - coldTimings.length - loadTimings.length);
    } else {
      coldTimings = await runPhase(iterations);
      loadTimings = [];
      hotTimings  = [];
    }

    const allTimings = [...coldTimings, ...loadTimings, ...hotTimings];
    const mean       = _mean(allTimings);
    const cv         = mean > 0 ? _std(allTimings) / mean : 0;

    const coldMean = _mean(coldTimings);
    const hotMean  = _mean(hotTimings.length ? hotTimings : coldTimings);
    const thermalGrowth = coldMean > 0 ? (hotMean - coldMean) / coldMean : 0;

    return {
      gpuPresent:    true,
      isSoftware,
      vendor:        adapterInfo.vendor      ?? 'unknown',
      architecture:  adapterInfo.architecture ?? 'unknown',
      timings:       allTimings,
      dispatchCV:    cv,
      thermalGrowth,
      coldMean,
      hotMean,
      // Heuristic: real GPU → thermalGrowth > 0.02 and CV > 0.04
      // Software renderer → thermalGrowth ≈ 0, CV < 0.02
      verdict: isSoftware ? 'software_renderer'
        : thermalGrowth > 0.02 && cv > 0.04 ? 'real_gpu'
        : thermalGrowth < 0 && cv < 0.02   ? 'virtual_gpu'
        : 'ambiguous',
    };
  } finally {
    bufA.destroy(); bufB.destroy(); bufC.destroy();
    device.destroy();
  }
}

/* ─── helpers ────────────────────────────────────────────────────────────── */

function _noGpu(reason) {
  return { gpuPresent: false, isSoftware: false, vendor: null,
           architecture: null, timings: [], dispatchCV: 0,
           thermalGrowth: 0, coldMean: 0, hotMean: 0,
           verdict: 'no_gpu', reason };
}

function _createBuffer(device, size, usage) {
  return device.createBuffer({ size, usage });
}

function _mean(arr) {
  return arr.length ? arr.reduce((s, v) => s + v, 0) / arr.length : 0;
}

function _std(arr) {
  const m = _mean(arr);
  return Math.sqrt(arr.reduce((s, v) => s + (v - m) ** 2, 0) / arr.length);
}

function _timeout(ms, msg) {
  return new Promise((_, reject) => setTimeout(() => reject(new Error(msg)), ms));
}

/**
 * @typedef {object} GpuEntropyResult
 * @property {boolean}  gpuPresent
 * @property {boolean}  isSoftware
 * @property {string|null} vendor
 * @property {string|null} architecture
 * @property {number[]}  timings
 * @property {number}    dispatchCV
 * @property {number}    thermalGrowth
 * @property {string}    verdict   'real_gpu' | 'virtual_gpu' | 'software_renderer' | 'no_gpu' | 'ambiguous'
 */

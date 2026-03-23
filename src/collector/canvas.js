/**
 * @sovereign/pulse — GPU Canvas Fingerprint
 *
 * Collects device-class signals from WebGL and 2D Canvas rendering.
 * The exact pixel values of GPU-rendered scenes are vendor/driver-specific
 * due to floating-point rounding in shader execution.  Virtual machines
 * expose software renderers (LLVMpipe, SwiftShader, Microsoft Basic Render
 * Driver) whose strings and output pixels are well-known and enumerable.
 *
 * NO persistent identifier is generated – only a content hash is retained.
 */

import { blake3Hex } from '../proof/fingerprint.js';

// ---------------------------------------------------------------------------
// Known software-renderer substrings (VM / headless environment indicators)
// ---------------------------------------------------------------------------
const SOFTWARE_RENDERER_PATTERNS = [
  'llvmpipe', 'swiftshader', 'softpipe', 'mesa offscreen',
  'microsoft basic render', 'vmware svga', 'virtualbox',
  'parallels', 'angle (', 'google swiftshader',
];

// ---------------------------------------------------------------------------
// collectCanvasFingerprint
// ---------------------------------------------------------------------------

/**
 * @returns {Promise<CanvasFingerprint>}
 */
export async function collectCanvasFingerprint() {
  const result = {
    webglRenderer:      null,
    webglVendor:        null,
    webglVersion:       null,
    webglPixelHash:     null,
    canvas2dHash:       null,
    extensionCount:     0,
    extensions:         [],
    isSoftwareRenderer: false,
    available:          false,
  };

  if (typeof document === 'undefined' && typeof OffscreenCanvas === 'undefined') {
    // Node.js / server-side with no DOM – skip gracefully.
    return result;
  }

  // ── WebGL fingerprint ────────────────────────────────────────────────────
  try {
    const canvas = _createCanvas(512, 512);
    let   gl     = canvas.getContext('webgl2') || canvas.getContext('webgl');

    if (gl) {
      result.webglVersion = gl instanceof WebGL2RenderingContext ? 2 : 1;
      result.available    = true;

      // Renderer info
      const dbgInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (dbgInfo) {
        result.webglRenderer = gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL);
        result.webglVendor   = gl.getParameter(dbgInfo.UNMASKED_VENDOR_WEBGL);
      }

      // Extension list (fingerprints driver capabilities)
      const exts = gl.getSupportedExtensions() ?? [];
      result.extensions    = exts;
      result.extensionCount = exts.length;

      // Software-renderer detection
      const rendererLc = (result.webglRenderer ?? '').toLowerCase();
      result.isSoftwareRenderer = SOFTWARE_RENDERER_PATTERNS.some(p =>
        rendererLc.includes(p)
      );

      // ── Render a Mandelbrot fragment scene ───────────────────────────────
      // Floating-point precision differences in the GPU's shader ALU cause
      // per-pixel rounding variations that are stable per device but differ
      // across GPU vendors, driver versions, and software renderers.
      const pixels = _renderMandelbrot(gl, canvas);
      result.webglPixelHash = pixels ? blake3Hex(pixels) : null;

      gl.getExtension('WEBGL_lose_context')?.loseContext();
    }
  } catch (_) {
    // WebGL blocked (privacy settings, etc.) – continue with 2D canvas.
  }

  // ── 2D Canvas fingerprint ────────────────────────────────────────────────
  try {
    const c2   = _createCanvas(200, 50);
    const ctx2 = c2.getContext('2d');

    if (ctx2) {
      // Text rendering differences: font hinting, subpixel AA, emoji rasterisation
      ctx2.textBaseline = 'top';
      ctx2.font         = '14px Arial, sans-serif';
      ctx2.fillStyle    = 'rgba(102,204,0,0.7)';
      ctx2.fillText('Cwm fjordbank glyphs vext quiz 🎯', 2, 5);

      // Shadow compositing (driver-specific blur kernel)
      ctx2.shadowBlur   = 10;
      ctx2.shadowColor  = 'blue';
      ctx2.fillStyle    = 'rgba(255,0,255,0.5)';
      ctx2.fillRect(100, 25, 80, 20);

      // Bezier curve (Bézier precision varies per 2D canvas implementation)
      ctx2.beginPath();
      ctx2.moveTo(10, 40);
      ctx2.bezierCurveTo(30, 0, 70, 80, 160, 30);
      ctx2.strokeStyle = 'rgba(0,0,255,0.8)';
      ctx2.lineWidth   = 1.5;
      ctx2.stroke();

      const dataUrl = c2.toDataURL('image/png');
      // Hash the data URL (not storing raw image data)
      const enc = new TextEncoder().encode(dataUrl);
      result.canvas2dHash = blake3Hex(enc);

      result.available = true;
    }
  } catch (_) {
    // 2D canvas blocked.
  }

  return result;
}

/**
 * @typedef {object} CanvasFingerprint
 * @property {string|null}  webglRenderer
 * @property {string|null}  webglVendor
 * @property {1|2|null}     webglVersion
 * @property {string|null}  webglPixelHash
 * @property {string|null}  canvas2dHash
 * @property {number}       extensionCount
 * @property {string[]}     extensions
 * @property {boolean}      isSoftwareRenderer
 * @property {boolean}      available
 */

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _createCanvas(w, h) {
  if (typeof OffscreenCanvas !== 'undefined') {
    return new OffscreenCanvas(w, h);
  }
  const c = document.createElement('canvas');
  c.width  = w;
  c.height = h;
  return c;
}

/**
 * Render a Mandelbrot set fragment using WebGL and read back pixels.
 * The number of iterations is fixed (100) so that rounding differences in
 * the smooth-colouring formula are the primary source of per-GPU variation.
 *
 * @param {WebGLRenderingContext} gl
 * @param {HTMLCanvasElement|OffscreenCanvas} canvas
 * @returns {Uint8Array|null}
 */
function _renderMandelbrot(gl, canvas) {
  const W = canvas.width;
  const H = canvas.height;

  // Vertex shader – full-screen quad
  const vsSource = `
    attribute vec4 a_pos;
    void main() { gl_Position = a_pos; }
  `;

  // Fragment shader – Mandelbrot with smooth colouring
  // Floating-point precision in the escape-radius and log() calls differs
  // between GPU vendors / drivers, producing per-device pixel signatures.
  const fsSource = `
    precision highp float;
    uniform vec2 u_res;
    void main() {
      vec2 uv  = (gl_FragCoord.xy / u_res - 0.5) * 3.5;
      uv.x    -= 0.5;
      vec2 c   = uv;
      vec2 z   = vec2(0.0);
      float n  = 0.0;
      for (int i = 0; i < 100; i++) {
        if (dot(z, z) > 4.0) break;
        z = vec2(z.x*z.x - z.y*z.y, 2.0*z.x*z.y) + c;
        n += 1.0;
      }
      float smooth_n = n - log2(log2(dot(z,z))) + 4.0;
      float t = smooth_n / 100.0;
      gl_FragColor = vec4(0.5 + 0.5*cos(6.28318*t + vec3(0.0, 0.4, 0.7)), 1.0);
    }
  `;

  const vs = _compileShader(gl, gl.VERTEX_SHADER,   vsSource);
  const fs = _compileShader(gl, gl.FRAGMENT_SHADER, fsSource);
  if (!vs || !fs) return null;

  const prog = gl.createProgram();
  gl.attachShader(prog, vs);
  gl.attachShader(prog, fs);
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return null;

  gl.useProgram(prog);

  // Full-screen quad
  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER,
    new Float32Array([-1,-1, 1,-1, -1,1, 1,1]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, 'a_pos');
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

  const resLoc = gl.getUniformLocation(prog, 'u_res');
  gl.uniform2f(resLoc, W, H);

  gl.viewport(0, 0, W, H);
  gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

  // Read back a 64×64 centre crop (reduces data without losing discriminating power)
  const x0 = Math.floor((W - 64) / 2);
  const y0 = Math.floor((H - 64) / 2);
  const pixels = new Uint8Array(64 * 64 * 4);
  gl.readPixels(x0, y0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, pixels);

  return pixels;
}

function _compileShader(gl, type, source) {
  const s = gl.createShader(type);
  gl.shaderSource(s, source);
  gl.compileShader(s);
  return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
}

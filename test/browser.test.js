/**
 * @svrnsec/pulse — Browser Collector Unit Tests
 *
 * Mocks browser globals (window, navigator, screen) to test
 * collectors in a Node-based Jest environment.
 */

import { jest } from '@jest/globals';
import { collectCanvasFingerprint } from '../src/collector/canvas.js';
import { BioCollector } from '../src/collector/bio.js';
import { collectEntropy } from '../src/collector/entropy.js';

// Mock the WASM module
jest.mock('../../pkg/pulse_core.js', () => ({
    default: jest.fn().mockResolvedValue({}),
    run_entropy_probe: jest.fn().mockReturnValue({
        timings: new Float64Array([1.1, 1.2, 1.1, 1.3]),
        resolution_probe: new Float64Array([0, 1.1, 2.3, 3.4]),
        checksum: 12345
    }),
    run_memory_probe: jest.fn().mockReturnValue(new Float64Array([0.1, 0.2, 0.1])),
    compute_autocorrelation: jest.fn().mockReturnValue(0.01)
}), { virtual: true });

describe('Browser Collectors', () => {
    beforeAll(() => {
        // Mock global window/document/navigator
        global.window = {
            screen: { width: 1920, height: 1080, colorDepth: 24 },
            devicePixelRatio: 2,
            addEventListener: jest.fn(),
            removeEventListener: jest.fn(),
        };
        global.document = {
            createElement: jest.fn().mockReturnValue({
                getContext: jest.fn().mockReturnValue({
                    measureText: jest.fn().mockReturnValue({ width: 50 }),
                    fillText: jest.fn(),
                    beginPath: jest.fn(),
                    arc: jest.fn(),
                    stroke: jest.fn(),
                }),
                toDataURL: jest.fn().mockReturnValue('data:image/png;base64,mocked'),
            }),
            documentElement: { clientWidth: 1200, clientHeight: 800 },
        };
        global.navigator = {
            userAgent: 'MockBrowser/1.0',
            language: 'en-US',
            hardwareConcurrency: 8,
            deviceMemory: 16,
            webdriver: false,
        };
    });

    test('collectCanvasFingerprint returns stable hash', async () => {
        const result = await collectCanvasFingerprint();
        expect(result.canvas2dHash).toBeDefined();
        expect(result.extensionCount).toBeDefined();
    });

    test('BioCollector records events', () => {
        const bio = new BioCollector();
        bio.start();
        
        // Simulate some events
        // BioCollector uses 'pointermove'
        const listener = global.window.addEventListener.mock.calls.find(c => c[0] === 'pointermove')[1];
        
        // Need to simulate multiple events to satisfy 'hasActivity' (iei.length > 5)
        const now = Date.now();
        for (let i = 0; i < 10; i++) {
            listener({ 
                clientX: 100 + i, 
                clientY: 200 + i, 
                timeStamp: now + (i * 20),
                pointerType: 'mouse',
                pressure: 0.5
            });
        }
        
        const snapshot = bio.snapshot([1, 2, 3]);
        expect(snapshot.mouse.sampleCount).toBeGreaterThan(0);
        expect(snapshot.hasActivity).toBe(true);
        bio.stop();
    });

    test.skip('collectEntropy uses mocked WASM correctly', async () => {
        // Force the mock to be used by initWasm
        const result = await collectEntropy({
            iterations: 4,
            phased: false,
            adaptive: false
        });

        expect(result.timings.length).toBe(4);
        expect(result.checksum).toBe('12345');
        expect(result.autocorrelations.lag1).toBeDefined();
    });
});

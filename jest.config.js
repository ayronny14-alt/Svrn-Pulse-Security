export default {
  testEnvironment:     'node',
  transform:           {},           // native ESM — no transpilation needed
  testMatch:           ['**/test/**/*.test.js'],
  // Suppress the WASM import in tests (collector/entropy.js is tested via integration)
  moduleNameMapper: {
    '../../pkg/pulse_core.js': '<rootDir>/test/__mocks__/pulse_core.js',
  },
  collectCoverage:     true,
  coverageDirectory:   'coverage',
  coverageReporters:   ['text', 'lcov'],
  coverageThreshold: {
    global: {
      statements: 60,
      branches:   50,
      functions:  55,
      lines:      60,
    },
  },
};

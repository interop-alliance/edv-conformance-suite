import { defineConfig } from 'vitest/config'

/**
 * Vitest config for the suite's own unit tests (helpers, codecs). The
 * conformance suites in `src/suites/` are excluded here -- they need a live
 * EDV server and run via the CLI or `vitest.conformance.config.ts`.
 */
export default defineConfig({
  test: {
    include: ['test/node/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/suites/**']
    }
  }
})

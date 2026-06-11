import { defineConfig } from 'vitest/config'

/**
 * Vitest config for running the conformance suites from source against a
 * live EDV server (dev mode):
 *
 *   EDV_CONFORMANCE_TARGET=https://localhost:18443 pnpm run conformance
 *
 * Published-package runs go through the CLI (`npx edv-conformance`), which
 * builds an equivalent inline config over `dist/suites/`.
 */
export default defineConfig({
  test: {
    include: ['src/suites/**/*.test.ts'],
    // conformance suites talk to a real server; allow slow operations
    testTimeout: 60_000,
    hookTimeout: 60_000
  }
})

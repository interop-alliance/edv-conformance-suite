/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite configuration for a locally running @interop/edv-server (the
 * fastify/filesystem implementation). The server uses the default plain
 * zcap-signed `POST /edvs` provisioning, returns bedrock-style
 * `{name: 'DuplicateError', ...}` error bodies, and (like bedrock) applies
 * a 10 MB write body limit rather than enforcing the 1 MiB chunk maximum.
 *
 * Usage:
 *   EDV_CONFORMANCE_TARGET=http://localhost:5000 \
 *   EDV_CONFORMANCE_CONFIG=$(pwd)/configs/edv-server.config.ts \
 *   pnpm run conformance
 */
import type { SuiteConfig } from '../src/index.js'

const config: SuiteConfig = {
  baseUrl: 'http://localhost:5000',
  edvsPath: '/edvs',
  features: {
    referenceId: true,
    chunks: true,
    revocation: true,
    strictErrorNames: true,
    enforcesChunkLimit: false
  },
  tls: {}
}

export default config

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Example suite configuration for a plain EDV server using the default
 * provisioning hook (a zcap-signed `POST /edvs` invoking the root zcap of
 * the vault collection endpoint).
 *
 * Usage:
 *   npx edv-conformance --target https://edv.example --config example.config.ts
 *
 * In an external project, import from '@interop/edv-conformance-suite'
 * instead of the relative path used here.
 */
import type { SuiteConfig } from '../src/index.js'

const config: SuiteConfig = {
  // overridden by --target / EDV_CONFORMANCE_TARGET when provided
  baseUrl: 'https://edv.example',
  edvsPath: '/edvs',
  features: {
    referenceId: true,
    chunks: true,
    revocation: true,
    // the EDV spec does not define error bodies; enable to assert
    // {name: 'DuplicateError'}-style bodies
    strictErrorNames: false,
    // enable for servers that enforce the 1 MiB chunk limit
    enforcesChunkLimit: false
  },
  // for dev servers with self-signed certificates:
  // tls: { rejectUnauthorized: false }
  tls: {}
}

export default config

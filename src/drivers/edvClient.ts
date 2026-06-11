/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * The edv-client driver: builds an `@interop/edv-client` `EdvClient` over the
 * suite's local key material. Happy paths, real JWE encryption, HMAC-blinded
 * index building, and zcap invocation all come from the client library.
 */
import https from 'node:https'
import { EdvClient } from '@interop/edv-client'
import { keyResolver } from './keys.js'
import type { TestKit } from './keys.js'
import type { ISigner } from '@interop/data-integrity-core'
import type { ResolvedSuiteConfig } from '../config.js'

const agentCache = new WeakMap<object, https.Agent>()

/**
 * Returns an `https.Agent` honoring the suite's TLS settings, or undefined
 * when default TLS verification applies. Cached per suite config.
 *
 * @param options {object}
 * @param options.suite {ResolvedSuiteConfig}
 *
 * @returns {https.Agent|undefined}
 */
export function getHttpsAgent({
  suite
}: {
  suite: ResolvedSuiteConfig
}): https.Agent | undefined {
  if (suite.tls.rejectUnauthorized) {
    return undefined
  }
  let agent = agentCache.get(suite)
  if (!agent) {
    agent = new https.Agent({ rejectUnauthorized: false })
    agentCache.set(suite, agent)
  }
  return agent
}

/**
 * Builds an EdvClient bound to a vault and a key kit.
 *
 * @param options {object}
 * @param options.suite {ResolvedSuiteConfig}
 * @param options.id {string} - The vault id (URL).
 * @param options.kit {TestKit} - Key material (kak, hmac, signer).
 * @param [options.invocationSigner] {ISigner} - Overrides the kit's signer.
 * @param [options.capability] {object|string} - A delegated zcap to use for
 *   all client operations (delegation tests).
 *
 * @returns {EdvClient}
 */
export function buildEdvClient({
  suite,
  id,
  kit,
  invocationSigner,
  capability
}: {
  suite: ResolvedSuiteConfig
  id?: string
  kit: TestKit
  invocationSigner?: ISigner
  capability?: object | string
}): EdvClient {
  return new EdvClient({
    id,
    capability,
    keyAgreementKey: kit.keyAgreementKey,
    hmac: kit.hmac,
    invocationSigner: invocationSigner ?? kit.invocationSigner,
    keyResolver,
    httpsAgent: getHttpsAgent({ suite })
  })
}

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Public API surface for implementer configs: the SuiteConfig types, the
 * default provisioning hook (so custom hooks can wrap it), and the building
 * blocks custom hooks receive. The conformance suites themselves live in
 * `suites/` and are run via the `edv-conformance` CLI or vitest.
 */
export { loadSuiteConfig } from './config.js'
export type {
  ProvisionVaultFn,
  ResolvedSuiteConfig,
  SuiteConfig,
  SuiteFeatures
} from './config.js'
export { defaultProvisionVault, ProvisioningError } from './provisioning.js'
export { createRawRequest } from './drivers/rawHttp.js'
export type {
  RawRequestFn,
  RawRequestOptions,
  RawResponse
} from './drivers/rawHttp.js'
export {
  createCapabilityAgent,
  createTestKit,
  documentLoader,
  keyResolver,
  LocalHmac
} from './drivers/keys.js'
export type { AgentKit, CapabilityAgent, TestKit } from './drivers/keys.js'
export { buildEdvClient, getHttpsAgent } from './drivers/edvClient.js'
export {
  decodeLocalId,
  encodeLocalId,
  generateLocalId,
  isValidLocalId
} from './helpers/ids.js'
export { delegate, rootZcapUrn } from './helpers/zcaps.js'
export { draftVaultConfig, freshVault } from './helpers/vault.js'
export type { VaultContext } from './helpers/vault.js'

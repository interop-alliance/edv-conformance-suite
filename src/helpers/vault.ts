/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Vault provisioning for the suites: `freshVault()` generates per-run key
 * material, provisions a vault through the configured (or default)
 * provisioning hook, and returns the bundle of handles tests compose --
 * the EdvClient, the raw-request function, the root zcap, and URLs.
 *
 * EDV has no vault-delete endpoint, so isolation comes from fresh
 * capability agents (and so fresh controllers/referenceIds) per run; run
 * the suite against an ephemeral or dev instance.
 */
import { buildEdvClient } from '../drivers/edvClient.js'
import { createRawRequest } from '../drivers/rawHttp.js'
import { createTestKit } from '../drivers/keys.js'
import { defaultProvisionVault } from '../provisioning.js'
import { rootZcapUrn } from './zcaps.js'
import type { EdvClient } from '@interop/edv-client'
import type { IEDVConfig, ISigner } from '@interop/data-integrity-core'
import type { RawRequestFn } from '../drivers/rawHttp.js'
import type { ResolvedSuiteConfig } from '../config.js'
import type { TestKit } from '../drivers/keys.js'

export interface VaultContext {
  /** The server-returned vault configuration. */
  config: IEDVConfig
  /** The vault id (an absolute URL). */
  vaultUrl: string
  /** `vaultUrl + '/documents'`. */
  documentsUrl: string
  /** The root zcap id for this vault. */
  rootZcap: string
  client: EdvClient
  kit: TestKit
  invocationSigner: ISigner
  rawRequest: RawRequestFn
}

/**
 * Builds the draft config for a new vault (the `POST /edvs` body).
 *
 * @param options {object}
 * @param options.suite {ResolvedSuiteConfig}
 * @param options.kit {TestKit}
 * @param [options.referenceId] {string}
 *
 * @returns {IEDVConfig}
 */
export function draftVaultConfig({
  suite,
  kit,
  referenceId
}: {
  suite: ResolvedSuiteConfig
  kit: TestKit
  referenceId?: string
}): IEDVConfig {
  const config: IEDVConfig = {
    sequence: 0,
    controller: kit.agent.id,
    keyAgreementKey: {
      id: kit.keyAgreementKey.id as string,
      type: kit.keyAgreementKey.type as string
    },
    hmac: { id: kit.hmac.id, type: kit.hmac.type },
    ...suite.extraVaultConfig
  }
  if (referenceId) {
    config.referenceId = referenceId
  }
  return config
}

/**
 * Provisions a fresh vault with fresh key material.
 *
 * @param options {object}
 * @param options.suite {ResolvedSuiteConfig}
 * @param [options.kit] {TestKit} - Reuse existing key material (e.g. to
 *   create a second vault for the same controller).
 * @param [options.referenceId] {string}
 *
 * @returns {Promise<VaultContext>}
 */
export async function freshVault({
  suite,
  kit,
  referenceId
}: {
  suite: ResolvedSuiteConfig
  kit?: TestKit
  referenceId?: string
}): Promise<VaultContext> {
  const vaultKit = kit ?? (await createTestKit())
  const rawRequest = createRawRequest({ tls: suite.tls })
  const draft = draftVaultConfig({ suite, kit: vaultKit, referenceId })
  const provision = suite.provisionVault ?? defaultProvisionVault
  const config = await provision({
    baseUrl: suite.baseUrl,
    edvsUrl: suite.edvsUrl,
    config: draft,
    invocationSigner: vaultKit.invocationSigner,
    rawRequest
  })
  const vaultUrl = config.id as string
  const client = buildEdvClient({ suite, id: vaultUrl, kit: vaultKit })
  return {
    config,
    vaultUrl,
    documentsUrl: `${vaultUrl}/documents`,
    rootZcap: rootZcapUrn({ url: vaultUrl }),
    client,
    kit: vaultKit,
    invocationSigner: vaultKit.invocationSigner,
    rawRequest
  }
}

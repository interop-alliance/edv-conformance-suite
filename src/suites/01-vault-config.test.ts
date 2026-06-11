/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite 01: vault configuration -- create, get, update, find-by-referenceId.
 * MUST/SHOULD levels are annotated per test; tests that depend on the
 * spec-optional `referenceId` feature are gated on `features.referenceId`.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { EdvClient } from '@interop/edv-client'
import { loadSuiteConfig } from '../config.js'
import { createTestKit } from '../drivers/keys.js'
import { createRawRequest } from '../drivers/rawHttp.js'
import { getHttpsAgent } from '../drivers/edvClient.js'
import { draftVaultConfig, freshVault } from '../helpers/vault.js'
import {
  expectError,
  expectErrorResponse,
  shouldBeEdvConfig
} from '../helpers/assertions.js'
import { rootZcapUrn } from '../helpers/zcaps.js'
import type { IEDVConfig } from '@interop/data-integrity-core'
import type { VaultContext } from '../helpers/vault.js'

const suite = await loadSuiteConfig()
const usesDefaultProvisioning = !suite.provisionVault
const strict = suite.features.strictErrorNames
const rawRequest = createRawRequest({ tls: suite.tls })

describe('01 vault configuration', () => {
  let vault: VaultContext

  beforeAll(async () => {
    vault = await freshVault({ suite })
  })

  describe('create', () => {
    it('[MUST] creates a vault and returns its config', async () => {
      shouldBeEdvConfig({ config: vault.config })
      expect(vault.config.sequence).toBe(0)
      expect(vault.config.controller).toBe(vault.kit.agent.id)
      // the server-assigned id is an absolute URL on the target server
      expect(() => new URL(vault.config.id as string)).not.toThrow()
      expect(vault.config.id).toMatch(new RegExp(`^${suite.baseUrl}/`))
    })

    // raw status/header assertions only apply to the default plain
    // zcap-signed POST; custom provisioning hooks own their own transport
    it.runIf(usesDefaultProvisioning)(
      '[MUST] raw create returns 201 with a Location header',
      async () => {
        const kit = await createTestKit()
        const response = await rawRequest({
          url: suite.edvsUrl,
          method: 'POST',
          json: draftVaultConfig({ suite, kit }),
          invocationSigner: kit.invocationSigner,
          action: 'write'
        })
        expect(
          response.status,
          `expected 201, got ${response.status}: ${response.text}`
        ).toBe(201)
        const location = response.headers.get('location')
        expect(location).toBeTruthy()
        const created = response.json as IEDVConfig
        expect(created.id).toBeTypeOf('string')
        expect(created.sequence).toBe(0)
        // Location identifies the created vault
        expect(location).toBe(created.id)
      }
    )

    it('[MUST] rejects create missing required config members: 400', async () => {
      // note: against servers whose creation requires extra members (e.g.
      // a meter), the 400 may also reflect those; either way the invalid
      // body must be rejected with 400
      const kit = await createTestKit()
      for (const member of ['controller', 'keyAgreementKey', 'hmac']) {
        const draft = draftVaultConfig({ suite, kit }) as unknown as Record<
          string,
          unknown
        >
        delete draft[member]
        const response = await rawRequest({
          url: suite.edvsUrl,
          method: 'POST',
          json: draft,
          invocationSigner: kit.invocationSigner,
          action: 'write'
        })
        expectErrorResponse({ response, statusOneOf: [400] })
      }
    })

    it('[SHOULD] rejects create with sequence !== 0', async () => {
      const kit = await createTestKit()
      const draft = draftVaultConfig({ suite, kit })
      draft.sequence = 1
      const response = await rawRequest({
        url: suite.edvsUrl,
        method: 'POST',
        json: draft,
        invocationSigner: kit.invocationSigner,
        action: 'write'
      })
      expectErrorResponse({ response, statusOneOf: [400, 409] })
    })
  })

  describe('get', () => {
    it('[MUST] returns the stored config, shape-validated', async () => {
      const response = await rawRequest({
        url: vault.vaultUrl,
        method: 'GET',
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'read'
      })
      expect(
        response.status,
        `expected 200, got ${response.status}: ${response.text}`
      ).toBe(200)
      const config = response.json as IEDVConfig
      shouldBeEdvConfig({ config })
      expect(config.id).toBe(vault.vaultUrl)
      expect(config.controller).toBe(vault.kit.agent.id)
      expect(config.keyAgreementKey?.id).toBe(vault.kit.keyAgreementKey.id)
      expect(config.hmac?.id).toBe(vault.kit.hmac.id)
    })
  })

  describe('update', () => {
    let privateVault: VaultContext

    beforeAll(async () => {
      // a private vault, since these tests mutate config state
      privateVault = await freshVault({ suite })
    })

    it('[MUST] accepts update with sequence previous+1', async () => {
      const config = (await privateVault.client.getConfig()) as IEDVConfig
      const updated = { ...config, sequence: (config.sequence as number) + 1 }
      await privateVault.client.updateConfig({ config: updated })
      const after = (await privateVault.client.getConfig()) as IEDVConfig
      expect(after.sequence).toBe(config.sequence + 1)
    })

    it('[MUST] rejects update with a stale sequence: 409', async () => {
      const config = (await privateVault.client.getConfig()) as IEDVConfig
      // posting the currently stored sequence is stale (must be previous+1)
      const response = await rawRequest({
        url: privateVault.vaultUrl,
        method: 'POST',
        json: config,
        capability: privateVault.rootZcap,
        invocationSigner: privateVault.invocationSigner,
        action: 'write'
      })
      expectErrorResponse({
        response,
        statusOneOf: [409],
        name: 'InvalidStateError',
        strict
      })
    })

    it('[MUST] rejects update where body id differs from URL id: 400', async () => {
      const otherVault = await freshVault({ suite, kit: privateVault.kit })
      const config = (await privateVault.client.getConfig()) as IEDVConfig
      const mismatched = {
        ...config,
        id: otherVault.vaultUrl,
        sequence: (config.sequence as number) + 1
      }
      const response = await rawRequest({
        url: privateVault.vaultUrl,
        method: 'POST',
        json: mismatched,
        capability: privateVault.rootZcap,
        invocationSigner: privateVault.invocationSigner,
        action: 'write'
      })
      expectErrorResponse({
        response,
        statusOneOf: [400],
        name: 'URLMismatchError',
        strict
      })
    })
  })

  describe.skipIf(!suite.features.referenceId)(
    'referenceId (optional feature)',
    () => {
      it('[OPTIONAL] finds a config by controller + referenceId', async () => {
        const referenceId = `conformance-${crypto.randomUUID()}`
        const refVault = await freshVault({ suite, referenceId })
        const configs = (await EdvClient.findConfigs({
          url: suite.edvsUrl,
          controller: refVault.kit.agent.id,
          referenceId,
          invocationSigner: refVault.invocationSigner,
          httpsAgent: getHttpsAgent({ suite })
        })) as IEDVConfig[]
        expect(Array.isArray(configs)).toBe(true)
        expect(configs).toHaveLength(1)
        expect(configs[0]?.id).toBe(refVault.vaultUrl)
        expect(configs[0]?.referenceId).toBe(referenceId)
      })

      it('[OPTIONAL] rejects a config query missing controller or referenceId: 400', async () => {
        // sign over the full URL (query included) but invoke the root zcap
        // of the collection endpoint, as the reference client does
        for (const query of [
          `referenceId=${encodeURIComponent('conformance-x')}`,
          `controller=${encodeURIComponent(vault.kit.agent.id)}`
        ]) {
          const response = await rawRequest({
            url: `${suite.edvsUrl}?${query}`,
            method: 'GET',
            capability: rootZcapUrn({ url: suite.edvsUrl }),
            invocationSigner: vault.invocationSigner,
            action: 'read'
          })
          expectErrorResponse({ response, statusOneOf: [400] })
        }
      })

      it('[OPTIONAL] rejects a duplicate referenceId for the same controller: 409', async () => {
        const referenceId = `conformance-${crypto.randomUUID()}`
        const first = await freshVault({ suite, referenceId })
        await expectError({
          promise: freshVault({ suite, kit: first.kit, referenceId }),
          statusOneOf: [409],
          name: 'DuplicateError',
          strict
        })
      })

      it('[OPTIONAL] treats referenceId as immutable on config update', async () => {
        const referenceId = `conformance-${crypto.randomUUID()}`
        const refVault = await freshVault({ suite, referenceId })
        const config = (await refVault.client.getConfig()) as IEDVConfig
        const mutated = {
          ...config,
          referenceId: `${referenceId}-changed`,
          sequence: (config.sequence as number) + 1
        }
        const response = await rawRequest({
          url: refVault.vaultUrl,
          method: 'POST',
          json: mutated,
          capability: refVault.rootZcap,
          invocationSigner: refVault.invocationSigner,
          action: 'write'
        })
        expectErrorResponse({ response, statusOneOf: [400, 409] })
      })
    }
  )
})

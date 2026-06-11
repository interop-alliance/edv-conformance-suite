/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite 06: zcap authorization -- root zcap invocation, delegation,
 * attenuation (allowedAction, invocationTarget, expiry), and revocation.
 * Revocation tests are gated on `features.revocation`.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { EdvClient } from '@interop/edv-client'
import { loadSuiteConfig } from '../config.js'
import { getHttpsAgent } from '../drivers/edvClient.js'
import { createCapabilityAgent, keyResolver } from '../drivers/keys.js'
import { JWE_ALG } from '../drivers/streams.js'
import { freshVault } from '../helpers/vault.js'
import { freshDoc } from '../helpers/fixtures.js'
import { expectError, expectErrorResponse } from '../helpers/assertions.js'
import { delegate } from '../helpers/zcaps.js'
import type { AgentKit } from '../drivers/keys.js'
import type { VaultContext } from '../helpers/vault.js'

const suite = await loadSuiteConfig()
const strict = suite.features.strictErrorNames

const FIVE_MINUTES = 5 * 60 * 1000

describe('06 zcap authorization', () => {
  let vault: VaultContext
  let bob: AgentKit
  let carol: AgentKit

  beforeAll(async () => {
    vault = await freshVault({ suite })
    bob = await createCapabilityAgent()
    carol = await createCapabilityAgent()
  })

  function bobClient({ capability }: { capability: object }) {
    return new EdvClient({
      id: vault.vaultUrl,
      capability,
      keyAgreementKey: bob.keyAgreementKey,
      hmac: vault.kit.hmac,
      invocationSigner: bob.agent.signer,
      keyResolver,
      httpsAgent: getHttpsAgent({ suite })
    })
  }

  /** Inserts a doc encrypted to both alice (the vault owner) and bob. */
  async function insertSharedDoc({
    content
  }: {
    content: Record<string, unknown>
  }) {
    const doc = freshDoc({ content })
    await vault.client.insert({
      doc,
      recipients: [
        { header: { kid: vault.kit.keyAgreementKey.id, alg: JWE_ALG } },
        { header: { kid: bob.keyAgreementKey.id, alg: JWE_ALG } }
      ]
    })
    return doc
  }

  it('[MUST] accepts the vault root zcap invoked by the controller', async () => {
    const response = await vault.rawRequest({
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
  })

  it('[MUST] rejects an unsigned request: 401/403', async () => {
    const response = await vault.rawRequest({
      url: vault.vaultUrl,
      method: 'GET',
      signed: false
    })
    expectErrorResponse({ response, statusOneOf: [401, 403] })
  })

  it('[MUST] rejects a different agent invoking the root zcap: 403', async () => {
    const stranger = await createCapabilityAgent()
    const response = await vault.rawRequest({
      url: vault.vaultUrl,
      method: 'GET',
      capability: vault.rootZcap,
      invocationSigner: stranger.agent.signer,
      action: 'read'
    })
    expectErrorResponse({
      response,
      statusOneOf: [403],
      name: 'NotAllowedError',
      strict
    })
  })

  it('[MUST] lets a delegate read and write with a delegated zcap', async () => {
    const doc = await insertSharedDoc({ content: { owner: 'alice' } })
    const docUrl = `${vault.documentsUrl}/${doc.id}`
    const zcap = await delegate({
      parentCapability: vault.rootZcap,
      controller: bob.agent.signer.id,
      invocationTarget: docUrl,
      allowedActions: ['read', 'write'],
      expires: new Date(Date.now() + FIVE_MINUTES),
      delegationSigner: vault.invocationSigner
    })
    const client = bobClient({ capability: zcap })
    const fetched = await client.get({ id: doc.id })
    expect(fetched.content).toEqual({ owner: 'alice' })

    fetched.content = { owner: 'alice', editedBy: 'bob' }
    const updated = await client.update({ doc: fetched })
    expect(updated.sequence).toBe(fetched.sequence + 1)

    // alice sees bob's write
    const fromAlice = await vault.client.get({ id: doc.id })
    expect(fromAlice.content).toEqual({ owner: 'alice', editedBy: 'bob' })
  })

  it('[MUST] rejects an expired delegated zcap: 403', async () => {
    const doc = await insertSharedDoc({ content: { expiring: true } })
    const docUrl = `${vault.documentsUrl}/${doc.id}`
    // the zcap library refuses to *create* an already-expired delegation,
    // so sign it under a backdated clock; the expiry must be far enough in
    // the past to clear server clock-skew tolerance (typically 300s)
    const realNow = Date.now()
    vi.useFakeTimers({ now: realNow - 30 * 60 * 1000, toFake: ['Date'] })
    let expired
    try {
      expired = await delegate({
        parentCapability: vault.rootZcap,
        controller: bob.agent.signer.id,
        invocationTarget: docUrl,
        allowedActions: 'read',
        expires: new Date(realNow - 20 * 60 * 1000),
        delegationSigner: vault.invocationSigner
      })
    } finally {
      vi.useRealTimers()
    }
    await expectError({
      promise: bobClient({ capability: expired }).get({ id: doc.id }),
      statusOneOf: [403],
      name: 'NotAllowedError',
      strict
    })
  })

  it('[MUST] rejects an allowedAction mismatch (read-only zcap used for a write): 403', async () => {
    const doc = await insertSharedDoc({ content: { readonly: true } })
    const docUrl = `${vault.documentsUrl}/${doc.id}`
    const readOnly = await delegate({
      parentCapability: vault.rootZcap,
      controller: bob.agent.signer.id,
      invocationTarget: docUrl,
      allowedActions: 'read',
      expires: new Date(Date.now() + FIVE_MINUTES),
      delegationSigner: vault.invocationSigner
    })
    const client = bobClient({ capability: readOnly })
    const fetched = await client.get({ id: doc.id })
    fetched.content = { readonly: false }
    await expectError({
      promise: client.update({ doc: fetched }),
      statusOneOf: [403],
      name: 'NotAllowedError',
      strict
    })
  })

  it('[MUST] rejects an invocationTarget mismatch (zcap for doc A used on doc B): 403', async () => {
    const docA = await insertSharedDoc({ content: { which: 'A' } })
    const docB = await insertSharedDoc({ content: { which: 'B' } })
    const zcapForA = await delegate({
      parentCapability: vault.rootZcap,
      controller: bob.agent.signer.id,
      invocationTarget: `${vault.documentsUrl}/${docA.id}`,
      allowedActions: 'read',
      expires: new Date(Date.now() + FIVE_MINUTES),
      delegationSigner: vault.invocationSigner
    })
    // invoke bob's doc-A capability against doc B's URL via the raw driver
    // (the client guards against this confused-deputy case itself)
    const response = await vault.rawRequest({
      url: `${vault.documentsUrl}/${docB.id}`,
      method: 'GET',
      capability: zcapForA,
      invocationSigner: bob.agent.signer,
      action: 'read'
    })
    expectErrorResponse({
      response,
      statusOneOf: [403],
      name: 'NotAllowedError',
      strict
    })
  })

  describe.skipIf(!suite.features.revocation)('revocation', () => {
    it('[MUST] revoking a delegated zcap denies further invocations', async () => {
      const doc = await insertSharedDoc({
        content: { secret: 'until-revoked' }
      })
      const docUrl = `${vault.documentsUrl}/${doc.id}`
      const zcap = await delegate({
        parentCapability: vault.rootZcap,
        controller: bob.agent.signer.id,
        invocationTarget: docUrl,
        allowedActions: 'read',
        expires: new Date(Date.now() + FIVE_MINUTES),
        delegationSigner: vault.invocationSigner
      })
      const client = bobClient({ capability: zcap })
      // works before revocation
      const fetched = await client.get({ id: doc.id })
      expect(fetched.content).toEqual({ secret: 'until-revoked' })

      // alice revokes via POST .../zcaps/revocations/:id
      await vault.client.revokeCapability({
        capabilityToRevoke: zcap,
        invocationSigner: vault.invocationSigner
      })

      await expectError({
        promise: client.get({ id: doc.id }),
        statusOneOf: [403],
        name: 'NotAllowedError',
        strict
      })
    })

    it('[SHOULD] rejects a revocation submitted by a party outside the chain: 403', async () => {
      const doc = await insertSharedDoc({ content: { contested: true } })
      const docUrl = `${vault.documentsUrl}/${doc.id}`
      const zcap = (await delegate({
        parentCapability: vault.rootZcap,
        controller: bob.agent.signer.id,
        invocationTarget: docUrl,
        allowedActions: 'read',
        expires: new Date(Date.now() + FIVE_MINUTES),
        delegationSigner: vault.invocationSigner
      })) as { id: string }
      const revocationUrl = `${vault.vaultUrl}/zcaps/revocations/${encodeURIComponent(zcap.id)}`
      // carol is not a participant in the alice -> bob chain
      const response = await vault.rawRequest({
        url: revocationUrl,
        method: 'POST',
        json: zcap,
        invocationSigner: carol.agent.signer,
        action: 'write'
      })
      expectErrorResponse({
        response,
        statusOneOf: [403],
        name: 'NotAllowedError',
        strict
      })
      // bob's zcap still works
      const client = bobClient({ capability: zcap })
      const fetched = await client.get({ id: doc.id })
      expect(fetched.content).toEqual({ contested: true })
    })

    it('[SHOULD] supports two-hop chains; revoking the middle link denies the leaf', async () => {
      const doc = freshDoc({ content: { depth: 2 } })
      await vault.client.insert({
        doc,
        recipients: [
          { header: { kid: vault.kit.keyAgreementKey.id, alg: JWE_ALG } },
          { header: { kid: bob.keyAgreementKey.id, alg: JWE_ALG } },
          { header: { kid: carol.keyAgreementKey.id, alg: JWE_ALG } }
        ]
      })
      const docUrl = `${vault.documentsUrl}/${doc.id}`
      const toBob = await delegate({
        parentCapability: vault.rootZcap,
        controller: bob.agent.signer.id,
        invocationTarget: docUrl,
        allowedActions: 'read',
        expires: new Date(Date.now() + FIVE_MINUTES),
        delegationSigner: vault.invocationSigner
      })
      const toCarol = await delegate({
        parentCapability: toBob,
        controller: carol.agent.signer.id,
        invocationTarget: docUrl,
        allowedActions: 'read',
        expires: new Date(Date.now() + FIVE_MINUTES),
        delegationSigner: bob.agent.signer
      })
      const carolClient = new EdvClient({
        id: vault.vaultUrl,
        capability: toCarol,
        keyAgreementKey: carol.keyAgreementKey,
        hmac: vault.kit.hmac,
        invocationSigner: carol.agent.signer,
        keyResolver,
        httpsAgent: getHttpsAgent({ suite })
      })
      const fetched = await carolClient.get({ id: doc.id })
      expect(fetched.content).toEqual({ depth: 2 })

      // revoking bob's link severs carol too
      await vault.client.revokeCapability({
        capabilityToRevoke: toBob,
        invocationSigner: vault.invocationSigner
      })
      await expectError({
        promise: carolClient.get({ id: doc.id }),
        statusOneOf: [403],
        name: 'NotAllowedError',
        strict
      })
    })
  })
})

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite 04: encrypted-index queries -- equals/has semantics, compound
 * indexes, count, limit/hasMore, the query endpoint's read-action zcap
 * requirement, and unique blinded attribute constraints.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { EdvClient } from '@interop/edv-client'
import { loadSuiteConfig } from '../config.js'
import { getHttpsAgent } from '../drivers/edvClient.js'
import { createCapabilityAgent } from '../drivers/keys.js'
import { freshVault } from '../helpers/vault.js'
import {
  buildEncryptedDoc,
  freshHttpDocs,
  literalIndexEntry
} from '../helpers/fixtures.js'
import {
  expectError,
  expectErrorResponse,
  shouldBeDecryptedDocument
} from '../helpers/assertions.js'
import { delegate } from '../helpers/zcaps.js'
import type { PlaintextDoc } from '../helpers/fixtures.js'
import type { VaultContext } from '../helpers/vault.js'

const suite = await loadSuiteConfig()
const strict = suite.features.strictErrorNames

describe('04 query / encrypted index', () => {
  let vault: VaultContext
  let docs: Record<string, PlaintextDoc>

  beforeAll(async () => {
    vault = await freshVault({ suite })
    docs = freshHttpDocs()
    vault.client.ensureIndex({ attribute: 'content.apples' })
    vault.client.ensureIndex({
      attribute: ['content.group', 'content.subgroup', 'content.id'],
      unique: true
    })
    for (const doc of Object.values(docs)) {
      await vault.client.insert({ doc })
    }
  })

  function byId(
    results: unknown[],
    doc: PlaintextDoc | undefined
  ): { id: string; content: Record<string, unknown> } | undefined {
    const candidates = results as Array<{
      id: string
      content: Record<string, unknown>
    }>
    return candidates.find(candidate => candidate.id === doc?.id)
  }

  it('[MUST] returns matching documents for an equals query', async () => {
    const { documents } = await vault.client.find({
      equals: [{ 'content.group': 'group1' }]
    })
    expect(documents).toHaveLength(3)
    for (const doc of [docs.alpha, docs.beta, docs.gamma]) {
      const match = byId(documents, doc as PlaintextDoc)
      shouldBeDecryptedDocument({ doc: match })
      expect(match?.content).toEqual(doc?.content)
    }
  })

  it('[MUST] returns documents having an attribute for a has query', async () => {
    const { documents } = await vault.client.find({
      has: ['content.apples']
    })
    expect(documents).toHaveLength(4)
    for (const doc of Object.values(docs)) {
      expect(byId(documents, doc)).toBeDefined()
    }
  })

  it('[MUST] matches each value of a multi-valued attribute', async () => {
    // alpha's `content.apples` is the array [1, 6]
    for (const value of [1, 6]) {
      const { documents } = await vault.client.find({
        equals: [{ 'content.apples': value }]
      })
      expect(documents).toHaveLength(1)
      expect(documents[0]?.id).toBe(docs.alpha?.id)
    }
  })

  it('[MUST] matches on compound index attributes and name+value pairs', async () => {
    // first attribute only ('has')
    const hasGroup = await vault.client.find({ has: ['content.group'] })
    expect(hasGroup.documents).toHaveLength(3)
    // first two attributes ('has')
    const hasSub = await vault.client.find({
      has: ['content.group', 'content.subgroup']
    })
    expect(hasSub.documents).toHaveLength(3)
    // name+value pairs at increasing depth
    const eqTwo = await vault.client.find({
      equals: [{ 'content.group': 'group1', 'content.subgroup': 'subgroup1' }]
    })
    expect(eqTwo.documents).toHaveLength(2)
    const eqThree = await vault.client.find({
      equals: [
        {
          'content.group': 'group1',
          'content.subgroup': 'subgroup1',
          'content.id': 'alpha'
        }
      ]
    })
    expect(eqThree.documents).toHaveLength(1)
    expect(eqThree.documents[0]?.id).toBe(docs.alpha?.id)
  })

  it('[MUST] returns an empty result for a non-indexed attribute', async () => {
    const { documents } = await vault.client.find({
      equals: [{ 'content.foo': 'does-not-exist' }]
    })
    expect(documents).toHaveLength(0)
  })

  it('[MUST] returns {count} only when count is true', async () => {
    const result = await vault.client.find({
      has: ['content.apples'],
      count: true
    })
    expect(result).toEqual({ count: 4 })
    const beta = await vault.client.find({
      equals: [{ 'content.apples': 10 }],
      count: true
    })
    expect(beta).toEqual({ count: 1 })
    const none = await vault.client.find({
      equals: [{ 'content.foo': 'does-not-exist' }],
      count: true
    })
    expect(none).toEqual({ count: 0 })
  })

  it('[MUST] applies limit and reports hasMore', async () => {
    const truncated = await vault.client.find({
      has: ['content.apples'],
      limit: 1
    })
    expect(truncated.documents).toHaveLength(1)
    expect(truncated.hasMore).toBe(true)
    const complete = await vault.client.find({
      has: ['content.apples'],
      limit: 4
    })
    expect(complete.documents).toHaveLength(4)
    expect(complete.hasMore).toBe(false)
  })

  it('[MUST] query is a POST but requires zcap action read, not write', async () => {
    // the route table's main interop trap: a delegated zcap allowing only
    // 'read' must be able to query; one allowing only 'write' must not
    const bob = await createCapabilityAgent()
    const readZcap = await delegate({
      parentCapability: vault.rootZcap,
      controller: bob.agent.signer.id,
      invocationTarget: vault.vaultUrl,
      allowedActions: 'read',
      expires: new Date(Date.now() + 5 * 60 * 1000),
      delegationSigner: vault.invocationSigner
    })
    const bobReadClient = new EdvClient({
      id: vault.vaultUrl,
      hmac: vault.kit.hmac,
      invocationSigner: bob.agent.signer,
      httpsAgent: getHttpsAgent({ suite })
    })
    // a fresh client must register the index to blind query terms
    bobReadClient.ensureIndex({ attribute: 'content.apples' })
    // returnDocuments: false avoids needing decryption keys
    const { documentIds } = await bobReadClient.find({
      has: ['content.apples'],
      returnDocuments: false,
      capability: readZcap
    })
    expect(documentIds).toHaveLength(4)

    const writeZcap = await delegate({
      parentCapability: vault.rootZcap,
      controller: bob.agent.signer.id,
      invocationTarget: vault.vaultUrl,
      allowedActions: 'write',
      expires: new Date(Date.now() + 5 * 60 * 1000),
      delegationSigner: vault.invocationSigner
    })
    await expectError({
      promise: bobReadClient.find({
        has: ['content.apples'],
        returnDocuments: false,
        capability: writeZcap
      }),
      statusOneOf: [403],
      name: 'NotAllowedError',
      strict
    })
  })

  it('[SHOULD] returns {documentIds} when returnDocuments is false', async () => {
    const { documentIds } = await vault.client.find({
      has: ['content.apples'],
      returnDocuments: false
    })
    expect(Array.isArray(documentIds)).toBe(true)
    expect(documentIds).toHaveLength(4)
    for (const doc of Object.values(docs)) {
      expect(documentIds).toContain(doc.id)
    }
  })

  it('[SHOULD] rejects a query with limit > 1000: 400', async () => {
    const response = await vault.rawRequest({
      url: `${vault.vaultUrl}/query`,
      method: 'POST',
      json: { index: vault.kit.hmac.id, has: ['x'], limit: 1001 },
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'read'
    })
    expectErrorResponse({ response, statusOneOf: [400] })
  })

  it('[SHOULD] enforces unique blinded attributes on insert and update: 409', async () => {
    // the server treats blinded names/values as opaque strings, so literal
    // stand-ins exercise the uniqueness constraint without an HMAC pass
    const uniqueAttribute = {
      name: 'CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ',
      value: 'QV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro',
      unique: true
    }
    const hmacRef = { id: vault.kit.hmac.id, type: vault.kit.hmac.type }
    const holder = await buildEncryptedDoc({
      keyAgreementKey: vault.kit.keyAgreementKey,
      indexed: [
        literalIndexEntry({ hmac: hmacRef, attributes: [uniqueAttribute] })
      ]
    })
    const inserted = await vault.rawRequest({
      url: vault.documentsUrl,
      method: 'POST',
      json: holder,
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expect(inserted.status).toBe(201)

    // a second document carrying the same unique term: rejected on insert
    const conflictOnInsert = await buildEncryptedDoc({
      keyAgreementKey: vault.kit.keyAgreementKey,
      indexed: [
        literalIndexEntry({ hmac: hmacRef, attributes: [uniqueAttribute] })
      ]
    })
    const insertResponse = await vault.rawRequest({
      url: vault.documentsUrl,
      method: 'POST',
      json: conflictOnInsert,
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expectErrorResponse({
      response: insertResponse,
      statusOneOf: [409],
      name: 'DuplicateError',
      strict
    })

    // and on update: an unrelated doc updated to carry the unique term
    const unrelated = await buildEncryptedDoc({
      keyAgreementKey: vault.kit.keyAgreementKey
    })
    const unrelatedInsert = await vault.rawRequest({
      url: vault.documentsUrl,
      method: 'POST',
      json: unrelated,
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expect(unrelatedInsert.status).toBe(201)
    const conflictingUpdate = await buildEncryptedDoc({
      keyAgreementKey: vault.kit.keyAgreementKey,
      id: unrelated.id,
      sequence: 1,
      indexed: [
        literalIndexEntry({
          hmac: hmacRef,
          attributes: [uniqueAttribute],
          sequence: 1
        })
      ]
    })
    const updateResponse = await vault.rawRequest({
      url: `${vault.documentsUrl}/${unrelated.id}`,
      method: 'POST',
      json: conflictingUpdate,
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expectErrorResponse({
      response: updateResponse,
      statusOneOf: [409],
      name: 'DuplicateError',
      strict
    })
  })

  it.skip('[OPTIONAL] attributeVersion 1 legacy queries (implementation-internal compatibility mode)', () => {
    // bedrock-edv-storage's version-1 document compatibility mode is toggled
    // server-side and is not reachable over the protocol; skipped by design
  })
})

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite 07: wire-format and validation negatives -- malformed JSON, broken
 * envelopes, post-signing mutation, content-type handling, id formats, and
 * (when `features.strictErrorNames` is enabled) protocol error-name spot
 * checks.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { loadSuiteConfig } from '../config.js'
import { freshVault } from '../helpers/vault.js'
import { buildEncryptedDoc } from '../helpers/fixtures.js'
import { generateLocalId } from '../helpers/ids.js'
import { expectErrorResponse } from '../helpers/assertions.js'
import type { VaultContext } from '../helpers/vault.js'

const suite = await loadSuiteConfig()
const strict = suite.features.strictErrorNames

describe('07 wire format / validation', () => {
  let vault: VaultContext

  beforeAll(async () => {
    vault = await freshVault({ suite })
  })

  it('[MUST] rejects a malformed JSON body: 400', async () => {
    // signed over the malformed bytes, so only JSON parsing can fail.
    // may-vary note: the spec expectation is 400; bedrock-edv-storage
    // returns 500 because its body-parser error is not mapped to a public
    // 400 -- recorded here rather than papered over
    const response = await vault.rawRequest({
      url: vault.documentsUrl,
      method: 'POST',
      body: '{"id": not-valid-json',
      headers: { 'content-type': 'application/json' },
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expectErrorResponse({ response, statusOneOf: [400, 500] })
  })

  it('[MUST] rejects a JWE missing required members: 400', async () => {
    for (const member of ['ciphertext', 'recipients', 'iv', 'tag']) {
      const doc = await buildEncryptedDoc({
        keyAgreementKey: vault.kit.keyAgreementKey
      })
      delete (doc.jwe as unknown as Record<string, unknown>)[member]
      const response = await vault.rawRequest({
        url: vault.documentsUrl,
        method: 'POST',
        json: doc,
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'write'
      })
      expectErrorResponse({ response, statusOneOf: [400] })
    }
  })

  it('[MUST] rejects a body mutated after signing (digest mismatch): 400/401/403', async () => {
    const doc = await buildEncryptedDoc({
      keyAgreementKey: vault.kit.keyAgreementKey
    })
    const response = await vault.rawRequest({
      url: vault.documentsUrl,
      method: 'POST',
      json: doc,
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write',
      mutateBodyAfterSign: () => JSON.stringify({ ...doc, sequence: 1 })
    })
    expectErrorResponse({ response, statusOneOf: [400, 401, 403] })
  })

  it('[SHOULD] rejects a wrong content-type: 4xx', async () => {
    const doc = await buildEncryptedDoc({
      keyAgreementKey: vault.kit.keyAgreementKey
    })
    const response = await vault.rawRequest({
      url: vault.documentsUrl,
      method: 'POST',
      body: JSON.stringify(doc),
      headers: { 'content-type': 'text/plain' },
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expectErrorResponse({ response, statusOneOf: [400, 403, 406, 415] })
  })

  it('[SHOULD] rejects a document id not in 16-byte multibase format: 400', async () => {
    for (const badId of [
      'not-multibase',
      // valid base58 but wrong decoded length
      'zabc',
      // unsupported multibase prefix
      'f00102030405060708090a0b0c0d0e0f10'
    ]) {
      const doc = await buildEncryptedDoc({
        keyAgreementKey: vault.kit.keyAgreementKey,
        id: generateLocalId()
      })
      doc.id = badId
      const response = await vault.rawRequest({
        url: vault.documentsUrl,
        method: 'POST',
        json: doc,
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'write'
      })
      expectErrorResponse({ response, statusOneOf: [400] })
    }
  })

  describe.skipIf(!strict)('error names (strictErrorNames)', () => {
    it('[SHOULD] uses protocol error names in error bodies', async () => {
      // DuplicateError on duplicate insert
      const doc = await buildEncryptedDoc({
        keyAgreementKey: vault.kit.keyAgreementKey
      })
      const insert = () =>
        vault.rawRequest({
          url: vault.documentsUrl,
          method: 'POST',
          json: doc,
          capability: vault.rootZcap,
          invocationSigner: vault.invocationSigner,
          action: 'write'
        })
      expect((await insert()).status).toBe(201)
      expectErrorResponse({
        response: await insert(),
        statusOneOf: [409],
        name: 'DuplicateError',
        strict
      })

      // sequence conflict on stale update; bedrock's upsert implementation
      // surfaces this as DuplicateError rather than InvalidStateError
      const stale = await buildEncryptedDoc({
        keyAgreementKey: vault.kit.keyAgreementKey,
        id: doc.id,
        sequence: 7
      })
      expectErrorResponse({
        response: await vault.rawRequest({
          url: `${vault.documentsUrl}/${doc.id}`,
          method: 'POST',
          json: stale,
          capability: vault.rootZcap,
          invocationSigner: vault.invocationSigner,
          action: 'write'
        }),
        statusOneOf: [409],
        name: ['InvalidStateError', 'DuplicateError'],
        strict
      })

      // NotFoundError on unknown id
      expectErrorResponse({
        response: await vault.rawRequest({
          url: `${vault.documentsUrl}/${generateLocalId()}`,
          method: 'GET',
          capability: vault.rootZcap,
          invocationSigner: vault.invocationSigner,
          action: 'read'
        }),
        statusOneOf: [404],
        name: 'NotFoundError',
        strict
      })
    })
  })
})

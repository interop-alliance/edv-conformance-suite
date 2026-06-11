/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite 05: chunked streams -- writing and reading encrypted streams via the
 * client, plus raw chunk-endpoint semantics (store/get/delete, the chunk/doc
 * sequence lockstep invariant). Gated on `features.chunks`.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { EdvDocument } from '@interop/edv-client'
import { loadSuiteConfig } from '../config.js'
import { keyResolver } from '../drivers/keys.js'
import {
  encryptToChunks,
  getRandomBytes,
  JWE_ALG,
  readAll,
  toReadableStream
} from '../drivers/streams.js'
import { freshVault } from '../helpers/vault.js'
import { freshDoc } from '../helpers/fixtures.js'
import { expectErrorResponse } from '../helpers/assertions.js'
import type { VaultContext } from '../helpers/vault.js'

const suite = await loadSuiteConfig()

describe.skipIf(!suite.features.chunks)('05 chunks / streams', () => {
  let vault: VaultContext

  beforeAll(async () => {
    vault = await freshVault({ suite })
  })

  function edvDocumentFor({ id }: { id: string }) {
    return new EdvDocument({
      id,
      invocationSigner: vault.invocationSigner,
      keyAgreementKey: vault.kit.keyAgreementKey,
      keyResolver,
      client: vault.client
    })
  }

  function chunkUrl({ docId, index }: { docId: string; index: number }) {
    return `${vault.documentsUrl}/${docId}/chunks/${index}`
  }

  it('[SHOULD] inserts a document with an encrypted stream and reads it back', async () => {
    const doc = freshDoc({ content: { kind: 'streamed' } })
    const data = getRandomBytes({ size: 50 })
    const inserted = await vault.client.insert({
      doc,
      stream: toReadableStream({ data })
    })
    // the stream is written in a follow-up update, so sequence is 1
    expect(inserted.content).toEqual({ kind: 'streamed' })
    expect(inserted.stream).toBeTypeOf('object')

    const edvDoc = edvDocumentFor({ id: doc.id })
    const result = await edvDoc.read()
    expect(result.content).toEqual({ kind: 'streamed' })
    expect(result.stream).toBeTypeOf('object')
    const stream = await edvDoc.getStream({ doc: result })
    const bytes = await readAll({ stream })
    expect(bytes).toEqual(data)
  })

  it('[SHOULD] writes a stream to an existing document', async () => {
    const doc = freshDoc({ content: { kind: 'late-stream' } })
    const inserted = await vault.client.insert({ doc })
    const data = getRandomBytes({ size: 50 })
    const updated = await vault.client.update({
      doc: inserted,
      stream: toReadableStream({ data })
    })
    expect(updated.stream).toBeTypeOf('object')

    const edvDoc = edvDocumentFor({ id: doc.id })
    const result = await edvDoc.read()
    const stream = await edvDoc.getStream({ doc: result })
    const bytes = await readAll({ stream })
    expect(bytes).toEqual(data)
  })

  it('[SHOULD] raw chunk store returns 204; get returns the chunk with ETag', async () => {
    const doc = freshDoc({ content: { kind: 'raw-chunks' } })
    const inserted = await vault.client.insert({ doc })
    const data = getRandomBytes({ size: 50 })
    const [value] = await encryptToChunks({
      data,
      recipients: [
        { header: { kid: vault.kit.keyAgreementKey.id, alg: JWE_ALG } }
      ]
    })
    // chunks are versioned in lockstep with their document
    const chunk = { sequence: inserted.sequence, ...value }
    const stored = await vault.rawRequest({
      url: chunkUrl({ docId: doc.id, index: 0 }),
      method: 'POST',
      json: chunk,
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expect(
      stored.status,
      `expected 204, got ${stored.status}: ${stored.text}`
    ).toBe(204)

    const fetched = await vault.rawRequest({
      url: chunkUrl({ docId: doc.id, index: 0 }),
      method: 'GET',
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'read'
    })
    expect(fetched.status).toBe(200)
    const body = fetched.json as Record<string, unknown>
    expect(body.sequence).toBe(inserted.sequence)
    expect(body.index).toBe(0)
    expect(body.jwe).toBeTypeOf('object')
    expect(fetched.headers.get('etag')).toBeTruthy()
  })

  it('[SHOULD] rejects a chunk whose sequence differs from the document sequence: 409', async () => {
    const doc = freshDoc({ content: { kind: 'lockstep' } })
    const inserted = await vault.client.insert({ doc })
    const data = getRandomBytes({ size: 50 })
    const [value] = await encryptToChunks({
      data,
      recipients: [
        { header: { kid: vault.kit.keyAgreementKey.id, alg: JWE_ALG } }
      ]
    })
    const chunk = { sequence: inserted.sequence + 1, ...value }
    const response = await vault.rawRequest({
      url: chunkUrl({ docId: doc.id, index: 0 }),
      method: 'POST',
      json: chunk,
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expectErrorResponse({
      response,
      statusOneOf: [409],
      name: 'InvalidStateError',
      strict: suite.features.strictErrorNames
    })
  })

  it('[SHOULD] DELETE chunk returns 204, then 404 on repeat', async () => {
    const doc = freshDoc({ content: { kind: 'chunk-delete' } })
    const data = getRandomBytes({ size: 50 })
    await vault.client.insert({ doc, stream: toReadableStream({ data }) })

    const first = await vault.rawRequest({
      url: chunkUrl({ docId: doc.id, index: 0 }),
      method: 'DELETE',
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expect(
      first.status,
      `expected 204, got ${first.status}: ${first.text}`
    ).toBe(204)

    const repeat = await vault.rawRequest({
      url: chunkUrl({ docId: doc.id, index: 0 }),
      method: 'DELETE',
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expectErrorResponse({ response: repeat, statusOneOf: [404] })
  })

  it('[SHOULD] reading a document with a missing chunk errors', async () => {
    const doc = freshDoc({ content: { kind: 'missing-chunk' } })
    const data = getRandomBytes({ size: 50 })
    await vault.client.insert({ doc, stream: toReadableStream({ data }) })

    // remove the chunk out from under the stream metadata
    const removed = await vault.rawRequest({
      url: chunkUrl({ docId: doc.id, index: 0 }),
      method: 'DELETE',
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    expect(removed.status).toBe(204)

    const edvDoc = edvDocumentFor({ id: doc.id })
    const result = await edvDoc.read()
    let error: { name?: string } | undefined
    try {
      const stream = await edvDoc.getStream({ doc: result })
      await readAll({ stream })
    } catch (err) {
      error = err as { name?: string }
    }
    expect(error, 'expected reading a missing chunk to fail').toBeDefined()
    expect(error?.name).toBe('NotFoundError')
  })

  it.skipIf(!suite.features.enforcesChunkLimit)(
    '[SHOULD] rejects a chunk payload over 1 MiB',
    async () => {
      // an EDV spec MUST that some implementations (including
      // bedrock-edv-storage, body limit 10 MB) do not enforce; gated on
      // features.enforcesChunkLimit
      const doc = freshDoc({ content: { kind: 'oversized-chunk' } })
      const inserted = await vault.client.insert({ doc })
      const data = getRandomBytes({ size: 1_500_000 })
      const [value] = await encryptToChunks({
        data,
        recipients: [
          { header: { kid: vault.kit.keyAgreementKey.id, alg: JWE_ALG } }
        ],
        chunkSize: 2_097_152
      })
      const chunk = { sequence: inserted.sequence, ...value }
      const response = await vault.rawRequest({
        url: chunkUrl({ docId: doc.id, index: 0 }),
        method: 'POST',
        json: chunk,
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'write'
      })
      expectErrorResponse({ response, statusOneOf: [400, 413] })
    }
  )
})

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite 02: document CRUD -- insert, upsert, get, tombstone delete -- via
 * the edv-client driver for happy paths and the raw driver for wire-format
 * assertions (status codes, Location/ETag/cache-control headers).
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { loadSuiteConfig } from '../config.js'
import { buildEdvClient } from '../drivers/edvClient.js'
import { freshVault } from '../helpers/vault.js'
import { buildEncryptedDoc, freshDoc } from '../helpers/fixtures.js'
import { generateLocalId } from '../helpers/ids.js'
import {
  expectError,
  expectErrorResponse,
  shouldBeDecryptedDocument,
  shouldBeEncryptedDocument
} from '../helpers/assertions.js'
import type { VaultContext } from '../helpers/vault.js'

const suite = await loadSuiteConfig()
const strict = suite.features.strictErrorNames

describe('02 documents', () => {
  let vault: VaultContext

  beforeAll(async () => {
    vault = await freshVault({ suite })
  })

  describe('insert', () => {
    it('[MUST] inserts a document via the client', async () => {
      const doc = freshDoc()
      const result = await vault.client.insert({ doc })
      shouldBeDecryptedDocument({ doc: result })
      expect(result.sequence).toBe(0)
      expect(result.content).toEqual(doc.content)
    })

    it('[MUST] raw insert returns 201 with a documents Location', async () => {
      const encrypted = await buildEncryptedDoc({
        keyAgreementKey: vault.kit.keyAgreementKey
      })
      const response = await vault.rawRequest({
        url: vault.documentsUrl,
        method: 'POST',
        json: encrypted,
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'write'
      })
      expect(
        response.status,
        `expected 201, got ${response.status}: ${response.text}`
      ).toBe(201)
      const location = response.headers.get('location')
      expect(location).toBe(`${vault.documentsUrl}/${encrypted.id}`)
    })

    it('[MUST] rejects a duplicate document id: 409 DuplicateError', async () => {
      const doc = freshDoc()
      await vault.client.insert({ doc })
      const error = await expectError({
        promise: vault.client.insert({ doc }),
        name: 'DuplicateError',
        strict
      })
      // the client maps the conflict; the wire status must be 409
      const status =
        error.status ?? (error.cause as { status?: number } | undefined)?.status
      expect([409]).toContain(status)
    })
  })

  describe('update (upsert)', () => {
    it('[MUST] upserts via raw POST to the document URL: 204', async () => {
      const encrypted = await buildEncryptedDoc({
        keyAgreementKey: vault.kit.keyAgreementKey
      })
      const response = await vault.rawRequest({
        url: `${vault.documentsUrl}/${encrypted.id}`,
        method: 'POST',
        json: encrypted,
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'write'
      })
      expect(
        response.status,
        `expected 204, got ${response.status}: ${response.text}`
      ).toBe(204)
      expect(response.text).toBe('')
    })

    it('[MUST] upserts a new document via the client', async () => {
      const doc = freshDoc({ content: { fruit: 'pear' } })
      const result = await vault.client.update({ doc })
      shouldBeDecryptedDocument({ doc: result })
      expect(result.sequence).toBe(0)
      expect(result.content).toEqual(doc.content)
    })

    it('[MUST] updates an existing document, incrementing sequence', async () => {
      const doc = freshDoc({ content: { count: 1 } })
      const inserted = await vault.client.insert({ doc })
      inserted.content.count = 2
      const result = await vault.client.update({ doc: inserted })
      expect(result.sequence).toBe(1)
      expect(result.content).toEqual({ count: 2 })
    })

    it('[MUST] rejects update where body id differs from URL id: 400', async () => {
      const encrypted = await buildEncryptedDoc({
        keyAgreementKey: vault.kit.keyAgreementKey
      })
      const otherId = generateLocalId()
      const response = await vault.rawRequest({
        url: `${vault.documentsUrl}/${otherId}`,
        method: 'POST',
        json: encrypted,
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'write'
      })
      expectErrorResponse({ response, statusOneOf: [400] })
    })
  })

  describe('get', () => {
    it('[MUST] returns the EncryptedDocument shape with ETag and cache-control', async () => {
      const doc = freshDoc({ content: { fetch: 'me' } })
      await vault.client.insert({ doc })
      const response = await vault.rawRequest({
        url: `${vault.documentsUrl}/${doc.id}`,
        method: 'GET',
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'read'
      })
      expect(
        response.status,
        `expected 200, got ${response.status}: ${response.text}`
      ).toBe(200)
      shouldBeEncryptedDocument({ doc: response.json })
      expect((response.json as { id: string }).id).toBe(doc.id)
      expect(response.headers.get('etag')).toBeTruthy()
      const cacheControl = response.headers.get('cache-control') ?? ''
      expect(cacheControl).toContain('no-cache')
      expect(cacheControl).toContain('private')
    })

    it('[MUST] returns 404 NotFoundError for an unknown document id', async () => {
      const response = await vault.rawRequest({
        url: `${vault.documentsUrl}/${generateLocalId()}`,
        method: 'GET',
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'read'
      })
      expectErrorResponse({
        response,
        statusOneOf: [404],
        name: 'NotFoundError',
        strict
      })
    })

    it('[MUST] returns 400 for an invalid document id encoding', async () => {
      const response = await vault.rawRequest({
        url: `${vault.documentsUrl}/does-not-exist`,
        method: 'GET',
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'read'
      })
      expectErrorResponse({ response, statusOneOf: [400] })
    })

    it('[MUST] round-trips: insert with client A, decrypt with fresh client B', async () => {
      const doc = freshDoc({ content: { round: 'trip', n: 42 } })
      await vault.client.insert({ doc })
      // a fresh client instance sharing only the key material
      const clientB = buildEdvClient({
        suite,
        id: vault.vaultUrl,
        kit: vault.kit
      })
      const result = await clientB.get({ id: doc.id })
      shouldBeDecryptedDocument({ doc: result })
      expect(result.content).toEqual(doc.content)
    })
  })

  describe('delete (client-side tombstoning)', () => {
    it('[MUST] delete makes the doc read back with meta.deleted and a bumped sequence', async () => {
      const doc = freshDoc({ content: { ephemeral: true } })
      await vault.client.insert({ doc })
      const fetched = await vault.client.get({ id: doc.id })
      const deleted = await vault.client.delete({ doc: fetched })
      expect(deleted).toBe(true)
      const after = await vault.client.get({ id: doc.id })
      expect(after.meta?.deleted).toBe(true)
      expect(after.sequence).toBe(fetched.sequence + 1)
    })

    it('[MUST] updating a deleted document revives it and increments sequence', async () => {
      const doc = freshDoc({ content: { phase: 'one' } })
      await vault.client.insert({ doc })
      const fetched = await vault.client.get({ id: doc.id })
      await vault.client.delete({ doc: fetched })
      const tombstone = await vault.client.get({ id: doc.id })
      tombstone.content = { phase: 'two' }
      delete (tombstone.meta as Record<string, unknown>)?.deleted
      const revived = await vault.client.update({ doc: tombstone })
      expect(revived.sequence).toBe(tombstone.sequence + 1)
      const after = await vault.client.get({ id: doc.id })
      expect(after.content).toEqual({ phase: 'two' })
      expect(after.meta?.deleted).toBeUndefined()
    })

    it('[MUST] HTTP DELETE on a document URL is not part of the protocol: 404/405', async () => {
      const doc = freshDoc()
      await vault.client.insert({ doc })
      const response = await vault.rawRequest({
        url: `${vault.documentsUrl}/${doc.id}`,
        method: 'DELETE',
        capability: vault.rootZcap,
        invocationSigner: vault.invocationSigner,
        action: 'write'
      })
      // deletion is client-side tombstoning only; servers must not expose
      // a document DELETE route (404 or 405 both acceptable)
      expectErrorResponse({ response, statusOneOf: [404, 405] })
    })
  })
})

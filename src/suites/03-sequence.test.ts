/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite 03: sequence-number invariants over HTTP -- the previous+1 update
 * rule, the boundary-value table, and rejection of out-of-range or
 * non-integer sequences. Raw pre-encrypted documents are used so arbitrary
 * sequence values can be expressed on the wire.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { loadSuiteConfig } from '../config.js'
import { freshVault } from '../helpers/vault.js'
import { buildEncryptedDoc, sequenceNumberTests } from '../helpers/fixtures.js'
import { expectErrorResponse } from '../helpers/assertions.js'
import type { VaultContext } from '../helpers/vault.js'

const suite = await loadSuiteConfig()
const strict = suite.features.strictErrorNames

describe('03 sequence invariants', () => {
  let vault: VaultContext

  beforeAll(async () => {
    vault = await freshVault({ suite })
  })

  async function rawInsert({ sequence }: { sequence: number }) {
    const encrypted = await buildEncryptedDoc({
      keyAgreementKey: vault.kit.keyAgreementKey,
      sequence
    })
    const response = await vault.rawRequest({
      url: vault.documentsUrl,
      method: 'POST',
      json: encrypted,
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
    return { encrypted, response }
  }

  async function rawUpdate({ id, sequence }: { id: string; sequence: number }) {
    const encrypted = await buildEncryptedDoc({
      keyAgreementKey: vault.kit.keyAgreementKey,
      id,
      sequence
    })
    return vault.rawRequest({
      url: `${vault.documentsUrl}/${id}`,
      method: 'POST',
      json: encrypted,
      capability: vault.rootZcap,
      invocationSigner: vault.invocationSigner,
      action: 'write'
    })
  }

  it('[MUST] rejects an update whose sequence is not previous+1: 409', async () => {
    const { encrypted, response } = await rawInsert({ sequence: 0 })
    expect(response.status).toBe(201)
    // may-vary note: the 409 status is the invariant; the error name
    // varies by implementation -- bedrock's document update is an upsert,
    // so a failed sequence match falls through to an insert attempt and
    // surfaces DuplicateError rather than InvalidStateError
    const sequenceConflictNames: Array<'InvalidStateError' | 'DuplicateError'> =
      ['InvalidStateError', 'DuplicateError']
    // skipping ahead (0 -> 5) violates the previous+1 rule
    const stale = await rawUpdate({ id: encrypted.id, sequence: 5 })
    expectErrorResponse({
      response: stale,
      statusOneOf: [409],
      name: sequenceConflictNames,
      strict
    })
    // replaying the current sequence does too
    const replay = await rawUpdate({ id: encrypted.id, sequence: 0 })
    expectErrorResponse({
      response: replay,
      statusOneOf: [409],
      name: sequenceConflictNames,
      strict
    })
  })

  // Insert-with-nonzero-sequence is reference-implementation behavior that
  // eases copying documents between vaults, not spec text -- hence SHOULD.
  for (const { label, sequence } of sequenceNumberTests) {
    it(`[SHOULD] accepts insert and previous+1 update at sequence ${label}`, async () => {
      const { encrypted, response } = await rawInsert({ sequence })
      expect(
        response.status,
        `insert at sequence ${label}: expected 201, got ` +
          `${response.status}: ${response.text}`
      ).toBe(201)
      const update = await rawUpdate({
        id: encrypted.id,
        sequence: sequence + 1
      })
      expect(
        update.status,
        `update to sequence ${label}+1: expected 204, got ` +
          `${update.status}: ${update.text}`
      ).toBe(204)
    })
  }

  it('[MUST] rejects a negative sequence: 400', async () => {
    const { response } = await rawInsert({ sequence: -1 })
    expectErrorResponse({ response, statusOneOf: [400] })
  })

  it('[MUST] rejects an update to sequence at MAX_SAFE_INTEGER: 400', async () => {
    const sequence = Number.MAX_SAFE_INTEGER - 1
    const { encrypted, response } = await rawInsert({ sequence })
    expect(
      response.status,
      `insert at MAX_SAFE_INTEGER-1: expected 201, got ` +
        `${response.status}: ${response.text}`
    ).toBe(201)
    const update = await rawUpdate({
      id: encrypted.id,
      sequence: Number.MAX_SAFE_INTEGER
    })
    expectErrorResponse({ response: update, statusOneOf: [400] })
  })

  it('[MUST] rejects a non-integer sequence: 400', async () => {
    const { response } = await rawInsert({ sequence: 1.5 })
    expectErrorResponse({ response, statusOneOf: [400] })
  })
})

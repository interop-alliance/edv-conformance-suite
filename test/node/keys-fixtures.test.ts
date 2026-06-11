/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Self-tests for the local (no-WebKMS) key kit and the pre-encrypted
 * fixture builders: the suite must be able to produce real did:key signers,
 * blinding HMACs, and decryptable JWE envelopes without any server.
 */
import { Cipher } from '@interop/minimal-cipher'
import { describe, expect, it } from 'vitest'
import {
  createCapabilityAgent,
  createTestKit,
  keyResolver,
  LocalHmac
} from '../../src/drivers/keys.js'
import {
  buildEncryptedDoc,
  freshHttpDocs,
  sequenceNumberTests
} from '../../src/helpers/fixtures.js'
import { isValidLocalId } from '../../src/helpers/ids.js'
import {
  decryptChunks,
  encryptToChunks,
  getRandomBytes,
  JWE_ALG
} from '../../src/drivers/streams.js'

describe('keys', () => {
  it('creates a did:key capability agent with a resolvable KAK', async () => {
    const { agent, keyAgreementKey } = await createCapabilityAgent()
    expect(agent.id).toMatch(/^did:key:z6Mk/)
    expect(agent.signer.id).toMatch(new RegExp(`^${agent.id}#`))
    const signature = await agent.signer.sign({
      data: new TextEncoder().encode('hello')
    })
    expect(signature).toBeInstanceOf(Uint8Array)
    expect(signature.length).toBe(64)
    // the KAK public form is registered with the shared resolver
    const resolved = (await keyResolver({
      id: keyAgreementKey.id
    })) as Record<string, unknown>
    expect(resolved.type).toBe('X25519KeyAgreementKey2020')
  })

  it('LocalHmac signs and verifies', async () => {
    const hmac = await LocalHmac.create()
    expect(hmac.id).toMatch(/^urn:uuid:/)
    expect(hmac.type).toBe('Sha256HmacKey2019')
    const data = new TextEncoder().encode('attribute')
    const signature = await hmac.sign({ data })
    expect(signature).toBeInstanceOf(Uint8Array)
    expect(await hmac.verify({ data, signature })).toBe(true)
    expect(
      await hmac.verify({
        data: new TextEncoder().encode('other'),
        signature
      })
    ).toBe(false)
  })
})

describe('fixtures', () => {
  it('builds a decryptable pre-encrypted document envelope', async () => {
    const kit = await createTestKit()
    const doc = await buildEncryptedDoc({
      keyAgreementKey: kit.keyAgreementKey,
      sequence: 7,
      content: { secret: 'sauce' }
    })
    expect(isValidLocalId({ id: doc.id })).toBe(true)
    expect(doc.sequence).toBe(7)
    expect(doc.jwe).toMatchObject({
      protected: expect.any(String),
      iv: expect.any(String),
      ciphertext: expect.any(String),
      tag: expect.any(String)
    })
    const cipher = new Cipher()
    const decrypted = (await cipher.decryptObject({
      jwe: doc.jwe,
      keyAgreementKey: kit.keyAgreementKey as never
    })) as { content: Record<string, unknown> }
    expect(decrypted.content).toEqual({ secret: 'sauce' })
  })

  it('generates fresh ids per call for the query docs', () => {
    const first = freshHttpDocs()
    const second = freshHttpDocs()
    for (const name of Object.keys(first)) {
      expect(isValidLocalId({ id: first[name]!.id })).toBe(true)
      expect(first[name]!.id).not.toBe(second[name]!.id)
    }
  })

  it('keeps the sequence boundary table within safe-integer bounds', () => {
    for (const { sequence } of sequenceNumberTests) {
      expect(Number.isSafeInteger(sequence)).toBe(true)
      expect(sequence).toBeGreaterThanOrEqual(0)
      // every entry must survive a previous+1 update below MAX_SAFE_INTEGER
      expect(sequence + 1).toBeLessThan(Number.MAX_SAFE_INTEGER)
    }
  })
})

describe('streams', () => {
  it('round-trips data through encrypted chunks', async () => {
    const kit = await createTestKit()
    const data = getRandomBytes({ size: 100 })
    const chunks = await encryptToChunks({
      data,
      recipients: [{ header: { kid: kit.keyAgreementKey.id, alg: JWE_ALG } }],
      chunkSize: 64
    })
    expect(chunks.length).toBeGreaterThan(1)
    for (const [index, chunk] of chunks.entries()) {
      expect(chunk.index).toBe(index)
      expect(chunk.jwe).toBeTypeOf('object')
    }
    const decrypted = await decryptChunks({
      chunks,
      keyAgreementKey: kit.keyAgreementKey
    })
    expect(decrypted).toEqual(data)
  })
})

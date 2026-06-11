/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Plaintext document fixtures (ported from bedrock-edv-storage's
 * `mock.data.js` httpDocs) and a pre-encrypted JWE document builder for raw
 * inserts with arbitrary envelope values (sequence boundaries, malformed
 * envelopes).
 */
import { Cipher } from '@interop/minimal-cipher'
import { generateLocalId } from './ids.js'
import { keyResolver } from '../drivers/keys.js'
import { JWE_ALG } from '../drivers/streams.js'
import type {
  IEncryptedDocument,
  IIndexEntry
} from '@interop/data-integrity-core'

const cipher = new Cipher()

export interface PlaintextDoc {
  id: string
  content: Record<string, unknown>
}

/**
 * Returns a fresh copy of the four standard query-test documents (alpha,
 * beta, gamma, delta) with newly generated ids. alpha/beta/gamma share
 * `group`; alpha/beta share `subgroup`; alpha's `apples` is multi-valued.
 *
 * @returns {Record<string, PlaintextDoc>}
 */
export function freshHttpDocs(): Record<string, PlaintextDoc> {
  return {
    alpha: {
      id: generateLocalId(),
      content: {
        apples: [1, 6],
        oranges: 2,
        pears: 3,
        group: 'group1',
        subgroup: 'subgroup1',
        id: 'alpha'
      }
    },
    beta: {
      id: generateLocalId(),
      content: {
        apples: 10,
        oranges: 20,
        pears: 30,
        group: 'group1',
        subgroup: 'subgroup1',
        id: 'beta'
      }
    },
    gamma: {
      id: generateLocalId(),
      content: {
        apples: 100,
        oranges: 200,
        pears: 300,
        group: 'group1',
        subgroup: 'subgroup2',
        id: 'gamma'
      }
    },
    delta: {
      id: generateLocalId(),
      content: {
        apples: 1000,
        oranges: 2000,
        pears: 3000
      }
    }
  }
}

/**
 * Returns a fresh single-purpose plaintext document.
 *
 * @param options {object}
 * @param [options.content] {object}
 *
 * @returns {PlaintextDoc}
 */
export function freshDoc({
  content = { someKey: 'someValue' }
}: {
  content?: Record<string, unknown>
} = {}): PlaintextDoc {
  return { id: generateLocalId(), content }
}

/**
 * Builds a pre-encrypted EncryptedDocument envelope with full control over
 * `id`, `sequence`, and `indexed` -- for raw POSTs the client library would
 * never send. The JWE payload is a real encryption of `{content}` to the
 * given key agreement key.
 *
 * @param options {object}
 * @param options.keyAgreementKey {object} - The recipient key (an object
 *   with at least an `id`, e.g. an X25519KeyAgreementKey2020 instance).
 * @param [options.id] {string} - Defaults to a fresh local id.
 * @param [options.sequence] {number} - Defaults to 0. Deliberately untyped
 *   beyond `number` so boundary/negative values can be expressed.
 * @param [options.content] {object}
 * @param [options.indexed] {IIndexEntry[]}
 *
 * @returns {Promise<IEncryptedDocument>}
 */
export async function buildEncryptedDoc({
  keyAgreementKey,
  id = generateLocalId(),
  sequence = 0,
  content = { someKey: 'someValue' },
  indexed = []
}: {
  keyAgreementKey: { id?: string }
  id?: string
  sequence?: number
  content?: Record<string, unknown>
  indexed?: IIndexEntry[]
}): Promise<IEncryptedDocument> {
  if (!keyAgreementKey.id) {
    throw new TypeError('"keyAgreementKey.id" is required.')
  }
  const jwe = await cipher.encryptObject({
    obj: { id, sequence, content },
    recipients: [{ header: { kid: keyAgreementKey.id, alg: JWE_ALG } }],
    keyResolver
  })
  return { id, sequence, jwe, indexed }
}

/**
 * Builds a blinded index entry from literal (already-opaque) attribute
 * strings. The server treats blinded names/values as opaque, so arbitrary
 * base64url-looking strings exercise the index/uniqueness machinery without
 * a real HMAC blinding pass.
 *
 * @param options {object}
 * @param options.hmac {object} - The vault's hmac reference ({id, type}).
 * @param options.attributes {Array} - `{name, value, unique?}` entries.
 * @param [options.sequence] {number}
 *
 * @returns {IIndexEntry}
 */
export function literalIndexEntry({
  hmac,
  attributes,
  sequence = 0
}: {
  hmac: { id: string; type: string }
  attributes: Array<{ name: string; value: string; unique?: boolean }>
  sequence?: number
}): IIndexEntry {
  return {
    hmac: { id: hmac.id, type: hmac.type },
    sequence,
    attributes
  }
}

/**
 * The sequence-number boundary table (ported from bedrock-edv-storage
 * `helpers.js`). Each value is exercised as an insert sequence and as the
 * base for a previous+1 update. Insert-with-nonzero-sequence is
 * reference-implementation behavior (eases copying docs between vaults)
 * rather than spec text.
 */
export const sequenceNumberTests: Array<{ label: string; sequence: number }> = [
  { label: '0', sequence: 0 },
  { label: '1', sequence: 1 },
  { label: '2**31-1', sequence: 2 ** 31 - 1 },
  { label: '2**31', sequence: 2 ** 31 },
  { label: '2**31+1', sequence: 2 ** 31 + 1 },
  { label: '2**32-1', sequence: 2 ** 32 - 1 },
  { label: '2**32', sequence: 2 ** 32 },
  { label: '2**32+1', sequence: 2 ** 32 + 1 },
  {
    label: 'midpoint of [2**32, MAX_SAFE_INTEGER]',
    sequence: 2 ** 32 + (Number.MAX_SAFE_INTEGER - 2 ** 32 - 1) / 2
  },
  { label: 'MAX_SAFE_INTEGER-2', sequence: Number.MAX_SAFE_INTEGER - 2 }
]

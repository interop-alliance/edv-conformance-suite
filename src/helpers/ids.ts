/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Codec for EDV-local identifiers (vault ids, document ids): multibase
 * base58btc-encoded multicodec identity-tagged 16-byte random values, i.e.
 * `'z' + base58btc(0x00 0x10 || <16 random bytes>)`.
 */
import { base58 } from '@scure/base'

// multicodec identity tag + length header for a 16-byte value
const HEADER = Uint8Array.from([0x00, 0x10])
const RAW_LENGTH = 16

/**
 * Generates a new random EDV-local identifier.
 *
 * @returns {string} A multibase base58btc-encoded 128-bit identifier.
 */
export function generateLocalId(): string {
  const bytes = new Uint8Array(RAW_LENGTH)
  crypto.getRandomValues(bytes)
  return encodeLocalId({ bytes })
}

/**
 * Encodes 16 raw bytes as an EDV-local identifier.
 *
 * @param options {object}
 * @param options.bytes {Uint8Array} - Exactly 16 bytes.
 *
 * @returns {string} The multibase base58btc-encoded identifier.
 */
export function encodeLocalId({ bytes }: { bytes: Uint8Array }): string {
  if (bytes.length !== RAW_LENGTH) {
    throw new TypeError(`"bytes" must be ${RAW_LENGTH} bytes long.`)
  }
  const tagged = new Uint8Array(HEADER.length + bytes.length)
  tagged.set(HEADER)
  tagged.set(bytes, HEADER.length)
  return 'z' + base58.encode(tagged)
}

/**
 * Decodes an EDV-local identifier back to its 16 raw bytes. Throws on any
 * encoding violation (missing multibase prefix, bad multicodec header, wrong
 * length, non-base58 characters).
 *
 * @param options {object}
 * @param options.id {string} - The multibase-encoded local identifier.
 *
 * @returns {Uint8Array} The 16 raw bytes.
 */
export function decodeLocalId({ id }: { id: string }): Uint8Array {
  if (typeof id !== 'string' || !id.startsWith('z')) {
    throw new TypeError('"id" must be a multibase base58btc string (z...).')
  }
  const tagged = base58.decode(id.slice(1))
  if (
    tagged.length !== HEADER.length + RAW_LENGTH ||
    tagged[0] !== HEADER[0] ||
    tagged[1] !== HEADER[1]
  ) {
    throw new TypeError(
      '"id" must decode to a multicodec identity-tagged 16-byte value.'
    )
  }
  return tagged.slice(HEADER.length)
}

/**
 * Tests whether a string is a valid EDV-local identifier.
 *
 * @param options {object}
 * @param options.id {string}
 *
 * @returns {boolean}
 */
export function isValidLocalId({ id }: { id: string }): boolean {
  try {
    decodeLocalId({ id })
    return true
  } catch {
    return false
  }
}

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
import { describe, expect, it } from 'vitest'
import {
  decodeLocalId,
  encodeLocalId,
  generateLocalId,
  isValidLocalId
} from '../../src/helpers/ids.js'

describe('ids', () => {
  it('generates multibase base58btc identifiers', () => {
    const id = generateLocalId()
    expect(id.startsWith('z')).toBe(true)
    expect(isValidLocalId({ id })).toBe(true)
  })

  it('round-trips encode/decode', () => {
    const bytes = new Uint8Array(16).map((_, index) => index)
    const id = encodeLocalId({ bytes })
    expect(decodeLocalId({ id })).toEqual(bytes)
  })

  it('accepts known-good reference ids', () => {
    // document ids from the reference implementation's fixtures
    for (const id of [
      'z19pjdSMQMkBqqJ5zsbbgbbbb',
      'z1ABxUcbcnSyMtnenFmeARhUn',
      'z19krtYWG3TdMyicpnbeXWwT4'
    ]) {
      expect(isValidLocalId({ id })).toBe(true)
    }
  })

  it('rejects malformed ids', () => {
    for (const id of [
      'not-multibase',
      'zabc',
      'f00102030405060708090a0b0c0d0e0f10',
      '',
      'z',
      // 0x00 0x10 header but only 15 payload bytes
      encodeLocalId({ bytes: new Uint8Array(16) }).slice(0, -2)
    ]) {
      expect(isValidLocalId({ id }), `expected ${id} to be invalid`).toBe(false)
    }
  })

  it('rejects wrong byte length on encode', () => {
    expect(() => encodeLocalId({ bytes: new Uint8Array(15) })).toThrow(
      TypeError
    )
  })
})

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Stream-cipher helpers over `@interop/minimal-cipher`: encrypt test data
 * into EDV chunk values for raw chunk-endpoint tests, and decrypt chunk
 * sequences back to bytes.
 */
import { Cipher } from '@interop/minimal-cipher'
import { keyResolver } from './keys.js'
import type { IJWE, IKeyAgreementKey } from '@interop/data-integrity-core'

const cipher = new Cipher()

export const JWE_ALG = 'ECDH-ES+A256KW'
const DEFAULT_CHUNK_SIZE = 1_048_576

export interface EncryptedChunkValue {
  index: number
  offset: number
  jwe: IJWE
  [key: string]: unknown
}

/**
 * Returns random bytes for use as stream data.
 *
 * @param options {object}
 * @param [options.size] {number}
 *
 * @returns {Uint8Array}
 */
export function getRandomBytes({ size = 50 }: { size?: number } = {}) {
  const data = new Uint8Array(size)
  crypto.getRandomValues(data)
  return data
}

/**
 * Wraps a single Uint8Array as a WHATWG ReadableStream (the shape
 * `EdvClient.insert({stream})` expects).
 *
 * @param options {object}
 * @param options.data {Uint8Array}
 *
 * @returns {ReadableStream}
 */
export function toReadableStream({
  data
}: {
  data: Uint8Array
}): ReadableStream<Uint8Array> {
  return new ReadableStream({
    pull(controller) {
      controller.enqueue(data)
      controller.close()
    }
  })
}

/**
 * Encrypts data into EDV chunk values (`{index, offset, jwe}`) using the
 * given recipients, for storing via the raw chunk endpoint.
 *
 * @param options {object}
 * @param options.data {Uint8Array}
 * @param options.recipients {Array} - JWE recipient headers
 *   (`[{header: {kid, alg}}]`).
 * @param [options.chunkSize] {number}
 *
 * @returns {Promise<EncryptedChunkValue[]>}
 */
export async function encryptToChunks({
  data,
  recipients,
  chunkSize = DEFAULT_CHUNK_SIZE
}: {
  data: Uint8Array
  recipients: object[]
  chunkSize?: number
}): Promise<EncryptedChunkValue[]> {
  const stream = toReadableStream({ data })
  const encryptStream = await cipher.createEncryptStream({
    recipients: recipients as never,
    keyResolver,
    chunkSize
  })
  const reader = stream.pipeThrough(encryptStream as never).getReader()
  const chunks: EncryptedChunkValue[] = []
  for (;;) {
    const { value, done } = await reader.read()
    if (done) {
      break
    }
    chunks.push(value as EncryptedChunkValue)
  }
  return chunks
}

/**
 * Decrypts a sequence of encrypted chunk values back into one byte array.
 *
 * @param options {object}
 * @param options.chunks {EncryptedChunkValue[]}
 * @param options.keyAgreementKey {IKeyAgreementKey}
 *
 * @returns {Promise<Uint8Array>}
 */
export async function decryptChunks({
  chunks,
  keyAgreementKey
}: {
  chunks: EncryptedChunkValue[]
  keyAgreementKey: IKeyAgreementKey | { id?: string }
}): Promise<Uint8Array> {
  const stream = new ReadableStream({
    pull(controller) {
      for (const chunk of chunks) {
        controller.enqueue(chunk)
      }
      controller.close()
    }
  })
  const decryptStream = await cipher.createDecryptStream({
    keyAgreementKey: keyAgreementKey as IKeyAgreementKey
  })
  const reader = stream.pipeThrough(decryptStream as never).getReader()
  let data = new Uint8Array(0)
  for (;;) {
    const { value, done } = await reader.read()
    if (done) {
      break
    }
    const chunk = value as Uint8Array
    const next = new Uint8Array(data.length + chunk.length)
    next.set(data)
    next.set(chunk, data.length)
    data = next
  }
  return data
}

/**
 * Reads a WHATWG ReadableStream of Uint8Array chunks to completion.
 *
 * @param options {object}
 * @param options.stream {ReadableStream}
 *
 * @returns {Promise<Uint8Array>}
 */
export async function readAll({
  stream
}: {
  stream: ReadableStream<Uint8Array>
}): Promise<Uint8Array> {
  const reader = stream.getReader()
  let data = new Uint8Array(0)
  for (;;) {
    const { value, done } = await reader.read()
    if (done) {
      break
    }
    const next = new Uint8Array(data.length + value.length)
    next.set(data)
    next.set(value, data.length)
    data = next
  }
  return data
}

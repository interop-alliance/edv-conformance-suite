/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Shape assertions and error matchers shared by the conformance suites. The
 * shapes mirror the EDV protocol's wire format (see the JSON Schemas in
 * bedrock-edv-storage's `schemas/`, re-expressed locally). Imports vitest's
 * `expect`, so this module is only usable inside a test run.
 */
import { expect } from 'vitest'
import type { RawResponse } from '../drivers/rawHttp.js'

/** Error names the protocol's reference implementation uses. */
export type EdvErrorName =
  | 'DuplicateError'
  | 'InvalidStateError'
  | 'NotFoundError'
  | 'NotAllowedError'
  | 'ValidationError'
  | 'SyntaxError'
  | 'URLMismatchError'
  | 'DataError'

/**
 * Asserts that a value has the shape of an EDV configuration.
 *
 * @param options {object}
 * @param options.config {unknown}
 */
export function shouldBeEdvConfig({ config }: { config: unknown }) {
  expect(config).toBeTypeOf('object')
  const candidate = config as Record<string, unknown>
  expect(candidate.id).toBeTypeOf('string')
  expect(candidate.controller).toBeTypeOf('string')
  expect(candidate.sequence).toBeTypeOf('number')
  expect(candidate.keyAgreementKey).toMatchObject({
    id: expect.any(String),
    type: expect.any(String)
  })
  expect(candidate.hmac).toMatchObject({
    id: expect.any(String),
    type: expect.any(String)
  })
}

/**
 * Asserts that a value has the shape of a server-stored encrypted document
 * (the wire format returned by `GET .../documents/:docId`).
 *
 * @param options {object}
 * @param options.doc {unknown}
 */
export function shouldBeEncryptedDocument({ doc }: { doc: unknown }) {
  expect(doc).toBeTypeOf('object')
  const candidate = doc as Record<string, unknown>
  expect(candidate.id).toBeTypeOf('string')
  expect(candidate.sequence).toBeTypeOf('number')
  expect(candidate.jwe).toBeTypeOf('object')
  const jwe = candidate.jwe as Record<string, unknown>
  expect(jwe.protected).toBeTypeOf('string')
  expect(Array.isArray(jwe.recipients)).toBe(true)
  expect((jwe.recipients as unknown[]).length).toBeGreaterThanOrEqual(1)
  expect(jwe.iv).toBeTypeOf('string')
  expect(jwe.ciphertext).toBeTypeOf('string')
  expect(jwe.tag).toBeTypeOf('string')
}

/**
 * Asserts that a value has the shape of a client-decrypted EDV document
 * (what `EdvClient.get()` returns).
 *
 * @param options {object}
 * @param options.doc {unknown}
 */
export function shouldBeDecryptedDocument({ doc }: { doc: unknown }) {
  expect(doc).toBeTypeOf('object')
  const candidate = doc as Record<string, unknown>
  expect(candidate.id).toBeTypeOf('string')
  expect(candidate.sequence).toBeTypeOf('number')
  expect(Array.isArray(candidate.indexed)).toBe(true)
  expect(candidate.content).toBeTypeOf('object')
}

/**
 * Asserts a raw response carries one of the accepted statuses, and
 * (optionally, when `strict` is set) one of the accepted protocol error
 * names in its body's `name` or `type` member.
 *
 * @param options {object}
 * @param options.response {RawResponse}
 * @param options.statusOneOf {number[]} - The accepted status set; multiple
 *   entries record a may-vary point in the protocol.
 * @param [options.name] {EdvErrorName|EdvErrorName[]} - Accepted error
 *   name(s); only asserted when `strict` is true.
 * @param [options.strict] {boolean} - The suite's
 *   `features.strictErrorNames` setting.
 */
export function expectErrorResponse({
  response,
  statusOneOf,
  name,
  strict = false
}: {
  response: RawResponse
  statusOneOf: number[]
  name?: EdvErrorName | EdvErrorName[]
  strict?: boolean
}) {
  expect(
    statusOneOf,
    `expected status in [${statusOneOf.join(', ')}], got ${response.status}: ` +
      response.text
  ).toContain(response.status)
  if (name && strict) {
    const names = Array.isArray(name) ? name : [name]
    const body = (response.json ?? {}) as Record<string, unknown>
    const actual = body.name ?? body.type
    expect(
      names as string[],
      `expected error name in [${names.join(', ')}], got ` +
        `${String(actual)} (body: ${response.text})`
    ).toContain(actual)
  }
}

/** The error shape thrown by edv-client / http-client on non-2xx replies. */
interface HttpishError {
  status?: number
  name?: string
  message?: string
  cause?: unknown
  response?: { status?: number }
  data?: { name?: string; type?: string }
  /** ProvisioningError carries the parsed response body here. */
  body?: { name?: string; type?: string }
}

/**
 * Awaits a promise expected to reject with an HTTP-ish error, asserting on
 * status and (optionally, when `strict`) protocol error name. Returns the
 * error for further assertions.
 *
 * @param options {object}
 * @param options.promise {Promise<unknown>}
 * @param [options.statusOneOf] {number[]}
 * @param [options.name] {EdvErrorName|EdvErrorName[]}
 * @param [options.strict] {boolean}
 *
 * @returns {Promise<HttpishError>} The thrown error.
 */
export async function expectError({
  promise,
  statusOneOf,
  name,
  strict = false
}: {
  promise: Promise<unknown>
  statusOneOf?: number[]
  name?: EdvErrorName | EdvErrorName[]
  strict?: boolean
}): Promise<HttpishError> {
  let error: HttpishError | undefined
  try {
    await promise
  } catch (err) {
    error = err as HttpishError
  }
  expect(
    error,
    'expected the operation to fail, but it succeeded'
  ).toBeDefined()
  const caught = error as HttpishError
  if (statusOneOf) {
    const status = caught.status ?? caught.response?.status
    expect(
      statusOneOf,
      `expected error status in [${statusOneOf.join(', ')}], got ` +
        `${String(status)} (${String(caught.message)})`
    ).toContain(status)
  }
  if (name && strict) {
    const names = Array.isArray(name) ? name : [name]
    const actual =
      caught.data?.name ??
      caught.data?.type ??
      caught.body?.name ??
      caught.body?.type ??
      caught.name
    expect(
      names as string[],
      `expected error name in [${names.join(', ')}], got ${String(actual)}`
    ).toContain(actual)
  }
  return caught
}

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Thin raw-HTTP driver for wire-format and negative tests: zcap-signed (or
 * deliberately unsigned) requests with full control over body and headers,
 * including mutation after signing. Never throws on non-2xx responses --
 * tests assert on the returned status/headers/body directly.
 */
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import { Agent, fetch } from 'undici'
import type { Dispatcher } from 'undici'
import type { ISigner } from '@interop/data-integrity-core'

export interface RawResponse {
  status: number
  headers: Headers
  text: string
  json?: unknown
}

export interface RawRequestOptions {
  url: string
  /** Defaults to 'POST' when a body is present, 'GET' otherwise. */
  method?: string
  /** JSON body; mutually exclusive with `body`. */
  json?: unknown
  /** Raw body; mutually exclusive with `json`. */
  body?: string | Uint8Array
  headers?: Record<string, string>
  /**
   * Root zcap id (string) or delegated zcap (object). Defaults to the root
   * zcap of `url` (`urn:zcap:root:<urlencoded url>`).
   */
  capability?: string | object
  invocationSigner?: ISigner
  /**
   * The zcap action to invoke. Defaults per route convention: 'read' for
   * GET, 'write' otherwise. Note the protocol's exception: query endpoints
   * are POSTs that require 'read'.
   */
  action?: string
  /** Set false to send the request unsigned (authn-failure tests). */
  signed?: boolean
  /** Mutate the final header set after signing (signature-breaking tests). */
  mutateHeadersAfterSign?: (
    headers: Record<string, string>
  ) => Record<string, string>
  /** Replace the body after signing (digest-mismatch tests). */
  mutateBodyAfterSign?: (
    body: string | Uint8Array | undefined
  ) => string | Uint8Array | undefined
}

export type RawRequestFn = (options: RawRequestOptions) => Promise<RawResponse>

/**
 * Builds a `rawRequest` function bound to the suite's TLS settings.
 *
 * @param options {object}
 * @param [options.tls] {object}
 * @param [options.tls.rejectUnauthorized] {boolean} - Set false to accept
 *   self-signed certificates (dev servers).
 *
 * @returns {RawRequestFn}
 */
export function createRawRequest({
  tls
}: {
  tls?: { rejectUnauthorized?: boolean }
} = {}): RawRequestFn {
  let dispatcher: Dispatcher | undefined
  if (tls?.rejectUnauthorized === false) {
    dispatcher = new Agent({ connect: { rejectUnauthorized: false } })
  }

  return async function rawRequest({
    url,
    method,
    json,
    body,
    headers = {},
    capability,
    invocationSigner,
    action,
    signed = true,
    mutateHeadersAfterSign,
    mutateBodyAfterSign
  }: RawRequestOptions): Promise<RawResponse> {
    if (json !== undefined && body !== undefined) {
      throw new TypeError('"json" and "body" must not be provided together.')
    }
    const hasBody = json !== undefined || body !== undefined
    const effectiveMethod = method ?? (hasBody ? 'POST' : 'GET')
    const capabilityAction =
      action ?? (effectiveMethod.toUpperCase() === 'GET' ? 'read' : 'write')

    // ask for JSON error bodies: some servers content-negotiate errors and
    // send plain text without this (the reference client always sends it)
    let finalHeaders: Record<string, string> = {
      accept: 'application/ld+json, application/json',
      ...headers
    }
    if (signed) {
      if (!invocationSigner) {
        throw new TypeError(
          '"invocationSigner" is required for signed requests.'
        )
      }
      finalHeaders = (await signCapabilityInvocation({
        url,
        method: effectiveMethod,
        headers: finalHeaders,
        json: json as object | undefined,
        body: typeof body === 'string' ? new TextEncoder().encode(body) : body,
        capability: (capability ??
          `urn:zcap:root:${encodeURIComponent(url)}`) as never,
        capabilityAction,
        invocationSigner
      })) as unknown as Record<string, string>
    } else if (hasBody && finalHeaders['content-type'] === undefined) {
      finalHeaders['content-type'] = 'application/json'
    }

    let finalBody: string | Uint8Array | undefined
    if (json !== undefined) {
      finalBody = JSON.stringify(json)
    } else {
      finalBody = body
    }
    if (mutateHeadersAfterSign) {
      finalHeaders = mutateHeadersAfterSign(finalHeaders)
    }
    if (mutateBodyAfterSign) {
      finalBody = mutateBodyAfterSign(finalBody)
    }

    const response = await fetch(url, {
      method: effectiveMethod,
      headers: finalHeaders,
      body: finalBody as never,
      dispatcher
    })
    const text = await response.text()
    const result: RawResponse = {
      status: response.status,
      headers: response.headers as unknown as Headers,
      text
    }
    try {
      result.json = JSON.parse(text)
    } catch {
      // non-JSON body; leave `json` undefined
    }
    return result
  }
}

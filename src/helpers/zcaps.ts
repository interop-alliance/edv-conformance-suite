/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * zcap helpers: root zcap URN synthesis and capability delegation via
 * `@interop/ezcap`'s ZcapClient (Ed25519Signature2020 delegation proofs).
 */
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { ZcapClient } from '@interop/ezcap'
import { documentLoader } from '../drivers/keys.js'
import type { IDelegatedZcap, ISigner } from '@interop/data-integrity-core'

/**
 * Returns the root zcap id for a resource URL:
 * `urn:zcap:root:<urlencoded url>`.
 *
 * @param options {object}
 * @param options.url {string} - The invocation target (e.g. the vault URL).
 *
 * @returns {string}
 */
export function rootZcapUrn({ url }: { url: string }): string {
  return `urn:zcap:root:${encodeURIComponent(url)}`
}

/**
 * Delegates a capability.
 *
 * @param options {object}
 * @param options.parentCapability {string|object} - Root zcap id (string) or
 *   delegated parent zcap (object).
 * @param options.controller {string} - The delegate (a DID or did:key key
 *   id) receiving the capability.
 * @param [options.invocationTarget] {string} - Narrowed target; required
 *   when delegating from a root zcap id.
 * @param [options.allowedActions] {string|string[]} - Attenuated actions
 *   (e.g. 'read').
 * @param [options.expires] {Date|string} - Expiry; defaults to 5 minutes
 *   from now. A past date produces an already-expired zcap (negative tests).
 * @param options.delegationSigner {ISigner} - The delegator's signer (must
 *   control the parent capability).
 *
 * @returns {Promise<IDelegatedZcap>} The signed delegated zcap.
 */
export async function delegate({
  parentCapability,
  controller,
  invocationTarget,
  allowedActions,
  expires,
  delegationSigner
}: {
  parentCapability: string | object
  controller: string
  invocationTarget?: string
  allowedActions?: string | string[]
  expires?: Date | string
  delegationSigner: ISigner
}): Promise<IDelegatedZcap> {
  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: delegationSigner,
    delegationSigner,
    documentLoader
  })
  return zcapClient.delegate({
    capability: parentCapability as never,
    controller,
    invocationTarget,
    allowedActions,
    expires
  })
}

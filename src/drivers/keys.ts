/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Fully local key material for driving an EDV server -- no WebKMS required.
 * Capability agents are did:key Ed25519 signers; the key agreement key is a
 * local X25519 pair derived from the agent's Ed25519 key; the blinding HMAC
 * is a local WebCrypto HMAC-SHA256 wrapper. The server never sees key
 * material, so these are indistinguishable from KMS-backed keys at the
 * protocol level.
 */
import * as didMethodKey from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { securityLoader } from '@interop/security-document-loader'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { constants as zcapConstants } from '@interop/zcap'
import type { ISigner } from '@interop/data-integrity-core'

const loader = securityLoader()
loader.addStatic(zcapConstants.ZCAP_CONTEXT_URL, zcapConstants.ZCAP_CONTEXT)

/** A JSON-LD document loader covering the security + zcap contexts. */
export const documentLoader = loader.build()

const didKeyDriver = didMethodKey.driver()
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey.from,
  // derive an X25519 keyAgreement key from the Ed25519 key so resolved
  // did:key documents include a keyAgreement verification method
  enableEncryptionKeyDerivation: true
})

/** A capability agent: a did:key controller plus its invocation signer. */
export interface CapabilityAgent {
  id: string
  signer: ISigner
}

export interface AgentKit {
  agent: CapabilityAgent
  keyAgreementKey: X25519KeyAgreementKey2020
}

/** A full per-vault key kit: agent, key agreement key, and blinding HMAC. */
export interface TestKit extends AgentKit {
  hmac: LocalHmac
  invocationSigner: ISigner
}

// process-wide store of public key agreement keys, resolvable by id
const keyStorage = new Map<string, object>()

/**
 * Resolves a key id to its public key document. Backed by the in-memory map
 * that `createCapabilityAgent` registers key agreement keys into.
 *
 * @param options {object}
 * @param options.id {string}
 *
 * @returns {Promise<object>} The public key document.
 */
export async function keyResolver({ id }: { id?: string }): Promise<object> {
  const key = id && keyStorage.get(id)
  if (key) {
    return key
  }
  throw new Error(`Key ${id} not found`)
}

/**
 * A local HMAC-SHA256 key for blinding indexable attributes, the conformance
 * suite's stand-in for a KMS-backed `Sha256HmacKey2019`.
 */
export class LocalHmac {
  id: string
  type: string
  algorithm: string
  key: CryptoKey

  constructor({
    id,
    type,
    algorithm,
    key
  }: {
    id: string
    type: string
    algorithm: string
    key: CryptoKey
  }) {
    this.id = id
    this.type = type
    this.algorithm = algorithm
    this.key = key
  }

  /**
   * Creates a new HMAC key with fresh random material.
   *
   * @returns {Promise<LocalHmac>}
   */
  static async create(): Promise<LocalHmac> {
    const id = `urn:uuid:${crypto.randomUUID()}`
    const type = 'Sha256HmacKey2019'
    const algorithm = 'HS256'
    const secret = new Uint8Array(32)
    crypto.getRandomValues(secret)
    const key = await crypto.subtle.importKey(
      'raw',
      secret,
      { name: 'HMAC', hash: { name: 'SHA-256' } },
      true,
      ['sign', 'verify']
    )
    return new LocalHmac({ id, type, algorithm, key })
  }

  async sign({ data }: { data: Uint8Array }): Promise<Uint8Array> {
    const signature = await crypto.subtle.sign(
      this.key.algorithm,
      this.key,
      data as BufferSource
    )
    return new Uint8Array(signature)
  }

  async verify({
    data,
    signature
  }: {
    data: Uint8Array
    signature: Uint8Array
  }): Promise<boolean> {
    return crypto.subtle.verify(
      this.key.algorithm,
      this.key,
      signature as BufferSource,
      data as BufferSource
    )
  }
}

/**
 * Creates a capability agent (did:key Ed25519 signer) plus its matching
 * X25519 key agreement key. The key agreement key's public form is registered
 * with the shared `keyResolver`.
 *
 * @returns {Promise<AgentKit>}
 */
export async function createCapabilityAgent(): Promise<AgentKit> {
  const verificationKeyPair = await Ed25519VerificationKey.generate()
  const { methodFor } = await didKeyDriver.fromKeyPair({
    verificationKeyPair
  })
  const capabilityInvocationKeyPair = methodFor({
    purpose: 'capabilityInvocation'
  })
  const signer = verificationKeyPair.signer()
  // did:key verification methods always carry id and controller
  signer.id = capabilityInvocationKeyPair.id as string
  const agent: CapabilityAgent = {
    id: capabilityInvocationKeyPair.controller as string,
    signer
  }

  const keyAgreementPublicKey = methodFor({ purpose: 'keyAgreement' })
  const keyAgreementKey =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: verificationKeyPair
    })
  keyAgreementKey.id = keyAgreementPublicKey.id as string
  keyAgreementKey.controller = keyAgreementPublicKey.controller as string
  keyStorage.set(
    keyAgreementKey.id,
    keyAgreementKey.export({ publicKey: true, includeContext: true })
  )

  return { agent, keyAgreementKey }
}

/**
 * Creates a complete per-vault key kit: capability agent, key agreement key,
 * and a fresh blinding HMAC.
 *
 * @returns {Promise<TestKit>}
 */
export async function createTestKit(): Promise<TestKit> {
  const { agent, keyAgreementKey } = await createCapabilityAgent()
  const hmac = await LocalHmac.create()
  return { agent, keyAgreementKey, hmac, invocationSigner: agent.signer }
}

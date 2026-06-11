/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite configuration for a locally running bedrock-edv-storage *test
 * harness* server (the suite's correctness baseline).
 *
 * Bedrock authorizes `POST /edvs` against a meter: the vault config must
 * carry a `meterId`, and the meter's controller must be the agent creating
 * the vault. This hook therefore creates a fresh meter (for the EDV product)
 * per provisioned vault, then defers to the default provisioning POST.
 *
 * Meter creation itself must be signed by an identity in the meter
 * service's `meterCreationAllowList`. By default that list contains
 * bedrock-app-identity's well-known development "app" identity
 * (did:key:z6MksNZwi2r6Qxjt3MYLrrZ44gs2fauzgv1dk4E372bNVjtc), whose
 * published dev seed this config uses by default. If the harness overrides
 * its app identity, export the matching multibase secret key seed as
 * BEDROCK_APP_IDENTITY_SEED.
 *
 * Usage:
 *   EDV_CONFORMANCE_TARGET=https://localhost:18443 \
 *   EDV_CONFORMANCE_CONFIG=$(pwd)/configs/bedrock.config.ts \
 *   pnpm run conformance
 *
 * Note: this requires the bedrock *test* harness (mock meter service and
 * product ids), not a production deployment.
 */
import https from 'node:https'
import { base58 } from '@scure/base'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { ZcapClient } from '@interop/ezcap'
import { defaultProvisionVault } from '../src/index.js'
import type { ProvisionVaultFn, SuiteConfig } from '../src/index.js'
import type { ISigner } from '@interop/data-integrity-core'

// bedrock-edv-storage test harness product id for the EDV service
const EDV_PRODUCT_ID = 'urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41'

// bedrock-app-identity's well-known development "app" identity seed
// (did:key:z6MksNZwi2r6Qxjt3MYLrrZ44gs2fauzgv1dk4E372bNVjtc) -- the default
// member of bedrock-meter-http's meterCreationAllowList; dev/test only
const DEFAULT_DEV_APP_SEED = 'z1AmMXgweztXscpTpxx19jsCLkPXUacTTBme2oxWGvuto9S'

const httpsAgent = new https.Agent({ rejectUnauthorized: false })

/**
 * Decodes a bedrock-style multibase secret key seed (`z...`, base58btc,
 * optionally multicodec identity-tagged) to raw 32 bytes.
 */
function decodeSeed({ seedMultibase }: { seedMultibase: string }): Uint8Array {
  if (!seedMultibase.startsWith('z')) {
    throw new Error('"BEDROCK_APP_IDENTITY_SEED" must be multibase (z...).')
  }
  const decoded = base58.decode(seedMultibase.slice(1))
  // strip a multicodec identity header (0x00 0x20) when present
  if (decoded.length === 34 && decoded[0] === 0x00 && decoded[1] === 0x20) {
    return decoded.slice(2)
  }
  if (decoded.length === 32) {
    return decoded
  }
  throw new Error('"BEDROCK_APP_IDENTITY_SEED" must decode to 32 bytes.')
}

let appIdentitySigner: Promise<ISigner> | undefined

async function getAppIdentitySigner(): Promise<ISigner> {
  if (!appIdentitySigner) {
    appIdentitySigner = (async () => {
      const seedMultibase =
        process.env.BEDROCK_APP_IDENTITY_SEED ?? DEFAULT_DEV_APP_SEED
      const seed = decodeSeed({ seedMultibase })
      const keyPair = await Ed25519VerificationKey.generate({ seed })
      const fingerprint = keyPair.fingerprint()
      keyPair.id = `did:key:${fingerprint}#${fingerprint}`
      keyPair.controller = `did:key:${fingerprint}`
      return keyPair.signer()
    })()
  }
  return appIdentitySigner
}

const provisionVault: ProvisionVaultFn = async options => {
  const { baseUrl, config } = options
  const meterSigner = await getAppIdentitySigner()
  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: meterSigner,
    agent: httpsAgent
  })
  const meterService = `${baseUrl}/meters`
  const response = (await zcapClient.write({
    url: meterService,
    json: {
      controller: config.controller,
      product: { id: EDV_PRODUCT_ID }
    }
  })) as { data: { meter: { id: string } } }
  const meterId = `${meterService}/${response.data.meter.id}`
  // IEDVConfig is open to implementation-specific members on the wire
  const withMeter = { ...config, meterId } as typeof config
  return defaultProvisionVault({ ...options, config: withMeter })
}

const config: SuiteConfig = {
  baseUrl: 'https://localhost:18443',
  provisionVault,
  features: {
    // bedrock returns {type: 'DuplicateError', ...} error bodies
    strictErrorNames: true,
    // bedrock's write body limit is 10 MB; it does not enforce the 1 MiB
    // chunk maximum
    enforcesChunkLimit: false
  },
  // the bedrock test harness uses a self-signed certificate
  tls: { rejectUnauthorized: false }
}

export default config

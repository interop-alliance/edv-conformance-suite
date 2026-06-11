/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Default vault provisioning: a plain zcap-signed `POST {edvsUrl}` invoking
 * the root zcap of the vault collection endpoint. Servers with
 * implementation-specific creation authority (e.g. Bedrock's meters) override
 * this via `SuiteConfig.provisionVault`.
 */
import type { IEDVConfig } from '@interop/data-integrity-core'
import type { ProvisionVaultFn } from './config.js'

/** An error thrown when vault provisioning fails; carries the HTTP status. */
export class ProvisioningError extends Error {
  status: number
  body?: unknown

  constructor({
    message,
    status,
    body
  }: {
    message: string
    status: number
    body?: unknown
  }) {
    super(message)
    this.name = 'ProvisioningError'
    this.status = status
    this.body = body
  }
}

export const defaultProvisionVault: ProvisionVaultFn = async ({
  edvsUrl,
  config,
  invocationSigner,
  rawRequest
}) => {
  const response = await rawRequest({
    url: edvsUrl,
    method: 'POST',
    json: config,
    invocationSigner,
    action: 'write'
  })
  if (response.status !== 201) {
    throw new ProvisioningError({
      message:
        `Vault provisioning failed: expected 201 from POST ${edvsUrl}, ` +
        `got ${response.status}: ${response.text}`,
      status: response.status,
      body: response.json
    })
  }
  if (!response.headers.get('location')) {
    throw new ProvisioningError({
      message:
        `Vault provisioning failed: 201 from POST ${edvsUrl} did ` +
        'not include a Location header.',
      status: response.status,
      body: response.json
    })
  }
  const created = response.json as IEDVConfig
  if (!created?.id) {
    throw new ProvisioningError({
      message: 'Vault provisioning failed: response body has no "id".',
      status: response.status,
      body: response.json
    })
  }
  return created
}

/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * Suite configuration: the `SuiteConfig` shape implementers provide, plus
 * `loadSuiteConfig()` which merges a config module (referenced by the
 * `EDV_CONFORMANCE_CONFIG` env var) with env-var overrides
 * (`EDV_CONFORMANCE_TARGET`, `EDV_CONFORMANCE_INSECURE_TLS`). The CLI sets
 * those env vars before starting vitest; test files call `loadSuiteConfig()`
 * in each worker process.
 */
import { pathToFileURL } from 'node:url'
import path from 'node:path'
import type { IEDVConfig, ISigner } from '@interop/data-integrity-core'
import type { RawRequestFn } from './drivers/rawHttp.js'

export interface SuiteFeatures {
  /** referenceId support (spec-optional). Default true. */
  referenceId?: boolean
  /** chunk/stream endpoints. Default true. */
  chunks?: boolean
  /** zcap revocation endpoint. Default true. */
  revocation?: boolean
  /**
   * Assert `{name: 'DuplicateError'}`-style error bodies. Default false: the
   * EDV spec does not normatively define error bodies.
   */
  strictErrorNames?: boolean
  /**
   * Assert that chunk payloads over 1 MiB are rejected (an EDV spec MUST that
   * some implementations -- including bedrock-edv-storage, whose body limit
   * is 10 MB -- do not enforce). Default false.
   */
  enforcesChunkLimit?: boolean
}

export type ProvisionVaultFn = (options: {
  baseUrl: string
  /** Absolute URL of the vault collection endpoint (baseUrl + edvsPath). */
  edvsUrl: string
  /** The draft config: controller, kak/hmac refs, sequence: 0, extras. */
  config: IEDVConfig
  invocationSigner: ISigner
  rawRequest: RawRequestFn
}) => Promise<IEDVConfig>

export interface SuiteConfig {
  /** Base URL of the server under test (the `--target` CLI option). */
  baseUrl?: string
  /** Path of the vault collection endpoint. Default '/edvs'. */
  edvsPath?: string
  /**
   * Extra properties merged into every `POST /edvs` body (e.g. Bedrock's
   * required `meterId`).
   */
  extraVaultConfig?: Record<string, unknown>
  /** Overrides the default plain zcap-signed `POST /edvs`. */
  provisionVault?: ProvisionVaultFn
  /** Optional out-of-band vault deletion hook (no EDV protocol equivalent). */
  cleanupVault?: (options: { vaultUrl: string }) => Promise<void>
  features?: SuiteFeatures
  /** TLS options; set `rejectUnauthorized: false` for self-signed certs. */
  tls?: { rejectUnauthorized?: boolean }
}

export interface ResolvedSuiteConfig {
  baseUrl: string
  edvsPath: string
  edvsUrl: string
  extraVaultConfig: Record<string, unknown>
  provisionVault?: ProvisionVaultFn
  cleanupVault?: (options: { vaultUrl: string }) => Promise<void>
  features: Required<SuiteFeatures>
  tls: { rejectUnauthorized: boolean }
}

const DEFAULT_FEATURES: Required<SuiteFeatures> = {
  referenceId: true,
  chunks: true,
  revocation: true,
  strictErrorNames: false,
  enforcesChunkLimit: false
}

let cached: Promise<ResolvedSuiteConfig> | undefined

/**
 * Loads and resolves the suite configuration for this process. The result is
 * cached; pass `reload: true` to force re-resolution (used in unit tests).
 *
 * @param options {object}
 * @param [options.reload] {boolean}
 *
 * @returns {Promise<ResolvedSuiteConfig>}
 */
export async function loadSuiteConfig({
  reload = false
}: { reload?: boolean } = {}): Promise<ResolvedSuiteConfig> {
  if (!cached || reload) {
    cached = _resolve()
  }
  return cached
}

async function _resolve(): Promise<ResolvedSuiteConfig> {
  let fileConfig: SuiteConfig = {}
  const configPath = process.env.EDV_CONFORMANCE_CONFIG
  if (configPath) {
    const moduleUrl = pathToFileURL(path.resolve(configPath)).href
    const imported = await import(moduleUrl)
    fileConfig = (imported.default ?? imported) as SuiteConfig
  }

  const baseUrl = (
    process.env.EDV_CONFORMANCE_TARGET ?? fileConfig.baseUrl
  )?.replace(/\/+$/, '')
  if (!baseUrl) {
    throw new Error(
      'No target server configured. Set EDV_CONFORMANCE_TARGET (or pass ' +
        '--target to the CLI), or provide "baseUrl" in the config file.'
    )
  }

  const edvsPath = fileConfig.edvsPath ?? '/edvs'
  const tls = { rejectUnauthorized: true, ...fileConfig.tls }
  if (process.env.EDV_CONFORMANCE_INSECURE_TLS === '1') {
    tls.rejectUnauthorized = false
  }

  return {
    baseUrl,
    edvsPath,
    edvsUrl: `${baseUrl}${edvsPath}`,
    extraVaultConfig: fileConfig.extraVaultConfig ?? {},
    provisionVault: fileConfig.provisionVault,
    cleanupVault: fileConfig.cleanupVault,
    features: { ...DEFAULT_FEATURES, ...fileConfig.features },
    tls
  }
}

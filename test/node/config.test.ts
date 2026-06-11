/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { loadSuiteConfig } from '../../src/config.js'

const ENV_VARS = [
  'EDV_CONFORMANCE_TARGET',
  'EDV_CONFORMANCE_CONFIG',
  'EDV_CONFORMANCE_INSECURE_TLS'
]
const saved = new Map(ENV_VARS.map(name => [name, process.env[name]]))

afterEach(() => {
  for (const [name, value] of saved) {
    if (value === undefined) {
      delete process.env[name]
    } else {
      process.env[name] = value
    }
  }
})

describe('loadSuiteConfig', () => {
  it('resolves from the target env var with defaults applied', async () => {
    process.env.EDV_CONFORMANCE_TARGET = 'https://edv.example/'
    delete process.env.EDV_CONFORMANCE_CONFIG
    delete process.env.EDV_CONFORMANCE_INSECURE_TLS
    const suite = await loadSuiteConfig({ reload: true })
    // trailing slash trimmed
    expect(suite.baseUrl).toBe('https://edv.example')
    expect(suite.edvsPath).toBe('/edvs')
    expect(suite.edvsUrl).toBe('https://edv.example/edvs')
    expect(suite.features).toEqual({
      referenceId: true,
      chunks: true,
      revocation: true,
      strictErrorNames: false,
      enforcesChunkLimit: false
    })
    expect(suite.tls.rejectUnauthorized).toBe(true)
    expect(suite.provisionVault).toBeUndefined()
  })

  it('throws without a target', async () => {
    delete process.env.EDV_CONFORMANCE_TARGET
    delete process.env.EDV_CONFORMANCE_CONFIG
    await expect(loadSuiteConfig({ reload: true })).rejects.toThrow(
      /No target server configured/
    )
  })

  it('merges a config module, env target, and insecure-TLS override', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'edv-conformance-'))
    const configPath = path.join(dir, 'suite.config.mjs')
    await writeFile(
      configPath,
      `export default {
        baseUrl: 'https://from-file.example',
        edvsPath: '/vaults',
        extraVaultConfig: { meterId: 'urn:meter:1' },
        features: { referenceId: false, strictErrorNames: true }
      }\n`
    )
    process.env.EDV_CONFORMANCE_CONFIG = configPath
    process.env.EDV_CONFORMANCE_TARGET = 'https://override.example'
    process.env.EDV_CONFORMANCE_INSECURE_TLS = '1'
    const suite = await loadSuiteConfig({ reload: true })
    // env target wins over the file's baseUrl
    expect(suite.baseUrl).toBe('https://override.example')
    expect(suite.edvsPath).toBe('/vaults')
    expect(suite.edvsUrl).toBe('https://override.example/vaults')
    expect(suite.extraVaultConfig).toEqual({ meterId: 'urn:meter:1' })
    expect(suite.features.referenceId).toBe(false)
    expect(suite.features.strictErrorNames).toBe(true)
    // unset features keep their defaults
    expect(suite.features.chunks).toBe(true)
    expect(suite.tls.rejectUnauthorized).toBe(false)
  })

  it('caches between calls unless reload is requested', async () => {
    process.env.EDV_CONFORMANCE_TARGET = 'https://one.example'
    delete process.env.EDV_CONFORMANCE_CONFIG
    const first = await loadSuiteConfig({ reload: true })
    process.env.EDV_CONFORMANCE_TARGET = 'https://two.example'
    const cachedResult = await loadSuiteConfig()
    expect(cachedResult).toBe(first)
    const reloaded = await loadSuiteConfig({ reload: true })
    expect(reloaded.baseUrl).toBe('https://two.example')
  })
})

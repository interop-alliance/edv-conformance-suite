#!/usr/bin/env node
/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * The `edv-conformance` CLI: resolves the target URL and (optional) config
 * module path, exports them to the vitest worker processes via env vars, and
 * runs the compiled conformance suites with vitest's programmatic API.
 *
 *   npx @interop/edv-conformance-suite --target https://edv.example \
 *     [--config ./my.config.ts] [--insecure] [--sequential] \
 *     [--reporter json --output-file report.json]
 */
import { existsSync } from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { fileURLToPath } from 'node:url'
import { startVitest } from 'vitest/node'

const HELP = `Usage: edv-conformance [options]

Runs the EDV conformance suite against a server.

Options:
  -t, --target <url>     Base URL of the EDV server under test
                          (or set "baseUrl" in the config file)
  -c, --config <path>    Path to a SuiteConfig module (.ts, .js, or .mjs)
  -k, --insecure         Accept self-signed TLS certificates
      --sequential       Run suite files one at a time (for servers that
                          rate-limit vault provisioning)
  -r, --reporter <name>  Vitest reporter (repeatable; e.g. default, json)
      --output-file <p>  Write machine-readable reporter output to a file
  -h, --help             Show this help

The target server accumulates vaults across runs (the EDV protocol has no
vault deletion); run against an ephemeral or dev instance.
`

async function main() {
  const { values } = parseArgs({
    options: {
      target: { type: 'string', short: 't' },
      config: { type: 'string', short: 'c' },
      insecure: { type: 'boolean', short: 'k', default: false },
      sequential: { type: 'boolean', default: false },
      reporter: { type: 'string', short: 'r', multiple: true },
      'output-file': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false }
    }
  })

  if (values.help) {
    process.stdout.write(HELP)
    return
  }
  if (!values.target && !values.config) {
    process.stderr.write(
      'Error: provide --target <url> and/or --config <path>.\n\n' + HELP
    )
    process.exitCode = 1
    return
  }

  // hand the resolved settings to the vitest worker processes
  if (values.target) {
    process.env.EDV_CONFORMANCE_TARGET = values.target
  }
  if (values.config) {
    const configPath = path.resolve(values.config)
    if (!existsSync(configPath)) {
      process.stderr.write(`Error: config file not found: ${configPath}\n`)
      process.exitCode = 1
      return
    }
    process.env.EDV_CONFORMANCE_CONFIG = configPath
  }
  if (values.insecure) {
    process.env.EDV_CONFORMANCE_INSECURE_TLS = '1'
  }

  // the suites live next to this file: dist/suites/ in the published
  // package, src/suites/ when running from a source checkout
  const here = path.dirname(fileURLToPath(import.meta.url))
  const packageRoot = path.dirname(here)
  const suitesDir = path.join(here, 'suites')
  if (!existsSync(suitesDir)) {
    process.stderr.write(`Error: suites directory not found: ${suitesDir}\n`)
    process.exitCode = 1
    return
  }
  const include = [
    path
      .join(path.relative(packageRoot, suitesDir), '**/*.test.{js,ts}')
      .replaceAll(path.sep, '/')
  ]

  const options: Record<string, unknown> = {
    root: packageRoot,
    config: false,
    include,
    watch: false,
    passWithNoTests: false,
    fileParallelism: !values.sequential,
    testTimeout: 60_000,
    hookTimeout: 60_000
  }
  if (values.reporter?.length) {
    options.reporters = values.reporter
  }
  if (values['output-file']) {
    options.outputFile = values['output-file']
  }

  const vitest = await startVitest('test', [], options)
  await vitest.close()
}

main().catch(err => {
  process.stderr.write(`${err?.stack ?? err}\n`)
  process.exitCode = 1
})

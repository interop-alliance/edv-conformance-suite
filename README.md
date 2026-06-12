# EDV Conformance Suite _(@interop/edv-conformance-suite)_

> A conformance test suite for
> [Encrypted Data Vault (EDV)](https://digitalbazaar.github.io/encrypted-data-vaults/)
> servers, runnable against any implementation over HTTPS.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Configuration](#configuration)
- [Test Catalog](#test-catalog)
- [Caveats and Preconditions](#caveats-and-preconditions)
- [Contribute](#contribute)
- [License](#license)

## Background

This suite treats the server under test as a black box reachable over HTTPS and
exercises the documented EDV protocol: routes, status codes, headers, body
shapes, sequence/uniqueness invariants, and zcap authorization (delegation,
attenuation, revocation).

It uses a hybrid driver:

- **`@interop/edv-client`** for crypto- and zcap-heavy happy paths (real JWE
  encryption, HMAC-blinded index building);
- **a thin raw-HTTP layer** for wire-format assertions (status codes,
  `Location`/`ETag`/`cache-control` headers, malformed-input rejection, bodies
  mutated after signing).

All key material is generated locally per run (did:key Ed25519 capability
agents, X25519 key agreement keys, WebCrypto blinding HMACs) -- no WebKMS or
other key server is required. The server never sees key material, so local keys
are indistinguishable from KMS-backed ones at the protocol level.

## Install

- Node.js 24+ is required.

Run directly via npx (no install):

```sh
npx @interop/edv-conformance-suite --target https://edv.example
```

Or install for development:

```sh
git clone https://github.com/interop-alliance/edv-conformance-suite.git
cd edv-conformance-suite
pnpm install
```

## Usage

### CLI

```sh
npx @interop/edv-conformance-suite --target https://edv.example \
  [--config ./my.config.ts] [--insecure] [--sequential] \
  [--reporter json --output-file report.json]
```

| Option           | Description                                                      |
| ---------------- | ---------------------------------------------------------------- |
| `-t, --target`   | Base URL of the server under test                                |
| `-c, --config`   | Path to a `SuiteConfig` module (`.ts`, `.js`, or `.mjs`)         |
| `-k, --insecure` | Accept self-signed TLS certificates                              |
| `--sequential`   | Run suite files one at a time (rate-limited vault provisioning)  |
| `-r, --reporter` | Vitest reporter (repeatable); `json` for machine-readable output |
| `--output-file`  | Write reporter output to a file                                  |

### Dev mode (from a source checkout)

```sh
EDV_CONFORMANCE_TARGET=https://localhost:18443 \
EDV_CONFORMANCE_CONFIG=$(pwd)/configs/example.config.ts \
pnpm run conformance
```

### Against bedrock-edv-storage (the reference baseline)

Start MongoDB (e.g. `docker run -d -p 27017:27017 mongo:8`), then start the
bedrock-edv-storage test harness as a persistent server (from its `test/`
directory, after `npm install`):

```sh
node --preserve-symlinks server.js
```

(`server.js` -- not `test.js`, which runs the harness's own mocha suite -- loads
`test.config.js` first, which is what configures the test database and lets the
server's internal loopback HTTPS calls accept its self-signed certificate.
Restarting the server drops the test database, cleaning up accumulated vaults.)

and run the suite against it:

```sh
EDV_CONFORMANCE_TARGET=https://localhost:18443 \
EDV_CONFORMANCE_CONFIG=$(pwd)/configs/bedrock.config.ts \
pnpm run conformance
```

Bedrock authorizes vault creation against a _meter_, so
`configs/bedrock.config.ts` provisions a fresh meter per vault. Meter creation
is signed with bedrock-app-identity's well-known development "app" identity (the
default member of the harness's `meterCreationAllowList`); if the harness
overrides its app identity, export the matching multibase secret key seed as
`BEDROCK_APP_IDENTITY_SEED`. This requires the bedrock _test_ harness (mock
meter service and product ids), not a production deployment.

## Configuration

A config module default-exports a `SuiteConfig`:

```ts
import type { SuiteConfig } from '@interop/edv-conformance-suite'

const config: SuiteConfig = {
  baseUrl: 'https://edv.example', // or pass --target
  edvsPath: '/edvs', // default
  // merged into every POST /edvs body (e.g. a server-required meterId)
  extraVaultConfig: {},
  // overrides the default plain zcap-signed POST /edvs
  // provisionVault: async ({ baseUrl, edvsUrl, config, invocationSigner,
  //   rawRequest }) => { ... return createdConfig },
  features: {
    referenceId: true, // spec-optional feature
    chunks: true,
    revocation: true,
    strictErrorNames: false, // assert {name: 'DuplicateError'}-style bodies
    enforcesChunkLimit: false // assert the 1 MiB chunk maximum is enforced
  },
  tls: { rejectUnauthorized: true }
}

export default config
```

See `configs/example.config.ts` and `configs/bedrock.config.ts`.

Feature-gated tests report as skipped, distinctly from failures. Where the spec
leaves status codes ambiguous (e.g. 401 vs 403 for unsigned requests), tests
accept an explicit `statusOneOf` set, annotated in the test source.

## Test Catalog

| Suite               | Covers                                                                                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `01-vault-config`   | create (201 + Location, server-assigned id, `sequence: 0`), get, update sequence rules, referenceId lookup/uniqueness/immutability                                  |
| `02-documents`      | insert/upsert/get (Location, ETag, cache-control), duplicate ids, invalid ids, round-trip decrypt, client-side tombstone delete, no HTTP DELETE                     |
| `03-sequence`       | previous+1 update rule, boundary-value table (0 .. MAX_SAFE_INTEGER-2), negative/non-integer/overflow rejection                                                     |
| `04-query-index`    | equals/has queries, compound indexes, multi-valued attributes, count, limit/hasMore, `returnDocuments: false`, POST-but-read zcap action, unique blinded attributes |
| `05-chunks-streams` | encrypted stream write/read, raw chunk store/get/delete, chunk/doc sequence lockstep, missing-chunk errors, 1 MiB limit (gated)                                     |
| `06-authz-zcap`     | root zcap invocation, unsigned/foreign-agent rejection, delegation, expiry, allowedAction and invocationTarget attenuation, revocation incl. two-hop chains         |
| `07-wire-format`    | malformed JSON, incomplete JWEs, post-signing body mutation, content-type, id formats, error-name spot checks (gated)                                               |

Levels: `[MUST]` / `[SHOULD]` / `[OPTIONAL]` annotations in each test title.
Behavior derived from the reference implementation rather than spec text (e.g.
insert-with-nonzero-sequence) is annotated in the test source.

## Caveats and Preconditions

- **No vault deletion exists in the EDV protocol**, so conformance runs
  accumulate vaults on the target. Run against an ephemeral or dev instance (a
  `cleanupVault` hook is available for servers with an out-of-band delete).
  Per-run key material means runs never collide.
- **did:key support is assumed**: the suite signs with did:key Ed25519 agents. A
  server restricting resolvable DID methods will fail authorization across the
  board.
- **Key ids are did:key / urn:uuid URIs** (not KMS URLs) in vault configs;
  servers must accept opaque string key references.
- The error-body `name` assertions are opt-in (`features.strictErrorNames`)
  because the spec does not define error bodies; bodies carrying either `name`
  or `type` are accepted.

## Contribute

PRs accepted. See [CONTRIBUTING.md](CONTRIBUTING.md) for editor setup (Prettier,
ESLint, and EditorConfig) and how it maps to CI.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT License](LICENSE.md) © 2026 Interop Alliance.

# hugin-pow

Proof of work for Hugin messages, shared by the Hugin apps and relays. It handles relay jobs,
nonces, targets, finding and checking shares, the `pow.auth` signature, and CN-Turtle-Lite v2
mining on all cores through
[kryptokrona-crypto](https://github.com/kryptokrona/kryptokrona-crypto) 2.x.

## Install

```bash
npm install hugin-pow kryptokrona-crypto
```

`kryptokrona-crypto` (`^2.0.0`) is an optional peer dependency. Only `hugin-pow/native` loads
it. Everything else is plain JavaScript.

## Platforms

| platform | hashing | entry points |
|---|---|---|
| Node.js ≥ 20, Electron | kryptokrona-crypto Node-API addon | all |
| React Native | kryptokrona-crypto native module | `hugin-pow/job`, `hugin-pow/mine`, `hugin-pow/native` |
| Bare | a backend passed in by the host | all except `hugin-pow/native` |

## Mining a share

```js
const { createHasher } = require('hugin-pow/native')
const { JobTracker } = require('hugin-pow/mine')

const backend = await createHasher()        // checks a known hash first
const tracker = new JobTracker()

relay.on('job', (job) => tracker.set(job))   // every job the relay sends

const found = await tracker.mine({ backend, timeBudgetMs: 90000 })
if (found) send(found.job, found.share)      // share: { job_id, nonce, result }
```

`JobTracker` keeps the jobs a relay handed out. Jobs of the newest block can be used, and jobs
of the block before stay usable for 15 seconds after a new block arrives. `tracker.mine` restarts
when a job of a new block comes in and only returns a share that can still be sent. Jobs above
`maxDifficulty` (default 2000) are not mined. For one job without a tracker, use
`mineShare({ job, backend, signal, timeBudgetMs })`.

On React Native, pass the module so the bundler includes it:

```js
import * as kryptokronaCrypto from 'kryptokrona-crypto'
import { createHasher } from 'hugin-pow/native'

const backend = await createHasher({ crypto: kryptokronaCrypto })
```

### Backends

A backend is an object with one or both of these functions:

```ts
findShare({ blobHex, targetHex, startNonce, maxAttempts }) // kryptokrona-crypto findPowShare shape
hash(blobHex): Promise<string>                              // CN-Turtle-Lite v2, 64 hex characters
```

In Bare, which cannot load kryptokrona-crypto, the host forwards these calls to a side that can,
for example the React Native side of an app:

```js
const backend = {
  findShare: (req) => host.request({ type: 'pow-find-share', ...req }),
  hash: (blobHex) => host.request({ type: 'pow-hash', blobHex })   // optional
}
const found = await tracker.mine({ backend })
```

## Checking proof of work (relays)

```js
const { createHasher } = require('hugin-pow/native')
const { verifyPow } = require('hugin-pow/verify')
const { postAuthContext } = require('hugin-pow/auth')

const res = await verifyPow({
  pow: message.pow,                  // { version: 2, job, shares, auth }
  hash: message.hash,
  timestamp: message.timestamp,
  context: postAuthContext(kind, cipher),
  hasher: await createHasher(),
  minDifficulty: 200
})
// { ok: true } or { ok: false, reason }
```

## Modules

- `hugin-pow/job`: blob, nonce and target helpers (`getNonceOffset`, `insertNonce`, `parseTarget`,
  `meetsTarget`, `difficultyToTarget`, `targetToDifficulty`, `validatePowJob`, `verifyShare`,
  `findShare`, `normalizeShare`, `powField`, ...).
- `hugin-pow/auth`: the `powsig:v2` signature (`buildPowAuth`, `verifyPowAuth`,
  `powAuthPayload`, `postAuthContext`, `registerAuthContext`).
- `hugin-pow/mine`: `JobTracker`, `mineShare`, `checkBackend`, `isStaleAnswer`, `StopController`.
- `hugin-pow/verify`: `verifyPow`.
- `hugin-pow/native`: `createHasher` (alias `createNativeBackend`).
- `hugin-pow`: everything above except `hugin-pow/native`.

## Tests

```bash
npm test             # Node.js (kryptokrona-crypto tests run when it is installed)
npm run test:bare    # Bare (needs bare installed)
```

## License

MIT

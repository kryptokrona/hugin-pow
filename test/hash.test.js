'use strict'

const test = require('brittle')
const { REFERENCE_VECTOR, REFERENCE_MISMATCH, checkReference } = require('../lib/reference.js')
const { checkBackend } = require('../lib/mine.js')
const { createHasher } = require('../lib/native.js')
const { insertNonce, verifyShare, difficultyToTarget, meetsTarget } = require('../lib/job.js')
const { CN, V, fakeHash, loadKryptokronaCrypto } = require('./helpers.js')

const kc = loadKryptokronaCrypto()

test('known-answer vectors: file shape, reference vector is the first', (t) => {
  t.is(CN.algorithm, 'cn_turtle_lite_slow_hash_v2')
  t.is(CN.vectors.length, 200)
  t.alike(Object.keys(CN).sort(), ['algorithm', 'description', 'vectors'])
  for (const v of CN.vectors) {
    t.ok(/^[0-9a-f]+$/.test(v.blob) && v.blob.length % 2 === 0)
    t.ok(/^[0-9a-f]{64}$/.test(v.hash))
  }
  t.alike({ blob: CN.vectors[0].blob, hash: CN.vectors[0].hash }, { ...REFERENCE_VECTOR })
})

test('reference check: a hash that gives the known answer passes, others are refused', async (t) => {
  await checkReference(fakeHash)
  await checkReference(async (b) => (await fakeHash(b)).toUpperCase())
  await t.exception(checkReference(async () => '00'.repeat(32)), new RegExp(REFERENCE_MISMATCH))
  await t.exception(checkReference(async () => { throw new Error('no backend') }), new RegExp(REFERENCE_MISMATCH))
  await t.exception(checkReference(async () => 42), new RegExp(REFERENCE_MISMATCH))

  await checkBackend({ hash: fakeHash })
  await checkBackend({ findShare: async () => null }) // nothing to check without hash
  const bad = { hash: async () => 'ab'.repeat(32) }
  await t.exception(checkBackend(bad), /hash backend does not match the reference vectors/)
  await t.exception(checkBackend(bad), /hash backend does not match the reference vectors/, 'remembered')
  await t.exception(checkBackend(null), /backend must be an object/)
})

test('createHasher: refuses a module without native findPowShare', async (t) => {
  await t.exception(createHasher({ crypto: {} }), /kryptokrona-crypto \^2\.0\.0 is required/)
  function Crypto() {}
  Crypto.isNative = false
  await t.exception(createHasher({ crypto: { Crypto, findPowShare: async () => null } }), /no native backend/)
})

test('createHasher: a module whose hash disagrees is refused', async (t) => {
  function Crypto() {}
  Crypto.prototype.cn_turtle_lite_slow_hash_v2 = async () => '11'.repeat(32)
  Crypto.isNative = true
  await t.exception(createHasher({ crypto: { Crypto, findPowShare: async () => null } }), /hash backend does not match the reference vectors/)
})

test('createHasher: a module that agrees gives hash and findShare (arguments passed through)', async (t) => {
  const calls = []
  function Crypto() {}
  Crypto.prototype.cn_turtle_lite_slow_hash_v2 = fakeHash
  Crypto.isNative = true
  Crypto.type = 4
  const backend = await createHasher({
    crypto: {
      Crypto,
      CryptoType: { NAPI: 4, REACTNATIVE: 5 },
      findPowShare: async (...args) => {
        calls.push(args)
        return null
      }
    }
  })
  t.is(backend.name, 'napi')
  t.is(await backend.hash(REFERENCE_VECTOR.blob), REFERENCE_VECTOR.hash)
  t.is(await backend.findShare({ blobHex: 'aa', targetHex: 'bb', startNonce: -1, maxAttempts: 840 }), null)
  t.alike(calls, [['aa', 'bb', 0xffffffff, 840, 0, 0]])
})

test('kryptokrona-crypto: every known-answer vector and the hugin-relay share', { skip: !kc }, async (t) => {
  const backend = await createHasher({ crypto: kc })
  for (const v of CN.vectors) t.is(await backend.hash(v.blob), v.hash)
  t.is(await backend.hash(V.pow.hashing_blob), V.pow.result)
  t.ok(await verifyShare(V.pow.job, V.pow.nonce, V.pow.result, backend))
})

test('kryptokrona-crypto: createHasher() without options loads the package', { skip: !kc }, async (t) => {
  const backend = await createHasher()
  t.ok(backend.name === 'napi' || backend.name === 'native')
  t.is(await backend.hash(REFERENCE_VECTOR.blob), REFERENCE_VECTOR.hash)
})

test('kryptokrona-crypto: findPowShare finds a share at difficulty 16 that verifies', { skip: !kc }, async (t) => {
  const backend = await createHasher({ crypto: kc })
  const job = { job_id: 'low', blob: V.pow.job.blob, target: difficultyToTarget(16) }
  const res = await backend.findShare({ blobHex: job.blob, targetHex: job.target, startNonce: 1000, maxAttempts: 840 * 8 })
  t.ok(res && res.nonce, 'share found')
  t.ok(meetsTarget(res.result, job.target))
  t.is(await backend.hash(insertNonce(job.blob, res.nonce).blobHex), res.result)
  t.ok(res.threads >= 1)
})

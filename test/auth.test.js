'use strict'

const test = require('brittle')
const b4a = require('b4a')
const auth = require('../lib/auth.js')
const { verifyPow } = require('../lib/verify.js')
const { V } = require('./helpers.js')

const SHARE = { job_id: V.pow.job.job_id, nonce: V.pow.nonce, result: V.pow.result }
const stubHash = async (blobHex) => (blobHex === V.pow.hashing_blob ? V.pow.result : 'ff'.repeat(32))

test('powsig:v2 auth: hugin-relay vectors (keypear signatures)', (t) => {
  const keyPair = auth.keyPairFromSeed(b4a.alloc(32, 7))
  for (const v of V.auth) {
    const payload = auth.powAuthPayload({ hash: v.hash, timestamp: v.timestamp, share: SHARE, context: v.context })
    t.is(payload, v.payload, 'payload')
    const a = auth.buildPowAuth({ hash: v.hash, timestamp: v.timestamp, shares: [SHARE], context: v.context, keyPair })
    t.is(a.pub, v.pub, 'pub')
    t.is(a.sig, v.sig, 'sig (byte-identical to keypear)')
    t.is(a.nonce, SHARE.nonce)
    t.is(auth.verifyPowAuth({ auth: a, hash: v.hash, timestamp: v.timestamp, shares: [SHARE], context: v.context }), v.verifies)
    t.absent(auth.verifyPowAuth({ auth: a, hash: v.hash, timestamp: v.timestamp + 1, shares: [SHARE], context: v.context }), 'other timestamp')
    t.absent(auth.verifyPowAuth({ auth: a, hash: v.hash, timestamp: v.timestamp, shares: [SHARE], context: v.context + 'x' }), 'other context')
    t.absent(auth.verifyPowAuth({ auth: { ...a, pub: 'zz' }, hash: v.hash, timestamp: v.timestamp, shares: [SHARE], context: v.context }), 'bad pub')
    t.absent(auth.verifyPowAuth({ auth: a, hash: v.hash, timestamp: v.timestamp, shares: [], context: v.context }), 'no shares')
  }
})

test('buildPowAuth: a fresh key each time, lowercase nonce, null without shares', (t) => {
  const shares = [{ job_id: 'job-1', nonce: 'A1B2C3D4', result: V.pow.result.toUpperCase() }]
  const a = auth.buildPowAuth({ hash: 'ab'.repeat(32), timestamp: 1, shares, context: 'c' })
  const b = auth.buildPowAuth({ hash: 'ab'.repeat(32), timestamp: 1, shares, context: 'c' })
  t.not(a.pub, b.pub)
  t.is(a.nonce, 'a1b2c3d4')
  t.ok(auth.verifyPowAuth({ auth: a, hash: 'ab'.repeat(32), timestamp: 1, shares, context: 'c' }))
  t.is(auth.buildPowAuth({ hash: 'x', timestamp: 1, shares: [], context: '' }), null)
})

test('auth contexts', (t) => {
  t.is(auth.postAuthContext('dm', 'cafe'), 'dm:cafe')
  t.is(auth.postAuthContext('', 'cafe'), 'cafe')
  t.is(auth.registerAuthContext('[1]'), '[1]')
  t.is(auth.registerAuthContext(undefined), '')
})

test('verifyPow: the relay check of a pow field', async (t) => {
  const keyPair = auth.keyPairFromSeed(b4a.alloc(32, 7))
  const v = V.auth[0]
  const a = auth.buildPowAuth({ hash: v.hash, timestamp: v.timestamp, shares: [SHARE], context: v.context, keyPair })
  const pow = { version: 2, job: V.pow.job, shares: [SHARE], auth: a }
  const check = (p, extra = {}) => verifyPow({ pow: p, hash: v.hash, timestamp: v.timestamp, context: v.context, hasher: stubHash, ...extra })

  t.alike(await check(pow), { ok: true })
  t.alike(await check(pow, { hasher: { hash: stubHash } }), { ok: true }, 'a backend object')
  t.alike(await check({ ...pow, version: 1 }), { ok: false, reason: 'invalid_pow' })
  t.alike(await check({ ...pow, job: { ...V.pow.job, target: 'ff' } }), { ok: false, reason: 'invalid_target' })
  t.alike(await check(pow, { minDifficulty: 200 }), { ok: false, reason: 'target_too_easy' }, 'job target ffffffff is difficulty 1')
  t.alike(await check({ ...pow, shares: [] }), { ok: false, reason: 'invalid_shares' })
  t.alike(await check({ ...pow, shares: [SHARE, SHARE] }), { ok: false, reason: 'invalid_share' }, 'same nonce twice')
  t.alike(await check({ ...pow, shares: [{ ...SHARE, job_id: 'other' }] }), { ok: false, reason: 'invalid_share' })
  t.alike(await check(pow, { timestamp: v.timestamp + 1 }), { ok: false, reason: 'invalid_auth' })
  t.alike(await check(pow, { hasher: async () => 'ff'.repeat(32) }), { ok: false, reason: 'invalid_share' }, 'hash does not give the result')
})

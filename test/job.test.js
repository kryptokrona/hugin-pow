'use strict'

const test = require('brittle')
const pow = require('../lib/job.js')
const hu = require('./fixtures/hugin-utils.js')
const { V, fakeHash } = require('./helpers.js')

/** Stand-in for CN-Turtle-Lite v2: the real hash for the vector blob, a high hash otherwise. */
const stubHash = async (blobHex) => (blobHex === V.pow.hashing_blob ? V.pow.result : 'ff'.repeat(32))

test('nonce offset, nonce insertion and prev_id: hugin-relay vectors', (t) => {
  t.is(pow.getNonceOffset(V.pow.job.blob), V.pow.nonce_offset)
  t.is(pow.getNonceOffset(V.pow.short_blob), V.pow.short_nonce_offset)
  t.is(pow.insertNonce(V.pow.job.blob, V.pow.nonce).blobHex, V.pow.hashing_blob)
  t.is(pow.insertNonce(V.pow.job.blob, V.pow.nonce).offset, V.pow.nonce_offset)
  t.is(pow.extractPrevIdFromBlob(V.pow.job.blob), V.pow.prev_id)
  t.is(pow.extractPrevIdFromBlob(V.pow.short_blob), V.pow.short_prev_id)
  t.is(pow.extractPrevIdFromBlob('0500ff'), V.pow.bad_prev_id)
})

test('hugin-utils 0.4.0: same nonce offset, insertNonce and prev_id on sample jobs', (t) => {
  const blobs = [
    V.pow.job.blob,
    V.pow.short_blob,
    '0500ff',
    '05',
    'ffffffffffffffffffffff' + '00'.repeat(40),
    '0e0e' + 'ffffffff0f' + '11'.repeat(32) + '00000000' + '22'.repeat(40),
    '8001' + '02' + '03' + '44'.repeat(32) + '00000000'
  ]
  const nonces = ['00000000', 'deadbeef', 'a1b2c3d4', 'ffffffff']
  for (const blob of blobs) {
    t.is(pow.extractPrevIdFromBlob(blob), hu.extractPrevIdFromBlob(blob), 'prev_id ' + blob.slice(0, 12))
    if (!blob.length) continue
    t.is(pow.getNonceOffset(blob), hu.getNonceOffset(blob), 'offset ' + blob.slice(0, 12))
    if (blob.length < 86) continue
    for (const n of nonces) t.alike(pow.insertNonce(blob, n), hu.insertNonce(blob, n), 'insertNonce ' + n)
  }
})

test('meetsTarget and checkHash: hugin-relay target table, same as hugin-utils', (t) => {
  for (const v of V.pow.meets_target) {
    t.is(pow.meetsTarget(v.hash, v.target), v.meets, v.target + ' ' + v.hash.slice(48))
    t.is(pow.meetsTarget(v.hash, v.target), hu.meetsTarget(v.hash, v.target))
    t.is(pow.checkHash(v.hash, v.target), hu.checkHash(v.hash, v.target))
  }
  t.absent(pow.meetsTarget('zz', '01000000'), 'not hex')
  t.absent(pow.meetsTarget('00'.repeat(31), '01000000'), 'short hash')
})

test('minTargetHex: same as hugin-utils', (t) => {
  const targets = ['ffffffff', '37894100', '14ae4701', '00000000', '', 'e8030000']
  for (const a of targets) for (const b of targets) t.is(pow.minTargetHex(a, b), hu.minTargetHex(a, b), a + ' ' + b)
})

test('target and difficulty: relay app difficulties and hugin-p2p vectors', (t) => {
  t.is(pow.difficultyToTarget(1000), '37894100')
  t.is(pow.difficultyToTarget(200), '14ae4701')
  t.is(pow.targetToDifficulty('37894100'), 1000)
  t.is(pow.targetToDifficulty('14ae4701'), 200)
  t.is(pow.targetToDifficulty('ffffffff'), 1)
  t.is(pow.difficultyToTarget(1), 'ffffffff')
  t.is(pow.difficultyToTarget(0), 'ffffffff', 'below 1 counts as 1')
  t.is(pow.targetToDifficulty('00000000'), 0, 'zero target: no work')
  t.is(pow.parseTarget('00000000'), null)
  t.is(pow.parseTarget('37894100'), 0xffffffffffffffffn / 1000n)
  t.is(pow.parseTarget('0102030405060708'), 0x0807060504030201n, '8-byte target as is')
  t.is(pow.parseTarget('zz'), null)
  t.is(pow.nonceToHex(0xd4c3b2a1), 'a1b2c3d4', 'little-endian')
  t.is(pow.nonceFromHex('a1b2c3d4'), 0xd4c3b2a1)
  t.is(pow.nonceFromHex('a1b2'), null)
  for (const d of [1, 2, 7, 100, 200, 1000, 10000, 123457]) t.is(pow.targetToDifficulty(pow.difficultyToTarget(d)), d, 'round trip ' + d)
})

test('verifyShare: hugin-relay share, same as hugin-utils', async (t) => {
  t.is(await pow.verifyShare(V.pow.job, V.pow.nonce, V.pow.result, stubHash), V.pow.verify_share)
  t.is(await pow.verifyShare(V.pow.job, 'a1b2c3d5', V.pow.result, stubHash), V.pow.verify_share_wrong_nonce)
  t.is(
    await pow.verifyShare(V.pow.job, V.pow.nonce, V.pow.result, stubHash),
    await hu.verifyShare(V.pow.job, V.pow.nonce, V.pow.result, stubHash)
  )
  t.is(await pow.verifyShare(V.pow.job, V.pow.nonce, V.pow.result.toUpperCase(), stubHash), false, 'result must match the hash as returned')
  t.is(await pow.verifyShare({ ...V.pow.job, target: 'zz' }, V.pow.nonce, V.pow.result, stubHash), false)
  t.is(await pow.verifyShare(V.pow.job, V.pow.nonce, V.pow.result, { hash: stubHash }), true, 'a backend object')
  await t.exception.all(pow.verifyShare(V.pow.job, V.pow.nonce, V.pow.result))
})

test('isValidPowJob: same as hugin-utils', (t) => {
  const jobs = [
    V.pow.job,
    null,
    'job',
    { ...V.pow.job, job_id: 5 },
    { ...V.pow.job, job_id: 'j'.repeat(33) },
    { ...V.pow.job, blob: 'xyz' },
    { ...V.pow.job, blob: V.pow.job.blob + 'a' },
    { ...V.pow.job, target: 'ffff' },
    { ...V.pow.job, target: 'gggggggg' }
  ]
  for (const job of jobs) t.is(pow.isValidPowJob(job), hu.isValidPowJob(job), JSON.stringify(job).slice(0, 40))
})

test('validatePowJob: reasons', (t) => {
  t.alike(pow.validatePowJob(V.pow.job), { ok: true })
  t.alike(pow.validatePowJob(null), { ok: false, reason: 'invalid_job' })
  t.alike(pow.validatePowJob({ ...V.pow.job, job_id: 5 }), { ok: false, reason: 'invalid_job_id' })
  t.alike(pow.validatePowJob({ ...V.pow.job, blob: 'xyz' }), { ok: false, reason: 'invalid_blob' })
  t.alike(pow.validatePowJob({ ...V.pow.job, blob: V.pow.job.blob + 'a' }), { ok: false, reason: 'invalid_blob_len' })
  t.alike(pow.validatePowJob({ ...V.pow.job, blob: 'aa'.repeat(1025) }), { ok: false, reason: 'blob_too_large' })
  t.alike(pow.validatePowJob({ ...V.pow.job, target: 'ffff' }), { ok: false, reason: 'invalid_target' })
  t.alike(pow.validatePowJob({ ...V.pow.job, blob: V.pow.short_blob.slice(0, 74) }), { ok: false, reason: 'nonce_out_of_bounds' })
})

test('validatePowJob: maxDifficulty', (t) => {
  const at = (d) => ({ ...V.pow.job, target: pow.difficultyToTarget(d) })
  t.is(pow.DEFAULT_MAX_DIFFICULTY, 2000)
  t.alike(pow.validatePowJob(at(1e9)), { ok: true }, 'no limit without maxDifficulty')
  t.alike(pow.validatePowJob(at(200), { maxDifficulty: 2000 }), { ok: true })
  t.alike(pow.validatePowJob(at(2000), { maxDifficulty: 2000 }), { ok: true }, 'the limit itself is mined')
  t.alike(pow.validatePowJob(at(2001), { maxDifficulty: 2000 }), { ok: false, reason: 'job_too_hard' })
  t.alike(pow.validatePowJob(at(1e9), { maxDifficulty: 2000 }), { ok: false, reason: 'job_too_hard' })
  t.alike(pow.validatePowJob({ ...V.pow.job, target: '00000000' }, { maxDifficulty: 2000 }), { ok: true }, 'zero target: no work')
  t.alike(pow.validatePowJob(at(1e9), { maxDifficulty: Infinity }), { ok: true })
  t.alike(pow.validatePowJob({ ...V.pow.job, target: 'ffff' }, { maxDifficulty: 2000 }), { ok: false, reason: 'invalid_target' }, 'shape first')
})

test('findShare: same share as hugin-utils findShare', async (t) => {
  const job = { job_id: 'j', blob: V.pow.job.blob, target: '01000000' }
  const winning = 'a1b2c3d4' // nonce 0xd4c3b2a1 little-endian
  const hash = async (blobHex) =>
    blobHex === pow.insertNonce(job.blob, winning).blobHex ? '33'.repeat(24) + '00'.repeat(8) : '33'.repeat(24) + 'ff'.repeat(8)
  const start = 0xd4c3b2a1 - 5
  const share = await pow.findShare({ job, hash, startNonce: start, maxAttempts: 10, timeBudgetMs: 60000 })
  t.alike(share, { job_id: 'j', nonce: winning, result: '33'.repeat(24) + '00'.repeat(8) })
  const theirs = await hu.findShare({ job, startNonce: start, hashFn: hash, hashesPerSecond: 10, timeBudgetMs: 1000 })
  t.alike(share, theirs, 'same share as hugin-utils findShare')
  t.is(await pow.findShare({ job, hash, startNonce: start, maxAttempts: 3, timeBudgetMs: 60000 }), null, 'gives up')
  t.is(await pow.findShare({ job: { job_id: 'j', blob: 'zz', target: '01000000' }, hash, maxAttempts: 3 }), null, 'invalid job')

  const easy = { job_id: 'e', blob: V.pow.job.blob, target: pow.difficultyToTarget(8) }
  const found = await pow.findShare({ job: easy, hash: fakeHash, startNonce: 0, maxAttempts: 2000, timeBudgetMs: 60000 })
  t.ok(found, 'finds a share at difficulty 8')
  t.ok(await pow.verifyShare(easy, found.nonce, found.result, fakeHash))
})

test('normalizeShare and powField', (t) => {
  t.alike(pow.normalizeShare({ job_id: 7, nonce: 'AB', result: 'CD' }), { job_id: '7', nonce: 'ab', result: 'cd' })
  t.is(pow.normalizeShare({ nonce: 1 }), null)
  t.alike(pow.powField({ job: 1, shares: 2, auth: 3 }), { version: 2, job: 1, shares: 2, auth: 3 })
})

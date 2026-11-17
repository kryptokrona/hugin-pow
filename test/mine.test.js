'use strict'

const test = require('brittle')
const { mineShare, StopController, SLICE_ROUND } = require('../lib/mine.js')
const { createHasher } = require('../lib/native.js')
const { verifyShare, difficultyToTarget, nonceFromHex } = require('../lib/job.js')
const { V, fakeHash, fakeFindShare, fakeClock, tick, never, loadKryptokronaCrypto } = require('./helpers.js')

const kc = loadKryptokronaCrypto()
const lowJob = (id = 'low', d = 16) => ({ job_id: id, blob: V.pow.job.blob, target: difficultyToTarget(d) })

test('mineShare with findShare: finds a share at low difficulty that verifies', async (t) => {
  const job = lowJob()
  const progress = []
  const share = await mineShare({
    job,
    backend: { findShare: fakeFindShare, hash: fakeHash },
    startNonce: 0,
    onProgress: (p) => progress.push(p)
  })
  t.ok(share)
  t.is(share.job_id, 'low')
  t.ok(await verifyShare(job, share.nonce, share.result, fakeHash))
  t.ok(progress.length >= 1)
  t.ok(progress[0].hashes >= 1)
  t.is(progress[0].threads, 1)
})

test('mineShare with findShare: consecutive slices cover consecutive nonce ranges', async (t) => {
  const calls = []
  const clock = fakeClock()
  const backend = {
    findShare: async (req) => {
      calls.push(req)
      clock.t += 100
      return calls.length < 4 ? { hashes_performed: req.maxAttempts, threads: 8 } : null
    }
  }
  const res = await mineShare({ job: lowJob(), backend, startNonce: 0xfffffff0, timeBudgetMs: 500, now: clock.now })
  t.is(res, null, 'time budget used up')
  t.is(calls.length, 5)
  for (const c of calls) {
    t.is(c.blobHex, V.pow.job.blob)
    t.is(c.targetHex, difficultyToTarget(16))
    t.is(c.maxAttempts % SLICE_ROUND, 0, 'a multiple of 840')
  }
  t.is(calls[0].startNonce, 0xfffffff0)
  for (let i = 1; i < calls.length; i++) {
    t.is(calls[i].startNonce, (calls[i - 1].startNonce + calls[i - 1].maxAttempts) >>> 0, 'next range starts where the last ended')
  }
})

test('mineShare with findShare: slices follow the measured hash rate', async (t) => {
  const calls = []
  const clock = fakeClock()
  const backend = {
    findShare: async (req) => {
      calls.push(req.maxAttempts)
      clock.t += (req.maxAttempts / 40000) * 1000 // 40000 H/s
      return { hashes_performed: req.maxAttempts, threads: 8 }
    }
  }
  await mineShare({ job: lowJob(), backend, startNonce: 0, timeBudgetMs: 3000, sliceMs: 250, now: clock.now })
  t.is(calls[0], 840, 'first slice: 1000 H/s assumed')
  t.ok(Math.max(...calls) >= 8400, 'later slices: about 250 ms at the measured rate')
  t.ok(Math.max(...calls) <= 840 * 13, 'not more than about 250 ms')
})

test('mineShare with findShare: a share whose result does not match the hash is refused', async (t) => {
  const job = { job_id: 'j', blob: V.pow.job.blob, target: 'ffffffff' }
  const backend = {
    findShare: async () => ({ nonce: '00000000', result: '00'.repeat(32), hashes_performed: 1, threads: 1 }),
    hash: fakeHash
  }
  await t.exception(mineShare({ job, backend }), /hash backend does not match the reference vectors/)
  const offTarget = { findShare: async () => ({ nonce: '00000000', result: 'ff'.repeat(32) }) }
  await t.exception(mineShare({ job: lowJob(), backend: offTarget }), /hash backend does not match the reference vectors/)
})

test('mineShare: refuses a backend whose hash disagrees, and invalid input', async (t) => {
  await t.exception(
    mineShare({ job: lowJob(), backend: { findShare: fakeFindShare, hash: async () => '00'.repeat(32) } }),
    /hash backend does not match the reference vectors/
  )
  await t.exception(mineShare({ job: { job_id: 'x', blob: 'zz', target: 'ffffffff' }, backend: { hash: fakeHash } }), /invalid job/)
  await t.exception(mineShare({ job: lowJob(), backend: {} }), /backend must have/)
})

test('mineShare with only hash: one nonce at a time', async (t) => {
  const job = lowJob('one', 8)
  const share = await mineShare({ job, backend: { hash: fakeHash }, startNonce: 5 })
  t.ok(share)
  t.ok(nonceFromHex(share.nonce) >= 5)
  t.ok(await verifyShare(job, share.nonce, share.result, fakeHash))
  const none = await mineShare({ job: lowJob('hard', 1e9), backend: { hash: fakeHash }, maxAttempts: 50 })
  t.is(none, null, 'gives up after maxAttempts')
})

test('mineShare: maxDifficulty refuses a harder job before any hashing', async (t) => {
  let calls = 0
  const backend = { findShare: async () => { calls++; return null } }
  await t.exception(() => mineShare({ job: lowJob('h', 2001), backend, maxDifficulty: 2000 }), /job_too_hard/)
  t.is(calls, 0)
  const share = await mineShare({ job: lowJob('ok', 16), backend: { findShare: fakeFindShare, hash: fakeHash }, maxDifficulty: 2000 })
  t.ok(share)
})

test('mineShare: stops at once when the signal aborts during a slice', async (t) => {
  const ctl = new StopController()
  let calls = 0
  const backend = {
    findShare: () => {
      calls++
      return never()
    }
  }
  const p = mineShare({ job: lowJob(), backend, signal: ctl.signal })
  await tick()
  t.is(calls, 1)
  ctl.abort('new_block')
  t.is(await p, null)
  t.is(calls, 1, 'no further slice')
})

test('mineShare: a share that arrives after the abort is dropped', async (t) => {
  const ctl = new StopController()
  const backend = {
    findShare: async (req) => {
      ctl.abort('new_block')
      return fakeFindShare(req)
    }
  }
  t.is(await mineShare({ job: lowJob(), backend, signal: ctl.signal, startNonce: 0 }), null)
})

test('mineShare: an aborted signal mines nothing; AbortController works too', async (t) => {
  const ctl = new StopController()
  ctl.abort()
  let called = false
  t.is(await mineShare({ job: lowJob(), backend: { findShare: async () => { called = true } }, signal: ctl.signal }), null)
  t.absent(called)

  if (typeof AbortController === 'function') {
    const ac = new AbortController()
    const p = mineShare({ job: lowJob(), backend: { findShare: never }, signal: ac.signal })
    await tick()
    ac.abort()
    t.is(await p, null)
  }
})

test('mineShare with only hash: stops when the signal aborts', async (t) => {
  const ctl = new StopController()
  let hashes = 0
  const backend = {
    hash: async (b) => {
      hashes++
      if (hashes === 20) ctl.abort()
      return hashes === 1 ? fakeHash(b) : 'ff'.repeat(32) // reference check, then no share
    }
  }
  t.is(await mineShare({ job: lowJob(), backend, signal: ctl.signal }), null)
  t.is(hashes, 20)
})

test('kryptokrona-crypto: mineShare finds a share at difficulty 32 and stops on abort', { skip: !kc }, async (t) => {
  const backend = await createHasher({ crypto: kc })
  const job = lowJob('native', 32)
  const share = await mineShare({ job, backend, timeBudgetMs: 60000 })
  t.ok(share)
  t.ok(await verifyShare(job, share.nonce, share.result, backend))

  const ctl = new StopController()
  const hard = { job_id: 'hard', blob: V.pow.job.blob, target: difficultyToTarget(1e9) }
  const started = Date.now()
  const p = mineShare({ job: hard, backend, signal: ctl.signal, timeBudgetMs: 60000 })
  setTimeout(() => ctl.abort('new_block'), 300)
  t.is(await p, null)
  t.ok(Date.now() - started < 2000, 'returned right after the abort')
})

'use strict'

const test = require('brittle')
const { JobTracker, StopController, isStaleAnswer } = require('../lib/mine.js')
const { difficultyToTarget, extractPrevIdFromBlob } = require('../lib/job.js')
const { fakeHash, fakeFindShare, jobOf, p2poolJobOf, fakeClock, tick, never } = require('./helpers.js')

const SHARE = (job) => ({ job_id: job.job_id, nonce: 'A1B2C3D4', result: 'CD'.repeat(32) })

test('JobTracker without height: blocks by prev_id, previous block for 15 s, older jobs stale', (t) => {
  const clock = fakeClock(1000)
  const jt = new JobTracker({ now: clock.now })
  const a1 = jobOf('a1', '11')
  const a2 = jobOf('a2', '11')
  const b1 = jobOf('b1', '22')
  const c1 = jobOf('c1', '33')

  t.is(jt.current, null)
  t.is(jt.status(a1), 'stale', 'unknown job')
  t.ok(jt.set(a1))
  t.absent(jt.set(a1), 'same job again')
  t.absent(jt.set({ job_id: 'bad', blob: 'zz', target: 'ffffffff' }), 'invalid job')
  t.is(jt.status(a1), 'current')

  const blockA = jt.signal
  t.ok(jt.set(a2))
  t.is(jt.current, a2)
  t.absent(blockA.aborted, 'a new job of the same block does not stop searches')
  t.is(jt.status(a1), 'current', 'every job of the current block is usable')

  clock.t = 5000
  t.ok(jt.set(b1))
  t.ok(blockA.aborted, 'a new block stops searches on the old one')
  t.absent(jt.signal.aborted)
  t.is(jt.status(b1), 'current')
  t.is(jt.status(a1), 'previous')
  t.is(jt.status(a2), 'previous')

  clock.t = 5000 + 15000
  t.is(jt.status(a2), 'previous', 'still usable 15 s after the new block')
  t.ok(jt.accept(a2, SHARE(a2)))
  clock.t = 5000 + 15001
  t.is(jt.status(a2), 'stale', 'dropped after 15 s')
  t.is(jt.accept(a2, SHARE(a2)), null)
  t.alike(jt.accept(b1, SHARE(b1)), { job_id: 'b1', nonce: 'a1b2c3d4', result: 'cd'.repeat(32) })

  clock.t = 30000
  jt.set(c1)
  t.is(jt.status(b1), 'previous')
  clock.t = 30001
  t.ok(jt.set(jobOf('c2', '33')))
  t.is(jt.status(a1), 'stale', 'two blocks back')
  t.is(jt.status(b1), 'previous')
  t.is(jt.generation, 5)
})

test('JobTracker: accept checks the share belongs to the job', (t) => {
  const jt = new JobTracker()
  const a = jobOf('a', '11')
  jt.set(a)
  t.is(jt.accept(a, { job_id: 'other', nonce: 'aa', result: 'bb' }), null)
  t.is(jt.accept(a, null), null)
  t.is(jt.accept(jobOf('x', '11'), SHARE(jobOf('x', '11'))), null, 'a job never set')
})

test('JobTracker: a job of the previous block set again is a block change', (t) => {
  const clock = fakeClock()
  const jt = new JobTracker({ now: clock.now })
  jt.set(jobOf('a', '11'))
  jt.set(jobOf('b', '22'))
  const s = jt.signal
  clock.t = 1000
  jt.set(jobOf('a2', '11'))
  t.ok(s.aborted)
  t.is(jt.status(jobOf('b', '22')), 'previous')
  t.is(jt.status(jobOf('a2', '11')), 'current')
  t.is(jt.status(jobOf('a', '11')), 'stale', 'jobs two block changes back are forgotten')
})

test('JobTracker: clear forgets jobs and stops searches', (t) => {
  const jt = new JobTracker()
  const a = jobOf('a', '11')
  jt.set(a)
  const s = jt.signal
  jt.clear()
  t.ok(s.aborted)
  t.is(jt.current, null)
  t.is(jt.status(a), 'stale')
})

test('JobTracker.mine: a new block stops the search and the new job is mined', async (t) => {
  const jt = new JobTracker()
  const d = difficultyToTarget(16)
  const a = jobOf('a', '11', d)
  const b = jobOf('b', '22', d)
  jt.set(a)
  const seen = []
  const backend = {
    hash: fakeHash,
    findShare: (req) => {
      seen.push(req.blobHex)
      return req.blobHex === a.blob ? never() : fakeFindShare(req)
    }
  }
  const p = jt.mine({ backend })
  await tick()
  await tick()
  t.alike(seen, [a.blob], 'mining job a')
  jt.set(b)
  const res = await p
  t.is(res.job, b)
  t.is(res.share.job_id, 'b')
  t.is(seen[seen.length - 1], b.blob)
})

test('JobTracker.mine: waits for a job, stops on its own signal', async (t) => {
  const jt = new JobTracker()
  const backend = { findShare: fakeFindShare, hash: fakeHash }
  const p = jt.mine({ backend })
  await tick()
  jt.set(jobOf('late', '44', difficultyToTarget(8)))
  const res = await p
  t.is(res.job.job_id, 'late')

  const ctl = new StopController()
  const q = jt.mine({ backend: { findShare: never }, signal: ctl.signal })
  await tick()
  ctl.abort()
  t.is(await q, null)

  const empty = new JobTracker()
  const ctl2 = new StopController()
  const r = empty.mine({ backend, signal: ctl2.signal })
  await tick()
  ctl2.abort()
  t.is(await r, null, 'no job and aborted')
})

test('JobTracker with height (p2pool jobs, zero prev_id): blocks by main-chain height', (t) => {
  const clock = fakeClock(0)
  const jt = new JobTracker({ now: clock.now })
  const h100a = p2poolJobOf('1', 100, '5a')
  const h100b = p2poolJobOf('2', 100, '6b')
  const h101 = p2poolJobOf('3', 101, '7c')
  const h102 = p2poolJobOf('4', 102, '8d')
  t.is(extractPrevIdFromBlob(h100a.blob), '00'.repeat(32), 'p2pool blobs carry a zero prev_id')

  t.ok(jt.set(h100a))
  const s100 = jt.signal
  t.ok(jt.set(h100b))
  t.absent(s100.aborted, 'same height: no restart')
  t.is(jt.status(h100a), 'current')
  t.is(jt.current, h100b)

  clock.t = 1000
  t.ok(jt.set(h101))
  t.ok(s100.aborted, 'new height: searches stop')
  t.is(jt.status(h101), 'current')
  t.is(jt.status(h100a), 'previous')
  t.is(jt.status(h100b), 'previous')
  clock.t = 16000
  t.is(jt.status(h100b), 'previous', '15 s after the new height arrived')
  clock.t = 16001
  t.is(jt.status(h100b), 'stale')

  clock.t = 20000
  const s101 = jt.signal
  jt.set(h102)
  t.ok(s101.aborted)
  t.is(jt.status(h101), 'previous')
  t.is(jt.status(h100a), 'stale', 'two heights back')

  const jump = new JobTracker({ now: clock.now })
  jump.set(h100a)
  jump.set(h102)
  t.is(jump.status(h100a), 'stale', 'a jump of two heights leaves no previous block')

  const str = new JobTracker({ now: clock.now })
  str.set(p2poolJobOf('s1', '100'))
  str.set(p2poolJobOf('s2', 101, '6b'))
  t.is(str.status(p2poolJobOf('s1', '100')), 'previous', 'a decimal string height counts too')
})

test('JobTracker without height and with a zero prev_id: every new job is a new block', (t) => {
  const clock = fakeClock(0)
  const jt = new JobTracker({ now: clock.now })
  const a = p2poolJobOf('a', undefined, '5a')
  const b = p2poolJobOf('b', undefined, '6b')
  const c = p2poolJobOf('c', undefined, '7c')
  jt.set(a)
  const sa = jt.signal
  clock.t = 100
  jt.set(b)
  t.ok(sa.aborted, 'restart on every new job')
  t.is(jt.status(b), 'current')
  t.is(jt.status(a), 'previous', 'the job before stays usable for 15 s')
  clock.t = 15101
  t.is(jt.status(a), 'stale')
  clock.t = 20000
  jt.set(c)
  t.is(jt.status(b), 'previous')
  t.is(jt.status(a), 'stale')
  const sc = jt.signal
  t.absent(jt.set(c), 'the same job again')
  t.absent(sc.aborted)
})

test('JobTracker.handle: job pushes and stale_job answers', (t) => {
  const jt = new JobTracker()
  const j1 = p2poolJobOf('1', 100)
  const j2 = p2poolJobOf('2', 101, '6b')
  t.alike(jt.handle({ type: 'job', job: j1 }), { jobSet: true, stale: false })
  t.alike(jt.handle({ success: false, reason: 'stale_job', id: 7 }), { jobSet: false, stale: true })
  t.alike(jt.handle({ type: 'job', job: j2, id: 7 }), { jobSet: true, stale: false }, 'the current job after the answer')
  t.is(jt.current, j2)
  t.alike(jt.handle({ success: false, reason: 'stale_job', job: j2 }), { jobSet: false, stale: true }, 'a job in the answer itself')
  t.alike(jt.handle(null), { jobSet: false, stale: false })
  t.ok(isStaleAnswer({ success: false, reason: 'pool_reject', rejects: [{ reason: 'stale_job', error: null }] }))
  t.absent(isStaleAnswer({ success: false, reason: 'cooldown' }))
  t.absent(isStaleAnswer({ success: true }))
})

test('JobTracker.mine: a p2pool job of a new height stops the search', async (t) => {
  const jt = new JobTracker()
  const d = difficultyToTarget(16)
  const a = p2poolJobOf('a', 500, '5a', d)
  const b = p2poolJobOf('b', 501, '6b', d)
  jt.set(a)
  const backend = { hash: fakeHash, findShare: (req) => (req.blobHex === a.blob ? never() : fakeFindShare(req)) }
  const p = jt.mine({ backend })
  await tick()
  await tick()
  jt.set(b)
  const res = await p
  t.is(res.job, b)
})

test('JobTracker: jobs above maxDifficulty are not mined', (t) => {
  const jt = new JobTracker()
  t.is(jt.maxDifficulty, 2000, 'default')
  const ok = jobOf('ok', '11', difficultyToTarget(200))
  const hard1 = jobOf('h1', '22', difficultyToTarget(2001))
  const hard2 = jobOf('h2', '33', difficultyToTarget(1e6))
  t.ok(jt.set(ok))
  const s = jt.signal
  t.absent(jt.set(hard1))
  t.is(jt.lastRefusal, 'job_too_hard')
  t.is(jt.tooHardJobs, 1)
  t.ok(jt.isTooHard(hard1))
  t.absent(jt.isTooHard(ok))
  t.absent(jt.set(hard2))
  t.absent(jt.set(hard2))
  t.is(jt.tooHardJobs, 3, 'counted in a row')
  t.is(jt.current, ok, 'the current job stays')
  t.absent(s.aborted, 'a refused job does not stop searches')
  t.is(jt.status(hard1), 'stale')
  t.absent(jt.set({ job_id: 'bad', blob: 'zz', target: 'ffffffff' }))
  t.is(jt.lastRefusal, 'invalid_blob')
  t.is(jt.tooHardJobs, 3, 'an invalid job does not reset the count')
  t.ok(jt.set(jobOf('ok2', '44', difficultyToTarget(16))))
  t.is(jt.tooHardJobs, 0, 'reset by the next job set')
  t.is(jt.lastRefusal, null)
  jt.set(hard1)
  jt.clear()
  t.is(jt.tooHardJobs, 0, 'reset by clear')

  const custom = new JobTracker({ maxDifficulty: 5000 })
  t.ok(custom.set(jobOf('c', '55', difficultyToTarget(4000))))
  t.absent(custom.set(jobOf('d', '66', difficultyToTarget(5001))))
  const open = new JobTracker({ maxDifficulty: Infinity })
  t.ok(open.set(jobOf('e', '77', difficultyToTarget(1e9))), 'Infinity: no limit')
  t.is(new JobTracker({ maxDifficulty: 0 }).maxDifficulty, 2000, 'invalid value: default')
})

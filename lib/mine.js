'use strict'

const { PowError } = require('./errors.js')

// Mining a share for one job, and the job tracker that stops a search when a new block's job
// arrives. Node.js, Electron, React Native and Bare: no host APIs and no native code here; the
// hashing comes from a backend the caller passes in.
//
// A backend is an object with one or both of
//
//   findShare({ blobHex, targetHex, startNonce, maxAttempts })
//       -> Promise<{ nonce, result, hashes_performed?, threads? } | { hashes_performed?, threads? } | null>
//     searches `maxAttempts` nonces from `startNonce` (32-bit, wrapping) on all cores. This is
//     the shape of kryptokrona-crypto 2.x `findPowShare` (Node-API addon and React Native
//     module): the attempts are split into equal contiguous parts, one per worker thread, and the
//     first share found stops the others. `null` (or an object without `nonce`) means no share in
//     that slice.
//   hash(blobHex) -> Promise<hex>
//     CN-Turtle-Lite v2 of one blob.
//
// hugin-pow/native builds both from kryptokrona-crypto. A host without kryptokrona-crypto (the
// Bare worklet of hugin-native) passes functions that call into the app (for example its
// `pow-find-share` request).
//
// When a backend has `hash`, it must give the reference answer before the first search
// (`hash backend does not match the reference vectors` otherwise), and every share that
// `findShare` reports is hashed again and must give the same result.

const {
  POW_MAX_JOB_TIME_MS,
  DEFAULT_MAX_DIFFICULTY,
  validatePowJob,
  insertNonce,
  nonceToHex,
  meetsTarget,
  normalizeShare,
  isHexString,
  extractPrevIdFromBlob
} = require('./job.js')
const { checkReference, referenceMismatch } = require('./reference.js')
const { StopController, anySignal, whenAborted, isSignal } = require('./signal.js')

/** Slices are a multiple of this (1..8 worker threads all split it into equal parts). */
const SLICE_ROUND = 840
/** Target length of one `findShare` call: how long a replaced job may keep the cores busy. */
const DEFAULT_SLICE_MS = 250
/** Hash rate assumed until the first slice has been timed. */
const DEFAULT_HASHES_PER_SECOND = 1000
/** Most attempts in one `findShare` call (kryptokrona-crypto's limit). */
const MAX_SLICE_ATTEMPTS = 5000000
/** How long a job of the previous block stays usable after the new block's first job arrived. */
const PREVIOUS_BLOCK_GRACE_MS = 15000

const ABORTED = Symbol('aborted')

const checkedBackends = new WeakMap()

function isAborted(signal) {
  return isSignal(signal) && signal.aborted === true
}

function randomNonce() {
  return (Math.random() * 0x100000000) >>> 0
}

function yieldToHost() {
  return new Promise((resolve) => setTimeout(resolve, 0))
}

/**
 * Resolves when the backend may be used for mining: its `hash` gives the reference answer
 * (checked once per backend object). A backend without `hash` resolves at once.
 * Rejects with `hash backend does not match the reference vectors`.
 */
function checkBackend(backend) {
  if (!backend || typeof backend !== 'object') {
    return Promise.reject(new PowError('backend must be an object with findShare and/or hash'))
  }
  if (typeof backend.hash !== 'function') return Promise.resolve()
  let p = checkedBackends.get(backend)
  if (!p) {
    p = checkReference((blobHex) => backend.hash(blobHex))
    p.catch(() => {})
    checkedBackends.set(backend, p)
  }
  return p
}

function needBackend(backend) {
  if (!backend || (typeof backend.findShare !== 'function' && typeof backend.hash !== 'function')) {
    throw new PowError('mineShare: backend must have findShare({ blobHex, targetHex, startNonce, maxAttempts }) or hash(blobHex)')
  }
}

/**
 * Searches a share for `job` until one is found, `timeBudgetMs` has passed, `maxAttempts`
 * nonces were tried, or `signal` aborts.
 *
 * With `backend.findShare` the search runs in slices of about `sliceMs` each (attempts sized
 * from the measured hash rate, a multiple of 840); consecutive slices cover consecutive,
 * disjoint nonce ranges. With only `backend.hash` it hashes one nonce at a time on this thread.
 *
 * When `signal` aborts the promise resolves `null` at once (a running native slice ends on its
 * own within about `sliceMs`, and its result is dropped): a share is never returned after the
 * signal aborted.
 *
 * @param {object} opts
 * @param {{ job_id: string, blob: string, target: string }} opts.job
 * @param {{ findShare?: Function, hash?: Function }} opts.backend
 * @param {AbortSignal|object} [opts.signal]
 * @param {number} [opts.timeBudgetMs]  default 90 s
 * @param {number} [opts.maxAttempts]
 * @param {number} [opts.startNonce]  default random
 * @param {number} [opts.sliceMs]  default 250
 * @param {number} [opts.hashesPerSecond]  rate assumed for the first slice (default 1000)
 * @param {number} [opts.maxDifficulty]  a job above this difficulty is refused (`job_too_hard`);
 *   default: no limit (`JobTracker` passes its own)
 * @param {(p: { hashes, hashesPerSecond, threads, elapsedMs }) => void} [opts.onProgress]
 * @param {() => number} [opts.now]
 * @returns {Promise<{ job_id: string, nonce: string, result: string } | null>}
 */
async function mineShare({
  job,
  backend,
  signal,
  timeBudgetMs = POW_MAX_JOB_TIME_MS,
  maxAttempts = Infinity,
  startNonce,
  sliceMs = DEFAULT_SLICE_MS,
  hashesPerSecond = DEFAULT_HASHES_PER_SECOND,
  maxDifficulty,
  onProgress,
  now = Date.now
} = {}) {
  const v = validatePowJob(job, { maxDifficulty })
  if (!v.ok) throw new PowError('mineShare: invalid job (' + v.reason + ')')
  needBackend(backend)
  if (isAborted(signal)) return null

  const stop = whenAborted(signal)
  const stopped = stop.promise.then(() => ABORTED)
  try {
    const checked = checkBackend(backend).then(() => null)
    if ((await Promise.race([checked, stopped])) === ABORTED) return null
    const ctx = {
      job,
      backend,
      signal,
      stopped,
      timeBudgetMs,
      maxAttempts,
      nonce: startNonce !== undefined ? startNonce >>> 0 : randomNonce(),
      sliceMs: Math.max(1, sliceMs),
      rate: Math.max(1, hashesPerSecond),
      progress: typeof onProgress === 'function' ? onProgress : null,
      now
    }
    return typeof backend.findShare === 'function' ? await mineSlices(ctx) : await mineOneByOne(ctx)
  } finally {
    stop.cancel()
  }
}

function report(ctx, data) {
  if (!ctx.progress) return
  try {
    ctx.progress(data)
  } catch {}
}

async function mineSlices(ctx) {
  const { job, backend, signal, stopped, now } = ctx
  const start = now()
  let total = 0
  let rate = ctx.rate
  let nonce = ctx.nonce
  for (;;) {
    if (isAborted(signal)) return null
    const elapsed = now() - start
    if (elapsed >= ctx.timeBudgetMs || total >= ctx.maxAttempts) return null

    const wanted = (rate * Math.min(ctx.sliceMs, ctx.timeBudgetMs - elapsed)) / 1000
    let attempts = Math.min(MAX_SLICE_ATTEMPTS, Math.max(SLICE_ROUND, Math.ceil(wanted / SLICE_ROUND) * SLICE_ROUND))
    if (Number.isFinite(ctx.maxAttempts)) attempts = Math.max(1, Math.min(attempts, ctx.maxAttempts - total))

    const t0 = now()
    const running = Promise.resolve().then(() =>
      backend.findShare({ blobHex: job.blob, targetHex: job.target, startNonce: nonce, maxAttempts: attempts })
    )
    running.catch(() => {})
    const out = await Promise.race([running, stopped])
    if (out === ABORTED || isAborted(signal)) return null
    const ms = now() - t0

    const res = out && typeof out === 'object' ? out : null
    const found = !!res && typeof res.nonce === 'string' && typeof res.result === 'string'
    const performed = res && Number.isFinite(res.hashes_performed) && res.hashes_performed > 0 ? res.hashes_performed : 0
    const hashes = performed || (found ? 1 : attempts)
    total += hashes
    if (!found && ms >= 20) rate = Math.max(1, (rate + hashes / (ms / 1000)) / 2)
    report(ctx, {
      hashes: total,
      hashesPerSecond: Math.round(rate),
      threads: res && Number.isFinite(res.threads) ? res.threads : undefined,
      elapsedMs: now() - start
    })

    if (found) {
      const share = normalizeShare({ job_id: job.job_id, nonce: res.nonce, result: res.result })
      const ok = await shareMatches(ctx, share)
      if (ok === ABORTED || isAborted(signal)) return null
      if (!ok) throw referenceMismatch()
      return share
    }
    nonce = (nonce + Math.max(attempts, performed)) >>> 0
  }
}

/** The share has the right shape, meets the target and (with `hash`) hashes to its result. */
async function shareMatches(ctx, share) {
  const { job, backend, stopped } = ctx
  if (!share || share.nonce.length !== 8 || !isHexString(share.nonce)) return false
  if (share.result.length !== 64 || !isHexString(share.result)) return false
  if (!meetsTarget(share.result, job.target)) return false
  if (typeof backend.hash !== 'function') return true
  const { blobHex } = insertNonce(job.blob, share.nonce)
  const again = Promise.resolve().then(() => backend.hash(blobHex))
  again.catch(() => {})
  const out = await Promise.race([again, stopped])
  if (out === ABORTED) return ABORTED
  return String(out).toLowerCase() === share.result
}

async function mineOneByOne(ctx) {
  const { job, backend, signal, stopped, now } = ctx
  const start = now()
  let lastReport = start
  let total = 0
  let nonce = ctx.nonce
  for (;;) {
    if (isAborted(signal)) return null
    if (now() - start >= ctx.timeBudgetMs || total >= ctx.maxAttempts) return null
    const nonceHex = nonceToHex(nonce)
    const { blobHex } = insertNonce(job.blob, nonceHex)
    const running = Promise.resolve().then(() => backend.hash(blobHex))
    running.catch(() => {})
    const out = await Promise.race([running, stopped])
    if (out === ABORTED || isAborted(signal)) return null
    total++
    const result = String(out).toLowerCase()
    if (meetsTarget(result, job.target)) return { job_id: String(job.job_id), nonce: nonceHex, result }
    nonce = (nonce + 1) >>> 0
    const t = now()
    if (t - lastReport >= 1000) {
      lastReport = t
      const secs = (t - start) / 1000
      report(ctx, { hashes: total, hashesPerSecond: Math.round(secs > 0 ? total / secs : 0), threads: 1, elapsedMs: t - start })
    }
    if (total % 64 === 0) await yieldToHost()
  }
}

// ---------------------------------------------------------------------------------------------
// job tracker

function sameJob(a, b) {
  return !!a && !!b && a.job_id === b.job_id && a.blob === b.blob
}

const ZERO_PREV_ID = '00'.repeat(32)

/** A job's `height` as a non-negative integer (a number or a decimal string), else null. */
function heightOf(job) {
  const h = typeof job.height === 'string' && /^[0-9]+$/.test(job.height) ? Number(job.height) : job.height
  return Number.isSafeInteger(h) && h >= 0 ? h : null
}

/**
 * The block a job belongs to: its main-chain `height` when the job has one (p2pool jobs through
 * xkrd), else the non-zero prev_id of its blob, else the job itself (every new job counts as a
 * new block).
 */
function blockOf(job) {
  const height = heightOf(job)
  if (height !== null) return { key: 'h:' + height, height }
  const prevId = extractPrevIdFromBlob(job.blob)
  if (prevId && prevId !== ZERO_PREV_ID) return { key: 'p:' + prevId, height: null }
  return { key: 'j:' + job.job_id + ':' + job.blob, height: null }
}

/** True for a relay answer that refused a post or registration as `stale_job`. */
function isStaleAnswer(res) {
  if (!res || typeof res !== 'object') return false
  if (res.reason === 'stale_job') return true
  return Array.isArray(res.rejects) && res.rejects.some((r) => r === 'stale_job' || (r && r.reason === 'stale_job'))
}

/**
 * The current job and which jobs a share may still be handed out for, by the relay's rule:
 *
 * - every job of the newest block is `current`;
 * - when the first job of a new block arrives, the jobs of the block before it stay usable
 *   (`previous`) for `graceMs` (15 s);
 * - every other job is `stale`: its shares are dropped and the new job is mined.
 *
 * A job's block is its `height` (xkrd hands out p2pool jobs with the main-chain height; their
 * blobs carry a zero prev_id). The previous block is then `height - 1`. A job without a height
 * is placed by the non-zero prev_id of its blob; a job with neither counts as a new block of its
 * own, so the search restarts on every such job and the job before it stays usable for 15 s.
 *
 * `signal` belongs to the newest block and aborts when a job of another block is set, which
 * stops every `mineShare` started with it. A new job of the same block replaces `current`
 * without stopping searches (their shares stay valid).
 *
 * Jobs whose difficulty is above `maxDifficulty` (default 2000) are not mined: `set` refuses
 * them (`lastRefusal` = `'job_too_hard'`) and keeps the current job. `tooHardJobs` counts such
 * jobs in a row (reset by the next job that is set, and by `clear()`), so a caller can move to
 * another relay after a few of them.
 */
class JobTracker {
  /**
   * @param {object} [opts]
   * @param {number} [opts.graceMs]  default 15000
   * @param {() => number} [opts.now]
   * @param {number} [opts.maxJobs]  jobs remembered (default 16)
   * @param {number} [opts.maxDifficulty]  highest job difficulty mined (default 2000;
   *   `Infinity` for no limit)
   */
  constructor({ graceMs = PREVIOUS_BLOCK_GRACE_MS, now = Date.now, maxJobs = 16, maxDifficulty = DEFAULT_MAX_DIFFICULTY } = {}) {
    this.graceMs = graceMs
    this.maxJobs = Math.max(2, maxJobs)
    this.maxDifficulty = typeof maxDifficulty === 'number' && maxDifficulty > 0 ? maxDifficulty : DEFAULT_MAX_DIFFICULTY
    /** Jobs above `maxDifficulty` set in a row (0 after a job that was set, and after `clear()`). */
    this.tooHardJobs = 0
    /** Why the last `set` refused a job (`validatePowJob` reasons, `'job_too_hard'`), or null. */
    this.lastRefusal = null
    this.generation = 0
    this._now = now
    this._current = null
    this._jobs = []
    this._block = null
    this._previousBlock = null
    this._blockSince = 0
    this._controller = new StopController()
    this._waiters = new Set()
  }

  /** The job to mine, or null. */
  get current() {
    return this._current
  }

  /** Aborts when a job of a new block replaces the current one (or on `clear()`). */
  get signal() {
    return this._controller.signal
  }

  /**
   * Sets a job the relay handed out (a `job` push, also the one that follows a `stale_job`
   * answer). Returns false for an invalid job, a job above `maxDifficulty` or the job already
   * current. A job of another block aborts `signal` and starts the previous block's 15 s.
   */
  set(job) {
    const v = validatePowJob(job, { maxDifficulty: this.maxDifficulty })
    if (!v.ok) {
      this.lastRefusal = v.reason
      if (v.reason === 'job_too_hard') this.tooHardJobs++
      return false
    }
    this.lastRefusal = null
    this.tooHardJobs = 0
    if (sameJob(this._current, job)) return false
    const { key, height } = blockOf(job)
    let replaced = null
    if (key !== this._block) {
      const old = this._block
      this._block = key
      this._previousBlock = height !== null ? (height > 0 ? 'h:' + (height - 1) : null) : old
      this._blockSince = this._now()
      this._jobs = this._jobs.filter((e) => e.key === this._previousBlock)
      replaced = this._controller
      this._controller = new StopController()
    }
    this._jobs = this._jobs.filter((e) => !sameJob(e.job, job))
    this._jobs.push({ job, key })
    if (this._jobs.length > this.maxJobs) this._jobs.splice(0, this._jobs.length - this.maxJobs)
    this._current = job
    this.generation++
    if (replaced) replaced.abort('new_block')
    const waiters = [...this._waiters]
    this._waiters.clear()
    for (const resolve of waiters) resolve(job)
    return true
  }

  /**
   * Feeds a relay message: a message with a `job` object (the `job` push, which also follows a
   * `stale_job` answer) is passed to `set`. Returns `{ jobSet, stale }`: whether a job was set,
   * and whether the message is a `stale_job` answer (mine the relay's current job and send
   * again).
   */
  handle(message) {
    const job = message && typeof message === 'object' && message.job && typeof message.job === 'object' ? message.job : null
    return { jobSet: job ? this.set(job) : false, stale: isStaleAnswer(message) }
  }

  /** `'current'` (a job of the newest block), `'previous'` (the block before it, within graceMs) or `'stale'`. */
  status(job) {
    if (!job) return 'stale'
    const entry = this._jobs.find((e) => sameJob(e.job, job))
    if (!entry) return 'stale'
    if (entry.key === this._block) return 'current'
    if (entry.key === this._previousBlock && this._now() - this._blockSince <= this.graceMs) return 'previous'
    return 'stale'
  }

  /** True when `job` is above `maxDifficulty` (it is not mined). */
  isTooHard(job) {
    return validatePowJob(job, { maxDifficulty: this.maxDifficulty }).reason === 'job_too_hard'
  }

  /** True when a share of `job` may be handed out. */
  isUsable(job) {
    return this.status(job) !== 'stale'
  }

  /**
   * The share (normalized) when it belongs to `job` and `job` is still usable, else null: what a
   * caller may put into a post or registration.
   */
  accept(job, share) {
    if (!this.isUsable(job)) return null
    const s = normalizeShare(share)
    if (!s || s.job_id !== String(job.job_id)) return null
    return s
  }

  /** Forgets every job and aborts `signal`. */
  clear() {
    const old = this._controller
    this._controller = new StopController()
    this._current = null
    this._jobs = []
    this._block = null
    this._previousBlock = null
    this._blockSince = 0
    this.tooHardJobs = 0
    this.lastRefusal = null
    old.abort('cleared')
  }

  /** The next job set (null when `signal` aborts or after `timeoutMs`). */
  nextJob({ signal, timeoutMs } = {}) {
    return new Promise((resolve) => {
      if (isAborted(signal)) return resolve(null)
      let timer = null
      const stop = whenAborted(signal)
      const done = (job) => {
        this._waiters.delete(done)
        stop.cancel()
        if (timer) clearTimeout(timer)
        resolve(job)
      }
      this._waiters.add(done)
      stop.promise.then(() => done(null))
      if (Number.isFinite(timeoutMs)) timer = setTimeout(() => done(null), Math.max(0, timeoutMs))
    })
  }

  /**
   * Mines the current job until a share is found that may be handed out. When a new block's
   * job arrives the search stops and starts over on the new job; a share whose job became stale
   * meanwhile is dropped. Without a current job it waits for one.
   *
   * @param {object} opts  `backend` and the `mineShare` options (signal, timeBudgetMs, sliceMs,
   *   hashesPerSecond, onProgress)
   * @returns {Promise<{ job, share } | null>} null when `signal` aborted or the time ran out
   */
  async mine({ backend, signal, timeBudgetMs = POW_MAX_JOB_TIME_MS, ...opts } = {}) {
    needBackend(backend)
    const start = this._now()
    for (;;) {
      if (isAborted(signal)) return null
      const remaining = timeBudgetMs - (this._now() - start)
      if (remaining <= 0) return null
      const job = this._current
      if (!job) {
        if (!(await this.nextJob({ signal, timeoutMs: remaining }))) return null
        continue
      }
      const blockSignal = this._controller.signal
      const both = anySignal([signal, blockSignal])
      let share
      try {
        share = await mineShare({
          ...opts,
          job,
          backend,
          signal: both.signal,
          timeBudgetMs: remaining,
          maxDifficulty: this.maxDifficulty,
          now: this._now
        })
      } finally {
        both.dispose()
      }
      if (share) {
        const accepted = this.accept(job, share)
        if (accepted) return { job, share: accepted }
        continue
      }
      if (isAborted(signal)) return null
      if (!blockSignal.aborted) return null
    }
  }
}

module.exports = {
  SLICE_ROUND,
  DEFAULT_SLICE_MS,
  DEFAULT_HASHES_PER_SECOND,
  MAX_SLICE_ATTEMPTS,
  PREVIOUS_BLOCK_GRACE_MS,
  checkBackend,
  mineShare,
  JobTracker,
  isStaleAnswer,
  StopController
}

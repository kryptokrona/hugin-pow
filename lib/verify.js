'use strict'

// What a relay (hugin-network nodes, other JavaScript relays) checks on the `pow` field of a
// post or registration: the job's shape, its target against the relay's difficulty, the
// `pow.auth` signature, and every share's CN-Turtle-Lite v2 hash. The hash is passed in (a
// function or the backend of hugin-pow/native). Whether the job is one the relay handed out
// recently, and for which block, is the relay's own bookkeeping.

const { POW_VERSION, MAX_SHARES, validatePowJob, targetToDifficulty, verifyShare, hashFunctionOf } = require('./job.js')
const { verifyPowAuth } = require('./auth.js')

/**
 * Checks the `pow` field `{ version, job, shares, auth }` of a post or registration.
 *
 * @param {object} opts
 * @param {object} opts.pow
 * @param {string} opts.hash  the message hash the auth signs
 * @param {number|string} opts.timestamp
 * @param {string} [opts.context]  `postAuthContext(kind, cipher)` or `registerAuthContext(data)`
 * @param {Function|{ hash: Function }} opts.hasher  `hash(blobHex) -> Promise<hex>` or a backend
 * @param {number} [opts.minDifficulty]  the job's target must be at least this hard
 * @param {number} [opts.requiredShares]  default 1
 * @returns {Promise<{ ok: true } | { ok: false, reason: string }>}
 */
async function verifyPow({ pow, hash, timestamp, context = '', hasher, minDifficulty = 0, requiredShares = 1 }) {
  const fn = hashFunctionOf(hasher)
  if (!pow || typeof pow !== 'object' || pow.version !== POW_VERSION) return { ok: false, reason: 'invalid_pow' }
  const { job, shares, auth } = pow
  const v = validatePowJob(job)
  if (!v.ok) return { ok: false, reason: v.reason }
  if (minDifficulty > 0 && targetToDifficulty(job.target) < minDifficulty) return { ok: false, reason: 'target_too_easy' }
  if (!Array.isArray(shares) || shares.length < Math.max(1, requiredShares) || shares.length > MAX_SHARES) {
    return { ok: false, reason: 'invalid_shares' }
  }
  const nonces = new Set()
  for (const s of shares) {
    if (!s || typeof s !== 'object' || String(s.job_id) !== job.job_id || typeof s.nonce !== 'string') {
      return { ok: false, reason: 'invalid_share' }
    }
    const n = s.nonce.toLowerCase()
    if (nonces.has(n)) return { ok: false, reason: 'invalid_share' }
    nonces.add(n)
  }
  if (!verifyPowAuth({ auth, hash, timestamp, shares, context })) return { ok: false, reason: 'invalid_auth' }
  for (const s of shares) {
    if (!(await verifyShare(job, s.nonce, s.result, fn))) return { ok: false, reason: 'invalid_share' }
  }
  return { ok: true }
}

module.exports = {
  verifyPow,
  verifyShare,
  verifyPowAuth
}

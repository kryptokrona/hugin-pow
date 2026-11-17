'use strict'

// Test helpers (Node.js and Bare).

const { insertNonce, nonceToHex, meetsTarget, validatePowJob } = require('../lib/job.js')
const CN = require('./vectors/cn-turtle-lite-v2.json')
const V = require('./vectors/hugin-relay.json')

// Known answers: the CN-Turtle-Lite v2 vectors and the hugin-relay share.
const KNOWN = new Map(CN.vectors.map((v) => [v.blob, v.hash]))
KNOWN.set(V.pow.hashing_blob, V.pow.result)

function fnv1a(str, seed) {
  let h = (0x811c9dc5 ^ seed) >>> 0
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h
}

/**
 * Stand-in for CN-Turtle-Lite v2: the known answer for a vector blob, a fast deterministic
 * 32-byte value (FNV-1a with 8 seeds) for any other blob. Gives the reference answer, so
 * backends built on it pass the reference check.
 */
function fakeHashSync(blobHex) {
  const known = KNOWN.get(blobHex)
  if (known) return known
  let out = ''
  for (let s = 0; s < 8; s++) out += nonceToHex(fnv1a(blobHex, Math.imul(s + 1, 0x9e3779b9) >>> 0))
  return out
}

async function fakeHash(blobHex) {
  return fakeHashSync(blobHex)
}

/** kryptokrona-crypto `findPowShare` on one thread with fakeHash (same arguments and result shape). */
async function fakeFindShare({ blobHex, targetHex, startNonce, maxAttempts }) {
  if (!validatePowJob({ job_id: '', blob: blobHex, target: targetHex }).ok) return null
  let nonce = startNonce >>> 0
  for (let i = 0; i < maxAttempts; i++) {
    const nonceHex = nonceToHex(nonce)
    const result = fakeHashSync(insertNonce(blobHex, nonceHex).blobHex)
    if (meetsTarget(result, targetHex)) return { job_id: '', nonce: nonceHex, result, hashes_performed: i + 1, threads: 1 }
    nonce = (nonce + 1) >>> 0
  }
  return { hashes_performed: maxAttempts, threads: 1 }
}

/** A job blob whose prev_id is 32 x `prevByte`. */
function jobOf(id, prevByte, target = 'ffffffff') {
  const blob = '0500' + 'e0afd2b906' + prevByte.repeat(32) + '00000000' + '5a'.repeat(32) + '01'
  return { job_id: id, blob, target }
}

/**
 * A p2pool-shaped job as xkrd hands it out: the blob's prev_id is zero, `height` is the
 * main-chain height (`fill` varies the rest of the blob between jobs).
 */
function p2poolJobOf(id, height, fill = '5a', target = 'ffffffff') {
  const blob = '0e0e' + 'e0afd2b906' + '00'.repeat(32) + '00000000' + fill.repeat(32) + '01'
  const job = { job_id: id, blob, target }
  if (height !== undefined) job.height = height
  return job
}

/** A clock that moves only when told to. */
function fakeClock(t = 0) {
  const clock = { t }
  clock.now = () => clock.t
  return clock
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0))

/** A promise that never settles. */
const never = () => new Promise(() => {})

/** kryptokrona-crypto when it loads here with native code (Node.js with the addon), else null. */
function loadKryptokronaCrypto() {
  try {
    const id = 'kryptokrona-crypto'
    const m = require(id)
    new m.Crypto() // eslint-disable-line no-new
    return m.Crypto.isNative === true && typeof m.findPowShare === 'function' ? m : null
  } catch {
    return null
  }
}

module.exports = {
  CN,
  V,
  fakeHash,
  fakeHashSync,
  fakeFindShare,
  jobOf,
  p2poolJobOf,
  fakeClock,
  tick,
  never,
  loadKryptokronaCrypto
}

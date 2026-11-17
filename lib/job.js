'use strict'

const { PowError } = require('./errors.js')

// Jobs, blobs, nonces, targets and shares of Hugin message proof of work.
// No dependencies and no host APIs: this file loads on Node.js,
// Electron, Bare and React Native (Metro).
//
// A job is `{ job_id, blob, target }` as a relay hands it out: `blob` is a block hashing blob
// (hex), `target` a 4-byte little-endian compact stratum target (8 hex characters). A share is a
// 4-byte nonce written at the nonce offset of the blob whose CN-Turtle-Lite v2 hash meets the
// target. Apps mine the blob exactly as the relay gives it.
//
// The blob and target helpers give the same results as hugin-utils 0.4.0 (`getNonceOffset`,
// `insertNonce`, `extractPrevIdFromBlob`, `meetsTarget`, `isValidPowJob`, `verifyShare`,
// `findShare`, `checkHash`, `minTargetHex`); `validatePowJob` is the apps' `validate_pow_job`.

const DEFAULT_NONCE_OFFSET = 39
const NONCE_BYTES = 4
const MAX_BLOB_BYTES = 1024
const POW_VERSION = 2
const POW_REQUIRED_SHARES = 1
const POW_MAX_JOB_TIME_MS = 90000
const MAX_SHARES = 5
/**
 * Highest job difficulty an app mines by default (`JobTracker`): ten times the relays' default
 * app difficulty of 200. Jobs above it are not mined (`job_too_hard`).
 */
const DEFAULT_MAX_DIFFICULTY = 2000

// ---------------------------------------------------------------------------------------------
// hex / varint

function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new Error('hex_to_bytes_invalid')
  if (hex.length % 2 !== 0) throw new Error('hex_to_bytes_len')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    if (!Number.isFinite(byte)) throw new Error('hex_to_bytes_parse')
    out[i] = byte
  }
  return out
}

function bytesToHex(bytes) {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0')
  return hex
}

function isHexString(value) {
  return typeof value === 'string' && /^[0-9a-f]+$/i.test(value)
}

function readVarint(buffer, offset) {
  let value = 0
  let shift = 0
  let bytes = 0
  while (offset + bytes < buffer.length) {
    const byte = buffer[offset + bytes]
    value |= (byte & 0x7f) << shift
    bytes += 1
    if ((byte & 0x80) === 0) return { value, bytes }
    shift += 7
    if (shift > 63) return null
  }
  return null
}

function readUInt32LE(bytes, offset) {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0
}

function readBigUInt64LE(bytes, offset) {
  const lo = BigInt(readUInt32LE(bytes, offset))
  const hi = BigInt(readUInt32LE(bytes, offset + 4))
  return (hi << 32n) | lo
}

// ---------------------------------------------------------------------------------------------
// blob

function nonceOffsetOf(blob) {
  try {
    let offset = 0
    const major = readVarint(blob, offset)
    if (!major) return DEFAULT_NONCE_OFFSET
    offset += major.bytes
    const minor = readVarint(blob, offset)
    if (!minor) return DEFAULT_NONCE_OFFSET
    offset += minor.bytes
    const timestamp = readVarint(blob, offset)
    if (!timestamp) return DEFAULT_NONCE_OFFSET
    offset += timestamp.bytes
    return offset + 32
  } catch {
    return DEFAULT_NONCE_OFFSET
  }
}

/**
 * Byte offset of the 4-byte nonce: after the varints major, minor, timestamp and the 32-byte
 * prev_id; 39 when the header does not parse.
 */
function getNonceOffset(blobHex) {
  return nonceOffsetOf(hexToBytes(blobHex))
}

/** `{ blobHex, offset }`: the blob with `nonceHex` (4 bytes as given) written at the nonce offset. */
function insertNonce(blobHex, nonceHex) {
  const blob = hexToBytes(blobHex)
  const nonce = hexToBytes(nonceHex)
  const offset = nonceOffsetOf(blob)
  blob.set(nonce, offset)
  return { blobHex: bytesToHex(blob), offset }
}

/** The 32-byte prev_id of a job blob as hex, or null. */
function extractPrevIdFromBlob(blobHex) {
  try {
    const blob = hexToBytes(blobHex)
    let offset = 0
    const major = readVarint(blob, offset)
    if (!major) return null
    offset += major.bytes
    const minor = readVarint(blob, offset)
    if (!minor) return null
    offset += minor.bytes
    const timestamp = readVarint(blob, offset)
    if (!timestamp) return null
    offset += timestamp.bytes
    if (offset + 32 > blob.length) return null
    return bytesToHex(blob.subarray(offset, offset + 32))
  } catch {
    return null
  }
}

/** A 32-bit nonce as 8 hex characters, little-endian (the bytes as they sit in the blob). */
function nonceToHex(nonce) {
  const n = nonce >>> 0
  return bytesToHex(new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]))
}

/** The 32-bit nonce of 8 hex characters (little-endian), or null. */
function nonceFromHex(nonceHex) {
  if (!isHexString(nonceHex) || nonceHex.length !== 8) return null
  return readUInt32LE(hexToBytes(nonceHex), 0)
}

// ---------------------------------------------------------------------------------------------
// target / difficulty

/**
 * 64-bit target of a stratum target: 4 bytes LE `raw` -> `u64::MAX / (0xFFFFFFFF / raw)`,
 * 8 bytes LE as is. null for a zero, empty or malformed target (counts as met, like hugin-utils).
 */
function parseTarget(targetHex) {
  if (!targetHex) return null
  let t
  try {
    t = hexToBytes(targetHex)
  } catch {
    return null
  }
  if (t.length === 4) {
    const raw = readUInt32LE(t, 0)
    if (raw === 0) return null
    const denom = 0xffffffffn / BigInt(raw)
    if (denom === 0n) return null
    return 0xffffffffffffffffn / denom
  }
  if (t.length === 8) return readBigUInt64LE(t, 0)
  return null
}

/** True when the last 8 bytes of the hash (LE u64) are at most the target. */
function meetsTarget(hashHex, targetHex) {
  const target = parseTarget(targetHex)
  if (target === null) return true
  let h
  try {
    h = hexToBytes(hashHex)
  } catch {
    return false
  }
  if (h.length < 32) return false
  return readBigUInt64LE(h, 24) <= target
}

/** hugin-utils `checkHash`: the same as `meetsTarget`. */
function checkHash(hashHex, targetHex) {
  return meetsTarget(hashHex, targetHex)
}

/** hugin-utils `minTargetHex`: the harder of two targets (a missing or zero one loses). */
function minTargetHex(a, b) {
  const aa = parseTarget(a)
  const bb = parseTarget(b)
  if (aa === null) return b
  if (bb === null) return a
  return aa <= bb ? a : b
}

/** Expected number of hashes per share for a target (`0xFFFFFFFF / raw` for 4-byte targets). */
function targetToDifficulty(targetHex) {
  const target = parseTarget(targetHex)
  if (target === null) return 0
  return Number(0xffffffffffffffffn / (target === 0n ? 1n : target))
}

/**
 * 4-byte LE stratum target for a difficulty, `floor(0xFFFFFFFF / difficulty)` (the relay's
 * `target_for_difficulty`; inverse of targetToDifficulty for 4-byte targets).
 */
function difficultyToTarget(difficulty) {
  const d = Math.max(1, Math.floor(Number(difficulty) || 1))
  const raw = Math.max(1, Math.floor(0xffffffff / d)) >>> 0
  return nonceToHex(raw)
}

// ---------------------------------------------------------------------------------------------
// jobs and shares

/**
 * Jobs pushed by a relay, as both apps check them before use. Returns `{ ok, reason? }`.
 * With `maxDifficulty` (a finite number), a job whose target difficulty (`targetToDifficulty`)
 * is above it is refused as `job_too_hard`; without it only the shape is checked.
 * @param {object} job
 * @param {{ maxDifficulty?: number }} [opts]
 */
function validatePowJob(job, { maxDifficulty } = {}) {
  if (!job || typeof job !== 'object') return { ok: false, reason: 'invalid_job' }
  if (typeof job.job_id !== 'string' || job.job_id.length > 32) return { ok: false, reason: 'invalid_job_id' }
  if (!isHexString(job.blob)) return { ok: false, reason: 'invalid_blob' }
  if (job.blob.length % 2 !== 0) return { ok: false, reason: 'invalid_blob_len' }
  if (job.blob.length / 2 > MAX_BLOB_BYTES) return { ok: false, reason: 'blob_too_large' }
  if (!isHexString(job.target) || job.target.length !== 8) return { ok: false, reason: 'invalid_target' }
  const offset = getNonceOffset(job.blob)
  if (typeof offset !== 'number' || offset < 0) return { ok: false, reason: 'invalid_nonce_offset' }
  if ((offset + NONCE_BYTES) * 2 > job.blob.length) return { ok: false, reason: 'nonce_out_of_bounds' }
  if (typeof maxDifficulty === 'number' && Number.isFinite(maxDifficulty) && targetToDifficulty(job.target) > maxDifficulty) {
    return { ok: false, reason: 'job_too_hard' }
  }
  return { ok: true }
}

/** hugin-utils `isValidPowJob`: the shape check a relay applies to the job of a post. */
function isValidPowJob(job) {
  if (!job || typeof job !== 'object') return false
  if (typeof job.job_id !== 'string' || job.job_id.length > 32) return false
  if (typeof job.blob !== 'string' || !isHexString(job.blob) || job.blob.length % 2 !== 0) return false
  if (typeof job.target !== 'string' || !isHexString(job.target) || job.target.length !== 8) return false
  return true
}

/** The `hash(blobHex) -> Promise<hex>` of a function or of a hasher (`createHasher`). */
function hashFunctionOf(hash) {
  if (typeof hash === 'function') return hash
  if (hash && typeof hash.hash === 'function') return (blobHex) => hash.hash(blobHex)
  throw new PowError('hash must be a function (blobHex) -> Promise<hex> or a hasher from createHasher()')
}

/**
 * Checks a share the way a relay does (hugin-utils `verifyShare`, with the hash passed in): the
 * CN-Turtle-Lite v2 hash of the blob with the nonce inserted must equal `result` (lowercase
 * hex, as the hash returns it) and meet the job's target.
 * @param {(blobHex: string) => Promise<string> | { hash: Function }} hash  a hash function or a hasher
 */
async function verifyShare(job, nonce, result, hash) {
  const fn = hashFunctionOf(hash)
  if (!isValidPowJob(job)) return false
  if (typeof nonce !== 'string' || nonce.length !== 8 || !isHexString(nonce)) return false
  if (typeof result !== 'string' || result.length !== 64 || !isHexString(result)) return false
  const { blobHex } = insertNonce(job.blob, nonce)
  const hashHex = await fn(blobHex)
  if (hashHex !== result) return false
  return meetsTarget(hashHex, job.target)
}

/**
 * Searches nonces one at a time from `startNonce` until a hash meets the job's target
 * (hugin-utils `findShare`), with the given hash. Stops after `maxAttempts` or `timeBudgetMs`.
 * For parallel mining with a stop signal use `mineShare` (hugin-pow/mine).
 * @returns {Promise<{ job_id, nonce, result } | null>} nonce and result lowercase hex
 */
async function findShare({
  job,
  hash,
  startNonce,
  maxAttempts,
  hashesPerSecond = 500,
  timeBudgetMs = 1000,
  yieldEvery = 200,
  now = Date.now
}) {
  const fn = hashFunctionOf(hash)
  const v = validatePowJob(job)
  if (!v.ok) return null
  const attempts =
    maxAttempts !== undefined ? maxAttempts : Math.max(1, Math.floor((hashesPerSecond * timeBudgetMs) / 1000))
  let nonce = startNonce !== undefined ? startNonce >>> 0 : (Math.random() * 0xffffffff) >>> 0
  const start = now()
  for (let attempt = 0; attempt < attempts; attempt++) {
    const nonceHex = nonceToHex(nonce)
    const { blobHex } = insertNonce(job.blob, nonceHex)
    const result = String(await fn(blobHex)).toLowerCase()
    if (meetsTarget(result, job.target)) return { job_id: String(job.job_id), nonce: nonceHex, result }
    nonce = (nonce + 1) >>> 0
    if (yieldEvery > 0 && attempt > 0 && attempt % yieldEvery === 0) {
      await new Promise((resolve) => setTimeout(resolve, 0))
    }
    if (now() - start >= timeBudgetMs) break
  }
  return null
}

/** `{ job_id: string, nonce, result }` with lowercase hex, as both apps put shares on the wire. */
function normalizeShare(share) {
  if (!share || typeof share.nonce !== 'string' || typeof share.result !== 'string') return null
  return {
    job_id: String(share.job_id),
    nonce: share.nonce.toLowerCase(),
    result: share.result.toLowerCase()
  }
}

/** The `pow` field of a post or registration. */
function powField({ job, shares, auth }) {
  return { version: POW_VERSION, job, shares, auth }
}

module.exports = {
  DEFAULT_NONCE_OFFSET,
  NONCE_BYTES,
  MAX_BLOB_BYTES,
  POW_VERSION,
  POW_REQUIRED_SHARES,
  POW_MAX_JOB_TIME_MS,
  MAX_SHARES,
  DEFAULT_MAX_DIFFICULTY,
  hexToBytes,
  bytesToHex,
  isHexString,
  readVarint,
  readUInt32LE,
  getNonceOffset,
  insertNonce,
  extractPrevIdFromBlob,
  nonceToHex,
  nonceFromHex,
  parseTarget,
  meetsTarget,
  checkHash,
  minTargetHex,
  targetToDifficulty,
  difficultyToTarget,
  validatePowJob,
  isValidPowJob,
  verifyShare,
  findShare,
  normalizeShare,
  powField,
  hashFunctionOf
}

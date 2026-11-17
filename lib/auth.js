'use strict'

const { PowError } = require('./errors.js')

// `pow.auth`: the `powsig:v2` signature that ties a share to one post or registration.
// The app signs with a one-time ed25519 key; the relay checks the signature for the `pub` it
// carries.
//
// Signatures are produced the way keypear (hugin-desktop) and the keypear shim of hugin-native
// produce them: the secret key is turned into its scalar (`extension_tweak_ed25519_sk_to_scalar`)
// and signed with `extension_tweak_ed25519_sign_detached`. They verify with the standard
// `crypto_sign_verify_detached` and are byte-identical to the apps' signatures.
//
// Node.js, Electron and Bare (sodium-universal); not loaded by hugin-pow/job or hugin-pow/mine.

const b4a = require('b4a')
const sodium = require('sodium-universal')

function keyPairFromSeed(seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return { publicKey, secretKey }
}

function randomKeyPair() {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

/** keypear-compatible detached signature of `message` (Uint8Array) with an ed25519 key pair. */
function keychainSign(keyPair, message) {
  if (!keyPair || !(keyPair.secretKey instanceof Uint8Array) || keyPair.secretKey.byteLength !== 64) {
    throw new PowError('keychainSign: keyPair.secretKey must be 64 bytes')
  }
  const scalar = b4a.alloc(32)
  sodium.extension_tweak_ed25519_sk_to_scalar(scalar, keyPair.secretKey)
  const sig = b4a.alloc(64)
  sodium.extension_tweak_ed25519_sign_detached(sig, message, scalar)
  return sig
}

/** `crypto_sign_verify_detached` that returns false instead of throwing on bad lengths. */
function verifyDetached(signature, message, publicKey) {
  if (!(signature instanceof Uint8Array) || signature.byteLength !== 64) return false
  if (!(publicKey instanceof Uint8Array) || publicKey.byteLength !== 32) return false
  if (!(message instanceof Uint8Array)) return false
  try {
    return sodium.crypto_sign_verify_detached(signature, message, publicKey)
  } catch {
    return false
  }
}

/** Auth context: `<kind>:<cipher>` for posts (just the cipher without a kind). */
function postAuthContext(kind, cipher) {
  return kind ? `${kind}:${String(cipher || '')}` : String(cipher || '')
}

/** Auth context of a registration: its `data`. */
function registerAuthContext(data) {
  return String(data || '')
}

/** `powsig:v2:<hash>:<timestamp>:<job_id>:<nonce>:<result>:<context>` (both apps' build_pow_auth). */
function powAuthPayload({ hash, timestamp, share, context = '' }) {
  return (
    'powsig:v2:' +
    String(hash || '') +
    ':' +
    `${timestamp}` +
    ':' +
    String(share.job_id || '') +
    ':' +
    String(share.nonce || '').toLowerCase() +
    ':' +
    String(share.result || '').toLowerCase() +
    ':' +
    String(context || '')
  )
}

/**
 * `pow.auth` for `shares[0]`, signed with a one-time ed25519 key (a fresh random one unless
 * `keyPair` is given).
 * @returns {{ pub, sig, nonce } | null}
 */
function buildPowAuth({ hash, timestamp, shares, context = '', keyPair }) {
  if (!Array.isArray(shares) || !shares.length || !shares[0]) return null
  const share = shares[0]
  const kp = keyPair || randomKeyPair()
  const payload = powAuthPayload({ hash, timestamp, share, context })
  const sig = keychainSign(kp, b4a.from(payload, 'utf8'))
  return {
    pub: b4a.toString(kp.publicKey, 'hex'),
    sig: b4a.toString(sig, 'hex'),
    nonce: String(share.nonce || '').toLowerCase()
  }
}

/**
 * The relay's auth check: the share is the one whose nonce equals `auth.nonce`, else
 * `shares[0]`; the signature must verify for `pub`.
 */
function verifyPowAuth({ auth, hash, timestamp, shares, context = '' }) {
  if (!auth || typeof auth.pub !== 'string' || typeof auth.sig !== 'string') return false
  if (!/^[0-9a-f]{64}$/i.test(auth.pub) || !/^[0-9a-f]{128}$/i.test(auth.sig)) return false
  if (!Array.isArray(shares) || !shares.length) return false
  const nonce = String(auth.nonce || '').toLowerCase()
  const share = shares.find((s) => s && String(s.nonce || '').toLowerCase() === nonce) || shares[0]
  if (!share) return false
  const payload = powAuthPayload({ hash, timestamp, share, context })
  return verifyDetached(b4a.from(auth.sig, 'hex'), b4a.from(payload, 'utf8'), b4a.from(auth.pub, 'hex'))
}

module.exports = {
  keyPairFromSeed,
  randomKeyPair,
  keychainSign,
  verifyDetached,
  postAuthContext,
  registerAuthContext,
  powAuthPayload,
  buildPowAuth,
  verifyPowAuth
}

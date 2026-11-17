'use strict'

// The mining and hashing backend from kryptokrona-crypto 2.x: on Node.js and Electron its
// Node-API addon, on React Native its Turbo Native Module (Metro picks the package's
// `react-native` entry). Both have `findPowShare` (the share search on up to 8 native worker
// threads, 80 % of the cores) and `Crypto#cn_turtle_lite_slow_hash_v2`.
//
// This file is the only one in hugin-pow that loads kryptokrona-crypto, and only when
// `createHasher()` runs without a `crypto` option. Bare cannot load kryptokrona-crypto; hosts
// there pass their own backend to mineShare (see lib/mine.js).

const { checkBackend } = require('./mine.js')

/**
 * kryptokrona-crypto through a computed require: bundlers do not follow it, and the module is
 * loaded only when this function runs. React Native apps pass the imported module instead.
 */
function loadKryptokronaCrypto() {
  const id = 'kryptokrona-crypto'
  return require(id)
}

function backendName(m) {
  const C = m.Crypto
  const types = m.CryptoType || {}
  if (C && types.REACTNATIVE !== undefined && C.type === types.REACTNATIVE) return 'react-native'
  if (C && types.NAPI !== undefined && C.type === types.NAPI) return 'napi'
  return 'native'
}

/**
 * The kryptokrona-crypto backend: `{ name, hash(blobHex), findShare({ blobHex, targetHex,
 * startNonce, maxAttempts }) }`, checked against the reference vector before it is returned.
 *
 * @param {object} [opts]
 * @param {object} [opts.crypto]  the kryptokrona-crypto module (React Native:
 *   `import * as kryptokronaCrypto from 'kryptokrona-crypto'`); loaded with require() otherwise
 * @returns {Promise<{ name: string, hash: Function, findShare: Function }>}
 *   rejects when kryptokrona-crypto is missing, older than 2.0, has no native code on this
 *   platform, or does not give the reference answer
 */
async function createHasher({ crypto } = {}) {
  let m = crypto
  if (!m) {
    try {
      m = loadKryptokronaCrypto()
    } catch (err) {
      const e = new Error('hugin-pow: kryptokrona-crypto ^2.0.0 is not installed')
      e.cause = err
      throw e
    }
  }
  if (!m || typeof m.Crypto !== 'function' || typeof m.findPowShare !== 'function') {
    throw new Error('hugin-pow: kryptokrona-crypto ^2.0.0 is required (findPowShare missing)')
  }
  const c = new m.Crypto()
  if (m.Crypto.isNative !== true) {
    throw new Error('hugin-pow: kryptokrona-crypto has no native backend on this platform')
  }
  const backend = {
    name: backendName(m),
    hash: (blobHex) => c.cn_turtle_lite_slow_hash_v2(blobHex),
    findShare: ({ blobHex, targetHex, startNonce, maxAttempts }) =>
      m.findPowShare(blobHex, targetHex, startNonce >>> 0, maxAttempts, 0, 0)
  }
  await checkBackend(backend)
  return backend
}

module.exports = { createHasher, createNativeBackend: createHasher }

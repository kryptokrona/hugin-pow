'use strict'

// The known answer every hash backend must give before it is used for mining: the first
// CN-Turtle-Lite v2 vector of test/vectors/cn-turtle-lite-v2.json (from the Rust
// implementation in xkr-crypto, the core of kryptokrona-crypto 2.x).

const REFERENCE_VECTOR = Object.freeze({
  blob: 'e90452623792dfb3b8ae8caf09a854f283adef559f504422920859ef265697fb0a5fb3b476df428936f1fac066e59904edb160687eb53bf2cbadf492cb6b9d2c0f501c27b107bbc674ff874c',
  hash: '1f7898187cc752f4a45be60dba0c43835b8bde8af6a1e2c402c68d6e5ff8d361'
})

const REFERENCE_MISMATCH = 'hash backend does not match the reference vectors'

/** An Error with `code: 'HUGIN_POW_REFERENCE_MISMATCH'`. */
function referenceMismatch() {
  const err = new Error(REFERENCE_MISMATCH)
  err.code = 'HUGIN_POW_REFERENCE_MISMATCH'
  return err
}

/**
 * Resolves when `hash(REFERENCE_VECTOR.blob)` gives the reference hash, rejects with
 * `hash backend does not match the reference vectors` otherwise (also when the hash throws).
 */
async function checkReference(hash) {
  let out
  try {
    out = await hash(REFERENCE_VECTOR.blob)
  } catch {
    throw referenceMismatch()
  }
  if (typeof out !== 'string' || out.toLowerCase() !== REFERENCE_VECTOR.hash) throw referenceMismatch()
}

module.exports = { REFERENCE_VECTOR, REFERENCE_MISMATCH, referenceMismatch, checkReference }

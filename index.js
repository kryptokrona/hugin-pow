'use strict'

// hugin-pow: proof of work for Hugin messages. Node.js, Electron and Bare. React Native code
// imports the parts it needs (hugin-pow/job, hugin-pow/mine, hugin-pow/native); this entry also
// loads the pow.auth signing code (sodium-universal). kryptokrona-crypto is loaded only by
// hugin-pow/native.

const job = require('./lib/job.js')
const auth = require('./lib/auth.js')
const mine = require('./lib/mine.js')
const { verifyPow } = require('./lib/verify.js')
const { REFERENCE_VECTOR, REFERENCE_MISMATCH } = require('./lib/reference.js')
const { PowError } = require('./lib/errors.js')

module.exports = {
  PowError,
  ...job,
  ...auth,
  ...mine,
  verifyPow,
  REFERENCE_VECTOR,
  REFERENCE_MISMATCH
}

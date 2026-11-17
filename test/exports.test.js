'use strict'

const test = require('brittle')
const main = require('../index.js')

test('main entry: the job, auth, mining and verify API; kryptokrona-crypto is not loaded', (t) => {
  for (const name of [
    'getNonceOffset',
    'insertNonce',
    'extractPrevIdFromBlob',
    'parseTarget',
    'meetsTarget',
    'checkHash',
    'minTargetHex',
    'targetToDifficulty',
    'difficultyToTarget',
    'validatePowJob',
    'isValidPowJob',
    'verifyShare',
    'findShare',
    'normalizeShare',
    'powField',
    'postAuthContext',
    'registerAuthContext',
    'powAuthPayload',
    'buildPowAuth',
    'verifyPowAuth',
    'verifyPow',
    'mineShare',
    'checkBackend',
    'StopController'
  ]) {
    t.is(typeof main[name], 'function', name)
  }
  t.is(typeof main.JobTracker, 'function')
  t.is(main.REFERENCE_MISMATCH, 'hash backend does not match the reference vectors')
  t.is(main.POW_VERSION, 2)
  t.is(main.DEFAULT_MAX_DIFFICULTY, 2000)
  t.absent('createHasher' in main, 'hugin-pow/native is a separate entry')
})

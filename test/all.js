'use strict'

// Runs every test file in one process (for `bare test/all.js`; brittle registers them all).
require('./job.test.js')
require('./auth.test.js')
require('./hash.test.js')
require('./mine.test.js')
require('./job-tracker.test.js')
require('./exports.test.js')

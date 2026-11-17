'use strict'

/** Errors thrown by hugin-pow for invalid arguments (a plain class, so callers can tell them apart). */
class PowError extends Error {
  constructor(message) {
    super(message)
    this.name = 'PowError'
  }
}

module.exports = { PowError }

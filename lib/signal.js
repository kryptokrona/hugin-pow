'use strict'

// A small stop signal with the AbortSignal surface hugin-pow uses (`aborted`, `reason`,
// `addEventListener('abort', fn)`, `removeEventListener`), so the same code runs on Node.js,
// Electron, React Native and Bare. Any AbortSignal (from an AbortController) is accepted where a
// signal is taken.

class StopSignal {
  constructor() {
    this.aborted = false
    this.reason = undefined
    this._listeners = new Set()
  }

  addEventListener(type, fn) {
    if (type === 'abort' && typeof fn === 'function') this._listeners.add(fn)
  }

  removeEventListener(type, fn) {
    if (type === 'abort') this._listeners.delete(fn)
  }
}

/** `{ signal, abort(reason) }`, like an AbortController. */
class StopController {
  constructor() {
    this.signal = new StopSignal()
  }

  abort(reason) {
    const s = this.signal
    if (s.aborted) return
    s.aborted = true
    s.reason = reason === undefined ? 'aborted' : reason
    const listeners = [...s._listeners]
    s._listeners.clear()
    for (const fn of listeners) {
      try {
        fn({ type: 'abort', target: s })
      } catch {}
    }
  }
}

/** True for a signal object hugin-pow can listen on. */
function isSignal(signal) {
  return !!signal && typeof signal === 'object' && typeof signal.addEventListener === 'function'
}

/**
 * A controller that aborts when any of `signals` aborts (missing ones are skipped). `dispose()`
 * removes its listeners from them.
 */
function anySignal(signals) {
  const controller = new StopController()
  const attached = []
  for (const s of signals) {
    if (!isSignal(s)) continue
    if (s.aborted) {
      controller.abort(s.reason)
      break
    }
    const fn = () => controller.abort(s.reason)
    s.addEventListener('abort', fn)
    attached.push([s, fn])
  }
  controller.dispose = () => {
    for (const [s, fn] of attached) s.removeEventListener('abort', fn)
    attached.length = 0
  }
  return controller
}

/**
 * Resolves `{ aborted: true }` once `signal` aborts (never without a signal). `cancel()` removes
 * the listener.
 */
function whenAborted(signal) {
  let fn = null
  const promise = new Promise((resolve) => {
    if (!isSignal(signal)) return
    if (signal.aborted) return resolve({ aborted: true })
    fn = () => resolve({ aborted: true })
    signal.addEventListener('abort', fn)
  })
  return {
    promise,
    cancel() {
      if (fn) signal.removeEventListener('abort', fn)
      fn = null
    }
  }
}

module.exports = { StopSignal, StopController, isSignal, anySignal, whenAborted }

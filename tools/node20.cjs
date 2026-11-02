// Test-only compatibility for running Undici 8 on Node.js 20.
const workerThreads = require('node:worker_threads')
const zlib = require('node:zlib')

Object.defineProperty(Promise, 'withResolvers', {
  configurable: true,
  writable: true,
  value: function withResolvers() {
    let resolve
    let reject
    const promise = new this((res, rej) => {
      resolve = res
      reject = rej
    })
    return { promise, resolve, reject }
  },
})

// Tests do not clone or transfer Undici's fetch objects between workers.
workerThreads.markAsUncloneable = () => {}

// Undici binds this at import time, but these tests do not use Zstandard.
zlib.createZstdDecompress = () => {
  throw new Error(
    'Zstandard decompression is unavailable in the Node.js 20 test shim',
  )
}

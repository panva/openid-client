import assert from 'node:assert/strict'
import test from 'node:test'

import { isSkippedUnhandledModule } from './modules.js'
import { missingHandlerMessage } from './report.js'
import { plan, unhandledModules } from './runner.js'

for (const { name, path } of unhandledModules) {
  if (isSkippedUnhandledModule(plan.name, name)) {
    test.skip(`unsupported conformance module: ${name}`, () => {})
  } else {
    test(`missing conformance handler: ${name}`, () => {
      assert.fail(missingHandlerMessage(name, path))
    })
  }
}

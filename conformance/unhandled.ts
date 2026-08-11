import { isSkippedUnhandledModule } from './modules.js'
import { missingHandlerMessage } from './report.js'
import { plan, test, unhandledModules } from './runner.js'

for (const { name, path } of unhandledModules) {
  if (isSkippedUnhandledModule(plan.name, name)) {
    test.skip(`unsupported conformance module: ${name}`, () => {})
  } else {
    test(`missing conformance handler: ${name}`, (t) => {
      t.fail(missingHandlerMessage(name, path))
    })
  }
}

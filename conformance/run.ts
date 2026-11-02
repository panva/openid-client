import { spec } from 'node:test/reporters'

import configure from './config.js'
import { runTests } from './execute.js'

if (process.argv.length > 2) {
  throw new TypeError(
    'The conformance runner does not accept command-line arguments',
  )
}

const { files, environmentVariables, reportStatusPath } = await configure()
Object.assign(process.env, environmentVariables)

const tests = runTests(files, reportStatusPath)
tests.on('test:fail', () => {
  process.exitCode = 1
})
tests.compose(spec).pipe(process.stdout)

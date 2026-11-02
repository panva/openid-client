import { run } from 'node:test'

import { requestReport } from './report.js'

export function runTests(files: string[], reportStatusPath: string) {
  const tests = run({ files, concurrency: 1 })
  tests.on('test:fail', ({ name }) => {
    requestReport(reportStatusPath, { type: 'failure', detail: name })
  })
  return tests
}

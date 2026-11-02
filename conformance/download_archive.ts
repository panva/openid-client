import test from 'node:test'

import { downloadArtifact } from './api.js'
import {
  clearReportRequest,
  formatReportSummary,
  reportIssues,
  reportRequested,
  setActionEnvironment,
  writeStepSummary,
} from './report.js'
import { plan, reportStatusPath, variant } from './runner.js'

test('emitting conformance diagnostics when needed', async (t) => {
  const requested = reportRequested(reportStatusPath)
  const submission = process.env.CONFORMANCE_SUBMISSION === 'true'

  if (!requested && !submission) {
    return
  }

  const issues = requested ? reportIssues(reportStatusPath) : []
  if (requested) {
    t.diagnostic(
      `Conformance diagnostics requested for ${JSON.stringify(issues)}`,
    )
  }

  try {
    await downloadArtifact(plan)
  } finally {
    if (requested) {
      clearReportRequest(reportStatusPath)
    }
  }

  if (requested) {
    writeStepSummary(formatReportSummary(plan, variant, issues))
    setActionEnvironment('CONFORMANCE_REPORT', 'true')
  }
})

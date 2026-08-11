import {
  formatReportSummary,
  setActionEnvironment,
  writeStepSummary,
} from './report.js'

const {
  CONFORMANCE_PLAN_ID = 'unavailable',
  CONFORMANCE_PLAN_NAME = 'unavailable',
  CONFORMANCE_PLAN_VARIANT = '{}',
} = process.env

writeStepSummary(
  formatReportSummary(
    { id: CONFORMANCE_PLAN_ID, name: CONFORMANCE_PLAN_NAME },
    JSON.parse(CONFORMANCE_PLAN_VARIANT),
    [
      {
        type: 'failure',
        detail: 'AVA runner failure (test details unavailable)',
      },
    ],
  ),
)
setActionEnvironment('CONFORMANCE_REPORT', 'true')

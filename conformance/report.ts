import { appendFileSync, existsSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const AFTER_EACH_TITLE_PREFIX = 'afterEach.always hook for '

export function normalizeAvaTestTitle(title: string) {
  return title.startsWith(AFTER_EACH_TITLE_PREFIX)
    ? title.slice(AFTER_EACH_TITLE_PREFIX.length)
    : title
}

export function validatePlanId(planId: string) {
  if (!/^[a-z0-9_-]{1,128}$/i.test(planId)) {
    throw new Error(`invalid conformance plan ID: ${planId}`)
  }
  return planId
}

export function getReportStatusPath(planId: string) {
  return join(
    tmpdir(),
    `openid-client-conformance-${validatePlanId(planId)}.report`,
  )
}

export interface ReportIssue {
  type: 'failure' | 'warning'
  detail: string
}

export function requestReport(path: string, issue: ReportIssue) {
  appendFileSync(path, `${JSON.stringify(issue)}\n`)
}

export function reportRequested(path: string) {
  return existsSync(path)
}

export function reportIssues(path: string): ReportIssue[] {
  if (!reportRequested(path)) {
    return []
  }

  const issues = readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as ReportIssue)

  return [
    ...new Map(
      issues.map((issue) => [`${issue.type}\0${issue.detail}`, issue]),
    ).values(),
  ]
}

export function clearReportRequest(path: string) {
  rmSync(path, { force: true })
}

export function setActionEnvironment(name: string, value: string) {
  if (!/^[a-z_][a-z0-9_]*$/i.test(name)) {
    throw new Error(`invalid GitHub Actions environment variable name: ${name}`)
  }
  if (/\r|\n/.test(value)) {
    throw new Error(`invalid multiline value for ${name}`)
  }

  if (process.env.GITHUB_ENV) {
    appendFileSync(process.env.GITHUB_ENV, `${name}=${value}\n`)
  }
}

export function writeStepSummary(content: string) {
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${content}\n`)
  }
}

export function missingHandlerMessage(name: string, path: string) {
  return `The conformance suite exposed a new test module named "${name}", but no handler exists at ${path}`
}

export function formatReportSummary(
  plan: { id: string; name: string },
  variant: Record<string, string>,
  issues: ReportIssue[],
) {
  const type = issues.some((issue) => issue.type === 'failure')
    ? 'failure'
    : 'warning'
  const heading =
    type === 'failure'
      ? '## ❌ Conformance failure'
      : '## ⚠️ Conformance warning'
  const inlineCode = (value: string) =>
    value.replaceAll('`', "'").replaceAll(/\r\n|[\r\n]/g, ' ')
  const affected = [...new Set(issues.map((issue) => issue.detail))]
    .map((detail) => `- \`${inlineCode(detail)}\``)
    .join('\n')

  return `${heading}

- Plan: \`${inlineCode(plan.name)}\`
- Plan ID: \`${inlineCode(plan.id)}\`

<details>
<summary>Variant</summary>

\`\`\`json
${JSON.stringify(variant, null, 2)}
\`\`\`

</details>

### Affected tests

${affected}`
}

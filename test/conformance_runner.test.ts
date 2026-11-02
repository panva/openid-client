import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { execFile } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

import test from 'node:test'
import assert from 'node:assert/strict'

import { downloadArtifact } from '../conformance/api.js'
import {
  getModuleHandler,
  isRunnableModule,
  isSkippedUnhandledModule,
  sortTestFiles,
} from '../conformance/modules.js'
import {
  clearReportRequest,
  formatReportSummary,
  missingHandlerMessage,
  reportIssues,
  reportRequested,
  requestReport,
  setActionEnvironment,
  validatePlanId,
} from '../conformance/report.js'

test('conformance failures are recorded before the final archive test', async (t) => {
  const directory = mkdtempSync(
    join(tmpdir(), 'openid-client-native-report-test-'),
  )
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const failedModule = join(directory, 'failed-module.mjs')
  const archive = join(directory, 'archive.mjs')
  const launcher = join(directory, 'launcher.mjs')
  const status = join(directory, 'status')
  const archivedStatus = join(directory, 'archived-status')
  const title = 'missing conformance handler: newly-exposed-test'

  writeFileSync(
    failedModule,
    `import test from 'node:test'
test(${JSON.stringify(title)}, () => { throw new Error('missing handler') })`,
  )
  writeFileSync(
    archive,
    `import test from 'node:test'
import { readFileSync, writeFileSync } from 'node:fs'
test('archive', () => {
  writeFileSync(${JSON.stringify(archivedStatus)}, readFileSync(${JSON.stringify(status)}))
})`,
  )

  writeFileSync(
    launcher,
    `import { runTests } from ${JSON.stringify(new URL('../conformance/execute.js', import.meta.url).href)}
for await (const event of runTests(${JSON.stringify([failedModule, archive])}, ${JSON.stringify(status)})) {}`,
  )
  const env = { ...process.env }
  delete env.NODE_TEST_CONTEXT
  await promisify(execFile)(process.execPath, [launcher], { env })
  assert.ok(
    reportIssues(status).some(
      (issue) => issue.type === 'failure' && issue.detail === title,
    ),
  )
  assert.match(readFileSync(archivedStatus, 'utf8'), /newly-exposed-test/)
})

test('conformance module response type filtering', () => {
  assert.strictEqual(
    isRunnableModule({ variant: { response_type: 'id_token token' } }),
    false,
  )
  assert.strictEqual(
    isRunnableModule({ variant: { response_type: 'code token' } }),
    false,
  )
  assert.strictEqual(
    isRunnableModule({ variant: { response_type: 'code id_token token' } }),
    false,
  )
  assert.strictEqual(
    isRunnableModule({ variant: { response_type: 'code' } }),
    true,
  )
  assert.strictEqual(isRunnableModule({ variant: null }), true)
})

test('known unsupported OIDC conformance modules are skipped', () => {
  for (const name of [
    'aggregated-claims',
    'discovery-jwks-uri-keys',
    'discovery-openid-config',
    'discovery-webfinger-acct',
    'discovery-webfinger-url',
    'distributed-claims',
    'signing-key-rotation',
    'signing-key-rotation-just-before-signing',
    'userinfo-bearer-body',
  ]) {
    assert.strictEqual(
      isSkippedUnhandledModule('oidcc-client-test-plan', name),
      true,
      name,
    )
    assert.strictEqual(
      isSkippedUnhandledModule(
        'fapi2-security-profile-final-client-test-plan',
        name,
      ),
      false,
      name,
    )
  }
  assert.strictEqual(
    isSkippedUnhandledModule('oidcc-client-test-plan', 'newly-exposed-test'),
    false,
  )
  assert.strictEqual(
    isSkippedUnhandledModule(
      'oidcc-client-test-plan',
      'discovery-issuer-mismatch',
    ),
    false,
  )
  assert.strictEqual(
    isSkippedUnhandledModule(
      'fapi2-security-profile-final-client-test-plan',
      'rs-dpop-auth-scheme-case-insensitivity',
    ),
    false,
  )
})

test('conformance diagnostics file always sorts last', () => {
  const diagnostics = '/workspace/conformance/download_archive.ts'
  const handlers = [
    '/workspace/conformance/modules/z-test.ts',
    '/workspace/conformance/modules/test-10.ts',
    '/workspace/conformance/modules/test-2.ts',
  ]

  assert.deepStrictEqual([diagnostics, ...handlers].sort(sortTestFiles), [
    handlers[2],
    handlers[1],
    handlers[0],
    diagnostics,
  ])
  assert.strictEqual(
    sortTestFiles(
      String.raw`C:\workspace\conformance\download_archive.ts`,
      String.raw`C:\workspace\conformance\modules\test.ts`,
    ) > 0,
    true,
  )
})

test('conformance module handlers', () => {
  assert.deepStrictEqual(getModuleHandler('oidcc-client-test-new-test'), {
    name: 'new-test',
    path: './conformance/modules/new-test.ts',
  })
  assert.deepStrictEqual(
    getModuleHandler('fapi2-message-signing-final-client-test-new-test'),
    {
      name: 'new-test',
      path: './conformance/modules/new-test.ts',
    },
  )
  const discoveryIssuerMismatch = {
    name: 'discovery-issuer-mismatch',
    path: './conformance/modules/discovery-issuer-mismatch.ts',
  }
  assert.deepStrictEqual(
    getModuleHandler('oidcc-client-test-discovery-issuer-mismatch'),
    discoveryIssuerMismatch,
  )
  assert.deepStrictEqual(
    getModuleHandler(
      'fapi2-security-profile-final-client-test-discovery-issuer-mismatch',
    ),
    discoveryIssuerMismatch,
  )
  assert.deepStrictEqual(
    getModuleHandler(
      'fapi2-security-profile-final-client-test-rs-dpop-auth-scheme-case-insensitivity',
    ),
    {
      name: 'rs-dpop-auth-scheme-case-insensitivity',
      path: './conformance/modules/rs-dpop-auth-scheme-case-insensitivity.ts',
    },
  )
  assert.throws(() => getModuleHandler('../new-test'), {
    message: 'invalid conformance module name: ../new-test',
  })
  assert.throws(() => getModuleHandler('oidcc-client-test-.hidden'), {
    message: 'invalid conformance module name: .hidden',
  })
  const longModule = 'a'.repeat(129)
  assert.throws(() => getModuleHandler(longModule), {
    message: `invalid conformance module name: ${longModule}`,
  })
})

test('conformance report inputs are safe for paths and GitHub environment files', () => {
  assert.strictEqual(validatePlanId('plan-123_abc'), 'plan-123_abc')
  assert.throws(() => validatePlanId('../plan'), {
    message: 'invalid conformance plan ID: ../plan',
  })
  const longPlanId = 'a'.repeat(129)
  assert.throws(() => validatePlanId(longPlanId), {
    message: `invalid conformance plan ID: ${longPlanId}`,
  })
  assert.throws(() => setActionEnvironment('INVALID-NAME', 'value'), {
    message: 'invalid GitHub Actions environment variable name: INVALID-NAME',
  })
  assert.throws(() => setActionEnvironment('VALID_NAME', 'first\r\nsecond'), {
    message: 'invalid multiline value for VALID_NAME',
  })
})

test('conformance archive rejects an unsafe plan ID before fetching', async () => {
  await assert.rejects(
    () =>
      downloadArtifact({
        id: '../plan',
        name: 'plan-name',
        modules: [],
      }),
    { message: 'invalid conformance plan ID: ../plan' },
  )
})

test('conformance archive rejects an unsuccessful response before writing', async (t) => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () =>
    new Response('download failed', { status: 500 })
  t.after(() => {
    globalThis.fetch = originalFetch
  })

  await assert.rejects(
    () =>
      downloadArtifact({
        id: 'failed-plan-id',
        name: 'plan-name',
        modules: [],
      }),
    { message: 'download failed' },
  )
})

test('missing conformance module handler message', () => {
  assert.strictEqual(
    missingHandlerMessage('new-test', './conformance/modules/new-test.ts'),
    'The conformance suite exposed a new test module named "new-test", but no handler exists at ./conformance/modules/new-test.ts',
  )
})

test('conformance issue report', (t) => {
  const directory = mkdtempSync(
    join(tmpdir(), 'openid-client-conformance-test-'),
  )
  const path = join(directory, 'report')
  t.after(() => rmSync(directory, { recursive: true, force: true }))

  requestReport(path, { type: 'warning', detail: 'warning-test' })
  requestReport(path, { type: 'failure', detail: 'failure-test' })
  requestReport(path, { type: 'failure', detail: 'failure-test' })

  assert.strictEqual(reportRequested(path), true)
  const issues = reportIssues(path)
  assert.deepStrictEqual(issues, [
    { type: 'warning', detail: 'warning-test' },
    { type: 'failure', detail: 'failure-test' },
  ])

  const summary = formatReportSummary(
    { id: 'plan-id', name: 'plan-name' },
    { response_type: 'code' },
    issues,
  )
  assert.strictEqual(summary.startsWith('## ❌ Conformance failure'), true)
  assert.strictEqual(summary.includes('- Plan: `plan-name`'), true)
  assert.strictEqual(summary.includes('- Plan ID: `plan-id`'), true)
  assert.strictEqual(summary.includes('<summary>Variant</summary>'), true)
  assert.strictEqual(summary.includes('"response_type": "code"'), true)
  assert.strictEqual(
    summary.endsWith(
      '### Affected tests\n\n- `warning-test`\n- `failure-test`',
    ),
    true,
  )

  clearReportRequest(path)
  assert.strictEqual(reportRequested(path), false)
})

test('warning-only conformance report', () => {
  const summary = formatReportSummary(
    { id: 'plan-id', name: 'plan-name' },
    {},
    [{ type: 'warning', detail: 'warning-test' }],
  )
  assert.strictEqual(summary.startsWith('## ⚠️ Conformance warning'), true)
})

test('conformance report sanitizes affected test details', () => {
  const summary = formatReportSummary(
    { id: 'plan-id', name: 'plan-name' },
    {},
    [{ type: 'warning', detail: 'first\r\n`second`' }],
  )
  assert.strictEqual(
    summary.endsWith("### Affected tests\n\n- `first 'second'`"),
    true,
  )
  assert.strictEqual(summary.includes('\r'), false)
})

test('GitHub Actions environment values', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'openid-client-actions-test-'))
  const path = join(directory, 'environment')
  const previous = process.env.GITHUB_ENV
  process.env.GITHUB_ENV = path
  t.after(() => {
    if (previous === undefined) {
      delete process.env.GITHUB_ENV
    } else {
      process.env.GITHUB_ENV = previous
    }
    rmSync(directory, { recursive: true, force: true })
  })

  setActionEnvironment('VALID_NAME', 'single-line')
  assert.strictEqual(readFileSync(path, 'utf8'), 'VALID_NAME=single-line\n')
})

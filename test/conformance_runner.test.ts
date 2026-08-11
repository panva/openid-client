import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import test from 'ava'

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
  normalizeAvaTestTitle,
  reportIssues,
  reportRequested,
  requestReport,
  setActionEnvironment,
  validatePlanId,
} from '../conformance/report.js'

test('AVA afterEach hook titles identify the affected test', (t) => {
  t.is(
    normalizeAvaTestTitle(
      'afterEach.always hook for missing conformance handler: newly-exposed-test',
    ),
    'missing conformance handler: newly-exposed-test',
  )
  t.is(normalizeAvaTestTitle('ordinary test title'), 'ordinary test title')
})

test('conformance module response type filtering', (t) => {
  t.false(isRunnableModule({ variant: { response_type: 'id_token token' } }))
  t.false(isRunnableModule({ variant: { response_type: 'code token' } }))
  t.false(
    isRunnableModule({ variant: { response_type: 'code id_token token' } }),
  )
  t.true(isRunnableModule({ variant: { response_type: 'code' } }))
  t.true(isRunnableModule({ variant: null }))
})

test('known unsupported OIDC conformance modules are skipped', (t) => {
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
    t.true(isSkippedUnhandledModule('oidcc-client-test-plan', name), name)
    t.false(
      isSkippedUnhandledModule(
        'fapi2-security-profile-final-client-test-plan',
        name,
      ),
      name,
    )
  }
  t.false(
    isSkippedUnhandledModule('oidcc-client-test-plan', 'newly-exposed-test'),
  )
  t.false(
    isSkippedUnhandledModule(
      'oidcc-client-test-plan',
      'discovery-issuer-mismatch',
    ),
  )
  t.false(
    isSkippedUnhandledModule(
      'fapi2-security-profile-final-client-test-plan',
      'rs-dpop-auth-scheme-case-insensitivity',
    ),
  )
})

test('conformance diagnostics file always sorts last', (t) => {
  const diagnostics = '/workspace/conformance/download_archive.ts'
  const handlers = [
    '/workspace/conformance/modules/z-test.ts',
    '/workspace/conformance/modules/test-10.ts',
    '/workspace/conformance/modules/test-2.ts',
  ]

  t.deepEqual([diagnostics, ...handlers].sort(sortTestFiles), [
    handlers[2],
    handlers[1],
    handlers[0],
    diagnostics,
  ])
  t.true(
    sortTestFiles(
      String.raw`C:\workspace\conformance\download_archive.ts`,
      String.raw`C:\workspace\conformance\modules\test.ts`,
    ) > 0,
  )
})

test('conformance module handlers', (t) => {
  t.deepEqual(getModuleHandler('oidcc-client-test-new-test'), {
    name: 'new-test',
    path: './conformance/modules/new-test.ts',
  })
  t.deepEqual(
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
  t.deepEqual(
    getModuleHandler('oidcc-client-test-discovery-issuer-mismatch'),
    discoveryIssuerMismatch,
  )
  t.deepEqual(
    getModuleHandler(
      'fapi2-security-profile-final-client-test-discovery-issuer-mismatch',
    ),
    discoveryIssuerMismatch,
  )
  t.deepEqual(
    getModuleHandler(
      'fapi2-security-profile-final-client-test-rs-dpop-auth-scheme-case-insensitivity',
    ),
    {
      name: 'rs-dpop-auth-scheme-case-insensitivity',
      path: './conformance/modules/rs-dpop-auth-scheme-case-insensitivity.ts',
    },
  )
  t.throws(() => getModuleHandler('../new-test'), {
    message: 'invalid conformance module name: ../new-test',
  })
  t.throws(() => getModuleHandler('oidcc-client-test-.hidden'), {
    message: 'invalid conformance module name: .hidden',
  })
  const longModule = 'a'.repeat(129)
  t.throws(() => getModuleHandler(longModule), {
    message: `invalid conformance module name: ${longModule}`,
  })
})

test('conformance report inputs are safe for paths and GitHub environment files', (t) => {
  t.is(validatePlanId('plan-123_abc'), 'plan-123_abc')
  t.throws(() => validatePlanId('../plan'), {
    message: 'invalid conformance plan ID: ../plan',
  })
  const longPlanId = 'a'.repeat(129)
  t.throws(() => validatePlanId(longPlanId), {
    message: `invalid conformance plan ID: ${longPlanId}`,
  })
  t.throws(() => setActionEnvironment('INVALID-NAME', 'value'), {
    message: 'invalid GitHub Actions environment variable name: INVALID-NAME',
  })
  t.throws(() => setActionEnvironment('VALID_NAME', 'first\r\nsecond'), {
    message: 'invalid multiline value for VALID_NAME',
  })
})

test('conformance archive rejects an unsafe plan ID before fetching', async (t) => {
  await t.throwsAsync(
    () =>
      downloadArtifact({
        id: '../plan',
        name: 'plan-name',
        modules: [],
      }),
    { message: 'invalid conformance plan ID: ../plan' },
  )
})

test.serial(
  'conformance archive rejects an unsuccessful response before writing',
  async (t) => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = async () =>
      new Response('download failed', { status: 500 })
    t.teardown(() => {
      globalThis.fetch = originalFetch
    })

    await t.throwsAsync(
      () =>
        downloadArtifact({
          id: 'failed-plan-id',
          name: 'plan-name',
          modules: [],
        }),
      { message: 'download failed' },
    )
  },
)

test('missing conformance module handler message', (t) => {
  t.is(
    missingHandlerMessage('new-test', './conformance/modules/new-test.ts'),
    'The conformance suite exposed a new test module named "new-test", but no handler exists at ./conformance/modules/new-test.ts',
  )
})

test('conformance issue report', (t) => {
  const directory = mkdtempSync(
    join(tmpdir(), 'openid-client-conformance-test-'),
  )
  const path = join(directory, 'report')
  t.teardown(() => rmSync(directory, { recursive: true, force: true }))

  requestReport(path, { type: 'warning', detail: 'warning-test' })
  requestReport(path, { type: 'failure', detail: 'failure-test' })
  requestReport(path, { type: 'failure', detail: 'failure-test' })

  t.true(reportRequested(path))
  const issues = reportIssues(path)
  t.deepEqual(issues, [
    { type: 'warning', detail: 'warning-test' },
    { type: 'failure', detail: 'failure-test' },
  ])

  const summary = formatReportSummary(
    { id: 'plan-id', name: 'plan-name' },
    { response_type: 'code' },
    issues,
  )
  t.true(summary.startsWith('## ❌ Conformance failure'))
  t.true(summary.includes('- Plan: `plan-name`'))
  t.true(summary.includes('- Plan ID: `plan-id`'))
  t.true(summary.includes('<summary>Variant</summary>'))
  t.true(summary.includes('"response_type": "code"'))
  t.true(
    summary.endsWith(
      '### Affected tests\n\n- `warning-test`\n- `failure-test`',
    ),
  )

  clearReportRequest(path)
  t.false(reportRequested(path))
})

test('warning-only conformance report', (t) => {
  const summary = formatReportSummary(
    { id: 'plan-id', name: 'plan-name' },
    {},
    [{ type: 'warning', detail: 'warning-test' }],
  )
  t.true(summary.startsWith('## ⚠️ Conformance warning'))
})

test('conformance report sanitizes affected test details', (t) => {
  const summary = formatReportSummary(
    { id: 'plan-id', name: 'plan-name' },
    {},
    [{ type: 'warning', detail: 'first\r\n`second`' }],
  )
  t.true(summary.endsWith("### Affected tests\n\n- `first 'second'`"))
  t.false(summary.includes('\r'))
})

test.serial('GitHub Actions environment values', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'openid-client-actions-test-'))
  const path = join(directory, 'environment')
  const previous = process.env.GITHUB_ENV
  process.env.GITHUB_ENV = path
  t.teardown(() => {
    if (previous === undefined) {
      delete process.env.GITHUB_ENV
    } else {
      process.env.GITHUB_ENV = previous
    }
    rmSync(directory, { recursive: true, force: true })
  })

  setActionEnvironment('VALID_NAME', 'single-line')
  t.is(readFileSync(path, 'utf8'), 'VALID_NAME=single-line\n')
})

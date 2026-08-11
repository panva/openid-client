import type { ModulePrescription } from './api.js'

const DIAGNOSTICS_FILE = 'conformance/download_archive.ts'
const SKIPPED_OIDC_MODULES = new Set([
  'aggregated-claims',
  'discovery-jwks-uri-keys',
  'discovery-openid-config',
  'discovery-webfinger-acct',
  'discovery-webfinger-url',
  'distributed-claims',
  'signing-key-rotation',
  'signing-key-rotation-just-before-signing',
  'userinfo-bearer-body',
])

export function sortTestFiles(first: string, second: string) {
  const firstIsDiagnostics = first
    .replaceAll('\\', '/')
    .endsWith(DIAGNOSTICS_FILE)
  const secondIsDiagnostics = second
    .replaceAll('\\', '/')
    .endsWith(DIAGNOSTICS_FILE)

  if (firstIsDiagnostics !== secondIsDiagnostics) {
    return firstIsDiagnostics ? 1 : -1
  }

  return first.localeCompare(second, [], { numeric: true })
}

export function isRunnableModule(module: Pick<ModulePrescription, 'variant'>) {
  switch (module.variant?.response_type) {
    case 'id_token token':
    case 'code token':
    case 'code id_token token':
      return false
    default:
      return true
  }
}

export function isSkippedUnhandledModule(planName: string, name: string) {
  return planName.startsWith('oidcc-') && SKIPPED_OIDC_MODULES.has(name)
}

export function getModuleHandler(testModule: string) {
  const name = testModule.replace(
    /(?:fapi2-(?:security-profile-final|message-signing-final)|fapi1-advanced-final|oidcc)-client-test-/,
    '',
  )

  if (!/^[a-z0-9][a-z0-9._+-]{0,127}$/i.test(name)) {
    throw new Error(`invalid conformance module name: ${name}`)
  }

  return { name, path: `./conformance/modules/${name}.ts` }
}

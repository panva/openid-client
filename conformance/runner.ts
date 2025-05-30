import anyTest from 'ava'
import type { ExecutionContext } from 'ava'
import type { Macro, TestFn } from 'ava'
import { importJWK, type JWK } from 'jose'
import * as undici from 'undici'
import { inspect } from 'node:util'

export const test = anyTest as TestFn<{ instance: Test }>

import { getScope, makePublicJwks } from './ava.config.js'
import * as client from '../src/index.js'
import {
  createTestFromPlan,
  waitForState,
  getTestExposed,
  type ModulePrescription,
  type Plan,
  type Test,
} from './api.js'

const conformance = JSON.parse(process.env.CONFORMANCE!)

const configuration: {
  alias: string
  client: {
    client_id: string
    client_secret?: string
    redirect_uri: string
    use_mtls_endpoint_aliases: boolean
    jwks: {
      keys: Array<JWK & { kid: string }>
    }
  }
  client2: {
    jwks: {
      keys: Array<JWK & { kid: string }>
    }
  }
} = conformance.configuration

const ALG = conformance.ALG as string
export const plan: Plan = conformance.plan
export const variant: Record<string, string> = conformance.variant
export const mtls: { key: string; cert: string } = conformance.mtls || {}

let prefix = ''

switch (plan.name) {
  case 'fapi1-advanced-final-client-test-plan':
  case 'fapi2-security-profile-final-client-test-plan':
    prefix = plan.name.slice(0, -4)
    break
  case 'fapi2-message-signing-final-client-test-plan':
    prefix = 'fapi2-security-profile-final-client-test-'
    break
  case 'oidcc-client-test-plan':
  case 'oidcc-client-basic-certification-test-plan':
  case 'oidcc-client-implicit-certification-test-plan':
  case 'oidcc-client-hybrid-certification-test-plan':
    prefix = 'oidcc-client-test-'
    break
  default:
    throw new Error()
}

async function importPrivateKey(alg: string, jwk: JWK) {
  const key = await importJWK(jwk, alg)
  if (!('type' in key)) {
    throw new Error()
  }
  return key
}

export function modules(metaUrl: string): ModulePrescription[] {
  const name = metaUrl.split('/').reverse()[0].replace('.ts', '')
  return conformance.plan.modules.filter((x: ModulePrescription) => {
    switch (x.variant?.response_type) {
      case 'id_token token':
      case 'code token':
      case 'code id_token token':
        return false
    }

    return (
      x.testModule ===
      (name === prefix.slice(0, -1) ? name : `${prefix}${name}`)
    )
  })
}

function usesJarm(variant: Record<string, string>) {
  return variant.fapi_response_mode === 'jarm'
}

function usesDpop(variant: Record<string, string>) {
  return variant.sender_constrain === 'dpop'
}

function usesPar(plan: Plan) {
  return (
    plan.name.startsWith('fapi2') ||
    variant.fapi_auth_request_method === 'pushed'
  )
}

export function nonRepudiation(plan: Plan) {
  return (
    plan.name.startsWith('fapi2-message-signing') ||
    plan.name.startsWith('fapi1')
  )
}

function usesRequestObject(planName: string, variant: Record<string, string>) {
  if (planName.startsWith('fapi1')) {
    return true
  }

  if (planName.startsWith('fapi2-message-signing')) {
    return true
  }

  if (variant.request_type === 'request_object') {
    return true
  }

  return false
}

function requiresNonce(planName: string, variant: Record<string, string>) {
  return (
    responseType(planName, variant).includes('id_token') ||
    (planName.startsWith('fapi1') && getScope(variant).includes('openid'))
  )
}

function requiresState(planName: string, variant: Record<string, string>) {
  return planName.startsWith('fapi1') && !getScope(variant).includes('openid')
}

function responseType(planName: string, variant: Record<string, string>) {
  if (variant.response_type) {
    return variant.response_type
  }

  if (!planName.startsWith('fapi1')) {
    return 'code'
  }

  return variant.fapi_response_mode === 'jarm' ? 'code' : 'code id_token'
}

function dcr(variant: Record<string, string>) {
  return variant.client_registration === 'dynamic_client'
}

export interface MacroOptions {
  useNonce?: boolean
  useState?: boolean
}

export const flow = (options?: MacroOptions) => {
  return test.macro({
    async exec(t, module: ModulePrescription) {
      t.timeout(15000)

      const instance = await createTestFromPlan(plan, module)
      t.context.instance = instance

      t.log('Test ID', instance.id)
      t.log('Test Name', instance.name)

      const variant: Record<string, string> = {
        ...conformance.variant,
        ...module.variant,
      }
      t.log('variant', variant)

      const { issuer: issuerIdentifier, accounts_endpoint } =
        await getTestExposed(instance)

      if (!issuerIdentifier) {
        throw new Error()
      }

      const issuer = new URL(issuerIdentifier)

      const response_type = responseType(plan.name, variant)
      const metadata: client.ClientMetadata = makePublicJwks({
        client_id: dcr(variant) ? undefined : configuration.client.client_id,
        client_secret: dcr(variant)
          ? undefined
          : configuration.client.client_secret,
        use_mtls_endpoint_aliases:
          configuration.client.use_mtls_endpoint_aliases,
        jwks: configuration.client.jwks,
        redirect_uris: [configuration.client.redirect_uri],
        response_types: [response_type],
        grant_types:
          response_type === 'code'
            ? ['authorization_code']
            : ['authorization_code', 'implicit'],
      })

      switch (variant.client_auth_type) {
        case 'mtls':
          metadata.token_endpoint_auth_method = 'self_signed_tls_client_auth'
          break
        case 'none':
        case 'private_key_jwt':
        case 'client_secret_basic':
        case 'client_secret_post':
          metadata.token_endpoint_auth_method = variant.client_auth_type
          break
      }

      if (instance.name.includes('client-secret-basic')) {
        metadata.token_endpoint_auth_method = 'client_secret_basic'
      }

      // @ts-expect-error
      const mtlsFetch: typeof fetch = async (
        ...args: Parameters<typeof fetch>
      ) => {
        // @ts-expect-error
        let response = await undici.fetch(args[0], {
          ...args[1],
          dispatcher: new undici.Agent({
            connect: {
              key: mtls.key,
              cert: mtls.cert,
            },
          }),
        })

        if (dcr(variant)) {
          // TODO: remove when https://gitlab.com/openid/conformance-suite/-/issues/1503 is fixed
          if (response.ok && (args[0] as string).endsWith('/register')) {
            const body = (await response.json()) as any
            if (body.client_secret) {
              body.client_secret_expires_at = 0
            }
            // @ts-expect-error
            response = new Response(JSON.stringify(body), response)
          }
        }

        return response
      }

      let dcrFetch: typeof fetch | undefined
      if (dcr(variant)) {
        // TODO: remove when https://gitlab.com/openid/conformance-suite/-/issues/1503 is fixed
        dcrFetch = async (...args: Parameters<typeof fetch>) => {
          let response = await fetch(...args)
          if (response.ok && (args[0] as string).endsWith('/register')) {
            const body = await response.json()
            if (body.client_secret) {
              body.client_secret_expires_at = 0
            }
            response = new Response(JSON.stringify(body), response)
          }
          return response
        }
      }

      const mtlsAuth = variant.client_auth_type === 'mtls'
      const mtlsConstrain =
        plan.name.startsWith('fapi1') || variant.sender_constrain === 'mtls'

      const execute: Array<(config: client.Configuration) => void> = []

      if (nonRepudiation(plan)) {
        execute.push(client.enableNonRepudiationChecks)
      }

      if (usesJarm(variant)) {
        execute.push(client.useJwtResponseMode)
      }

      if (response_type === 'code id_token') {
        execute.push(client.useCodeIdTokenResponseType)
        if (plan.name.startsWith('fapi1')) {
          execute.push(client.enableDetachedSignatureResponseChecks)
        }
      }

      if (response_type === 'id_token') {
        execute.push(client.useIdTokenResponseType)
      }

      const [jwk] = configuration.client.jwks.keys
      const clientPrivateKey = {
        kid: jwk.kid,
        key: await importPrivateKey(ALG, jwk),
      }
      const client_secret = dcr(variant) ? undefined : metadata.client_secret

      let clientAuth: client.ClientAuth | undefined
      if (metadata.token_endpoint_auth_method === 'private_key_jwt') {
        clientAuth = client.PrivateKeyJwt(clientPrivateKey)
      } else if (
        metadata.token_endpoint_auth_method === 'client_secret_basic'
      ) {
        clientAuth = client.ClientSecretBasic(client_secret)
      }

      let config: client.Configuration
      if (dcr(variant)) {
        config = await client.dynamicClientRegistration(
          issuer,
          metadata,
          clientAuth,
          {
            execute,
            [client.customFetch]:
              mtlsAuth || mtlsConstrain || metadata.use_mtls_endpoint_aliases
                ? mtlsFetch
                : dcr(variant)
                  ? dcrFetch
                  : undefined,
          },
        )
      } else {
        config = await client.discovery(
          issuer,
          configuration.client.client_id,
          metadata,
          clientAuth,
          {
            execute,
            [client.customFetch]:
              mtlsAuth || mtlsConstrain || metadata.use_mtls_endpoint_aliases
                ? mtlsFetch
                : undefined,
          },
        )
      }

      if (module.testModule.includes('encrypted')) {
        const jwk = configuration.client.jwks.keys[0]
        const key = await importPrivateKey('RSA-OAEP', jwk)
        client.enableDecryptingResponses(config, undefined, {
          key,
          kid: `enc-${jwk.kid}`,
        })
      }

      t.log('AS Metadata discovered for', issuer.href)
      if (dcr(variant)) {
        t.log(
          'Client Metadata registered for',
          config.clientMetadata().client_id,
        )
      }

      const DPoP = usesDpop(variant)
        ? client.getDPoPHandle(config, await client.randomDPoPKeyPair(ALG))
        : undefined

      const code_verifier = client.randomPKCECodeVerifier()
      const code_challenge =
        await client.calculatePKCECodeChallenge(code_verifier)
      const code_challenge_method = 'S256'

      if (
        !config.serverMetadata().supportsPKCE() &&
        !response_type.includes('id_token')
      ) {
        options ||= {}
        options.useState = true
      }

      const scope = getScope(variant)
      let nonce =
        options?.useNonce || requiresNonce(plan.name, variant)
          ? client.randomNonce()
          : undefined
      let state =
        options?.useState || requiresState(plan.name, variant)
          ? client.randomState()
          : undefined

      let params: URLSearchParams = new URLSearchParams()
      if (code_challenge) {
        params.set('code_challenge', code_challenge)
      }
      if (code_challenge_method) {
        params.set('code_challenge_method', code_challenge_method)
      }
      params.set('redirect_uri', configuration.client.redirect_uri)
      params.set('scope', scope)
      if (typeof nonce === 'string') {
        params.set('nonce', nonce)
      }
      if (typeof state === 'string') {
        params.set('state', state)
      }

      if (usesRequestObject(plan.name, variant)) {
        ;({ searchParams: params } = await client.buildAuthorizationUrlWithJAR(
          config,
          params,
          clientPrivateKey,
        ))
      }

      let authorizationUrl: URL

      if (usesPar(plan)) {
        t.log('PAR request with', Object.fromEntries(params.entries()))
        authorizationUrl = await client.buildAuthorizationUrlWithPAR(
          config,
          params,
          {
            DPoP,
          },
        )
        t.log(
          'PAR request_uri',
          authorizationUrl.searchParams.get('request_uri'),
        )
      } else {
        if (params.has('request') && plan.name.startsWith('fapi1')) {
          const plain = client.buildAuthorizationUrl(config, {})
          params.set('response_type', plain.searchParams.get('response_type')!)
          params.set('scope', 'openid')
        }
        authorizationUrl = client.buildAuthorizationUrl(config, params)
      }

      await Promise.allSettled([
        fetch(authorizationUrl.href, { redirect: 'manual' }),
      ])

      t.log(
        'redirect with',
        Object.fromEntries(authorizationUrl.searchParams.entries()),
      )

      const { authorization_endpoint_response_redirect } =
        await getTestExposed(instance)

      if (!authorization_endpoint_response_redirect) {
        throw new Error()
      }

      const currentUrl = new URL(authorization_endpoint_response_redirect)

      t.log('response redirect to', currentUrl.href)

      if (response_type === 'id_token') {
        const response = await client.implicitAuthentication(
          config,
          currentUrl,
          nonce!,
          {
            expectedState: state,
          },
        )

        t.log('validated ID Token Claims Set', {
          ...response,
        })
      } else {
        const response = await client.authorizationCodeGrant(
          config,
          currentUrl,
          {
            expectedNonce: nonce,
            expectedState: state,
            pkceCodeVerifier: code_verifier,
          },
          undefined,
          { DPoP },
        )

        t.log('token endpoint response', { ...response })

        if (
          !plan.name.startsWith('fapi1') &&
          scope.includes('openid') &&
          config.serverMetadata().userinfo_endpoint
        ) {
          // fetch userinfo response
          t.log('fetching', config.serverMetadata().userinfo_endpoint)
          const userinfo = await client.fetchUserInfo(
            config,
            response.access_token,
            response.claims()?.sub!,
            {
              DPoP,
            },
          )
          t.log('userinfo endpoint response', { ...userinfo })
        }

        if (accounts_endpoint) {
          const resource = await client.fetchProtectedResource(
            config,
            response.access_token,
            new URL(accounts_endpoint),
            'GET',
            null,
            undefined,
            { DPoP },
          )

          const result = await resource.text()
          try {
            t.log('accounts endpoint response', JSON.parse(result))
          } catch {
            t.log('accounts endpoint response body', result)
          }
        }
      }

      await waitForState(instance)
      if (module.skipLogTestFinished !== true) {
        t.log('Test Finished')
      }
      t.pass()
    },
    title(providedTitle = '', module: ModulePrescription) {
      if (module.variant) {
        return `${providedTitle}${plan.name} (${plan.id}) - ${module.testModule} - ${JSON.stringify(
          module.variant,
        )}`
      }
      return `${providedTitle}${plan.name} (${plan.id}) - ${module.testModule}`
    },
  })
}

interface ErrorAssertion {
  name: string
  code: string
  message: string | RegExp
}

export type CodeErrorAssertion = Partial<ErrorAssertion> &
  Pick<ErrorAssertion, 'code'>
export type NameErrorAssertion = Partial<ErrorAssertion> &
  Pick<ErrorAssertion, 'name'>
export type MessageErrorAssertion = Partial<ErrorAssertion> &
  Pick<ErrorAssertion, 'message'>

function assertError(
  t: ExecutionContext,
  actual: unknown,
  expected: Partial<ErrorAssertion>,
) {
  if (!(actual instanceof Error)) {
    t.fail('expected and Error instance')
  }

  // @ts-ignore
  if (expected.code) t.is(actual.code, expected.code)
  if (expected.name) t.is(actual.name, expected.name)
  if (expected.message) {
    if (typeof expected.message === 'string') {
      t.is(actual.message, expected.message)
    } else {
      t.regex(actual.message, expected.message)
    }
  }
}

export const rejects = (
  macro: Macro<[module: ModulePrescription], { instance: Test }>,
) => {
  return test.macro({
    async exec(
      t,
      module: ModulePrescription,
      expected: CodeErrorAssertion | MessageErrorAssertion,
      cause?: CodeErrorAssertion | MessageErrorAssertion,
    ) {
      const err = await t.throwsAsync(
        () => macro.exec(t, { ...module, skipLogTestFinished: true }) as any,
      )
      t.log('rejected with', inspect(err, { depth: Infinity }))

      expected.name ||= 'ClientError'
      assertError(t, err, expected)

      if (cause) {
        cause.name ||= 'OperationProcessingError'
        if (!(err.cause instanceof Error)) {
          t.fail('expected and Error instance')
        }
        t.truthy(
          err.cause,
          'expected err to have a [cause] that is an Error instance',
        )

        if (typeof cause !== 'boolean') {
          assertError(t, err.cause, cause)
        }
      }

      await waitForState(t.context.instance)
      t.log('Test Finished')
      t.pass()
    },
    title: macro.title as any,
  })
}

export const skippable = (
  macro: Macro<[module: ModulePrescription], { instance: Test }>,
) => {
  return test.macro({
    async exec(t, module: ModulePrescription) {
      await Promise.allSettled([
        macro.exec(t, { ...module, skipLogTestFinished: true }),
      ])

      await waitForState(t.context.instance, {
        results: new Set(['SKIPPED', 'PASSED']),
      })
      t.log('Test Finished')
      t.pass()
    },
    title: macro.title as any,
  })
}

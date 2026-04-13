import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { Readable } from 'node:stream'
import * as crypto from 'node:crypto'

import test from 'ava'
import type passport from 'passport'
import * as client from '../src/index.js'
import { Strategy } from '../src/passport.js'
import type { AuthenticateOptions } from '../src/passport.js'

function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => {
      if (err) {
        reject(err)
        return
      }
      resolve()
    })
  })
}

async function startTokenEndpoint(
  tokenResponse?: () => {
    status: number
    body: unknown
    headers?: Record<string, string>
  },
  options?: { handlePAR?: boolean },
) {
  const requests: string[] = []
  const parRequests: string[] = []

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1')

    if (req.method === 'POST' && url.pathname === '/token') {
      let body = ''
      for await (const chunk of req) {
        body += chunk
      }

      requests.push(body)

      const response = tokenResponse?.() ?? {
        status: 200,
        body: { access_token: 'ok', token_type: 'bearer' },
      }

      res.writeHead(response.status, {
        'content-type': 'application/json',
        ...response.headers,
      })
      res.end(JSON.stringify(response.body))
      return
    }

    if (
      options?.handlePAR &&
      req.method === 'POST' &&
      url.pathname === '/par'
    ) {
      let body = ''
      for await (const chunk of req) {
        body += chunk
      }
      parRequests.push(body)

      res.writeHead(201, { 'content-type': 'application/json' })
      res.end(
        JSON.stringify({
          request_uri: 'urn:ietf:params:oauth:request_uri:par_ref',
          expires_in: 60,
        }),
      )
      return
    }

    res.writeHead(404)
    res.end()
  })

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve)
  })

  const { port } = server.address() as AddressInfo

  return {
    port,
    requests,
    parRequests,
    server,
  }
}

function createConfiguration(
  port: number,
  metadataOverrides?: Record<string, unknown>,
) {
  const config = new client.Configuration(
    {
      issuer: `http://127.0.0.1:${port}/issuer`,
      authorization_endpoint: `http://127.0.0.1:${port}/authorize`,
      code_challenge_methods_supported: ['S256'],
      token_endpoint: `http://127.0.0.1:${port}/token`,
      ...metadataOverrides,
    },
    'client',
    undefined,
    client.None(),
  )

  client.allowInsecureRequests(config)

  return config
}

type StrategyHarness = passport.StrategyCreated<
  Strategy,
  Strategy & passport.StrategyCreatedStatic
>

interface HarnessResult {
  strategy: StrategyHarness
  session: Record<string, unknown>
  results: {
    redirectTo?: string
    error?: unknown
    failInfo?: unknown
    successUser?: Express.User
  }
}

function createStrategyHarness(
  port: number,
  verify?: (
    tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers,
    verified: passport.AuthenticateCallback,
  ) => void,
  strategyOptions?: Partial<{
    callbackURL: string
    passReqToCallback: boolean
    scope: string
    resource: string | string[]
    sessionKey: string
  }>,
  metadataOverrides?: Record<string, unknown>,
): HarnessResult {
  const results: HarnessResult['results'] = {}
  const session: Record<string, unknown> = {}

  const strategy = new Strategy(
    {
      callbackURL:
        strategyOptions?.callbackURL ?? `http://127.0.0.1:${port}/cb`,
      config: createConfiguration(port, metadataOverrides),
      ...strategyOptions,
    } as any,
    verify ??
      ((_tokens, verified) => verified(null, { sub: 'user' } as Express.User)),
  ) as StrategyHarness

  strategy.redirect = (href: string) => {
    results.redirectTo = href
  }
  strategy.error = (err: unknown) => {
    results.error = err
  }
  strategy.fail = (info: unknown) => {
    results.failInfo = info
  }
  strategy.success = (user: Express.User) => {
    results.successUser = user
  }

  return { strategy, session, results }
}

async function doAuthorizationRequest(
  harness: HarnessResult,
  options: AuthenticateOptions = {},
): Promise<string> {
  await Strategy.prototype.authorizationRequest.call(
    harness.strategy,
    { session: harness.session } as any,
    options,
  )
  return harness.results.redirectTo!
}

async function doAuthorizationCodeGrant(
  harness: HarnessResult,
  callbackUrl: string,
  options: AuthenticateOptions = {},
  method = 'GET',
): Promise<void> {
  await Strategy.prototype.authorizationCodeGrant.call(
    harness.strategy,
    {
      method,
      session: harness.session,
    } as any,
    new URL(callbackUrl),
    options,
  )
}

// --- Constructor ---

test('constructor throws on missing config', (t) => {
  t.throws(() => new Strategy({} as any, () => {}), {
    instanceOf: TypeError,
  })
})

test('constructor throws on non-function verify', (t) => {
  const { port } = { port: 0 }
  t.throws(
    () =>
      new Strategy(
        { config: createConfiguration(port) } as any,
        'not a function' as any,
      ),
    { instanceOf: TypeError },
  )
})

test('constructor uses issuer host as default name and sessionKey', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})
  t.is(strategy.name, '127.0.0.1:9999')
  t.is(strategy._sessionKey, '127.0.0.1:9999')
})

test('constructor accepts custom name and sessionKey', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy(
    { config, name: 'custom-name', sessionKey: 'custom-key' },
    () => {},
  )
  t.is(strategy.name, 'custom-name')
  t.is(strategy._sessionKey, 'custom-key')
})

// --- authenticate routing ---

test('authenticate errors when session is missing', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {}) as StrategyHarness

  let error: unknown
  strategy.error = (err: unknown) => {
    error = err
  }

  Strategy.prototype.authenticate.call(strategy, {} as any, {})
  t.true(error instanceof Error)
  t.regex((error as Error).message, /session/i)
})

// --- shouldInitiateAuthRequest ---

test('shouldInitiateAuthRequest returns true for plain GET without callback params', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})
  const url = new URL('http://localhost/login')
  t.true(strategy.shouldInitiateAuthRequest({ method: 'GET' } as any, url, {}))
})

test('shouldInitiateAuthRequest returns false when code param present', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})
  const url = new URL('http://localhost/cb?code=abc')
  t.false(strategy.shouldInitiateAuthRequest({ method: 'GET' } as any, url, {}))
})

test('shouldInitiateAuthRequest returns false when error param present', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})
  const url = new URL('http://localhost/cb?error=access_denied')
  t.false(strategy.shouldInitiateAuthRequest({ method: 'GET' } as any, url, {}))
})

test('shouldInitiateAuthRequest returns false when response param present', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})
  const url = new URL('http://localhost/cb?response=jarm')
  t.false(strategy.shouldInitiateAuthRequest({ method: 'GET' } as any, url, {}))
})

test('shouldInitiateAuthRequest returns false for POST', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})
  const url = new URL('http://localhost/cb')
  t.false(
    strategy.shouldInitiateAuthRequest({ method: 'POST' } as any, url, {}),
  )
})

// --- Authorization Request ---

test('authorizationRequest redirects and stores state in session', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness)

  const url = new URL(redirectTo)
  t.truthy(url.searchParams.get('code_challenge'))
  t.is(url.searchParams.get('code_challenge_method'), 'S256')
  t.truthy(url.searchParams.get('redirect_uri'))

  // Session state was stored
  const sessionKey = harness.strategy._sessionKey
  const stateData = harness.session[sessionKey] as any
  t.truthy(stateData)
  t.truthy(stateData.code_verifier)
})

test('authorizationRequest includes scope from options', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness, {
    scope: 'openid profile',
  })

  const url = new URL(redirectTo)
  t.is(url.searchParams.get('scope'), 'openid profile')
})

test('authorizationRequest includes scope array from options', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness, {
    scope: ['openid', 'email'],
  })

  const url = new URL(redirectTo)
  t.is(url.searchParams.get('scope'), 'openid email')
})

test('authorizationRequest uses strategy-level scope as fallback', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port, undefined, {
    scope: 'openid',
  })
  const redirectTo = await doAuthorizationRequest(harness)

  const url = new URL(redirectTo)
  t.is(url.searchParams.get('scope'), 'openid')
})

test('authorizationRequest includes loginHint', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness, {
    loginHint: 'user@example.com',
  })

  const url = new URL(redirectTo)
  t.is(url.searchParams.get('login_hint'), 'user@example.com')
})

test('authorizationRequest includes prompt', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness, {
    prompt: 'consent',
  })

  const url = new URL(redirectTo)
  t.is(url.searchParams.get('prompt'), 'consent')
})

test('authorizationRequest includes resource', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness, {
    resource: 'https://rs.example.com',
  })

  const url = new URL(redirectTo)
  t.is(url.searchParams.get('resource'), 'https://rs.example.com')
})

test('authorizationRequest includes strategy-level resource as fallback', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port, undefined, {
    resource: 'https://rs.example.com',
  })
  const redirectTo = await doAuthorizationRequest(harness)

  const url = new URL(redirectTo)
  t.is(url.searchParams.get('resource'), 'https://rs.example.com')
})

// --- Authorization Code Grant (callback) ---

test('callback with missing session state calls fail', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)

  // No authorizationRequest was made, so session is empty
  await doAuthorizationCodeGrant(harness, `http://127.0.0.1:${port}/cb?code=ok`)

  t.truthy(harness.results.failInfo)
  t.like(harness.results.failInfo as Record<string, unknown>, {
    message: 'Unable to verify authorization request state',
  })
})

test('verify callback error propagates via strategy.error', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const verifyError = new Error('verify failed')
  const harness = createStrategyHarness(port, (_tokens, verified) => {
    verified(verifyError)
  })

  const redirectTo = await doAuthorizationRequest(harness)
  await doAuthorizationCodeGrant(
    harness,
    `${new URL(redirectTo).origin}/cb?code=ok`,
  )

  t.is(harness.results.error, verifyError)
})

test('verify callback with no user calls fail', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port, (_tokens, verified) => {
    verified(null, false, { message: 'no such user' })
  })

  const redirectTo = await doAuthorizationRequest(harness)
  await doAuthorizationCodeGrant(
    harness,
    `${new URL(redirectTo).origin}/cb?code=ok`,
  )

  t.truthy(harness.results.failInfo)
})

test('access_denied error response calls fail instead of error', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness)

  await doAuthorizationCodeGrant(
    harness,
    `${new URL(redirectTo).origin}/cb?error=access_denied&error_description=user+denied`,
  )

  t.truthy(harness.results.failInfo)
  t.falsy(harness.results.error)
  t.like(harness.results.failInfo as Record<string, unknown>, {
    message: 'user denied',
  })
})

test('non-access_denied error response calls error', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness)

  await doAuthorizationCodeGrant(
    harness,
    `${new URL(redirectTo).origin}/cb?error=server_error`,
  )

  t.truthy(harness.results.error)
  t.true(harness.results.error instanceof client.AuthorizationResponseError)
})

test('callbackURL option overrides strategy-level callbackURL in callback', async (t) => {
  const { port, server, requests } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness)

  const overrideUrl = `http://127.0.0.1:${port}/other-cb`

  await doAuthorizationCodeGrant(
    harness,
    `${new URL(redirectTo).origin}/cb?code=ok`,
    { callbackURL: overrideUrl },
  )

  t.truthy(harness.results.successUser)
  // The token request should include the overridden redirect_uri
  const tokenBody = new URLSearchParams(requests[0])
  t.is(tokenBody.get('redirect_uri'), overrideUrl)
})

test('passReqToCallback passes request to verify function', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  let receivedReq: unknown
  const strategy = new Strategy(
    {
      callbackURL: `http://127.0.0.1:${port}/cb`,
      config: createConfiguration(port),
      passReqToCallback: true,
    },
    (req, _tokens, verified) => {
      receivedReq = req
      verified(null, { sub: 'user' } as Express.User)
    },
  ) as StrategyHarness

  const session: Record<string, unknown> = {}
  const results: HarnessResult['results'] = {}

  strategy.redirect = (href: string) => {
    results.redirectTo = href
  }
  strategy.error = (err: unknown) => {
    results.error = err
  }
  strategy.fail = (info: unknown) => {
    results.failInfo = info
  }
  strategy.success = (user: Express.User) => {
    results.successUser = user
  }

  await Strategy.prototype.authorizationRequest.call(
    strategy,
    { session } as any,
    {},
  )

  const fakeReq = { method: 'GET', session, marker: 'the-request' }

  await Strategy.prototype.authorizationCodeGrant.call(
    strategy,
    fakeReq as any,
    new URL(`${new URL(results.redirectTo!).origin}/cb?code=ok`),
    {},
  )

  t.truthy(results.successUser)
  t.is((receivedReq as any).marker, 'the-request')
})

test('token endpoint request includes code_verifier from session', async (t) => {
  const { port, server, requests } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness)

  await doAuthorizationCodeGrant(
    harness,
    `${new URL(redirectTo).origin}/cb?code=test_code`,
  )

  t.truthy(harness.results.successUser)
  const tokenBody = new URLSearchParams(requests[0])
  t.is(tokenBody.get('grant_type'), 'authorization_code')
  t.is(tokenBody.get('code'), 'test_code')
  t.truthy(tokenBody.get('code_verifier'))
})

// --- authorizationRequestParams: idTokenHint ---

test('authorizationRequest includes idTokenHint', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness, {
    idTokenHint: 'eyJ.previous.token',
  })

  const url = new URL(redirectTo)
  t.is(url.searchParams.get('id_token_hint'), 'eyJ.previous.token')
})

// --- authorizationRequestParams: authorizationDetails ---

test('authorizationRequest includes authorizationDetails from options', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const details: client.AuthorizationDetails = {
    type: 'payment_initiation',
    actions: ['initiate'],
  }
  const redirectTo = await doAuthorizationRequest(harness, {
    authorizationDetails: details,
  })

  const url = new URL(redirectTo)
  const parsed = JSON.parse(url.searchParams.get('authorization_details')!)
  t.true(Array.isArray(parsed))
  t.is(parsed[0].type, 'payment_initiation')
})

test('authorizationRequest includes authorizationDetails array from options', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const details: client.AuthorizationDetails[] = [
    { type: 'payment_initiation' },
    { type: 'account_information' },
  ]
  const redirectTo = await doAuthorizationRequest(harness, {
    authorizationDetails: details,
  })

  const url = new URL(redirectTo)
  const parsed = JSON.parse(url.searchParams.get('authorization_details')!)
  t.is(parsed.length, 2)
  t.is(parsed[0].type, 'payment_initiation')
  t.is(parsed[1].type, 'account_information')
})

// --- authorizationRequestParams: callbackURL override in auth request ---

test('authorizationRequest includes callbackURL option as redirect_uri', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness, {
    callbackURL: `http://127.0.0.1:${port}/override-cb`,
  })

  const url = new URL(redirectTo)
  t.is(
    url.searchParams.get('redirect_uri'),
    `http://127.0.0.1:${port}/override-cb`,
  )
})

// --- authorizationDetails strategy-level fallback ---

test('authorizationRequest uses strategy-level authorizationDetails as fallback', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const details: client.AuthorizationDetails = { type: 'payment_initiation' }
  const config = createConfiguration(port)
  const strategy = new Strategy(
    {
      callbackURL: `http://127.0.0.1:${port}/cb`,
      config,
      authorizationDetails: details,
    },
    (_tokens, verified) => verified(null, { sub: 'user' } as Express.User),
  ) as StrategyHarness

  const session: Record<string, unknown> = {}
  const results: HarnessResult['results'] = {}
  strategy.redirect = (href: string) => {
    results.redirectTo = href
  }
  strategy.error = (err: unknown) => {
    results.error = err
  }

  await Strategy.prototype.authorizationRequest.call(
    strategy,
    { session } as any,
    {},
  )

  const url = new URL(results.redirectTo!)
  const parsed = JSON.parse(url.searchParams.get('authorization_details')!)
  t.true(Array.isArray(parsed))
  t.is(parsed[0].type, 'payment_initiation')
})

// --- Session state stores nonce, state, max_age ---

test('authorizationRequest stores max_age in session when present', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)

  // Provide max_age via the overridable authorizationRequestParams
  const origParams = Strategy.prototype.authorizationRequestParams
  harness.strategy.authorizationRequestParams = function (req, options) {
    const params = new URLSearchParams(origParams.call(this, req, options))
    params.set('max_age', '3600')
    return params
  }

  await doAuthorizationRequest(harness)

  const sessionKey = harness.strategy._sessionKey
  const stateData = harness.session[sessionKey] as any
  t.is(stateData.max_age, 3600)
  t.truthy(stateData.code_verifier)
})

// --- authorizationRequest error handling ---

test('authorizationRequest error routes to strategy.error', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)

  // Force an error by making buildAuthorizationUrl throw via bad params
  harness.strategy.authorizationRequestParams = () => {
    throw new Error('params failed')
  }

  await doAuthorizationRequest(harness)

  t.truthy(harness.results.error)
  t.is((harness.results.error as Error).message, 'params failed')
  t.falsy(harness.results.redirectTo)
})

// --- resource forwarded to token endpoint ---

test('resource option is forwarded to token endpoint request', async (t) => {
  const { port, server, requests } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness)

  await doAuthorizationCodeGrant(
    harness,
    `${new URL(redirectTo).origin}/cb?code=ok`,
    { resource: 'https://rs.example.com' },
  )

  t.truthy(harness.results.successUser)
  const tokenBody = new URLSearchParams(requests[0])
  t.is(tokenBody.get('resource'), 'https://rs.example.com')
})

// --- currentUrl ---

test('currentUrl constructs URL from request properties', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})

  const req = {
    protocol: 'https',
    host: 'example.com',
    originalUrl: '/cb?code=abc&state=xyz',
    get(header: string) {
      if (header === 'host') return 'example.com'
      return undefined
    },
    socket: { remoteAddress: '127.0.0.1' },
    app: {
      get() {
        return () => false
      },
    },
  }

  const url = strategy.currentUrl(req as any)
  t.is(url.origin, 'https://example.com')
  t.is(url.pathname, '/cb')
  t.is(url.searchParams.get('code'), 'abc')
  t.is(url.searchParams.get('state'), 'xyz')
})

test('currentUrl falls back to req.url when originalUrl is absent', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})

  const req = {
    protocol: 'http',
    host: 'localhost:3000',
    url: '/callback?code=test',
    get(header: string) {
      if (header === 'host') return 'localhost:3000'
      return undefined
    },
    socket: { remoteAddress: '127.0.0.1' },
    app: {
      get() {
        return () => false
      },
    },
  }

  const url = strategy.currentUrl(req as any)
  t.is(url.href, 'http://localhost:3000/callback?code=test')
})

// --- authenticate integration ---

test('authenticate routes to authorizationRequest for initial GET', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)

  // Provide enough request shape for currentUrl + authenticate
  const req = {
    method: 'GET',
    protocol: 'http',
    host: `127.0.0.1:${port}`,
    originalUrl: '/login',
    session: harness.session,
    get(header: string) {
      if (header === 'host') return `127.0.0.1:${port}`
      return undefined
    },
    socket: { remoteAddress: '127.0.0.1' },
    app: {
      get() {
        return () => false
      },
    },
  }

  Strategy.prototype.authenticate.call(harness.strategy, req as any, {})

  // Give the async authorizationRequest time to complete
  await new Promise((resolve) => setTimeout(resolve, 100))

  t.truthy(harness.results.redirectTo)
  const url = new URL(harness.results.redirectTo!)
  t.truthy(url.searchParams.get('code_challenge'))
})

test('authenticate routes to authorizationCodeGrant for callback GET with code', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)

  // First, do the auth request to populate session
  const redirectTo = await doAuthorizationRequest(harness)

  const req = {
    method: 'GET',
    protocol: 'http',
    host: `127.0.0.1:${port}`,
    originalUrl: '/cb?code=ok',
    session: harness.session,
    get(header: string) {
      if (header === 'host') return `127.0.0.1:${port}`
      return undefined
    },
    socket: { remoteAddress: '127.0.0.1' },
    app: {
      get() {
        return () => false
      },
    },
  }

  Strategy.prototype.authenticate.call(harness.strategy, req as any, {})

  // Give the async authorizationCodeGrant time to complete
  await new Promise((resolve) => setTimeout(resolve, 500))

  t.truthy(harness.results.successUser)
})

// --- Constructor: callbackURL string→URL conversion ---

test('constructor converts string callbackURL to URL instance', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy(
    { config, callbackURL: 'http://example.com/cb' },
    () => {},
  )
  t.true(strategy._callbackURL instanceof URL)
  t.is(strategy._callbackURL!.href, 'http://example.com/cb')
})

test('constructor accepts URL callbackURL', (t) => {
  const config = createConfiguration(9999)
  const url = new URL('http://example.com/cb')
  const strategy = new Strategy({ config, callbackURL: url }, () => {})
  t.true(strategy._callbackURL instanceof URL)
  t.is(strategy._callbackURL!.href, 'http://example.com/cb')
})

test('constructor leaves _callbackURL undefined when not provided', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})
  t.is(strategy._callbackURL, undefined)
})

// --- State stored in session when server lacks PKCE support ---

test('authorizationRequest adds state to session when server lacks PKCE support', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  // No code_challenge_methods_supported → supportsPKCE() returns false
  const harness = createStrategyHarness(port, undefined, undefined, {
    code_challenge_methods_supported: undefined,
  })
  const redirectTo = await doAuthorizationRequest(harness)

  const url = new URL(redirectTo)
  // PKCE is still always used
  t.truthy(url.searchParams.get('code_challenge'))
  // State should be added as fallback
  t.truthy(url.searchParams.get('state'))

  const sessionKey = harness.strategy._sessionKey
  const stateData = harness.session[sessionKey] as any
  t.truthy(stateData.state)
  t.is(stateData.state, url.searchParams.get('state'))
})

// --- Nonce stored in session for implicit/hybrid flows ---

test('authorizationRequest stores nonce in session when response_type includes id_token', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)

  // Override authorizationRequestParams to inject response_type with id_token
  harness.strategy.authorizationRequestParams = function (_req, _options) {
    return new URLSearchParams({ response_type: 'code id_token' })
  }

  await doAuthorizationRequest(harness)

  const sessionKey = harness.strategy._sessionKey
  const stateData = harness.session[sessionKey] as any
  t.truthy(stateData.nonce)
  t.truthy(stateData.code_verifier)

  // response_mode should default to form_post for implicit
  const url = new URL(harness.results.redirectTo!)
  t.is(url.searchParams.get('response_mode'), 'form_post')
  t.truthy(url.searchParams.get('nonce'))
})

// --- passReqToCallback option-level override ---

test('options.passReqToCallback overrides strategy-level passReqToCallback', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  let argCount = 0
  const strategy = new Strategy(
    {
      callbackURL: `http://127.0.0.1:${port}/cb`,
      config: createConfiguration(port),
      passReqToCallback: true,
    },
    // This verify has the req signature, but we track arg count
    ((...args: unknown[]) => {
      argCount = args.length
      const verified = args[args.length - 1] as passport.AuthenticateCallback
      verified(null, { sub: 'user' } as Express.User)
    }) as any,
  ) as StrategyHarness

  const session: Record<string, unknown> = {}
  const results: HarnessResult['results'] = {}

  strategy.redirect = (href: string) => {
    results.redirectTo = href
  }
  strategy.error = (err: unknown) => {
    results.error = err
  }
  strategy.fail = (info: unknown) => {
    results.failInfo = info
  }
  strategy.success = (user: Express.User) => {
    results.successUser = user
  }

  await Strategy.prototype.authorizationRequest.call(
    strategy,
    { session } as any,
    {},
  )

  // Override passReqToCallback to false at the option level
  await Strategy.prototype.authorizationCodeGrant.call(
    strategy,
    { method: 'GET', session } as any,
    new URL(`${new URL(results.redirectTo!).origin}/cb?code=ok`),
    { passReqToCallback: false },
  )

  t.truthy(results.successUser)
  // With passReqToCallback=false override, verify receives (tokens, verified) = 2 args
  t.is(argCount, 2)
})

// --- currentUrl: x-forwarded-host ---

test('currentUrl uses x-forwarded-host when trust proxy is configured', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})

  const req = {
    protocol: 'https',
    host: 'proxy.example.com',
    originalUrl: '/cb?code=abc',
    get(header: string) {
      if (header === 'x-forwarded-host') return 'frontend.example.com'
      if (header === 'host') return 'backend.internal'
      return undefined
    },
    socket: { remoteAddress: '10.0.0.1' },
    app: {
      get() {
        // Trust all proxies
        return () => true
      },
    },
  }

  const url = strategy.currentUrl(req as any)
  t.is(url.host, 'frontend.example.com')
})

test('currentUrl ignores x-forwarded-host when trust proxy rejects', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})

  const req = {
    protocol: 'https',
    host: 'backend.internal',
    originalUrl: '/cb?code=abc',
    get(header: string) {
      if (header === 'x-forwarded-host') return 'attacker.example.com'
      if (header === 'host') return 'backend.internal'
      return undefined
    },
    socket: { remoteAddress: '10.0.0.1' },
    app: {
      get() {
        // Don't trust any proxy
        return () => false
      },
    },
  }

  const url = strategy.currentUrl(req as any)
  t.is(url.host, 'backend.internal')
})

test('currentUrl trims first value from multi-value x-forwarded-host', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})

  const req = {
    protocol: 'https',
    host: 'backend.internal',
    originalUrl: '/cb?code=abc',
    get(header: string) {
      if (header === 'x-forwarded-host')
        return 'frontend.example.com , proxy2.internal'
      if (header === 'host') return 'backend.internal'
      return undefined
    },
    socket: { remoteAddress: '10.0.0.1' },
    app: {
      get() {
        return () => true
      },
    },
  }

  const url = strategy.currentUrl(req as any)
  t.is(url.host, 'frontend.example.com')
})

test('currentUrl falls back to req.host when app.get throws', (t) => {
  const config = createConfiguration(9999)
  const strategy = new Strategy({ config }, () => {})

  // Simulates non-express environment (e.g. fastify-express)
  const req = {
    protocol: 'http',
    host: 'fastify.local:3000',
    originalUrl: '/cb?code=test',
    app: {
      get() {
        throw new Error('not express')
      },
    },
  }

  const url = strategy.currentUrl(req as any)
  t.is(url.host, 'fastify.local:3000')
})

// --- POST (form_post) callback ---

test('callback handles POST form_post response', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness)

  // Simulate a form_post: the authorization response params come in the POST body
  const formBody = 'code=post_code'
  const bodyStream = Readable.from(Buffer.from(formBody))

  await Strategy.prototype.authorizationCodeGrant.call(
    harness.strategy,
    {
      method: 'POST',
      session: harness.session,
      headersDistinct: {
        'content-type': ['application/x-www-form-urlencoded'],
      },
      ...bodyStream,
      [Symbol.asyncIterator]: bodyStream[Symbol.asyncIterator].bind(bodyStream),
    } as any,
    new URL(`http://127.0.0.1:${port}/cb`),
    {},
  )

  t.truthy(harness.results.successUser)
})

// --- DPoP: dpop_jkt in authorization request ---

test('authorizationRequest includes dpop_jkt when DPoP is configured', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const keyPair = await client.randomDPoPKeyPair()
  const config = createConfiguration(port)
  const dpopHandle = client.getDPoPHandle(config, keyPair)

  const strategy = new Strategy(
    {
      callbackURL: `http://127.0.0.1:${port}/cb`,
      config,
      DPoP: () => dpopHandle,
    },
    (_tokens, verified) => verified(null, { sub: 'user' } as Express.User),
  ) as StrategyHarness

  const session: Record<string, unknown> = {}
  const results: HarnessResult['results'] = {}

  strategy.redirect = (href: string) => {
    results.redirectTo = href
  }
  strategy.error = (err: unknown) => {
    results.error = err
  }

  await Strategy.prototype.authorizationRequest.call(
    strategy,
    { session } as any,
    {},
  )

  t.falsy(results.error)
  const url = new URL(results.redirectTo!)
  t.truthy(url.searchParams.get('dpop_jkt'))
})

// --- useJAR ---

test('authorizationRequest uses JAR when useJAR is configured', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  )

  const config = createConfiguration(port)
  const strategy = new Strategy(
    {
      callbackURL: `http://127.0.0.1:${port}/cb`,
      config,
      useJAR: keyPair.privateKey,
    },
    (_tokens, verified) => verified(null, { sub: 'user' } as Express.User),
  ) as StrategyHarness

  const session: Record<string, unknown> = {}
  const results: HarnessResult['results'] = {}

  strategy.redirect = (href: string) => {
    results.redirectTo = href
  }
  strategy.error = (err: unknown) => {
    results.error = err
  }

  await Strategy.prototype.authorizationRequest.call(
    strategy,
    { session } as any,
    {},
  )

  t.falsy(results.error)
  const url = new URL(results.redirectTo!)
  // JAR replaces individual params with a `request` JWT
  t.truthy(url.searchParams.get('request'))
  t.truthy(url.searchParams.get('client_id'))
  // The individual params should have been collapsed into the request object
  t.falsy(url.searchParams.get('code_challenge'))
})

test('authorizationRequest uses JAR with modifyAssertion function', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  )

  let modifyCalled = false
  const config = createConfiguration(port)
  const strategy = new Strategy(
    {
      callbackURL: `http://127.0.0.1:${port}/cb`,
      config,
      useJAR: [
        keyPair.privateKey,
        (header, _payload) => {
          modifyCalled = true
          // just verify we can modify the header
          header.kid = 'custom-kid'
        },
      ],
    },
    (_tokens, verified) => verified(null, { sub: 'user' } as Express.User),
  ) as StrategyHarness

  const session: Record<string, unknown> = {}
  const results: HarnessResult['results'] = {}

  strategy.redirect = (href: string) => {
    results.redirectTo = href
  }
  strategy.error = (err: unknown) => {
    results.error = err
  }

  await Strategy.prototype.authorizationRequest.call(
    strategy,
    { session } as any,
    {},
  )

  t.falsy(results.error)
  t.true(modifyCalled)
  const url = new URL(results.redirectTo!)
  t.truthy(url.searchParams.get('request'))
})

// --- usePAR ---

test('authorizationRequest uses PAR when usePAR is configured', async (t) => {
  const { port, server } = await startTokenEndpoint(undefined, {
    handlePAR: true,
  })
  t.teardown(() => close(server))

  const config = createConfiguration(port, {
    pushed_authorization_request_endpoint: `http://127.0.0.1:${port}/par`,
  })

  const strategy = new Strategy(
    {
      callbackURL: `http://127.0.0.1:${port}/cb`,
      config,
      usePAR: true,
    },
    (_tokens, verified) => verified(null, { sub: 'user' } as Express.User),
  ) as StrategyHarness

  const session: Record<string, unknown> = {}
  const results: HarnessResult['results'] = {}

  strategy.redirect = (href: string) => {
    results.redirectTo = href
  }
  strategy.error = (err: unknown) => {
    results.error = err
  }

  await Strategy.prototype.authorizationRequest.call(
    strategy,
    { session } as any,
    {},
  )

  t.falsy(results.error)
  const url = new URL(results.redirectTo!)
  // PAR replaces individual params with request_uri
  t.truthy(url.searchParams.get('request_uri'))
  t.truthy(url.searchParams.get('client_id'))
  // Individual params should not be in the redirect URL
  t.falsy(url.searchParams.get('code_challenge'))
})

// --- Multiple resource values ---

test('authorizationRequest includes multiple resource values from array', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness, {
    resource: ['https://rs1.example.com', 'https://rs2.example.com'],
  })

  const url = new URL(redirectTo)
  const resources = url.searchParams.getAll('resource')
  t.is(resources.length, 2)
  t.is(resources[0], 'https://rs1.example.com')
  t.is(resources[1], 'https://rs2.example.com')
})

// --- Option-level scope overrides strategy-level scope ---

test('option-level scope takes precedence over strategy-level scope', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port, undefined, {
    scope: 'openid',
  })
  const redirectTo = await doAuthorizationRequest(harness, {
    scope: 'openid profile email',
  })

  const url = new URL(redirectTo)
  t.is(url.searchParams.get('scope'), 'openid profile email')
})

// --- Custom sessionKey isolates state between strategies ---

test('custom sessionKey isolates state from another strategy', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness1 = createStrategyHarness(port, undefined, {
    sessionKey: 'strategy-a',
  })
  const harness2 = createStrategyHarness(port, undefined, {
    sessionKey: 'strategy-b',
  })

  // Share the same session
  harness2.session = harness1.session

  await doAuthorizationRequest(harness1)
  await doAuthorizationRequest(harness2)

  t.truthy(harness1.session['strategy-a'])
  t.truthy(harness1.session['strategy-b'])
  t.not(harness1.session['strategy-a'], harness1.session['strategy-b'])
})

// --- Session state cleanup ---

test('successful callback calls success and clears session state', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness)

  await doAuthorizationCodeGrant(
    harness,
    `${new URL(redirectTo).origin}/cb?code=ok`,
  )

  t.truthy(harness.results.successUser)
  t.deepEqual(harness.session, {})
})

test('replayed callback fails because state was consumed', async (t) => {
  const { port, server } = await startTokenEndpoint()
  t.teardown(() => close(server))

  const harness = createStrategyHarness(port)
  const redirectTo = await doAuthorizationRequest(harness)
  const callbackUrl = `${new URL(redirectTo).origin}/cb?code=ok`

  // First callback succeeds
  await doAuthorizationCodeGrant(harness, callbackUrl)
  t.truthy(harness.results.successUser)

  // Reset results
  harness.results.successUser = undefined
  harness.results.failInfo = undefined

  // Second callback with same session should fail
  await doAuthorizationCodeGrant(harness, callbackUrl)
  t.truthy(harness.results.failInfo)
  t.like(harness.results.failInfo as Record<string, unknown>, {
    message: 'Unable to verify authorization request state',
  })
})

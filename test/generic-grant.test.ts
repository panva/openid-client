import test from 'ava'
import * as client from '../src/index.js'
import * as undici from 'undici'
import * as jose from 'jose'

test('genericGrantRequest accepts n_a token type in token exchange grant response', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const mockAgent = agent.get('https://as.example.com')

  // Mock the token endpoint to return a response with n_a token type
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      200,
      {
        access_token: 'test-access-token',
        token_type: 'n_a',
        expires_in: 3600,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )

  const config = new client.Configuration(
    {
      issuer: 'https://as.example.com',
      token_endpoint: 'https://as.example.com/token',
    },
    'test-client-id',
    undefined,
    client.None(),
  )

  client.allowInsecureRequests(config)
  // @ts-ignore
  config[client.customFetch] = (url, options) => {
    return undici.fetch(url, { ...options, dispatcher: agent })
  }

  const result = await client.genericGrantRequest(
    config,
    'urn:ietf:params:oauth:grant-type:token-exchange',
    {
      subject_token: 'subject-token-value',
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    },
  )

  t.is(result.access_token, 'test-access-token')
  t.is(result.token_type, 'n_a')
  t.is(result.expires_in, 3600)
  t.is(
    result.issued_token_type,
    'urn:ietf:params:oauth:token-type:access_token',
  )

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('genericGrantRequest with other grant types does not add n_a token type recognition', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const mockAgent = agent.get('https://as.example.com')

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      200,
      {
        access_token: 'test-access-token',
        token_type: 'n_a',
        expires_in: 3600,
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )

  const config = new client.Configuration(
    {
      issuer: 'https://as.example.com',
      token_endpoint: 'https://as.example.com/token',
    },
    'test-client-id',
    undefined,
    client.None(),
  )

  client.allowInsecureRequests(config)
  // @ts-ignore
  config[client.customFetch] = (url, options) => {
    return undici.fetch(url, { ...options, dispatcher: agent })
  }

  // This should throw because n_a token type is not recognized for JWT bearer grants
  await t.throwsAsync(
    client.genericGrantRequest(
      config,
      'urn:ietf:params:oauth:grant-type:jwt-bearer',
      {
        assertion: 'jwt-assertion-value',
        scope: 'test-scope',
      },
    ),
    {
      message: /unsupported operation/,
    },
  )

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('genericGrantRequest retries DPoP nonce errors', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const mockAgent = agent.get('https://as.example.com')

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      headers({ dpop }) {
        return (
          typeof dpop === 'string' && jose.decodeJwt(dpop).nonce === undefined
        )
      },
    })
    .reply(
      400,
      {},
      {
        headers: {
          'dpop-nonce': 'use this',
          'www-authenticate': 'dpop error="use_dpop_nonce"',
        },
      },
    )

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      headers({ dpop }) {
        return (
          typeof dpop === 'string' && jose.decodeJwt(dpop).nonce === 'use this'
        )
      },
    })
    .reply(
      200,
      {
        access_token: 'test-access-token',
        token_type: 'DPoP',
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )

  const config = new client.Configuration(
    {
      issuer: 'https://as.example.com',
      token_endpoint: 'https://as.example.com/token',
    },
    'test-client-id',
    undefined,
    client.None(),
  )

  // @ts-ignore
  config[client.customFetch] = (url, options) => {
    return undici.fetch(url, { ...options, dispatcher: agent })
  }

  const DPoP = client.getDPoPHandle(
    config,
    await client.randomDPoPKeyPair('ES256'),
  )

  const result = await client.genericGrantRequest(
    config,
    'urn:ietf:params:oauth:grant-type:jwt-bearer',
    {
      assertion: 'jwt-assertion-value',
    },
    { DPoP },
  )

  t.is(result.access_token, 'test-access-token')
  t.is(result.token_type, 'dpop')

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('genericGrantRequest applies non-repudiation checks to ID Tokens', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://as.example.com')
  const keyPair = await client.randomDPoPKeyPair('ES256')
  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      200,
      {
        access_token: 'test-access-token',
        token_type: 'bearer',
        id_token: await new jose.SignJWT()
          .setProtectedHeader({ alg: 'ES256' })
          .setIssuer(issuer.href)
          .setAudience('test-client-id')
          .setSubject('subject')
          .setIssuedAt()
          .setExpirationTime('1m')
          .sign(keyPair.privateKey),
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )

  mockAgent
    .intercept({
      method: 'GET',
      path: '/jwks',
    })
    .reply(
      200,
      {
        keys: [await jose.exportJWK(keyPair.publicKey)],
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )

  const config = new client.Configuration(
    {
      issuer: issuer.href,
      token_endpoint: `${issuer.origin}/token`,
      jwks_uri: `${issuer.origin}/jwks`,
      id_token_signing_alg_values_supported: ['ES256'],
    },
    'test-client-id',
    undefined,
    client.None(),
  )

  client.enableNonRepudiationChecks(config)
  // @ts-ignore
  config[client.customFetch] = (url, options) => {
    return undici.fetch(url, { ...options, dispatcher: agent })
  }

  const result = await client.genericGrantRequest(
    config,
    'urn:ietf:params:oauth:grant-type:jwt-bearer',
    {
      assertion: 'jwt-assertion-value',
    },
  )

  t.is(result.claims()?.sub, 'subject')
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

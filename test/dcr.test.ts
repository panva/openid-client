import test from 'ava'
import * as client from '../src/index.js'
import * as oauth from 'oauth4webapi'
import * as undici from 'undici'
import * as jose from 'jose'

test('dpop may be used with DCR w/ initial access token', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')
  const kp = await client.randomDPoPKeyPair('ES256')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
      headers({ dpop, authorization }) {
        return typeof dpop === 'string' && authorization === 'DPoP token'
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
      path: '/reg',
      headers({ dpop, authorization }) {
        const { nonce } = jose.decodeJwt(dpop)
        return nonce === 'use this' && authorization === 'DPoP token'
      },
    })
    .reply(201, {
      client_id: 'foo',
    })

  await client.dynamicClientRegistration(issuer, {}, undefined, {
    initialAccessToken: 'token',
    DPoP: oauth.DPoP({}, kp),
    // @ts-ignore
    [client.customFetch](url, options) {
      return undici.fetch(url, { ...options, dispatcher: agent })
    },
  })

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('dpop may be used with DCR w/o initial access token', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')
  const kp = await client.randomDPoPKeyPair('ES256')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
      headers({ dpop, authorization }) {
        return typeof dpop === 'string' && authorization === undefined
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
      path: '/reg',
      headers({ dpop, authorization }) {
        const { nonce } = jose.decodeJwt(dpop)
        return nonce === 'use this' && authorization === undefined
      },
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  await client.dynamicClientRegistration(issuer, {}, undefined, {
    DPoP: oauth.DPoP({}, kp),
    // @ts-ignore
    [client.customFetch](url, options) {
      return undici.fetch(url, { ...options, dispatcher: agent })
    },
  })

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('DCR uses client_secret_post by default when client_secret was returned', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  const config = await client.dynamicClientRegistration(issuer, {}, undefined, {
    // @ts-ignore
    [client.customFetch](url, options) {
      return undici.fetch(url, { ...options, dispatcher: agent })
    },
  })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      body(body) {
        const params = new URLSearchParams(body)
        t.true(params.has('client_id'))
        t.true(params.has('client_secret'))
        return true
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('DCR uses none by default when client_secret was not returned', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
    })

  const config = await client.dynamicClientRegistration(issuer, {}, undefined, {
    // @ts-ignore
    [client.customFetch](url, options) {
      return undici.fetch(url, { ...options, dispatcher: agent })
    },
  })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      body(body) {
        const params = new URLSearchParams(body)
        t.true(params.has('client_id'))
        return true
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('DCR can use ClientSecretBasic without having a secret at hand prior to the registration', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  const config = await client.dynamicClientRegistration(
    issuer,
    {},
    client.ClientSecretBasic(),
    {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    },
  )

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      headers(headers) {
        return headers.authorization === 'Basic Zm9vOmJhcg=='
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('DCR can use ClientSecretPost without having a secret at hand prior to the registration', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  const config = await client.dynamicClientRegistration(
    issuer,
    {},
    client.ClientSecretPost(),
    {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    },
  )

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      body(body) {
        const params = new URLSearchParams(body)
        t.true(params.has('client_id'))
        t.true(params.has('client_secret'))
        return true
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('DCR can use ClientSecretJwt without having a secret at hand prior to the registration', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(200, {
      issuer: issuer.href,
      registration_endpoint: `${issuer.origin}/reg`,
      token_endpoint: `${issuer.origin}/token`,
    })

  mockAgent
    .intercept({
      method: 'POST',
      path: '/reg',
    })
    .reply(201, {
      client_id: 'foo',
      client_secret: 'bar',
      client_secret_expires_at: 0,
    })

  const config = await client.dynamicClientRegistration(
    issuer,
    {},
    client.ClientSecretJwt(),
    {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    },
  )

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
      body(body) {
        const params = new URLSearchParams(body)
        t.true(params.has('client_id'))
        t.true(params.has('client_assertion_type'))
        t.true(params.has('client_assertion'))
        return true
      },
    })
    .reply(200, {
      access_token: 'token',
      token_type: 'bearer',
    })
    .times(2)

  await client.clientCredentialsGrant(config)
  await client.clientCredentialsGrant(config)

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

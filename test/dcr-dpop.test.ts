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

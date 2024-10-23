// see https://github.com/panva/openid-client/issues/707#issuecomment-2419779410

import test from 'ava'
import * as client from '../src/index.js'
import * as undici from 'undici'
import * as jose from 'jose'

test('30x on discoveries and jwks_uri can be worked around', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const issuer = new URL('https://op.example.com/')
  const kp = await client.randomDPoPKeyPair('ES256')

  const mockAgent = agent.get(issuer.origin)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/.well-known/openid-configuration',
    })
    .reply(302, new Uint8Array(), {
      headers: {
        location: 'https://op.example.com/not-conform-redirect',
      },
    })
    .times(2)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/jwks',
    })
    .reply(302, new Uint8Array(), {
      headers: {
        location: 'https://op.example.com/not-conform-jwks',
      },
    })
    .times(2)

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      200,
      {
        access_token: 'foo',
        token_type: 'bearer',
        id_token: await new jose.SignJWT()
          .setProtectedHeader({ alg: 'ES256' })
          .setIssuer(issuer.href)
          .setAudience('decoy')
          .setIssuedAt()
          .setExpirationTime('1m')
          .setSubject('decoy')
          .sign(kp.privateKey),
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )
    .times(2)

  mockAgent
    .intercept({
      method: 'GET',
      path: '/not-conform-redirect',
    })
    .reply(
      200,
      {
        issuer: issuer.href,
        token_endpoint: 'https://op.example.com/token',
        jwks_uri: 'https://op.example.com/jwks',
        id_token_signing_alg_values_supported: ['ES256'],
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
      path: '/not-conform-jwks',
    })
    .reply(
      200,
      {
        keys: [await jose.exportJWK(kp.publicKey)],
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )

  const hit = new Set<string>()

  let err = await t.throwsAsync(
    client.discovery(issuer, 'decoy', 'decoy', undefined, {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    }),
    {
      code: 'OAUTH_RESPONSE_IS_NOT_CONFORM',
      message: 'unexpected HTTP response status code',
    },
  )

  t.regex((err.cause as Response).url, /well-known/)

  const config = await client.discovery(issuer, 'decoy', 'decoy', undefined, {
    execute: [client.enableNonRepudiationChecks],
    // @ts-ignore
    [client.customFetch](url, options) {
      if (url.includes('.well-known')) {
        // @ts-expect-error
        options.redirect = 'follow'
      } else {
        if (hit.has(url)) {
          // @ts-expect-error
          options.redirect = 'follow'
        } else {
          hit.add(url)
        }
      }
      return undici.fetch(url, { ...options, dispatcher: agent })
    },
  })

  err = await t.throwsAsync(
    client.authorizationCodeGrant(
      config,
      new URL('https://rp.example.com/cb?code=foo'),
    ),
    {
      code: 'OAUTH_RESPONSE_IS_NOT_CONFORM',
      message: 'unexpected HTTP response status code',
    },
  )

  t.regex((err.cause as Response).url, /jwks/)

  await t.notThrowsAsync(
    client.authorizationCodeGrant(
      config,
      new URL('https://rp.example.com/cb?code=foo'),
    ),
  )

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

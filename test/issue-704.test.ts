// see https://github.com/panva/openid-client/discussions/704

import test from 'ava'
import * as client from '../src/index.js'
import * as undici from 'undici'
import * as jose from 'jose'

const urls = [
  new URL('https://login.microsoftonline.com/common/v2.0'),
  new URL('https://login.microsoftonline.com/common/v2.0/'),
  new URL('https://login.microsoftonline.com/organizations/v2.0'),
  new URL('https://login.microsoftonline.com/organizations/v2.0/'),
]

let i = 0
for (const url of urls) {
  i++
  test(`handles Entra ID multi-tenant issuer identifiers ${i}/${urls.length}`, async (t) => {
    let agent = new undici.MockAgent()
    agent.disableNetConnect()

    const wellKnown = new URL(
      `${url.pathname}/.well-known/openid-configuration`.replace('//', '/'),
      url,
    )

    const mockAgent = agent.get(url.origin)

    mockAgent
      .intercept({
        method: 'GET',
        path: wellKnown.pathname,
      })
      .reply(
        200,
        {
          issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
          token_endpoint: 'https://login.microsoftonline.com/token',
          id_token_signing_alg_values_supported: ['none'],
        },
        {
          headers: {
            'content-type': 'application/json',
          },
        },
      )

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
          id_token: new jose.UnsecuredJWT({
            iss: 'https://login.microsoftonline.com/foobar/v2.0',
            tid: 'foobar',
          })
            .setAudience('decoy')
            .setIssuedAt()
            .setExpirationTime('1m')
            .setSubject('decoy')
            .encode(),
        },
        {
          headers: {
            'content-type': 'application/json',
          },
        },
      )

    await t.notThrowsAsync(async () => {
      const config = await client.discovery(url, 'decoy', 'decoy', undefined, {
        // @ts-ignore
        [client.customFetch](url, options) {
          return undici.fetch(url, { ...options, dispatcher: agent })
        },
      })

      await client.authorizationCodeGrant(
        config,
        new URL('https://rp.example.com/cb?code=foo'),
      )
    })

    t.notThrows(() => agent.assertNoPendingInterceptors())
  })
}

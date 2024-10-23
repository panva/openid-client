// see https://github.com/panva/openid-client/issues/718

import test from 'ava'
import * as client from '../src/index.js'
import * as undici from 'undici'

const tenantName = 'openidclientdemo.onmicrosoft.com'
const tenantId = '0e96f835-6e34-470c-800b-2e2c5908c54c'
const policy = 'B2C_1_signupsignin'

const urls = [
  new URL(`https://openidclientdemo.b2clogin.com/${tenantName}/${policy}/v2.0`),
  new URL(`https://openidclientdemo.b2clogin.com/${tenantId}/${policy}/v2.0`),
  new URL(
    `https://openidclientdemo.b2clogin.com/${tenantName}/${policy}/v2.0/`,
  ),
  new URL(`https://openidclientdemo.b2clogin.com/${tenantId}/${policy}/v2.0/`),
]

let i = 0
for (const url of urls) {
  i++
  test(`accepts b2clogin.com issuer identifier for whatever value it is ${i}/${urls.length}`, async (t) => {
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
          issuer:
            'https://openidclientdemo.b2clogin.com/0e96f835-6e34-470c-800b-2e2c5908c54c/v2.0/',
        },
        {
          headers: {
            'content-type': 'application/json',
          },
        },
      )

    await t.notThrowsAsync(
      client.discovery(url, 'decoy', 'decoy', undefined, {
        // @ts-ignore
        [client.customFetch](url, options) {
          return undici.fetch(url, { ...options, dispatcher: agent })
        },
      }),
    )

    t.notThrows(() => agent.assertNoPendingInterceptors())
  })
}

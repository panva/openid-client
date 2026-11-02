import test from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'
import * as undici from 'undici'

test('issuer discovery matching', async () => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const url = new URL('https://op.example.com')

  const mockAgent = agent.get(url.origin)
  let i = 0

  mockAgent
    .intercept({
      method: 'GET',
      path: '.well-known/openid-configuration',
    })
    .reply(
      200,
      function () {
        switch (i++) {
          case 0:
            return { issuer: 'https://op.example.com/' }
          case 1:
            return { issuer: 'https://op.example.com' }
          case 2:
            return { issuer: 'https://op.example.com/pathname' }
          case 3:
            return { issuer: 'https://op.example.com/pathname' }
        }
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )
    .times(4)

  await assert.doesNotReject(
    client.discovery(url, 'decoy', 'decoy', undefined, {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    }),
  )

  await assert.doesNotReject(
    client.discovery(url, 'decoy', 'decoy', undefined, {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    }),
  )

  await assert.rejects(
    client.discovery(url, 'decoy', 'decoy', undefined, {
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, { ...options, dispatcher: agent })
      },
    }),
  )

  await assert.doesNotReject(
    client.discovery(
      new URL('https://op.example.com/.well-known/openid-configuration'),
      'decoy',
      'decoy',
      undefined,
      {
        // @ts-ignore
        [client.customFetch](url, options) {
          return undici.fetch(url, { ...options, dispatcher: agent })
        },
      },
    ),
  )

  assert.doesNotThrow(() => agent.assertNoPendingInterceptors())
})

// see https://github.com/panva/openid-client/issues/885

// @ts-expect-error
delete globalThis.navigator
// @ts-expect-error
globalThis.navigator = { userAgent: 'Mozilla/5.0 foo' }

const client = await import('../src/index.js')

import test from 'ava'

test('fetchProtectedResource does not set user-agent in browsers', async (t) => {
  const config = new client.Configuration(
    { issuer: 'https://as.example.com' },
    'client-id',
  )

  let headers: Headers | undefined
  config[client.customFetch] = async (_url, options) => {
    headers = new Headers(options?.headers)
    return new Response()
  }

  await client.fetchProtectedResource(
    config,
    'access-token',
    new URL('https://rs.example.com/resource'),
    'GET',
  )

  t.false(headers?.has('user-agent'))
})

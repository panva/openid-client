import test from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'

for (const streaming of [true, false]) {
  test(`fetchProtectedResource handles a DPoP nonce challenge with a ${streaming ? 'stream' : 'string'} body`, async () => {
    const config = new client.Configuration(
      { issuer: 'https://as.example.com' },
      'client',
    )
    const DPoP = client.getDPoPHandle(
      config,
      await client.randomDPoPKeyPair('ES256'),
    )
    const challenge = new Response(null, {
      status: 401,
      headers: {
        'www-authenticate': 'DPoP error="use_dpop_nonce"',
        'dpop-nonce': 'nonce',
      },
    })
    const success = new Response()
    const bodies: string[] = []
    config[client.customFetch] = async (_url, options) => {
      assert.ok(
        typeof options.body === 'string' ||
          options.body instanceof ReadableStream,
      )
      bodies.push(await new Response(options.body).text())
      return bodies.length === 1 ? challenge : success
    }

    const request = client.fetchProtectedResource(
      config,
      'access_token',
      new URL('https://rs.example.com/resource'),
      'POST',
      streaming ? new Blob(['payload']).stream() : 'payload',
      undefined,
      { DPoP },
    )
    if (streaming) {
      await assert.rejects(request, (err: unknown) => {
        assert.ok(err instanceof client.WWWAuthenticateChallengeError)
        assert.strictEqual(err.response, challenge)
        return true
      })
      assert.deepStrictEqual(bodies, ['payload'])
    } else {
      assert.strictEqual(await request, success)
      assert.deepStrictEqual(bodies, ['payload', 'payload'])
    }
  })
}

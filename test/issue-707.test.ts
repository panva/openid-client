// see https://github.com/panva/openid-client/issues/707#issuecomment-2419779410

import { once } from 'node:events'
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import test from 'ava'
import * as client from '../src/index.js'
import * as undici from 'undici'
import * as jose from 'jose'

test('30x on discoveries and jwks_uri can be worked around', async (t) => {
  const kp = await client.randomDPoPKeyPair('ES256')
  const publicJwk = await jose.exportJWK(kp.publicKey)
  const requests: string[] = []

  // Exercise real fetch redirects: Undici 8's MockAgent cancels redirected requests.
  const server = http.createServer((req, res) => {
    const route = `${req.method} ${req.url}`
    requests.push(route)

    switch (route) {
      case 'GET /.well-known/openid-configuration':
        res.writeHead(302, {
          location: new URL('/not-conform-redirect', issuer).href,
        })
        res.end()
        return
      case 'GET /jwks':
        res.writeHead(302, {
          location: new URL('/not-conform-jwks', issuer).href,
        })
        res.end()
        return
      case 'GET /not-conform-redirect':
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(
          JSON.stringify({
            issuer: issuer.href,
            token_endpoint: new URL('/token', issuer).href,
            jwks_uri: new URL('/jwks', issuer).href,
            id_token_signing_alg_values_supported: ['ES256'],
          }),
        )
        return
      case 'GET /not-conform-jwks':
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ keys: [publicJwk] }))
        return
      case 'POST /token':
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(
          JSON.stringify({
            access_token: 'foo',
            token_type: 'bearer',
            id_token: idToken,
          }),
        )
        return
      default:
        res.writeHead(404)
        res.end()
    }
  })

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.teardown(async () => {
    server.close()
    await once(server, 'close')
  })

  const { port } = server.address() as AddressInfo
  const issuer = new URL(`http://127.0.0.1:${port}/`)
  const idToken = await new jose.SignJWT()
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(issuer.href)
    .setAudience('decoy')
    .setIssuedAt()
    .setExpirationTime('1m')
    .setSubject('decoy')
    .sign(kp.privateKey)

  const hit = new Set<string>()

  let err = await t.throwsAsync(
    client.discovery(issuer, 'decoy', 'decoy', undefined, {
      execute: [client.allowInsecureRequests],
      // @ts-ignore
      [client.customFetch](url, options) {
        return undici.fetch(url, options)
      },
    }),
    {
      code: 'OAUTH_RESPONSE_IS_NOT_CONFORM',
      message: 'unexpected HTTP response status code',
    },
  )

  t.regex((err.cause as Response).url, /well-known/)

  const config = await client.discovery(issuer, 'decoy', 'decoy', undefined, {
    execute: [client.allowInsecureRequests, client.enableNonRepudiationChecks],
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
      return undici.fetch(url, options)
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

  t.deepEqual(requests, [
    'GET /.well-known/openid-configuration',
    'GET /.well-known/openid-configuration',
    'GET /not-conform-redirect',
    'POST /token',
    'GET /jwks',
    'POST /token',
    'GET /jwks',
    'GET /not-conform-jwks',
  ])
})

import test from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'
import * as jose from 'jose'

const issuer = new URL('https://as.example.com')
const signing = await jose.generateKeyPair('ES256')
const encryption = await jose.generateKeyPair('ECDH-ES')
const jwks = { keys: [await jose.exportJWK(signing.publicKey)] }
const encoder = new TextEncoder()

function configuration(enabled = true) {
  const config = new client.Configuration(
    {
      issuer: issuer.href,
      token_endpoint: `${issuer.origin}/token`,
      userinfo_endpoint: `${issuer.origin}/userinfo`,
      introspection_endpoint: `${issuer.origin}/introspection`,
      jwks_uri: `${issuer.origin}/jwks`,
      id_token_signing_alg_values_supported: ['ES256'],
      authorization_signing_alg_values_supported: ['ES256'],
      userinfo_signing_alg_values_supported: ['ES256'],
      introspection_signing_alg_values_supported: ['ES256'],
    },
    'client',
    undefined,
    client.None(),
  )
  if (enabled) {
    client.enableDecryptingResponses(config, ['A128GCM'], encryption.privateKey)
  }
  return config
}

function respond(config: client.Configuration, response: client.CustomFetch) {
  config[client.customFetch] = async (url, options) =>
    new URL(url).pathname === '/jwks'
      ? Response.json(jwks)
      : response(url, options)
}

function sign(claims: jose.JWTPayload = {}, typ?: string) {
  return new jose.SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', typ })
    .setIssuer(issuer.href)
    .setAudience('client')
    .setSubject(typeof claims.sub === 'string' ? claims.sub : 'subject')
    .setIssuedAt()
    .setExpirationTime('1m')
    .sign(signing.privateKey)
}

function encrypt(jwt: string) {
  return new jose.CompactEncrypt(encoder.encode(jwt))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })
    .encrypt(encryption.publicKey)
}

function tokenResponse(id_token?: string) {
  return Response.json({
    access_token: 'access_token',
    token_type: 'bearer',
    id_token,
  })
}

function callback(parameters: Record<string, string>, fragment = false) {
  const url = new URL('https://rp.example.com/cb')
  if (fragment) {
    url.hash = new URLSearchParams(parameters).toString()
  } else {
    url.search = new URLSearchParams(parameters).toString()
  }
  return url
}

for (const encrypted of [false, true]) {
  test(`code grant ${encrypted ? 'retains decrypted' : 'does not retain unencrypted'} ID Token`, async () => {
    const config = configuration()
    const jwt = await sign()
    const wire = encrypted ? await encrypt(jwt) : jwt
    respond(config, async () => tokenResponse(wire))

    const result = await client.authorizationCodeGrant(
      config,
      callback({ code: 'code' }),
    )
    assert.deepStrictEqual(
      client.getDecryptedResponses(result),
      encrypted ? { id_token: { token_endpoint: jwt } } : undefined,
    )
    assert.strictEqual(result.id_token, wire)
    assert.strictEqual(result.claims()?.sub, 'subject')
    assert.deepStrictEqual(Object.keys(result), [
      'access_token',
      'token_type',
      'id_token',
    ])
    assert.strictEqual(client.getDecryptedResponses({ ...result }), undefined)
    if (encrypted) {
      assert.ok(Object.isFrozen(client.getDecryptedResponses(result)))
      assert.ok(Object.isFrozen(client.getDecryptedResponses(result)?.id_token))
    }
  })
}

test('code grant capture requires decryption support to be enabled', async () => {
  const config = configuration(false)
  respond(config, async () => tokenResponse(await sign()))
  const result = await client.authorizationCodeGrant(
    config,
    callback({ code: 'code' }),
  )
  assert.strictEqual(client.getDecryptedResponses(result), undefined)
})

test('code grant without JWTs has no decrypted responses', async () => {
  const config = configuration()
  respond(config, async () => tokenResponse())
  const result = await client.authorizationCodeGrant(
    config,
    callback({ code: 'code' }),
  )
  assert.strictEqual(client.getDecryptedResponses(result), undefined)
})

const grants = [
  {
    name: 'refreshTokenGrant',
    run: (config: client.Configuration) =>
      client.refreshTokenGrant(config, 'refresh_token'),
  },
  {
    name: 'genericGrantRequest',
    run: (config: client.Configuration) =>
      client.genericGrantRequest(config, 'custom_grant', {}),
  },
  {
    name: 'pollDeviceAuthorizationGrant',
    run: (config: client.Configuration) =>
      client.pollDeviceAuthorizationGrant(config, {
        device_code: 'device-code',
        user_code: 'user-code',
        verification_uri: `${issuer.origin}/device`,
        expires_in: 600,
        interval: 0,
      }),
  },
  {
    name: 'pollBackchannelAuthenticationGrant',
    run: (config: client.Configuration) =>
      client.pollBackchannelAuthenticationGrant(config, {
        auth_req_id: 'auth-req-id',
        expires_in: 600,
        interval: 0,
      }),
  },
]

for (const grant of grants) {
  for (const encrypted of [false, true]) {
    test(`${grant.name} ${encrypted ? 'retains decrypted' : 'does not retain unencrypted'} ID Token`, async () => {
      const config = configuration()
      const jwt = await sign()
      const wire = encrypted ? await encrypt(jwt) : jwt
      respond(config, async () => tokenResponse(wire))
      const result = await grant.run(config)
      assert.strictEqual(
        client.getDecryptedResponses(result),
        encrypted ? jwt : undefined,
      )
      assert.strictEqual(result.id_token, wire)
      assert.strictEqual(result.claims()?.sub, 'subject')
    })
  }

  test(`${grant.name} does not retain JWTs without decryption support`, async () => {
    const config = configuration(false)
    respond(config, async () => tokenResponse(await sign()))
    assert.strictEqual(
      client.getDecryptedResponses(await grant.run(config)),
      undefined,
    )
  })

  test(`${grant.name} without an ID Token has no decrypted response`, async () => {
    const config = configuration()
    respond(config, async () => tokenResponse())
    assert.strictEqual(
      client.getDecryptedResponses(await grant.run(config)),
      undefined,
    )
  })
}

for (const encrypted of [false, true]) {
  test(`implicit authentication ${encrypted ? 'retains decrypted' : 'does not retain unencrypted'} ID Token`, async () => {
    const config = configuration()
    client.useIdTokenResponseType(config)
    const jwt = await sign({ nonce: 'nonce' })
    respond(config, async () => assert.fail('unexpected request'))
    const result = await client.implicitAuthentication(
      config,
      callback({ id_token: encrypted ? await encrypt(jwt) : jwt }, true),
      'nonce',
    )
    assert.strictEqual(
      client.getDecryptedResponses(result),
      encrypted ? jwt : undefined,
    )
    assert.strictEqual(result.sub, 'subject')
  })
}

test('implicit authentication capture requires decryption support', async () => {
  const config = configuration(false)
  client.useIdTokenResponseType(config)
  respond(config, async () => assert.fail('unexpected request'))
  const result = await client.implicitAuthentication(
    config,
    callback({ id_token: await sign({ nonce: 'nonce' }) }, true),
    'nonce',
  )
  assert.strictEqual(client.getDecryptedResponses(result), undefined)
})

for (const kind of ['userinfo', 'introspection'] as const) {
  const contentType =
    kind === 'userinfo'
      ? 'application/jwt'
      : 'application/token-introspection+jwt'
  const fetch = (config: client.Configuration) =>
    kind === 'userinfo'
      ? client.fetchUserInfo(config, 'access_token', 'subject')
      : client.tokenIntrospection(config, 'access_token')

  for (const encrypted of [false, true]) {
    test(`${kind} ${encrypted ? 'retains decrypted' : 'does not retain unencrypted'} JWT`, async () => {
      const config = configuration()
      client.enableNonRepudiationChecks(config)
      const jwt = await sign(
        kind === 'userinfo'
          ? { name: 'End User' }
          : { token_introspection: { active: true, sub: 'subject' } },
        kind === 'introspection' ? 'token-introspection+jwt' : undefined,
      )
      const wire = encrypted ? await encrypt(jwt) : jwt
      respond(
        config,
        async () =>
          new Response(wire, { headers: { 'content-type': contentType } }),
      )
      const result = await fetch(config)
      assert.strictEqual(
        client.getDecryptedResponses(result),
        encrypted ? jwt : undefined,
      )
      assert.strictEqual(result.sub, 'subject')
    })
  }

  test(`${kind} capture requires decryption support`, async () => {
    const config = configuration(false)
    const jwt = await sign(
      kind === 'userinfo' ? {} : { token_introspection: { active: true } },
      kind === 'introspection' ? 'token-introspection+jwt' : undefined,
    )
    respond(
      config,
      async () =>
        new Response(jwt, { headers: { 'content-type': contentType } }),
    )
    assert.strictEqual(
      client.getDecryptedResponses(await fetch(config)),
      undefined,
    )
  })

  test(`${kind} JSON response has no decrypted response`, async () => {
    const config = configuration()
    respond(config, async () =>
      Response.json(
        kind === 'userinfo' ? { sub: 'subject' } : { active: false },
      ),
    )
    assert.strictEqual(
      client.getDecryptedResponses(await fetch(config)),
      undefined,
    )
  })
}

for (const authorizationEncrypted of [false, true]) {
  for (const tokenEncrypted of [false, true]) {
    test(`JARM encrypted=${authorizationEncrypted} and ID Token encrypted=${tokenEncrypted} retain only decrypted JWTs`, async () => {
      const config = configuration()
      client.useJwtResponseMode(config)
      const authorization = await sign({ code: 'code' })
      const jwt = await sign()
      respond(config, async () =>
        tokenResponse(tokenEncrypted ? await encrypt(jwt) : jwt),
      )
      const result = await client.authorizationCodeGrant(
        config,
        callback({
          response: authorizationEncrypted
            ? await encrypt(authorization)
            : authorization,
        }),
      )
      assert.deepStrictEqual(
        client.getDecryptedResponses(result),
        authorizationEncrypted || tokenEncrypted
          ? {
              ...(authorizationEncrypted
                ? { authorization_response: authorization }
                : {}),
              ...(tokenEncrypted ? { id_token: { token_endpoint: jwt } } : {}),
            }
          : undefined,
      )
    })
  }
}

test('JARM is retained when the token endpoint does not issue an ID Token', async () => {
  const config = configuration()
  client.useJwtResponseMode(config)
  const authorization = await sign({ code: 'code' })
  respond(config, async () => tokenResponse())
  const result = await client.authorizationCodeGrant(
    config,
    callback({ response: await encrypt(authorization) }),
  )
  assert.deepStrictEqual(client.getDecryptedResponses(result), {
    authorization_response: authorization,
  })
})

async function hash(value: string) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value))
  return jose.base64url.encode(new Uint8Array(digest).subarray(0, 16))
}

for (const detached of [false, true]) {
  for (const authorizationEncrypted of [false, true]) {
    for (const tokenEncrypted of [false, true]) {
      test(`${detached ? 'detached signature' : 'hybrid'} authorization ID Token encrypted=${authorizationEncrypted} and token endpoint ID Token encrypted=${tokenEncrypted} retain only decrypted JWTs`, async () => {
        const config = configuration()
        client.useCodeIdTokenResponseType(config)
        if (detached) client.enableDetachedSignatureResponseChecks(config)
        const authorization = await sign({
          nonce: 'nonce',
          c_hash: await hash('code'),
          ...(detached ? { s_hash: await hash('state') } : {}),
        })
        const jwt = await sign({ nonce: 'nonce' })
        const wire = tokenEncrypted ? await encrypt(jwt) : jwt
        respond(config, async () => tokenResponse(wire))
        const result = await client.authorizationCodeGrant(
          config,
          callback(
            {
              code: 'code',
              state: 'state',
              id_token: authorizationEncrypted
                ? await encrypt(authorization)
                : authorization,
            },
            true,
          ),
          { expectedNonce: 'nonce', expectedState: 'state' },
        )
        assert.deepStrictEqual(
          client.getDecryptedResponses(result),
          authorizationEncrypted || tokenEncrypted
            ? {
                id_token: {
                  ...(authorizationEncrypted
                    ? { authorization_endpoint: authorization }
                    : {}),
                  ...(tokenEncrypted ? { token_endpoint: jwt } : {}),
                },
              }
            : undefined,
        )
        assert.strictEqual(result.id_token, wire)
      })
    }
  }
}

test('JARM is decrypted once and retained across a token endpoint DPoP retry', async (t) => {
  const config = configuration()
  client.useJwtResponseMode(config)
  const authorization = await sign({ code: 'code' })
  const jwt = await sign()
  const authorizationWire = await encrypt(authorization)
  const tokenWire = await encrypt(jwt)
  const DPoP = client.getDPoPHandle(
    config,
    await client.randomDPoPKeyPair('ES256'),
  )
  const decrypt = t.mock.method(crypto.subtle, 'decrypt')
  const nonces: unknown[] = []
  respond(config, async (_url, options) => {
    nonces.push(jose.decodeJwt(options.headers.dpop).nonce)
    if (nonces.length === 1) {
      return Response.json(
        { error: 'use_dpop_nonce' },
        { status: 400, headers: { 'dpop-nonce': 'nonce' } },
      )
    }
    return tokenResponse(tokenWire)
  })
  const result = await client.authorizationCodeGrant(
    config,
    callback({ response: authorizationWire }),
    undefined,
    undefined,
    { DPoP },
  )
  assert.deepStrictEqual(nonces, [undefined, 'nonce'])
  assert.strictEqual(decrypt.mock.callCount(), 2)
  assert.deepStrictEqual(client.getDecryptedResponses(result), {
    authorization_response: authorization,
    id_token: { token_endpoint: jwt },
  })
})

test('concurrent grants keep decrypted responses associated with their own results', async () => {
  const config = configuration()
  const firstJwt = await sign({ sub: 'first' })
  const secondJwt = await sign({ sub: 'second' })
  const responses = new Map([
    ['first', await encrypt(firstJwt)],
    ['second', await encrypt(secondJwt)],
  ])
  respond(config, async (_url, options) => {
    const code = new URLSearchParams(options.body as string).get('code')!
    return tokenResponse(responses.get(code))
  })
  const [first, second] = await Promise.all([
    client.authorizationCodeGrant(config, callback({ code: 'first' })),
    client.authorizationCodeGrant(config, callback({ code: 'second' })),
  ])
  assert.deepStrictEqual(client.getDecryptedResponses(first), {
    id_token: { token_endpoint: firstJwt },
  })
  assert.deepStrictEqual(client.getDecryptedResponses(second), {
    id_token: { token_endpoint: secondJwt },
  })
  assert.strictEqual(first.claims()?.sub, 'first')
  assert.strictEqual(second.claims()?.sub, 'second')

  respond(config, async () => tokenResponse())
  const third = await client.authorizationCodeGrant(
    config,
    callback({ code: 'third' }),
  )
  assert.strictEqual(client.getDecryptedResponses(third), undefined)
  assert.deepStrictEqual(client.getDecryptedResponses(first), {
    id_token: { token_endpoint: firstJwt },
  })
})

test('capture preserves response validation failures and prior result associations', async () => {
  const config = configuration()
  const jwt = await sign()
  respond(config, async () => tokenResponse(await encrypt(jwt)))
  const result = await client.authorizationCodeGrant(
    config,
    callback({ code: 'valid' }),
  )

  respond(config, async () =>
    tokenResponse(await encrypt(await sign({ nonce: 'wrong' }))),
  )
  await assert.rejects(
    client.authorizationCodeGrant(config, callback({ code: 'invalid' })),
    { code: 'OAUTH_JWT_CLAIM_COMPARISON_FAILED' },
  )
  assert.deepStrictEqual(client.getDecryptedResponses(result), {
    id_token: { token_endpoint: jwt },
  })

  const otherKey = await jose.generateKeyPair('ECDH-ES')
  const invalid = await new jose.CompactEncrypt(encoder.encode(jwt))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })
    .encrypt(otherKey.publicKey)
  respond(config, async () => tokenResponse(invalid))
  await assert.rejects(
    client.authorizationCodeGrant(config, callback({ code: 'invalid' })),
    { code: 'OAUTH_DECRYPTION_FAILED' },
  )
  assert.deepStrictEqual(client.getDecryptedResponses(result), {
    id_token: { token_endpoint: jwt },
  })
})

test('JARM signature verification still rejects an invalid decrypted signature', async () => {
  const config = configuration()
  const jwt = (await sign({ code: 'code' })).split('.')
  jwt[2] = `${jwt[2][0] === 'A' ? 'B' : 'A'}${jwt[2].slice(1)}`
  const invalid = await encrypt(jwt.join('.'))
  client.useJwtResponseMode(config)
  respond(config, async () => assert.fail('token exchange must not be reached'))
  await assert.rejects(
    client.authorizationCodeGrant(config, callback({ response: invalid })),
    { code: 'OAUTH_INVALID_RESPONSE' },
  )
})

test('client credentials does not decrypt ID Tokens', async (t) => {
  const config = configuration()
  const jwt = await encrypt(await sign())
  const decrypt = t.mock.method(crypto.subtle, 'decrypt')
  respond(config, async () => tokenResponse(jwt))
  await assert.rejects(client.clientCredentialsGrant(config), {
    code: 'OAUTH_UNSUPPORTED_OPERATION',
  })
  assert.strictEqual(decrypt.mock.callCount(), 0)
})

test('client credentials does not apply non-repudiation checks to ID Tokens', async () => {
  const config = configuration()
  client.enableNonRepudiationChecks(config)
  const jwt = (await sign()).split('.')
  jwt[2] = `${jwt[2][0] === 'A' ? 'B' : 'A'}${jwt[2].slice(1)}`
  const idToken = jwt.join('.')
  const requests: string[] = []
  config[client.customFetch] = async (url) => {
    const path = new URL(url).pathname
    requests.push(path)
    return path === '/jwks' ? Response.json(jwks) : tokenResponse(idToken)
  }
  const result = await client.clientCredentialsGrant(config)
  assert.strictEqual(result.id_token, idToken)
  assert.strictEqual(result.claims()?.sub, 'subject')
  assert.strictEqual(client.getDecryptedResponses(result), undefined)
  assert.deepStrictEqual(requests, ['/token'])
})

for (const kind of ['userinfo', 'introspection'] as const) {
  for (const status of kind === 'userinfo' ? [200, 401] : [401]) {
    for (const body of ['errored', 'pending'] as const) {
      test(`${kind} preserves status ${status} authentication challenge with ${body} JWT body`, async () => {
        const config = configuration()
        let controller!: ReadableStreamDefaultController<Uint8Array>
        const response = new Response(
          new ReadableStream<Uint8Array>({
            start(value) {
              controller = value
              if (body === 'errored') {
                controller.error(new DOMException('body failed', 'AbortError'))
              }
            },
          }),
          {
            status,
            headers: {
              'content-type':
                kind === 'userinfo'
                  ? 'application/jwt'
                  : 'application/token-introspection+jwt',
              'www-authenticate': 'Bearer error="invalid_token"',
            },
          },
        )
        respond(config, async () => response)
        const guard = setTimeout(() => {
          controller.error(
            new DOMException('body never completed', 'AbortError'),
          )
        }, 250)
        try {
          await assert.rejects(
            kind === 'userinfo'
              ? client.fetchUserInfo(config, 'access_token', 'subject')
              : client.tokenIntrospection(config, 'access_token'),
            (error: unknown) => {
              assert.ok(error instanceof client.WWWAuthenticateChallengeError)
              assert.strictEqual(error.response, response)
              assert.strictEqual(error.status, status)
              assert.strictEqual(
                error.cause[0].parameters.error,
                'invalid_token',
              )
              return true
            },
          )
        } finally {
          clearTimeout(guard)
          controller.error(new DOMException('test completed', 'AbortError'))
        }
      })
    }
  }
}

for (const kind of ['JARM', 'hybrid', 'detached signature'] as const) {
  test(`${kind} retains the decrypted JWT when the input URL changes during JWKS retrieval`, async () => {
    const config = configuration()
    const claims =
      kind === 'JARM'
        ? { code: 'code' }
        : {
            nonce: 'nonce',
            c_hash: await hash('code'),
            ...(kind === 'detached signature'
              ? { s_hash: await hash('state') }
              : {}),
          }
    const original = await sign(claims)
    const replacement = await sign({
      ...claims,
      jti: 'unvalidated replacement',
    })
    const originalWire = await encrypt(original)
    const replacementWire = await encrypt(replacement)
    const token = kind === 'JARM' ? undefined : await sign({ nonce: 'nonce' })
    const input =
      kind === 'JARM'
        ? callback({ response: originalWire })
        : callback(
            { code: 'code', state: 'state', id_token: originalWire },
            true,
          )
    if (kind === 'JARM') {
      client.useJwtResponseMode(config)
    } else {
      client.useCodeIdTokenResponseType(config)
      if (kind === 'detached signature') {
        client.enableDetachedSignatureResponseChecks(config)
      }
    }

    let mutations = 0
    config[client.customFetch] = async (url, options) => {
      if (new URL(url).pathname === '/jwks') {
        mutations++
        if (kind === 'JARM') {
          input.searchParams.set('response', replacementWire)
        } else {
          input.hash = new URLSearchParams({
            code: 'code',
            state: 'state',
            id_token: replacementWire,
          }).toString()
        }
        return Response.json(jwks)
      }
      assert.strictEqual(
        new URLSearchParams(options.body as string).get('code'),
        'code',
      )
      return tokenResponse(token)
    }
    const result = await client.authorizationCodeGrant(
      config,
      input,
      kind === 'JARM'
        ? undefined
        : { expectedNonce: 'nonce', expectedState: 'state' },
    )
    assert.strictEqual(mutations, 1)
    assert.deepStrictEqual(
      client.getDecryptedResponses(result),
      kind === 'JARM'
        ? { authorization_response: original }
        : {
            id_token: {
              authorization_endpoint: original,
            },
          },
    )
  })
}

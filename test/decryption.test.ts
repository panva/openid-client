import test from 'ava'
import * as client from '../src/index.js'
import * as jose from 'jose'

for (const { name, kid, extraKey, message } of [
  { name: 'omitted kid', kid: undefined, extraKey: false, message: undefined },
  {
    name: 'matching kid',
    kid: 'client-key',
    extraKey: false,
    message: undefined,
  },
  {
    name: 'unknown kid',
    kid: 'unknown-key',
    extraKey: false,
    message: 'no applicable decryption key selected',
  },
  {
    name: 'omitted kid with ambiguous keys',
    kid: undefined,
    extraKey: true,
    message: 'multiple applicable decryption keys selected',
  },
]) {
  test(`JWE decryption with ${name}`, async (testContext) => {
    const issuer = new URL('https://as.example.com')
    const signingKeyPair = await jose.generateKeyPair('ES256')
    const encryptionKeyPair = await jose.generateKeyPair('RSA-OAEP-256')
    const idToken = await new jose.SignJWT()
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(issuer.href)
      .setAudience('client')
      .setSubject('subject')
      .setIssuedAt()
      .setExpirationTime('1m')
      .sign(signingKeyPair.privateKey)
    const encryptedIdToken = await new jose.CompactEncrypt(
      new TextEncoder().encode(idToken),
    )
      .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A128GCM', kid })
      .encrypt(encryptionKeyPair.publicKey)

    const config = new client.Configuration(
      {
        issuer: issuer.href,
        token_endpoint: `${issuer.origin}/token`,
        id_token_signing_alg_values_supported: ['ES256'],
      },
      'client',
    )
    const keys: client.DecryptionKey[] = [
      { key: encryptionKeyPair.privateKey, kid: 'client-key' },
    ]
    if (extraKey) {
      keys.push({
        key: (await jose.generateKeyPair('RSA-OAEP-256')).privateKey,
        kid: 'another-key',
      })
    }
    client.enableDecryptingResponses(config, ['A128GCM'], ...keys)
    config[client.customFetch] = async () =>
      Response.json({
        access_token: 'access_token',
        token_type: 'bearer',
        id_token: encryptedIdToken,
      })

    const pending = client.authorizationCodeGrant(
      config,
      new URL('https://rp.example.com/cb?code=code'),
      { idTokenExpected: true },
    )
    if (message) {
      const error = await testContext.throwsAsync(pending, {
        instanceOf: client.ClientError,
        message,
      })
      testContext.is(error?.code, 'OAUTH_DECRYPTION_FAILED')
    } else {
      testContext.is((await pending).claims()?.sub, 'subject')
    }
  })
}

test('RSA-OAEP JWE decryption ignores unrelated keys without kid', async (t) => {
  const issuer = new URL('https://as.example.com')
  const signingKeyPair = await client.randomDPoPKeyPair('ES256')
  const rsaKeyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-1',
    },
    false,
    ['encrypt', 'decrypt'],
  )
  const ecdhKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  )

  const idToken = await new jose.SignJWT()
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(issuer.href)
    .setAudience('test-client-id')
    .setSubject('subject')
    .setIssuedAt()
    .setExpirationTime('1m')
    .sign(signingKeyPair.privateKey)

  const encryptedIdToken = await new jose.CompactEncrypt(
    new TextEncoder().encode(idToken),
  )
    .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
    .encrypt(rsaKeyPair.publicKey)

  const config = new client.Configuration(
    {
      issuer: issuer.href,
      token_endpoint: `${issuer.origin}/token`,
      id_token_signing_alg_values_supported: ['ES256'],
    },
    'test-client-id',
    undefined,
    client.None(),
  )

  client.enableDecryptingResponses(
    config,
    undefined,
    ecdhKeyPair.privateKey,
    rsaKeyPair.privateKey,
  )
  config[client.customFetch] = async () => {
    return new Response(
      JSON.stringify({
        access_token: 'test-access-token',
        token_type: 'bearer',
        id_token: encryptedIdToken,
      }),
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )
  }

  const result = await client.authorizationCodeGrant(
    config,
    new URL('https://rp.example.com/cb?code=code'),
    { idTokenExpected: true },
  )

  t.is(result.claims()?.sub, 'subject')
  const { claims } = result
  t.is(claims()?.sub, 'subject')
})

import test from 'ava'
import * as client from '../src/index.js'
import * as jose from 'jose'

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
})

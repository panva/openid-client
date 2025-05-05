import * as lib from '../src/index.js'
import { isBlink, isBrowser, isBun, isDeno, isElectron } from './env.js'
import * as jose from 'jose'

export function random() {
  return Math.random() < 0.5
}

export async function setup(
  kp: CryptoKeyPair,
  authMethod: string,
  jar: boolean,
  jwtUserinfo: boolean,
  jwtIntrospection: boolean,
  grantTypes: string[],
  encryption: boolean,
): Promise<{
  metadata: lib.ClientMetadata
  issuerIdentifier: URL
  clientSigningKey: lib.PrivateKey
  clientDecryptionKey: lib.DecryptionKey
}> {
  const clientKeyPair = kp
  const jwk = await jose.exportJWK(clientKeyPair.publicKey)
  const alg = 'ES256'
  const clientJwk = {
    ...jwk,
    alg,
    use: 'sig',
    kid: await jose.calculateJwkThumbprint(jwk),
    key_ops: undefined,
    ext: undefined,
  }

  let encKp: lib.CryptoKeyPair
  let encAlg: string
  let keyType: string
  do {
    keyType = ['RSA-OAEP', 'P-256', 'X25519'][Math.floor(Math.random() * 3)]
  } while ((isBrowser || isBun || isDeno) && keyType === 'X25519')

  switch (keyType) {
    case 'RSA-OAEP':
      encAlg = ['RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512'][
        Math.floor(Math.random() * 4)
      ]
      encKp = await jose.generateKeyPair(encAlg, {
        modulusLength: 2048,
      })
      break
    case 'P-256':
    case 'X25519':
      do {
        encAlg = [
          'ECDH-ES',
          'ECDH-ES+A128KW',
          'ECDH-ES+A192KW',
          'ECDH-ES+A256KW',
        ][Math.floor(Math.random() * 3)]
      } while (
        (isBlink && encAlg.includes('192')) ||
        (isElectron && encAlg.includes('KW'))
      )
      encKp = await jose.generateKeyPair(encAlg, { crv: keyType })
      break
    default:
      throw new Error('unreachable')
  }

  const encJwk = await jose.exportJWK(encKp.publicKey)
  const clientEncJwk = {
    ...encJwk,
    alg: encAlg,
    use: 'enc',
    kid: await jose.calculateJwkThumbprint(encJwk),
    key_ops: undefined,
    ext: undefined,
  }

  const authEndpoint =
    grantTypes.includes('authorization_code') || grantTypes.includes('implicit')

  const metadata = {
    token_endpoint_auth_method: authMethod,
    redirect_uris: [] as string[],
    id_token_signed_response_alg: alg,
    request_object_signing_alg: jar ? alg : undefined,
    userinfo_signed_response_alg: jwtUserinfo ? alg : undefined,
    introspection_signed_response_alg: alg,
    authorization_signed_response_alg: alg,
    ...(encryption
      ? {
          authorization_encrypted_response_alg: encAlg,
          id_token_encrypted_response_alg: encAlg,
          userinfo_encrypted_response_alg: jwtUserinfo ? encAlg : undefined,
          introspection_encrypted_response_alg: jwtIntrospection
            ? encAlg
            : undefined,
        }
      : undefined),
    response_types: [] as string[],
    require_auth_time: random(),
    default_max_age: random() ? 30 : undefined,
    grant_types: grantTypes,
    backchannel_token_delivery_mode: 'poll',
    jwks: {
      keys: [] as lib.JsonObject[],
    },
  }

  if (authMethod === 'private_key_jwt' || jar) {
    metadata.jwks.keys.push(clientJwk)
  }
  if (encryption) {
    metadata.jwks.keys.push(clientEncJwk)
  }

  if (authEndpoint) {
    metadata.redirect_uris.push('http://localhost:3000/cb')
    if (grantTypes.includes('implicit')) {
      if (grantTypes.includes('authorization_code')) {
        metadata.response_types.push('code id_token')
      } else {
        metadata.response_types.push('id_token')
      }
    } else {
      metadata.response_types.push('code')
    }
  }

  const configuration = await lib.dynamicClientRegistration(
    new URL('http://localhost:3000'),
    metadata,
    undefined,
    {
      execute: [lib.allowInsecureRequests],
    },
  )

  return {
    metadata: {
      ...configuration.clientMetadata(),
      introspection_signed_response_alg: jwtIntrospection ? alg : undefined,
    },
    clientSigningKey: {
      kid: clientJwk.kid,
      key: clientKeyPair.privateKey,
    },
    clientDecryptionKey: {
      alg: clientEncJwk.alg,
      kid: clientEncJwk.kid,
      key: encKp.privateKey,
    },
    issuerIdentifier: new URL('http://localhost:3000'),
  }
}

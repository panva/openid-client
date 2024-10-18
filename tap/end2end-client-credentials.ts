import type QUnit from 'qunit'
import * as jose from 'jose'

import { setup } from './helper.js'
import * as client from '../src/index.js'

function label(testCase: Record<string, string | boolean>) {
  const keys = Object.keys(
    Object.fromEntries(Object.entries(testCase).filter(([, v]) => v === true)),
  )
  return keys.length
    ? `${testCase.authMethod} w/ ${keys.join(', ')}`
    : testCase.authMethod
}

export default (QUnit: QUnit) => {
  const { module, test } = QUnit
  module('end2end-client-credentials.ts')

  const alg = 'ES256'

  const authMethodOptions: string[] = [
    'client_secret_basic',
    'client_secret_post',
    'private_key_jwt',
    'client_secret_jwt',
    'none',
  ]

  const options = (
    authMethod: string,
    ...flags: Array<'dpop' | 'jwtIntrospection' | 'encryption'>
  ) => {
    const conf = {
      authMethod,
      dpop: false,
      jwtIntrospection: false,
      encryption: false,
    }
    for (const flag of flags) {
      conf[flag] = true
    }
    return conf
  }

  // - every auth method with all options off
  // - dpop alone
  // - jwtIntrospection alone
  // - jwtIntrospection & encryption
  const testCases = [
    ...authMethodOptions.map((authMethod) => options(authMethod)),
    options(authMethodOptions[0], 'dpop'),
    options(authMethodOptions[0], 'jwtIntrospection'),
    options(authMethodOptions[0], 'jwtIntrospection', 'encryption'),
  ]

  for (const testCase of testCases) {
    const { authMethod, dpop, jwtIntrospection, encryption } = testCase

    test(`end-to-end client auth, client credentials, introspection, revocation ${label(
      testCase,
    )}`, async (t) => {
      const kp = (await jose.generateKeyPair('ES256', {
        extractable: true,
      })) as client.CryptoKeyPair
      const {
        metadata,
        issuerIdentifier,
        clientSigningKey,
        clientDecryptionKey,
      } = await setup(
        kp,
        authMethod,
        false,
        false,
        jwtIntrospection,
        ['client_credentials'],
        encryption,
      )

      let clientAuth: client.ClientAuth | undefined

      if (authMethod === 'private_key_jwt') {
        clientAuth = client.PrivateKeyJwt(clientSigningKey)
      } else if (authMethod === 'client_secret_jwt') {
        clientAuth = client.ClientSecretJwt(metadata.client_secret as string)
      } else if (authMethod === 'client_secret_basic') {
        clientAuth = client.ClientSecretBasic(metadata.client_secret as string)
      }

      const config = await client.discovery(
        issuerIdentifier,
        metadata.client_id,
        metadata,
        clientAuth,
        {
          execute: [
            client.allowInsecureRequests,
            client.enableNonRepudiationChecks,
          ],
        },
      )

      if (encryption) {
        client.enableDecryptingResponses(config, undefined, clientDecryptionKey)
      }

      const DPoP = dpop
        ? client.getDPoPHandle(config, await client.randomDPoPKeyPair(alg))
        : undefined

      const params = new URLSearchParams()
      const resource = 'urn:example:resource:opaque'
      params.set('resource', resource)
      params.set('scope', 'api:write')

      {
        const cc = await client.clientCredentialsGrant(config, params, { DPoP })

        const { access_token, token_type } = cc
        t.equal(token_type, dpop ? 'dpop' : 'bearer')

        {
          const introspection = await client.tokenIntrospection(
            config,
            access_token,
          )

          t.propContains(introspection, {
            active: true,
            scope: 'api:write',
            aud: resource,
            token_type: dpop ? 'DPoP' : 'Bearer',
          })
        }

        await client.tokenRevocation(config, access_token)
      }

      t.ok(1)
    })
  }
}

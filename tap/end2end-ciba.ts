import type QUnit from 'qunit'

import { setup } from './helper.js'
import * as client from '../src/index.js'
import * as jose from 'jose'

export default (QUnit: QUnit) => {
  const { module, test } = QUnit
  module('end2end-ciba.ts')

  const alg = 'ES256'

  for (const feat of [undefined, 'dpop', 'abort', 'encryption']) {
    let dpop = false
    let abort = false
    let encryption = false
    let title: string
    switch (feat) {
      case 'dpop':
        title = 'end-to-end CIBA flow w/ dpop'
        dpop = true
        break
      case 'abort':
        title = 'end-to-end CIBA flow w/ abort'
        abort = true
        break
      case 'encryption':
        title = 'end-to-end CIBA flow w/ encryption'
        encryption = true
        break
      default:
        title = 'end-to-end CIBA flow'
        break
    }

    test(title, async (t) => {
      const kp = (await jose.generateKeyPair('ES256', {
        extractable: true,
      })) as client.CryptoKeyPair
      const { metadata, issuerIdentifier, clientDecryptionKey } = await setup(
        kp,
        'client_secret_post',
        false,
        false,
        false,
        ['refresh_token', 'urn:openid:params:grant-type:ciba'],
        encryption,
      )

      const config = await client.discovery(
        issuerIdentifier,
        metadata.client_id,
        metadata,
        undefined,
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

      const resource = 'urn:example:resource:jwt'
      const params = new URLSearchParams()
      params.set('resource', resource)
      params.set('scope', 'openid api:write')
      params.set('login_hint', 'user')

      const backchannelAuthenticationResponse =
        await client.initiateBackchannelAuthentication(config, params)

      if (!abort) {
        fetch('http://localhost:3000/ciba-sim', {
          method: 'POST',
          body: new URLSearchParams({
            action: 'allow',
            auth_req_id: backchannelAuthenticationResponse.auth_req_id,
          }),
        })
      }

      {
        let signal: AbortSignal | undefined
        if (abort) {
          const controller = new AbortController()
          signal = controller.signal
          setTimeout(() => controller.abort(), 250)
        }
        let result: client.TokenEndpointResponse
        const polling = client.pollBackchannelAuthenticationGrant(
          config,
          backchannelAuthenticationResponse,
          undefined,
          { DPoP, signal },
        )

        if (abort) {
          const err = await polling.catch((err) => err)
          t.true(err instanceof Error)
          t.propContains(err, { code: 'OAUTH_ABORT' })
          t.equal(err.cause.name, 'AbortError')
          return
        } else {
          result = await polling
        }

        const { access_token, token_type } = result
        t.ok(access_token)
        t.equal(token_type, dpop ? 'dpop' : 'bearer')

        await client
          .fetchProtectedResource(
            config,
            access_token,
            new URL(config.serverMetadata().userinfo_endpoint!),
            'GET',
            undefined,
            undefined,
            { DPoP },
          )
          .then(() => {
            t.ok(0)
          })
          .catch((err) => {
            if (err instanceof client.WWWAuthenticateChallengeError) {
              const [{ parameters }] = err.cause
              // TODO: check why the server responds with scheme bearer in dpop case
              // t.equal(scheme, dpop ? 'dpop' : 'bearer')
              t.equal(parameters.error, 'invalid_token')
            } else {
              t.ok(0)
            }
          })
      }

      t.ok(1)
    })
  }
}

import type QUnit from 'qunit'

import { setup, random } from './helper.js'
import * as client from '../src/index.js'
import * as jose from 'jose'

function label(testCase: Record<string, boolean>) {
  const keys = Object.keys(
    Object.fromEntries(Object.entries(testCase).filter(([, v]) => v === true)),
  )
  let msg = `w/ response_type=${testCase.hybrid ? 'code id_token' : testCase.implicit ? 'id_token' : 'code'}`
  return keys.length ? `${msg}, ${keys.join(', ')}` : msg
}

export default (QUnit: QUnit) => {
  const { module, test } = QUnit
  module('end2end.ts')

  const alg = 'ES256'

  const options = (
    ...flags: Array<
      | 'jarm'
      | 'par'
      | 'jar'
      | 'dpop'
      | 'jwtUserinfo'
      | 'hybrid'
      | 'nonrepudiation'
      | 'encryption'
      | 'implicit'
      | 'form_post'
      | 'error_response'
    >
  ) => {
    const conf = {
      jarm: false,
      par: false,
      jar: false,
      dpop: false,
      jwtUserinfo: false,
      hybrid: false,
      encryption: false,
      implicit: false,
      nonrepudiation: false,
      form_post: false,
      error_response: false,
    }
    for (const flag of flags) {
      conf[flag] = true
    }
    return conf
  }

  const testCases = [
    options(),
    options('error_response'),
    options('form_post'),
    options('form_post', 'error_response'),
    options('nonrepudiation'),
    options('nonrepudiation', 'encryption'),
    options('par'),
    options('jar'),
    options('dpop'),
    options('par', 'jar'),
    options('par', 'dpop'),
    options('encryption'),
    options('jarm'),
    options('jarm', 'error_response'),
    options('jarm', 'encryption'),
    options('jarm', 'encryption', 'error_response'),
    options('jwtUserinfo'),
    options('jwtUserinfo', 'encryption'),
    options('hybrid'),
    options('hybrid', 'error_response'),
    options('hybrid', 'form_post'),
    options('hybrid', 'form_post', 'error_response'),
    options('hybrid', 'encryption'),
    options('hybrid', 'encryption'),
    options('implicit'),
    options('implicit', 'error_response'),
    options('implicit', 'form_post'),
    options('implicit', 'form_post', 'error_response'),
    options('implicit', 'encryption'),
    options('implicit', 'encryption'),
  ]

  for (const testCase of testCases) {
    const {
      jarm,
      par,
      jar,
      dpop,
      jwtUserinfo,
      hybrid,
      implicit,
      encryption,
      nonrepudiation,
      form_post,
      error_response,
    } = testCase

    test(`end-to-end ${label(testCase)}`, async (t) => {
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
        'client_secret_post',
        jar,
        jwtUserinfo,
        false,
        hybrid
          ? ['implicit', 'authorization_code', 'refresh_token']
          : implicit
            ? ['implicit']
            : ['authorization_code', 'refresh_token'],
        encryption,
      )

      const execute: Array<(config: client.Configuration) => void> = [
        client.allowInsecureRequests,
      ]

      if (nonrepudiation) {
        execute.push(client.enableNonRepudiationChecks)
      }
      if (jarm) {
        execute.push(client.useJwtResponseMode)
      }
      if (hybrid) {
        execute.push(client.useCodeIdTokenResponseType)
      }
      if (implicit) {
        execute.push(client.useIdTokenResponseType)
      }
      const config = await client.discovery(
        issuerIdentifier,
        metadata.client_id,
        metadata,
        undefined,
        { execute },
      )

      // https://github.com/panva/openid-client/issues/710
      {
        t.true(
          config
            .serverMetadata()
            .code_challenge_methods_supported?.includes('S256'),
        )
        t.false(
          config
            .serverMetadata()
            .code_challenge_methods_supported?.includes('plain'),
        )
        t.true(config.serverMetadata().supportsPKCE())
        t.true(config.serverMetadata().supportsPKCE('S256'))
        t.false(config.serverMetadata().supportsPKCE('plain'))
      }

      if (encryption) {
        client.enableDecryptingResponses(config, undefined, clientDecryptionKey)
      }

      const DPoP = dpop
        ? client.getDPoPHandle(config, await client.randomDPoPKeyPair(alg))
        : undefined

      let params = new URLSearchParams()

      const code_verifier = client.randomPKCECodeVerifier()
      const code_challenge =
        await client.calculatePKCECodeChallenge(code_verifier)
      const code_challenge_method = 'S256'
      params.set('code_challenge', code_challenge)
      params.set('code_challenge_method', code_challenge_method)

      const maxAge = random() ? 30 : undefined

      let nonce: string | undefined
      if (hybrid || implicit) {
        nonce = client.randomNonce()
        params.set('nonce', nonce)
      }

      params.set('redirect_uri', 'http://localhost:3000/cb')
      params.set('scope', 'openid offline_access')
      params.set('prompt', 'consent')

      if (maxAge !== undefined) {
        params.set('max_age', maxAge.toString())
      }

      let authorizationUrl: URL
      if (jar && par) {
        authorizationUrl = await client.buildAuthorizationUrlWithJAR(
          config,
          params,
          clientSigningKey,
        )
        authorizationUrl = await client.buildAuthorizationUrlWithPAR(
          config,
          authorizationUrl.searchParams,
          { DPoP },
        )
      } else if (par) {
        authorizationUrl = await client.buildAuthorizationUrlWithPAR(
          config,
          params,
        )
      } else {
        authorizationUrl = client.buildAuthorizationUrl(config, params)
      }

      let currentUrl: URL
      {
        const body = new URLSearchParams({
          goto: authorizationUrl.href,
        })
        if (error_response) {
          body.append('cancel', '1')
        }
        currentUrl = new URL(
          await fetch('http://localhost:3000/drive', {
            method: 'POST',
            body,
          }).then((r) => r.text()),
        )
      }

      let input: URL | Request
      if (form_post) {
        input = new Request(
          `${currentUrl.protocol}//${currentUrl.host}${currentUrl.pathname}`,
          {
            method: 'POST',
            headers: {
              'content-type': 'application/x-www-form-urlencoded',
            },
            body:
              implicit || hybrid
                ? currentUrl.hash.slice(1)
                : currentUrl.searchParams.toString(),
          },
        )
      } else {
        switch ([URL, Request][Math.floor(Math.random() * 2)]) {
          case URL:
            input = currentUrl
            break
          case Request:
            input = new Request(currentUrl)
            break
          default:
            throw new Error('unreachable')
        }
      }

      try {
        if (implicit) {
          await client.implicitAuthentication(config, input, nonce!, {
            maxAge,
          })
        } else {
          const response = await client.authorizationCodeGrant(
            config,
            input,
            {
              expectedNonce: nonce,
              pkceCodeVerifier: code_verifier,
              maxAge,
            },
            undefined,
            { DPoP },
          )

          await client.fetchUserInfo(
            config,
            response.access_token,
            response.claims()?.sub!,
            {
              DPoP,
            },
          )

          await client.refreshTokenGrant(
            config,
            response.refresh_token!,
            undefined,
            {
              DPoP,
            },
          )
        }

        if (jarm || hybrid || nonrepudiation || implicit) {
          const cache = client.getJwksCache(config)
          t.ok(cache?.uat)
          t.ok(cache?.jwks)
        } else {
          t.notOk(client.getJwksCache(config))
        }
      } catch (err) {
        if (
          error_response &&
          err instanceof client.AuthorizationResponseError
        ) {
          t.equal(err.error, 'access_denied')
        } else {
          throw err
        }
      }

      t.ok(1)
    })
  }
}

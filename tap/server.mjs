import * as crypto from 'node:crypto'
import { promisify } from 'node:util'
import { createServer } from 'node:http'
import { once } from 'node:events'

import { fetch } from 'undici'
import { CookieJar } from 'tough-cookie'
import { CookieAgent } from 'http-cookie-agent/undici'
import { Browser } from 'happy-dom'
import Provider from 'oidc-provider'
import raw from 'raw-body'

import koaCors from '@koa/cors'

const generateKeyPair = promisify(crypto.generateKeyPair)

const es256 = await generateKeyPair('ec', { namedCurve: 'P-256' })

const jwks = {
  keys: [{ ...es256.privateKey.export({ format: 'jwk' }), alg: 'ES256' }],
}

const encryptionAlgs = [
  'RSA-OAEP',
  'RSA-OAEP-256',
  'RSA-OAEP-384',
  'RSA-OAEP-512',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A192KW',
  'ECDH-ES+A256KW',
]

const provider = new Provider('http://localhost:3000', {
  jwks,
  clientBasedCORS: () => true,
  features: {
    dPoP: {
      enabled: true,
      nonceSecret: crypto.randomBytes(32),
      requireNonce: () => true,
    },
    introspection: { enabled: true },
    encryption: { enabled: true },
    revocation: { enabled: true },
    clientCredentials: { enabled: true },
    registration: { enabled: true },
    deviceFlow: { enabled: true },
    jwtIntrospection: { enabled: true },
    jwtResponseModes: { enabled: true },
    jwtUserinfo: { enabled: true },
    pushedAuthorizationRequests: { enabled: true },
    ciba: {
      enabled: true,
      processLoginHint(ctx, loginHint) {
        return loginHint
      },
      verifyUserCode() {},
      validateRequestContext() {},
      triggerAuthenticationDevice() {},
      deliveryModes: ['poll'],
    },
    resourceIndicators: {
      enabled: true,
      getResourceServerInfo: (ctx, resource) => ({
        scope: 'api:write',
        ...(resource.includes('jwt')
          ? {
              accessTokenFormat: 'jwt',
              jwt: { sign: { alg: 'ES256' } },
            }
          : { accessTokenFormat: 'opaque' }),
      }),
      useGrantedResource: () => true,
    },
    requestObjects: {
      enabled: true,
    },
    userinfo: { enabled: true },
    mTLS: {
      enabled: true,
      certificateBoundAccessTokens: true,
      selfSignedTlsClientAuth: true,
    },
  },
  clientAuthMethods: [
    'client_secret_basic',
    'client_secret_post',
    'client_secret_jwt',
    'private_key_jwt',
    'none',
    'self_signed_tls_client_auth',
  ],
  enabledJWA: {
    idTokenEncryptionAlgValues: encryptionAlgs,
    authorizationEncryptionAlgValues: encryptionAlgs,
    introspectionEncryptionAlgValues: encryptionAlgs,
    userinfoEncryptionAlgValues: encryptionAlgs,
  },
})

const { invalidate: orig } = provider.Client.Schema.prototype

provider.Client.Schema.prototype.invalidate = function invalidate(
  message,
  code,
) {
  if (code === 'implicit-force-https' || code === 'implicit-forbid-localhost') {
    return
  }

  orig.call(this, message)
}

let location
provider.use(async (ctx, next) => {
  try {
    await next()
  } finally {
    location = ctx.response.headers.location
  }
})

const cors = koaCors()
provider.use((ctx, next) => {
  if (ctx.URL.pathname === '/drive' || ctx.URL.pathname === '/reg') {
    return cors(ctx, next)
  }

  return next()
})

provider.use(async (ctx, next) => {
  if (ctx.path === '/ciba-sim' && ctx.method === 'POST') {
    const body = await raw(ctx.req, {
      length: ctx.request.length,
      encoding: ctx.charset,
    })

    const params = new URLSearchParams(body.toString())
    const auth_req_id = params.get('auth_req_id')
    const action = params.get('action')

    const request =
      await provider.BackchannelAuthenticationRequest.find(auth_req_id)

    if (action === 'allow') {
      const client = await provider.Client.find(request.clientId)
      const grant = new provider.Grant({
        client,
        accountId: request.accountId,
      })
      grant.addOIDCScope(request.scope)
      let claims = []
      if (request.claims.id_token) {
        claims = claims.concat(Object.keys(request.claims.id_token))
      }
      if (request.claims.userinfo) {
        claims = claims.concat(Object.keys(request.claims.userinfo))
      }
      grant.addOIDCClaims(claims)
      // eslint-disable-next-line no-restricted-syntax
      for (const indicator of request.params.resource) {
        grant.addResourceScope(indicator, request.params.scope)
      }
      await grant.save()
      await provider
        .backchannelResult(request, grant, {
          acr: 'urn:mace:incommon:iap:silver',
          authTime: Math.floor(Date.now() / 1000),
        })
        .catch(() => {})
    } else {
      await provider
        .backchannelResult(
          request,
          new errors.AccessDenied('end-user cancelled request'),
        )
        .catch(() => {})
    }

    ctx.body = { done: true }
    return undefined
  }

  if (ctx.URL.pathname === '/drive' && ctx.method === 'POST') {
    let browser
    let rp
    try {
      const jar = new CookieJar()
      const agent = new CookieAgent({ cookies: { jar } })

      const body = await raw(ctx.req, {
        length: ctx.request.length,
        encoding: ctx.charset,
      })
      const params = new URLSearchParams(body.toString())
      let target = new URL(params.get('goto'))
      const cancel = params.has('cancel')
      browser = new Browser()
      const page = browser.newPage()
      rp = createServer((req, res) => {
        res.statusCode = 204
        res.setHeader('Content-Length', '0')
        res.end()
      }).listen(8080)
      await once(rp, 'listening')

      let response = await fetch(target, {
        dispatcher: agent,
        redirect: 'follow',
      })

      while (target) {
        if (target.origin === 'http://localhost:8080') {
          ctx.body = location
          break
        }

        if (response.bodyUsed) {
          response = await fetch(target, {
            dispatcher: agent,
            redirect: 'follow',
          })
        }

        page.url = response.url
        page.content = await response.text()

        let document = page.mainFrame.window.document
        switch (document.title) {
          case 'Sign-in': {
            if (cancel) {
              response = await fetch(document.links[0].href, {
                dispatcher: agent,
                redirect: 'follow',
              })
            } else {
              response = await fetch(document.forms[0].action, {
                dispatcher: agent,
                method: 'POST',
                redirect: 'follow',
                body: new URLSearchParams({
                  prompt: 'login',
                  login: 'user',
                  password: 'pass',
                }),
              })
            }
            target = new URL(response.url)
            continue
          }
          case 'Consent': {
            response = await fetch(document.forms[0].action, {
              dispatcher: agent,
              method: 'POST',
              redirect: 'follow',
              body: new URLSearchParams({
                prompt: 'consent',
              }),
            })

            target = new URL(response.url)
            continue
          }
          case 'Sign-in Success': {
            target = new URL('http://localhost:8080')
            continue
          }
          case 'Device Login Confirmation': // Fall through
          case 'Submitting Callback': {
            const body = new URLSearchParams()
            for (const input of document.forms[0].getElementsByTagName(
              'input',
            )) {
              body.append(input.name, input.value)
            }
            response = await fetch(document.forms[0].action, {
              dispatcher: agent,
              method: 'POST',
              redirect: 'follow',
              body: body.size ? body : undefined,
            })

            target = new URL(response.url)
            continue
          }
          default:
            console.log(page.url)
            console.log(page.content)
            throw new Error(document.title)
        }
      }
    } finally {
      await browser?.close()
      rp?.close()
      if (rp) await once(rp, 'close')
    }
  } else if (ctx.URL.pathname === '/cb') {
    ctx.body = ctx.URL.href
  } else {
    await next()
    if (typeof ctx.body === 'string' && ctx.body.includes('Continue')) {
      ctx.body = ctx.body.replace(
        '<title>Sign-in</title>',
        '<title>Consent</title>',
      )
    }
    if (ctx.body?.verification_uri_complete || ctx.body?.auth_req_id) {
      ctx.body.interval = 0.1
    }
  }
})

provider.listen(3000)

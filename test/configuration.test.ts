import test from 'ava'
import * as client from '../src/index.js'

const issuer = new URL('https://op.example.com')
const server: client.ServerMetadata = {
  issuer: issuer.href,
  token_endpoint: `${issuer.origin}/token`,
  registration_endpoint: `${issuer.origin}/reg`,
}

for (const method of ['constructor', 'discovery', 'registration']) {
  for (const timeout of [undefined, 5, 0]) {
    test(`${method} timeout: ${timeout ?? 'default'}`, async (t) => {
      let tokenRequests = 0
      const fetch: client.CustomFetch = async (url, options) => {
        switch (new URL(url).pathname) {
          case '/.well-known/openid-configuration':
            return Response.json(server)
          case '/reg':
            return Response.json({ client_id: 'client' }, { status: 201 })
          case '/token':
            tokenRequests++
            t.is(options.signal instanceof AbortSignal, timeout !== 0)
            return Response.json({
              access_token: 'access_token',
              token_type: 'bearer',
            })
          default:
            throw new Error(`unexpected request to ${url}`)
        }
      }

      let config: client.Configuration
      const options = { [client.customFetch]: fetch, timeout }
      switch (method) {
        case 'constructor':
          config = new client.Configuration(server, 'client')
          config[client.customFetch] = fetch
          if (timeout !== undefined) config.timeout = timeout
          break
        case 'discovery':
          config = await client.discovery(
            issuer,
            'client',
            undefined,
            undefined,
            options,
          )
          break
        default:
          config = await client.dynamicClientRegistration(
            issuer,
            {},
            undefined,
            options,
          )
      }

      t.is(config.timeout, timeout ?? 30)
      await client.clientCredentialsGrant(config)
      t.is(tokenRequests, 1)
    })
  }
}

test('request timeouts can be disabled with undefined', async (t) => {
  const config = new client.Configuration(server, 'client')
  config.timeout = undefined
  config[client.customFetch] = async (_url, options) => {
    t.is(options.signal, undefined)
    return Response.json({ access_token: 'access_token', token_type: 'bearer' })
  }

  await client.clientCredentialsGrant(config)
})

import test from 'ava'
import * as client from '../src/index.js'
import * as undici from 'undici'

test('genericGrantRequest accepts n_a token type in token exchange grant response', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const mockAgent = agent.get('https://as.example.com')

  // Mock the token endpoint to return a response with n_a token type
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      200,
      {
        access_token: 'test-access-token',
        token_type: 'n_a',
        expires_in: 3600,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )

  const config = new client.Configuration(
    {
      issuer: 'https://as.example.com',
      token_endpoint: 'https://as.example.com/token',
    },
    'test-client-id',
    undefined,
    client.None(),
  )

  client.allowInsecureRequests(config)
  // @ts-ignore
  config[client.customFetch] = (url, options) => {
    return undici.fetch(url, { ...options, dispatcher: agent })
  }

  const result = await client.genericGrantRequest(
    config,
    'urn:ietf:params:oauth:grant-type:token-exchange',
    {
      subject_token: 'subject-token-value',
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    },
  )

  t.is(result.access_token, 'test-access-token')
  t.is(result.token_type, 'n_a')
  t.is(result.expires_in, 3600)
  t.is(
    result.issued_token_type,
    'urn:ietf:params:oauth:token-type:access_token',
  )

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('genericGrantRequest with other grant types does not add n_a token type recognition', async (t) => {
  let agent = new undici.MockAgent()
  agent.disableNetConnect()

  const mockAgent = agent.get('https://as.example.com')

  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      200,
      {
        access_token: 'test-access-token',
        token_type: 'n_a',
        expires_in: 3600,
      },
      {
        headers: {
          'content-type': 'application/json',
        },
      },
    )

  const config = new client.Configuration(
    {
      issuer: 'https://as.example.com',
      token_endpoint: 'https://as.example.com/token',
    },
    'test-client-id',
    undefined,
    client.None(),
  )

  client.allowInsecureRequests(config)
  // @ts-ignore
  config[client.customFetch] = (url, options) => {
    return undici.fetch(url, { ...options, dispatcher: agent })
  }

  // This should throw because n_a token type is not recognized for JWT bearer grants
  await t.throwsAsync(
    client.genericGrantRequest(
      config,
      'urn:ietf:params:oauth:grant-type:jwt-bearer',
      {
        assertion: 'jwt-assertion-value',
        scope: 'test-scope',
      },
    ),
    {
      message: /unsupported operation/,
    },
  )

  t.notThrows(() => agent.assertNoPendingInterceptors())
})

import test from 'ava'
import * as client from '../src/index.js'
import * as undici from 'undici'

const issuer = new URL('https://op.example.com')

async function setupMockAgent() {
  const agent = new undici.MockAgent()
  agent.disableNetConnect()

  const mockAgent = agent.get(issuer.origin)

  return { agent, mockAgent }
}

function createConfig(agent: undici.MockAgent) {
  const config = new client.Configuration(
    {
      issuer: issuer.href,
      token_endpoint: `${issuer.origin}/token`,
    },
    'client_id',
  )

  // @ts-ignore
  config[client.customFetch] = (url, options) => {
    return undici.fetch(url, { ...options, dispatcher: agent })
  }

  return config
}

// Tests for Device Authorization Grant polling with retry-after

test('pollBackchannelAuthenticationGrant - respects retry-after header with numeric seconds', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  const startTime = Date.now()

  // First poll - return 503 with retry-after
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(503, '503 Service Unavailable', {
      headers: {
        'retry-after': '2', // 2 seconds
      },
    })

  // Second poll - return success
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(200, {
      access_token: 'access_token',
      token_type: 'bearer',
    })

  const config = createConfig(agent)

  // Mock device authorization response to test polling directly
  const response = {
    auth_req_id: 'req-id',
    expires_in: 600,
    interval: 1,
  }

  const result = await client.pollBackchannelAuthenticationGrant(
    config,
    response,
  )

  const elapsed = Date.now() - startTime
  // Should take ~3 seconds (1 second initial interval, 2 second retry-after the initial response)
  t.true(
    elapsed >= 3000 && elapsed <= 4000,
    `expected ~3s wait, got ${elapsed}ms`,
  )
  t.is(result.access_token, 'access_token')
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('pollBackchannelAuthenticationGrant - respects retry-after header with date', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  const futureDate = new Date(Date.now() + 3000) // 3 seconds from now, means 2 seconds from the initial poll
  const startTime = Date.now()

  // First poll - return 503 with retry-after date
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(503, '503 Service Unavailable', {
      headers: {
        'retry-after': futureDate.toUTCString(),
      },
    })

  // Second poll - return success
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(200, {
      access_token: 'access_token',
      token_type: 'bearer',
    })

  const config = createConfig(agent)

  const response = {
    auth_req_id: 'req-id',
    expires_in: 600,
    interval: 1,
  }

  const result = await client.pollBackchannelAuthenticationGrant(
    config,
    response,
  )

  const elapsed = Date.now() - startTime
  // Should take ~3 seconds (1 second initial interval, 2 second retry-after the initial response)
  t.true(
    elapsed >= 3000 && elapsed <= 4000,
    `expected ~3s wait, got ${elapsed}ms`,
  )
  t.is(result.access_token, 'access_token')
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('pollBackchannelAuthenticationGrant - throws on invalid retry-after header when status is 503', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  // Return 503 with invalid retry-after
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(503, '503 Service Unavailable', {
      headers: {
        'retry-after': 'invalid-value',
      },
    })

  const config = createConfig(agent)

  const response = {
    auth_req_id: 'req-id',
    expires_in: 600,
    interval: 5,
  }

  const error = await t.throwsAsync(
    client.pollBackchannelAuthenticationGrant(config, response),
  )

  t.true(error.message.includes('invalid Retry-After header value'))
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('pollBackchannelAuthenticationGrant - respects retry-after on authorization_pending error', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  const startTime = Date.now()

  // First poll - return authorization_pending with retry-after
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      400,
      {
        error: 'authorization_pending',
      },
      {
        headers: {
          'retry-after': '2',
          'content-type': 'application/json',
        },
      },
    )

  // Second poll - return success
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(200, {
      access_token: 'access_token',
      token_type: 'bearer',
    })

  const config = createConfig(agent)

  const response = {
    auth_req_id: 'req-id',
    expires_in: 600,
    interval: 1,
  }

  const result = await client.pollBackchannelAuthenticationGrant(
    config,
    response,
  )

  const elapsed = Date.now() - startTime
  // Should take ~3 seconds (1 second initial interval, 2 second retry-after the initial response)
  t.true(
    elapsed >= 3000 && elapsed <= 4000,
    `expected ~3s wait, got ${elapsed}ms`,
  )
  t.is(result.access_token, 'access_token')
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('pollBackchannelAuthenticationGrant - ignores invalid retry-after on authorization_pending error', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  const startTime = Date.now()

  // First poll - return authorization_pending with invalid retry-after (should be ignored)
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      400,
      {
        error: 'authorization_pending',
      },
      {
        headers: {
          'retry-after': 'invalid',
          'content-type': 'application/json',
        },
      },
    )

  // Second poll - return success
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(200, {
      access_token: 'access_token',
      token_type: 'bearer',
    })

  const config = createConfig(agent)

  const response = {
    auth_req_id: 'req-id',
    expires_in: 600,
    interval: 1,
  }

  const result = await client.pollBackchannelAuthenticationGrant(
    config,
    response,
  )

  const elapsed = Date.now() - startTime
  // Should only wait for the normal intervals (twice 1 second)
  t.true(
    elapsed >= 2000 && elapsed <= 3000,
    `expected ~2s wait, got ${elapsed}ms`,
  )
  t.is(result.access_token, 'access_token')
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

// Tests for Device Authorization Grant polling with retry-after

test('pollDeviceAuthorizationGrant - respects retry-after header with numeric seconds', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  const startTime = Date.now()

  // First poll - return 503 with retry-after
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(503, '503 Service Unavailable', {
      headers: {
        'retry-after': '2', // 2 seconds
      },
    })

  // Second poll - return success
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(200, {
      access_token: 'access_token',
      token_type: 'bearer',
    })

  const config = createConfig(agent)

  // Mock device authorization response to test polling directly
  const deviceAuthorizationResponse = {
    device_code: 'device123',
    user_code: 'user123',
    verification_uri: 'https://op.example.com/device',
    expires_in: 600,
    interval: 1,
  }

  const result = await client.pollDeviceAuthorizationGrant(
    config,
    deviceAuthorizationResponse,
  )

  const elapsed = Date.now() - startTime
  // Should take ~3 seconds (1 second initial interval, 2 second retry-after the initial response)
  t.true(
    elapsed >= 3000 && elapsed <= 4000,
    `expected ~3s wait, got ${elapsed}ms`,
  )
  t.is(result.access_token, 'access_token')
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('pollDeviceAuthorizationGrant - respects retry-after header with date', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  const futureDate = new Date(Date.now() + 3000) // 3 seconds from now, means 2 seconds from the initial poll
  const startTime = Date.now()

  // First poll - return 503 with retry-after date
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(503, '503 Service Unavailable', {
      headers: {
        'retry-after': futureDate.toUTCString(),
      },
    })

  // Second poll - return success
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(200, {
      access_token: 'access_token',
      token_type: 'bearer',
    })

  const config = createConfig(agent)

  const deviceAuthorizationResponse = {
    device_code: 'device123',
    user_code: 'user123',
    verification_uri: 'https://op.example.com/device',
    expires_in: 600,
    interval: 1,
  }

  const result = await client.pollDeviceAuthorizationGrant(
    config,
    deviceAuthorizationResponse,
  )

  const elapsed = Date.now() - startTime
  // Should take ~3 seconds (1 second initial interval, 2 second retry-after the initial response)
  t.true(
    elapsed >= 3000 && elapsed <= 4000,
    `expected ~3s wait, got ${elapsed}ms`,
  )
  t.is(result.access_token, 'access_token')
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('pollDeviceAuthorizationGrant - throws on invalid retry-after header when status is 503', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  // Return 503 with invalid retry-after
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(503, '503 Service Unavailable', {
      headers: {
        'retry-after': 'invalid-value',
      },
    })

  const config = createConfig(agent)

  const deviceAuthorizationResponse = {
    device_code: 'device123',
    user_code: 'user123',
    verification_uri: 'https://op.example.com/device',
    expires_in: 600,
    interval: 5,
  }

  const error = await t.throwsAsync(
    client.pollDeviceAuthorizationGrant(config, deviceAuthorizationResponse),
  )

  t.true(error.message.includes('invalid Retry-After header value'))
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('pollDeviceAuthorizationGrant - respects retry-after on authorization_pending error', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  const startTime = Date.now()

  // First poll - return authorization_pending with retry-after
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      400,
      {
        error: 'authorization_pending',
      },
      {
        headers: {
          'retry-after': '2',
          'content-type': 'application/json',
        },
      },
    )

  // Second poll - return success
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(200, {
      access_token: 'access_token',
      token_type: 'bearer',
    })

  const config = createConfig(agent)

  const deviceAuthorizationResponse = {
    device_code: 'device123',
    user_code: 'user123',
    verification_uri: 'https://op.example.com/device',
    expires_in: 600,
    interval: 1,
  }

  const result = await client.pollDeviceAuthorizationGrant(
    config,
    deviceAuthorizationResponse,
  )

  const elapsed = Date.now() - startTime
  // Should take ~3 seconds (1 second initial interval, 2 second retry-after the initial response)
  t.true(
    elapsed >= 3000 && elapsed <= 4000,
    `expected ~3s wait, got ${elapsed}ms`,
  )
  t.is(result.access_token, 'access_token')
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

test('pollDeviceAuthorizationGrant - ignores invalid retry-after on authorization_pending error', async (t) => {
  const { agent, mockAgent } = await setupMockAgent()

  const startTime = Date.now()

  // First poll - return authorization_pending with invalid retry-after (should be ignored)
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(
      400,
      {
        error: 'authorization_pending',
      },
      {
        headers: {
          'retry-after': 'invalid',
          'content-type': 'application/json',
        },
      },
    )

  // Second poll - return success
  mockAgent
    .intercept({
      method: 'POST',
      path: '/token',
    })
    .reply(200, {
      access_token: 'access_token',
      token_type: 'bearer',
    })

  const config = createConfig(agent)

  const deviceAuthorizationResponse = {
    device_code: 'device123',
    user_code: 'user123',
    verification_uri: 'https://op.example.com/device',
    expires_in: 600,
    interval: 1,
  }

  const result = await client.pollDeviceAuthorizationGrant(
    config,
    deviceAuthorizationResponse,
  )

  const elapsed = Date.now() - startTime
  // Should only wait for the normal intervals (twice 1 second)
  t.true(
    elapsed >= 2000 && elapsed <= 3000,
    `expected ~2s wait, got ${elapsed}ms`,
  )
  t.is(result.access_token, 'access_token')
  t.notThrows(() => agent.assertNoPendingInterceptors())
})

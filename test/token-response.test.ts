import { mock } from 'node:test'
import test from 'ava'
import * as client from '../src/index.js'

async function getTokens(expiresIn?: number) {
  const config = new client.Configuration(
    {
      issuer: 'https://op.example.com',
      token_endpoint: 'https://op.example.com/token',
    },
    'client',
  )
  config[client.customFetch] = async () =>
    Response.json({
      access_token: 'access_token',
      token_type: 'bearer',
      expires_in: expiresIn,
    })
  return client.clientCredentialsGrant(config)
}

for (const { name, now, expiresIn } of [
  { name: 'spring forward', now: '2026-03-29T00:30:00Z', expiresIn: 7200 },
  { name: 'fall back', now: '2026-10-25T00:30:00Z', expiresIn: 3600 },
]) {
  test.serial(
    `expiresIn uses elapsed time across ${name}`,
    async (testContext) => {
      const originalTimeZone = process.env.TZ
      testContext.teardown(() => {
        mock.timers.reset()
        if (originalTimeZone === undefined) {
          delete process.env.TZ
        } else {
          process.env.TZ = originalTimeZone
        }
      })
      process.env.TZ = 'Europe/Prague'
      mock.timers.enable({ apis: ['Date'], now: Date.parse(now) })

      const tokens = await getTokens(expiresIn)
      testContext.is(tokens.expiresIn(), expiresIn)
      mock.timers.tick(1000)
      testContext.is(tokens.expiresIn(), expiresIn - 1)
      mock.timers.tick((expiresIn - 1) * 1000)
      testContext.is(tokens.expiresIn(), 0)
      mock.timers.tick(1000)
      testContext.is(tokens.expiresIn(), 0)
    },
  )
}

test('expiresIn returns undefined when no lifetime was provided', async (testContext) => {
  const tokens = await getTokens()
  testContext.is(tokens.expiresIn(), undefined)
})

test('expiresIn returns zero for an already expired token', async (testContext) => {
  const tokens = await getTokens(0)
  testContext.is(tokens.expiresIn(), 0)
})

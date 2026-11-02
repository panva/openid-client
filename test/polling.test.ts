import { getEventListeners } from 'node:events'
import test, { mock } from 'node:test'
import assert from 'node:assert/strict'
import * as client from '../src/index.js'
import * as jose from 'jose'

const issuer = new URL('https://op.example.com')
const authorizationResponse = {
  device_code: 'device-code',
  user_code: 'user-code',
  verification_uri: `${issuer.origin}/device`,
  auth_req_id: 'auth-req-id',
  expires_in: 600,
  interval: 0,
}

for (const poll of [
  client.pollDeviceAuthorizationGrant,
  client.pollBackchannelAuthenticationGrant,
]) {
  test(`${poll.name} preserves intervals, parameters, and its deadline`, async (testContext) => {
    const config = new client.Configuration(
      { issuer: issuer.href, token_endpoint: `${issuer.origin}/token` },
      'client',
    )
    const schedule = setTimeout
    let elapsed = 0
    const timerMock = mock.method(
      globalThis,
      'setTimeout',
      (callback: () => void, milliseconds = 0) => {
        elapsed += milliseconds
        return schedule(callback, 0)
      },
    )
    const timeoutMock = mock.method(AbortSignal, 'timeout')
    testContext.after(() => {
      timerMock.mock.restore()
      timeoutMock.mock.restore()
    })
    const requestTimes: number[] = []
    const resource = 'https://resource.example.com'
    config[client.customFetch] = async (_url, options) => {
      requestTimes.push(elapsed)
      const parameters = new URLSearchParams(options.body as string)
      assert.strictEqual(parameters.get('resource'), resource)
      const device = poll === client.pollDeviceAuthorizationGrant
      assert.strictEqual(
        parameters.get('grant_type'),
        device
          ? 'urn:ietf:params:oauth:grant-type:device_code'
          : 'urn:openid:params:grant-type:ciba',
      )
      assert.strictEqual(
        parameters.get(device ? 'device_code' : 'auth_req_id'),
        device
          ? authorizationResponse.device_code
          : authorizationResponse.auth_req_id,
      )
      switch (requestTimes.length) {
        case 1:
          return Response.json({ error: 'slow_down' }, { status: 400 })
        case 2:
          return Response.json(
            { error: 'authorization_pending' },
            { status: 400 },
          )
        default:
          return Response.json({
            access_token: 'access_token',
            token_type: 'bearer',
          })
      }
    }

    const input = { ...authorizationResponse, interval: 1 }
    const result = await poll(config, input, { resource })
    assert.deepStrictEqual(requestTimes, [1000, 7000, 13000])
    assert.deepStrictEqual(
      timeoutMock.mock.calls.map((call) => call.arguments[0]),
      [600_000, 30_000, 30_000, 30_000],
    )
    assert.strictEqual(input.interval, 1)
    assert.strictEqual(result.access_token, 'access_token')
    assert.strictEqual(result.claims(), undefined)
  })

  for (const intermediate of ['authorization_pending', '503']) {
    test(`${poll.name} resets DPoP retry limits after ${intermediate}`, async () => {
      const config = new client.Configuration(
        { issuer: issuer.href, token_endpoint: `${issuer.origin}/token` },
        'client',
      )
      const DPoP = client.getDPoPHandle(
        config,
        await client.randomDPoPKeyPair('ES256'),
      )
      const nonces: unknown[] = []
      config[client.customFetch] = async (_url, options) => {
        nonces.push(jose.decodeJwt(options.headers.dpop).nonce)
        switch (nonces.length) {
          case 1:
          case 3:
            return Response.json(
              { error: 'use_dpop_nonce' },
              {
                status: 400,
                headers: {
                  'dpop-nonce': nonces.length === 1 ? 'first' : 'second',
                },
              },
            )
          case 2:
            return intermediate === '503'
              ? new Response(null, {
                  status: 503,
                  headers: { 'retry-after': '0' },
                })
              : Response.json({ error: intermediate }, { status: 400 })
          default:
            return Response.json({
              access_token: 'access_token',
              token_type: 'dpop',
            })
        }
      }

      const options = Object.freeze({ DPoP })
      const result = await poll(
        config,
        authorizationResponse,
        undefined,
        options,
      )
      assert.deepStrictEqual(nonces, [undefined, 'first', 'first', 'second'])
      assert.strictEqual(result.token_type, 'dpop')
    })
  }

  test(`${poll.name} stops after repeated DPoP nonce challenges`, async () => {
    const config = new client.Configuration(
      { issuer: issuer.href, token_endpoint: `${issuer.origin}/token` },
      'client',
    )
    const DPoP = client.getDPoPHandle(
      config,
      await client.randomDPoPKeyPair('ES256'),
    )
    let requests = 0
    config[client.customFetch] = async () => {
      requests++
      assert.strictEqual(requests <= 2, true)
      return Response.json(
        { error: 'use_dpop_nonce' },
        {
          status: 400,
          headers: { 'dpop-nonce': `nonce-${requests}` },
        },
      )
    }

    await assert.rejects(
      poll(config, authorizationResponse, undefined, { DPoP }),
      (error: unknown) => {
        assert.ok(error instanceof client.ResponseBodyError)
        assert.strictEqual(error.error, 'use_dpop_nonce')
        return true
      },
    )
    assert.strictEqual(requests, 2)
  })

  for (const abortSource of ['caller', 'timeout']) {
    test(`${poll.name} cancels body reads on ${abortSource} abort`, async (testContext) => {
      const config = new client.Configuration(
        { issuer: issuer.href, token_endpoint: `${issuer.origin}/token` },
        'client',
      )
      const caller = new AbortController()
      const timeout = new AbortController()
      const timeoutMock = mock.method(
        AbortSignal,
        'timeout',
        (milliseconds: number) => {
          assert.strictEqual(milliseconds, 30_000)
          return timeout.signal
        },
      )
      testContext.after(() => timeoutMock.mock.restore())

      let startReading!: () => void
      const reading = new Promise<void>((resolve) => {
        startReading = resolve
      })
      let requestSignal!: AbortSignal
      let finishResponse!: () => void
      config[client.customFetch] = async (_url, options) => {
        requestSignal = options.signal!
        return new Response(
          new ReadableStream<Uint8Array>(
            {
              start(controller) {
                requestSignal.addEventListener(
                  'abort',
                  () => {
                    controller.error(requestSignal.reason)
                  },
                  { once: true },
                )
                finishResponse = () => {
                  if (!requestSignal.aborted) {
                    controller.enqueue(
                      new TextEncoder().encode(
                        JSON.stringify({
                          access_token: 'access_token',
                          token_type: 'bearer',
                        }),
                      ),
                    )
                    controller.close()
                  }
                }
              },
              pull() {
                startReading()
              },
            },
            { highWaterMark: 0 },
          ),
          { headers: { 'content-type': 'application/json' } },
        )
      }

      const pending = poll(config, authorizationResponse, undefined, {
        signal: caller.signal,
      })
      const failure = assert.rejects(pending, client.ClientError)
      await reading
      const source = abortSource === 'caller' ? caller : timeout
      const reason = new DOMException('cancelled', 'AbortError')
      source.abort(reason)
      finishResponse()

      await failure
      assert.strictEqual(requestSignal.aborted, true)
      assert.strictEqual(requestSignal.reason, reason)
      assert.strictEqual(getEventListeners(caller.signal, 'abort').length, 0)
      assert.strictEqual(getEventListeners(timeout.signal, 'abort').length, 0)
    })
  }
}

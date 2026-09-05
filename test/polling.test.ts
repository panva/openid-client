import { getEventListeners } from 'node:events'
import { mock } from 'node:test'
import test from 'ava'
import * as client from '../src/index.js'

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
  for (const abortSource of ['caller', 'timeout']) {
    test.serial(
      `${poll.name} cancels body reads on ${abortSource} abort`,
      async (testContext) => {
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
            testContext.is(milliseconds, 30_000)
            return timeout.signal
          },
        )
        testContext.teardown(() => timeoutMock.mock.restore())

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
        const failure = testContext.throwsAsync(pending, {
          instanceOf: client.ClientError,
        })
        await reading
        const source = abortSource === 'caller' ? caller : timeout
        const reason = new DOMException('cancelled', 'AbortError')
        source.abort(reason)
        finishResponse()

        await failure
        testContext.true(requestSignal.aborted)
        testContext.is(requestSignal.reason, reason)
        testContext.is(getEventListeners(caller.signal, 'abort').length, 0)
        testContext.is(getEventListeners(timeout.signal, 'abort').length, 0)
      },
    )
  }
}

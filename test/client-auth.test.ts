import test from 'ava'
import * as client from '../src/index.js'
import * as jose from 'jose'

const server = {
  issuer: 'https://op.example.com',
  token_endpoint: 'https://op.example.com/token',
}
const factories = [
  client.ClientSecretPost,
  client.ClientSecretBasic,
  client.ClientSecretJwt,
]

async function authenticate(
  auth: client.ClientAuth,
  metadata: client.ClientMetadata,
) {
  const body = new URLSearchParams()
  const headers = new Headers()
  await auth(server, metadata, body, headers)
  return { body, headers }
}

for (const firstFactory of factories) {
  test(`lazy authentication remains isolated after ${firstFactory.name}`, async (testContext) => {
    const metadata = Object.freeze({
      client_id: 'client',
      client_secret: 'example-client-secret'.repeat(2),
    })
    const expectedBasic = await authenticate(
      client.ClientSecretBasic(metadata.client_secret),
      metadata,
    )
    for (const factory of [
      firstFactory,
      ...factories.filter((factory) => factory !== firstFactory),
    ]) {
      const { body, headers } = await authenticate(factory(), metadata)
      switch (factory) {
        case client.ClientSecretPost:
          testContext.is(body.get('client_id'), metadata.client_id)
          testContext.is(body.get('client_secret'), metadata.client_secret)
          testContext.false(headers.has('authorization'))
          break
        case client.ClientSecretBasic:
          testContext.is(
            headers.get('authorization'),
            expectedBasic.headers.get('authorization'),
          )
          testContext.false(body.has('client_secret'))
          break
        default:
          testContext.is(
            body.get('client_assertion_type'),
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          )
          testContext.is(
            jose.decodeJwt(body.get('client_assertion')!).sub,
            metadata.client_id,
          )
          testContext.false(body.has('client_secret'))
          testContext.false(headers.has('authorization'))
      }
    }
  })
}

test('lazy JWT handlers retain their own assertion modifiers', async (testContext) => {
  const metadata = Object.freeze({
    client_id: 'client',
    client_secret: 'example-client-secret'.repeat(2),
  })
  const handlers = ['first', 'second'].map((marker) =>
    client.ClientSecretJwt(undefined, {
      [client.modifyAssertion](_header, payload) {
        payload.marker = marker
      },
    }),
  )

  for (const index of [0, 1, 0, 1]) {
    const { body } = await authenticate(handlers[index], metadata)
    testContext.is(
      jose.decodeJwt(body.get('client_assertion')!).marker,
      index === 0 ? 'first' : 'second',
    )
  }
})

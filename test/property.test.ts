import { createHash } from 'node:crypto'

import test from 'ava'
import fc from 'fast-check'

import * as client from '../src/index.js'

const options = { numRuns: 100 }
const pkceCharacters =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
const codeVerifiers = fc
  .array(fc.constantFrom(...pkceCharacters), { minLength: 43, maxLength: 128 })
  .map((characters) => characters.join(''))
const unicodeStrings = fc.string({ unit: 'grapheme', maxLength: 256 })
const clientIds = fc.string({ unit: 'grapheme', minLength: 1, maxLength: 64 })
const authorizationParameterNames = fc
  .string({ unit: 'grapheme', maxLength: 32 })
  .map((name) => `custom:${name}`)
const authorizationParameters = fc.array(
  fc.tuple(authorizationParameterNames, unicodeStrings),
  { maxLength: 12 },
)

function mutate(value: string, position: number): string {
  const offset = position % value.length
  const current = pkceCharacters.indexOf(value[offset])
  const replacement = pkceCharacters[(current + 1) % pkceCharacters.length]

  return `${value.slice(0, offset)}${replacement}${value.slice(offset + 1)}`
}

test('S256 PKCE challenges match the independent digest', async (t) => {
  await fc.assert(
    fc.asyncProperty(codeVerifiers, fc.nat(), async (verifier, position) => {
      const challenge = await client.calculatePKCECodeChallenge(verifier)
      const expected = createHash('sha256').update(verifier).digest('base64url')

      t.is(challenge, expected)
      t.not(
        await client.calculatePKCECodeChallenge(mutate(verifier, position)),
        challenge,
      )
    }),
    options,
  )
})

test('authorization URLs preserve arbitrary parameters and add defaults', (t) => {
  fc.assert(
    fc.property(clientIds, authorizationParameters, (clientId, parameters) => {
      const config = new client.Configuration(
        {
          issuer: 'https://as.example.com',
          authorization_endpoint:
            'https://as.example.com/authorize?existing=server',
        },
        clientId,
      )
      const input = new URLSearchParams(parameters)
      const before = input.toString()
      const result = client.buildAuthorizationUrl(config, input)

      t.is(input.toString(), before)
      t.is(result.origin, 'https://as.example.com')
      t.is(result.pathname, '/authorize')
      t.deepEqual(result.searchParams.getAll('existing'), ['server'])
      t.deepEqual(result.searchParams.getAll('client_id'), [clientId])
      t.deepEqual(result.searchParams.getAll('response_type'), ['code'])

      for (const name of new Set(input.keys())) {
        t.deepEqual(result.searchParams.getAll(name), input.getAll(name))
      }
    }),
    options,
  )
})

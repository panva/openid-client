// Type-level regression tests. Nothing here runs; compilation is the assertion.
import type * as client from 'openid-client'
import type * as oauth from 'oauth4webapi'
import type { CryptoKey as JoseCryptoKey } from 'jose'

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

const _isDependencyCryptoKey: Equals<client.CryptoKey, oauth.CryptoKey> = true
const _isHostCryptoKey: Equals<client.CryptoKey, CryptoKey> = true
const _isJoseCryptoKey: Equals<client.CryptoKey, JoseCryptoKey> = true
const _isDependencyCryptoKeyPair: Equals<
  client.CryptoKeyPair,
  oauth.CryptoKeyPair
> = true
const _isDependencyJwk: Equals<client.JWK, oauth.JWK> = true
const _duplex: Equals<client.CustomFetchOptions['duplex'], 'half' | undefined> =
  true

// @ts-expect-error `any` would accept this
const _notAny: client.CryptoKey = 'definitely not a key'

declare const pair: client.CryptoKeyPair
declare const clientJwk: client.JWK
declare const hostJwk: JsonWebKey

const _dependencyPair: oauth.CryptoKeyPair = pair
const _privateKey: CryptoKey = pair.privateKey
const _publicKey: CryptoKey = pair.publicKey
const _clientJwkToHost: JsonWebKey = clientJwk
const _hostJwkToClient: client.JWK = hostJwk

import type * as client from 'openid-client'
import type { StrategyOptions } from 'openid-client/passport'
import type * as oauth from 'oauth4webapi'
import type { JsonWebKey, webcrypto } from 'node:crypto'
import type { CryptoKey as JoseCryptoKey } from 'jose'

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

const _isDependencyCryptoKey: Equals<client.CryptoKey, oauth.CryptoKey> = true
const _isHostCryptoKey: Equals<client.CryptoKey, webcrypto.CryptoKey> = true
const _isJoseCryptoKey: Equals<client.CryptoKey, JoseCryptoKey> = true
const _isDependencyCryptoKeyPair: Equals<
  client.CryptoKeyPair,
  oauth.CryptoKeyPair
> = true
const _isDependencyJwk: Equals<client.JWK, oauth.JWK> = true

// @ts-expect-error `any` would accept this
const _notAny: client.CryptoKey = 'definitely not a key'

declare const hostKey: webcrypto.CryptoKey
declare const clientKey: client.CryptoKey
declare const pair: client.CryptoKeyPair
declare const clientJwk: client.JWK
declare const hostJwk: JsonWebKey
declare const webcryptoHostJwk: webcrypto.JsonWebKey

const _toClient: client.CryptoKey = hostKey
const _toHost: webcrypto.CryptoKey = clientKey
const _privateKey: webcrypto.CryptoKey = pair.privateKey
const _publicKey: webcrypto.CryptoKey = pair.publicKey
const _passportUseJAR: NonNullable<StrategyOptions['useJAR']> = hostKey
const _clientJwkToHost: JsonWebKey = clientJwk
const _hostJwkToClient: client.JWK = hostJwk
const _clientJwkToWebcryptoHost: webcrypto.JsonWebKey = clientJwk
const _webcryptoHostJwkToClient: client.JWK = webcryptoHostJwk

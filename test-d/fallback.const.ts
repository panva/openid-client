// A lexical `const crypto` is not a property of `globalThis`, so oauth4webapi's fallback is used.
import * as client from 'openid-client'
import type * as oauth from 'oauth4webapi'
import type { CryptoKey as JoseCryptoKey } from 'jose'

declare global {
  const crypto: Crypto
}

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

const _isDependencyCryptoKey: Equals<client.CryptoKey, oauth.CryptoKey> = true
const _isJoseCryptoKey: Equals<client.CryptoKey, JoseCryptoKey> = true
const _usesFallback: Equals<
  'hostMarker' extends keyof client.CryptoKey ? true : false,
  false
> = true
const _isDependencyCryptoKeyPair: Equals<
  client.CryptoKeyPair,
  oauth.CryptoKeyPair
> = true

// @ts-expect-error the fallback must not degrade to any
const _notAny: client.CryptoKey = 'definitely not a key'

declare const hostKey: CryptoKey
declare const clientKey: client.CryptoKey
declare const clientPair: client.CryptoKeyPair

const _toClient: client.CryptoKey = hostKey
const _toHost: CryptoKey = clientKey
const _toHostPair: CryptoKeyPair = clientPair

crypto.subtle.exportKey('raw', clientKey)
client.PrivateKeyJwt(hostKey)

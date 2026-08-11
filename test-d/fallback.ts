// Selects oauth4webapi's CryptoKey structural fallback without DOM or Node ambient types.
import * as client from 'openid-client'
import type * as oauth from 'oauth4webapi'
import type { CryptoKey as JoseCryptoKey } from 'jose'

declare global {
  interface AbortSignal {}
  interface Headers {}
  interface ReadableStream<R = any> {}
  interface Request {}
  interface Response {}
  interface URL {}
  interface URLSearchParams {}

  abstract class CryptoKey {
    readonly algorithm: { name: string }
    readonly extractable: boolean
    readonly type: string
    readonly usages: string[]
  }
}

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

const _isDependencyCryptoKey: Equals<client.CryptoKey, oauth.CryptoKey> = true
const _isJoseCryptoKey: Equals<client.CryptoKey, JoseCryptoKey> = true
const _algorithm: Equals<client.CryptoKey['algorithm'], { name: string }> = true
const _extractable: Equals<client.CryptoKey['extractable'], boolean> = true
const _type: Equals<client.CryptoKey['type'], string> = true
const _usages: Equals<client.CryptoKey['usages'], string[]> = true
const _isDependencyCryptoKeyPair: Equals<
  client.CryptoKeyPair,
  oauth.CryptoKeyPair
> = true

// @ts-expect-error the fallback must not degrade to any
const _notAny: client.CryptoKey = 'definitely not a key'

declare const hostKey: CryptoKey
declare const clientKey: client.CryptoKey

const _toClient: client.CryptoKey = hostKey
const _toHost: CryptoKey = clientKey

client.PrivateKeyJwt(hostKey)

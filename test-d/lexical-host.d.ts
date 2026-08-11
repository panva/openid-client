export {}

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

    // Makes oauth4webapi's inferred host branch distinguishable from its structural fallback.
    readonly hostMarker?: true
  }

  interface CryptoKeyPair {
    privateKey: CryptoKey
    publicKey: CryptoKey
  }

  interface SubtleCrypto {
    generateKey(
      algorithm: string,
      extractable: boolean,
      keyUsages: string[],
    ): Promise<CryptoKey | CryptoKeyPair>
    exportKey(format: string, key: CryptoKey): Promise<ArrayBuffer>
  }

  interface Crypto {
    readonly subtle: SubtleCrypto
  }
}

# Interface: DecryptionKey

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

## Properties

### key

• **key**: [`CryptoKey`](https://developer.mozilla.org/docs/Web/API/CryptoKey)

An asymmetric private CryptoKey. Its algorithm must be compatible with a
supported JWE Key Management Algorithm Identifier

***

### alg?

• `optional` **alg**: `string`

The key's JWE Key Management Algorithm Identifier, this can be used to
limit ECDH and X25519 keys to only a specified ECDH-ES* JWE Key Management
Algorithm (The other (RSA) keys have a JWE Key Management Algorithm
Identifier fully specified by their CryptoKey algorithm).

***

### kid?

• `optional` **kid**: `string`

The key's JWK Key ID.

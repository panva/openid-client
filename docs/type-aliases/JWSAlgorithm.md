# Type Alias: JWSAlgorithm

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

• **JWSAlgorithm** = `"PS256"` \| `"ES256"` \| `"RS256"` \| `"Ed25519"` \| `"ES384"` \| `"PS384"` \| `"RS384"` \| `"ES512"` \| `"PS512"` \| `"RS512"` \| `"ML-DSA-44"` \| `"ML-DSA-65"` \| `"ML-DSA-87"` \| `"EdDSA"`

A supported JWS `alg` identifier for digital signature validation.

The identifiers come from the
[JSON Web Signature and Encryption Algorithms IANA registry](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms)
and are limited to those for which digital signature validation is implemented.

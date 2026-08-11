# Type Alias: CryptoKey

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

• **CryptoKey** = *typeof* `globalThis` *extends* `object` ? [`Extract`](https://www.typescriptlang.org/docs/handbook/utility-types.html#extracttype-union)\<`R`, \{ `type`: `string`; \}\> : `CryptoKeyStructuralFallback`

A Web Cryptography key as declared by the host runtime.

This aliases the key type returned by the host's `SubtleCrypto.generateKey()` API when it is
exposed on `globalThis`. A structural fallback is used otherwise, keeping the package portable to
runtimes and TypeScript projects that do not include DOM or Node.js ambient types.

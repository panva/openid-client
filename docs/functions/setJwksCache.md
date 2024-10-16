# Function: setJwksCache()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **setJwksCache**(`config`, `jwksCache`): `void`

DANGER ZONE - Use of this function has security implications that must be
understood, assessed for applicability, and accepted before use. It is
critical that the JSON Web Key Set cache only be writable by your own code.

This option is intended for cloud computing runtimes that cannot keep an in
memory cache between their code's invocations. Use in runtimes where an in
memory cache between requests is available is not desirable.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `config` | [`Configuration`](../classes/Configuration.md) | - |
| `jwksCache` | [`ExportedJWKSCache`](../interfaces/ExportedJWKSCache.md) | JWKS Cache previously obtained from [getJwksCache](getJwksCache.md) |

## Returns

`void`

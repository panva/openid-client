# Function: getJwksCache()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **getJwksCache**(`config`): `undefined` \| [`ExportedJWKSCache`](../interfaces/ExportedJWKSCache.md)

This function can be used to export the JSON Web Key Set and the timestamp at
which it was last fetched if the client used the
[authorization server's JWK Set](../interfaces/ServerMetadata.md#jwks_uri) to validate
digital signatures.

This function is intended for cloud computing runtimes that cannot keep an in
memory cache between their code's invocations. Use in runtimes where an in
memory cache between requests is available is not desirable.

Note: the client only uses the authorization server's JWK Set when
[enableNonRepudiationChecks](enableNonRepudiationChecks.md), [useJwtResponseMode](useJwtResponseMode.md),
[useCodeIdTokenResponseType](useCodeIdTokenResponseType.md), or [useIdTokenResponseType](useIdTokenResponseType.md) is used.

## Parameters

| Parameter | Type |
| ------ | ------ |
| `config` | [`Configuration`](../classes/Configuration.md) |

## Returns

`undefined` \| [`ExportedJWKSCache`](../interfaces/ExportedJWKSCache.md)

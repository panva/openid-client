# Function: useIdTokenResponseType()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **useIdTokenResponseType**(`config`): `void`

This changes the `response_type` used by the client to be `id_token`, this
subsequently requires that the authorization server response be passed to
[implicitAuthentication](implicitAuthentication.md) (instead of [authorizationCodeGrant](authorizationCodeGrant.md)) and
for it to be one described by
[OpenID Connect 1.0 Implicit Flow](https://openid.net/specs/openid-connect-core-1_0-errata2.html#ImplicitFlowAuth).

Note:
[URL of the authorization server's JWK Set document](../interfaces/ServerMetadata.md#jwks_uri)
must be configured.

## Parameters

| Parameter | Type |
| ------ | ------ |
| `config` | [`Configuration`](../classes/Configuration.md) |

## Returns

`void`

## Examples

Usage with a [Configuration](../classes/Configuration.md) obtained through [discovery](discovery.md)

```ts
let server!: URL
let clientId!: string
let clientMetadata!: Partial<client.ClientMetadata> | undefined
let clientAuth = client.None()

let config = await client.discovery(
  server,
  clientId,
  clientMetadata,
  clientAuth,
  {
    execute: [client.useIdTokenResponseType],
  },
)
```

Usage with a [Configuration](../classes/Configuration.md) instance

```ts
let config!: client.Configuration

client.useIdTokenResponseType(config)
```

## See

[OpenID Connect 1.0 Hybrid Flow](https://openid.net/specs/openid-connect-core-1_0-errata2.html#HybridFlowAuth)

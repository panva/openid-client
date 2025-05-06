# Function: implicitAuthentication()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **implicitAuthentication**(`config`, `currentUrl`, `expectedNonce`, `checks`?): [`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`IDToken`](../interfaces/IDToken.md)\>

This method validates the authorization server's
[Implicit Authentication Flow](https://openid.net/specs/openid-connect-core-1_0-errata2.html#ImplicitFlowAuth)
Response.

Note:
[URL of the authorization server's JWK Set document](../interfaces/ServerMetadata.md#jwks_uri)
must be configured.

Note: Only `response_type=id_token` responses are supported and prior use of
[useIdTokenResponseType](useIdTokenResponseType.md) is required.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `config` | [`Configuration`](../classes/Configuration.md) | - |
| `currentUrl` | [`URL`](https://developer.mozilla.org/docs/Web/API/URL) \| [`Request`](https://developer.mozilla.org/docs/Web/API/Request) | Current [URL](https://developer.mozilla.org/docs/Web/API/URL) the Authorization Server provided an Authorization Response to or a [Request](https://developer.mozilla.org/docs/Web/API/Request), the [Authentication Response Parameters](https://openid.net/specs/openid-connect-core-1_0-errata2.html#ImplicitAuthResponse) are extracted from this. |
| `expectedNonce` | `string` | Expected value of the `nonce` ID Token claim. This value must match exactly. |
| `checks`? | [`ImplicitAuthenticationResponseChecks`](../interfaces/ImplicitAuthenticationResponseChecks.md) | Additional optional Implicit Authentication Response checks |

## Returns

[`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`IDToken`](../interfaces/IDToken.md)\>

ID Token Claims Set

## Examples

Using an incoming [Request](https://developer.mozilla.org/docs/Web/API/Request) instance

```ts
let config!: client.Configuration
let expectedNonce!: string
let request!: Request

let idTokenClaims = await client.implicitAuthentication(
  config,
  request,
  expectedNonce,
)
```

When using a `form_post` response mode without a [Request](https://developer.mozilla.org/docs/Web/API/Request) instance

```ts
let config!: client.Configuration
let expectedNonce!: string
let getCurrentUrl!: (...args: any) => URL
let getBody!: (...args: any) => Record<string, string>

let url = getCurrentUrl()
url.hash = new URLSearchParams(getBody()).toString()

let idTokenClaims = await client.implicitAuthentication(
  config,
  url,
  expectedNonce,
)
```

In a browser environment

```ts
let config!: client.Configuration
let getCodeVerifierFromSession!: (...args: any) => string
let getCurrentUrl!: (...args: any) => URL

let tokens = await client.authorizationCodeGrant(
  config,
  new URL(location.href),
  {
    pkceCodeVerifier: getCodeVerifierFromSession(),
  },
)
```

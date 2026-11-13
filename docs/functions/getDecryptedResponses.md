# Function: getDecryptedResponses()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

## Call Signature

▸ **getDecryptedResponses**\<`S`\>(`result`): `S` \| `undefined`

Returns the inner compact JWS values decrypted from a successfully processed
response.

[enableDecryptingResponses](enableDecryptingResponses.md) must have been enabled when the response was
processed. Only JWTs decrypted from a JWE are retained. Unencrypted responses
do not contribute any values.

For [authorizationCodeGrant](authorizationCodeGrant.md), returns a
[DecryptedAuthorizationCodeResponses](../interfaces/DecryptedAuthorizationCodeResponses.md) record covering both the
authorization response and any token endpoint ID Token.
[refreshTokenGrant](refreshTokenGrant.md), [genericGrantRequest](genericGrantRequest.md),
[pollDeviceAuthorizationGrant](pollDeviceAuthorizationGrant.md),
[pollBackchannelAuthenticationGrant](pollBackchannelAuthenticationGrant.md), [implicitAuthentication](implicitAuthentication.md),
[fetchUserInfo](fetchUserInfo.md), and [tokenIntrospection](tokenIntrospection.md) return a single compact
JWS. Returns `undefined` whenever no JWT was decrypted, including
authorization code grants.

Returns `undefined` if decryption support was not enabled or the argument is
not the original result object. Retrieving a JWS does not enable signature
verification beyond the checks already configured for the operation.

### Type Parameters

| Type Parameter |
| ------ |
| <a id="type-parameter-s"></a> `S` *extends* `string` \| [`DecryptedAuthorizationCodeResponses`](../interfaces/DecryptedAuthorizationCodeResponses.md) |

### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `result` | `object` | Original result returned by a response-processing operation. |

### Returns

`S` \| `undefined`

### Examples

```ts
let config!: client.Configuration
let key!: client.CryptoKey
let currentUrl!: URL

client.enableDecryptingResponses(config, undefined, key)

let tokens = await client.authorizationCodeGrant(config, currentUrl)
let signed = client.getDecryptedResponses(tokens)
signed?.id_token?.token_endpoint
signed?.id_token?.authorization_endpoint
signed?.authorization_response
```

```ts
let config!: client.Configuration
let key!: client.CryptoKey
let accessToken!: string
let subject!: string

client.enableDecryptingResponses(config, undefined, key)

let userInfo = await client.fetchUserInfo(config, accessToken, subject)
let signed: string | undefined = client.getDecryptedResponses(userInfo)
```

## Call Signature

▸ **getDecryptedResponses**(`result`): `string` \| [`DecryptedAuthorizationCodeResponses`](../interfaces/DecryptedAuthorizationCodeResponses.md) \| `undefined`

### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `result` | [`TokenEndpointResponse`](../interfaces/TokenEndpointResponse.md) \| [`IDToken`](../interfaces/IDToken.md) \| [`UserInfoResponse`](../interfaces/UserInfoResponse.md) \| [`IntrospectionResponse`](../interfaces/IntrospectionResponse.md) | Original result returned by a response-processing operation. |

### Returns

`string` \| [`DecryptedAuthorizationCodeResponses`](../interfaces/DecryptedAuthorizationCodeResponses.md) \| `undefined`

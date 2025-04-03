# Function: pollBackchannelAuthenticationGrant()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **pollBackchannelAuthenticationGrant**(`config`, `backchannelAuthenticationResponse`, `parameters`?, `options`?): [`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`TokenEndpointResponse`](../interfaces/TokenEndpointResponse.md) & [`TokenEndpointResponseHelpers`](../interfaces/TokenEndpointResponseHelpers.md)\>

Continuously polls the [token endpoint](../interfaces/ServerMetadata.md#token_endpoint)
until the end-user finishes the
[Client-Initiated Backchannel Authentication Grant](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html) process

Note:
[URL of the authorization server's token endpoint](../interfaces/ServerMetadata.md#token_endpoint)
must be configured.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `config` | [`Configuration`](../classes/Configuration.md) | - |
| `backchannelAuthenticationResponse` | [`BackchannelAuthenticationResponse`](../interfaces/BackchannelAuthenticationResponse.md) | Backchannel Authentication Response obtained from [initiateBackchannelAuthentication](initiateBackchannelAuthentication.md) |
| `parameters`? | [`Record`](https://www.typescriptlang.org/docs/handbook/utility-types.html#recordkeys-type)\<`string`, `string`\> \| [`URLSearchParams`](https://developer.mozilla.org/docs/Web/API/URLSearchParams) | Additional parameters that will be sent to the token endpoint, typically used for parameters such as `scope` and a `resource` ([Resource Indicator](https://www.rfc-editor.org/rfc/rfc8707)) |
| `options`? | [`BackchannelAuthenticationGrantPollOptions`](../interfaces/BackchannelAuthenticationGrantPollOptions.md) | - |

## Returns

[`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`TokenEndpointResponse`](../interfaces/TokenEndpointResponse.md) & [`TokenEndpointResponseHelpers`](../interfaces/TokenEndpointResponseHelpers.md)\>

## Example

```ts
let config!: client.Configuration
let scope!: string
let login_hint!: string // one of login_hint, id_token_hint, or login_hint_token parameters must be provided in CIBA

let backchannelAuthenticationResponse =
  await client.initiateBackchannelAuthentication(config, {
    scope,
    login_hint,
  })

// OPTIONAL: If your client is configured with Ping Mode you'd invoke the following after getting the CIBA Ping Callback (its implementation is framework specific and therefore out of scope for openid-client)

let { auth_req_id } = backchannelAuthenticationResponse

let tokenEndpointResponse =
  await client.pollBackchannelAuthenticationGrant(
    config,
    backchannelAuthenticationResponse,
  )
```

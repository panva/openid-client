# Function: initiateBackchannelAuthentication()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **initiateBackchannelAuthentication**(`config`, `parameters`): [`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`BackchannelAuthenticationResponse`](../interfaces/BackchannelAuthenticationResponse.md)\>

Initiates a [Client-Initiated Backchannel Authentication Grant](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html) using
parameters from the `parameters` argument.

Note:
[URL of the authorization server's backchannel authentication endpoint](../interfaces/ServerMetadata.md#backchannel_authentication_endpoint)
must be configured.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `config` | [`Configuration`](../classes/Configuration.md) | - |
| `parameters` | [`Record`](https://www.typescriptlang.org/docs/handbook/utility-types.html#recordkeys-type)\<`string`, `string`\> \| [`URLSearchParams`](https://developer.mozilla.org/docs/Web/API/URLSearchParams) | Authorization request parameters that will be sent to the backchannel authentication endpoint |

## Returns

[`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`BackchannelAuthenticationResponse`](../interfaces/BackchannelAuthenticationResponse.md)\>

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

let { auth_req_id } = backchannelAuthenticationResponse
```

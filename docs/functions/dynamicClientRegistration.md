# Function: dynamicClientRegistration()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **dynamicClientRegistration**(`server`, `metadata`, `clientAuthentication`?, `options`?): [`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`Configuration`](../classes/Configuration.md)\>

Performs Authorization Server Metadata discovery and subsequently a Dynamic
Client Registration at the discovered Authorization Server's
[ServerMetadata.registration\_endpoint](../interfaces/ServerMetadata.md#registration_endpoint) using the provided client
metadata.

Note: This method also accepts a URL pointing directly to the Authorization
Server's discovery document. Doing so is NOT RECOMMENDED as it disables the
[ServerMetadata.issuer](../interfaces/ServerMetadata.md#issuer) validation.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `server` | [`URL`](https://developer.mozilla.org/docs/Web/API/URL) | URL representation of the Authorization Server's Issuer Identifier |
| `metadata` | [`Partial`](https://www.typescriptlang.org/docs/handbook/utility-types.html#partialtype)\<[`ClientMetadata`](../interfaces/ClientMetadata.md)\> | Client Metadata to register at the Authorization Server |
| `clientAuthentication`? | [`ClientAuth`](../type-aliases/ClientAuth.md) | Implementation of the Client's Authentication Method at the Authorization Server. Default is [ClientSecretPost](ClientSecretPost.md) using the [ClientMetadata.client\_secret](../interfaces/ClientMetadata.md#client_secret) that the Authorization Server issued. |
| `options`? | [`DynamicClientRegistrationRequestOptions`](../interfaces/DynamicClientRegistrationRequestOptions.md) |  |

## Returns

[`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`Configuration`](../classes/Configuration.md)\>

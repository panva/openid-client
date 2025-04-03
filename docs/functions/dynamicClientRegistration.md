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

Note: The method does not contain any logic to default the registered
"token_endpoint_auth_method" based on
[ServerMetadata.token\_endpoint\_auth\_methods\_supported](../interfaces/ServerMetadata.md#token_endpoint_auth_methods_supported), nor does it
default the "clientAuthentication" argument value beyond what its description
says.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `server` | [`URL`](https://developer.mozilla.org/docs/Web/API/URL) | URL representation of the Authorization Server's Issuer Identifier |
| `metadata` | [`Partial`](https://www.typescriptlang.org/docs/handbook/utility-types.html#partialtype)\<[`ClientMetadata`](../interfaces/ClientMetadata.md)\> | Client Metadata to register at the Authorization Server |
| `clientAuthentication`? | [`ClientAuth`](../type-aliases/ClientAuth.md) | Implementation of the Client's Authentication Method at the Authorization Server. Default is [ClientSecretPost](ClientSecretPost.md) using the [ClientMetadata.client\_secret](../interfaces/ClientMetadata.md#client_secret) that the Authorization Server issued, [None](None.md) otherwise. |
| `options`? | [`DynamicClientRegistrationRequestOptions`](../interfaces/DynamicClientRegistrationRequestOptions.md) |  |

## Returns

[`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`Configuration`](../classes/Configuration.md)\>

## See

 - [RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol (DCR)](https://www.rfc-editor.org/rfc/rfc7591.html)
 - [OpenID Connect Dynamic Client Registration 1.0 (DCR)](https://openid.net/specs/openid-connect-registration-1_0-errata2.html)
 - [RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html#name-protected-resource-access)

# Function: discovery()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **discovery**(`server`, `clientId`, `metadata`?, `clientAuthentication`?, `options`?): [`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`Configuration`](../classes/Configuration.md)\>

Performs Authorization Server Metadata discovery and returns a
[Configuration](../classes/Configuration.md) with the discovered
[Authorization Server](../interfaces/ServerMetadata.md) metadata.

Passing the Authorization Server's Issuer Identifier to this method is the
RECOMMENDED method of client configuration.

This has the same effect as calling the [Configuration](../classes/Configuration.md) constructor
except that the server metadata is discovered from its own Authorization
Server Metadata discovery document.

Note: This method also accepts a URL pointing directly to the Authorization
Server's discovery document, doing so is merely a shorthand for using
[fetch](https://developer.mozilla.org/docs/Web/API/Window/fetch) and passing the discovered JSON metadata (as
[ServerMetadata](../interfaces/ServerMetadata.md)) into the [Configuration](../classes/Configuration.md) constructor. Doing so is
NOT RECOMMENDED as it disables the [ServerMetadata.issuer](../interfaces/ServerMetadata.md#issuer) validation.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `server` | [`URL`](https://developer.mozilla.org/docs/Web/API/URL) | URL representation of the Authorization Server's Issuer Identifier |
| `clientId` | `string` | Client Identifier at the Authorization Server |
| `metadata`? | `string` \| [`Partial`](https://www.typescriptlang.org/docs/handbook/utility-types.html#partialtype)\<[`ClientMetadata`](../interfaces/ClientMetadata.md)\> | Client Metadata, when a string is passed it is a shorthand for passing just [ClientMetadata.client\_secret](../interfaces/ClientMetadata.md#client_secret) |
| `clientAuthentication`? | [`ClientAuth`](../type-aliases/ClientAuth.md) | Implementation of the Client's Authentication Method at the Authorization Server. Default is [ClientSecretPost](ClientSecretPost.md) using the [ClientMetadata.client\_secret](../interfaces/ClientMetadata.md#client_secret). |
| `options`? | [`DiscoveryRequestOptions`](../interfaces/DiscoveryRequestOptions.md) |  |

## Returns

[`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<[`Configuration`](../classes/Configuration.md)\>

# Interface: BackchannelAuthenticationResponse

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

## Indexable

\[`parameter`: `string`\]: `undefined` \| [`JsonValue`](../type-aliases/JsonValue.md)

## Properties

### auth\_req\_id

• `readonly` **auth\_req\_id**: `string`

Unique identifier to identify the authentication request.

***

### expires\_in

• `readonly` **expires\_in**: `number`

The lifetime in seconds of the "auth_req_id".

***

### interval?

• `readonly` `optional` **interval**: `number`

The minimum amount of time in seconds that the client should wait between polling requests to
the token endpoint.

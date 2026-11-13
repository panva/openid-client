# Interface: DecryptedAuthorizationCodeResponses

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

Inner compact JWS values decrypted by [authorizationCodeGrant](../functions/authorizationCodeGrant.md).

## Properties

### authorization\_response?

• `readonly` `optional` **authorization\_response?**: `string`

Inner signed JWT Secured Authorization Response Mode (JARM) response.

***

### id\_token?

• `readonly` `optional` **id\_token?**: `object`

Inner signed ID Tokens decrypted from Token and Authorization Endpoint
responses.

#### authorization\_endpoint?

• `readonly` `optional` **authorization\_endpoint?**: `string`

Inner signed ID Token decrypted from a hybrid or FAPI 1.0 Advanced
detached-signature authorization response.

#### token\_endpoint?

• `readonly` `optional` **token\_endpoint?**: `string`

Inner signed ID Token decrypted from the Token Endpoint response.

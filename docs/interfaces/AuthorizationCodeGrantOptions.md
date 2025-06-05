# Interface: AuthorizationCodeGrantOptions

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

## Properties

### cutUri?

• `optional` **cutUri**: `boolean`

cutUri will cut URI search params and last slash, before passing it on token endpoint.

***

### DPoP?

• `optional` **DPoP**: [`DPoPHandle`](DPoPHandle.md)

DPoP handle to use for requesting a sender-constrained access token.
Usually obtained from [getDPoPHandle](../functions/getDPoPHandle.md)

#### See

[RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)

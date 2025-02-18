# Interface: DPoPHandle

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

DPoP handle to use for requesting a sender-constrained access token. Obtained
from [getDPoPHandle](../functions/getDPoPHandle.md)

## See

[RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)

## Methods

### calculateThumbprint()

▸ **calculateThumbprint**(): [`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<`string`\>

Calculates the JWK Thumbprint of the DPoP public key using the SHA-256 hash function for use as
the optional `dpop_jkt` authorization request parameter.

#### Returns

[`Promise`](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)\<`string`\>

#### See

[RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html#name-authorization-code-binding-)

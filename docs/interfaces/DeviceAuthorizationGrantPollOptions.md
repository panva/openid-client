# Interface: DeviceAuthorizationGrantPollOptions

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

## Properties

### DPoP?

• `optional` **DPoP**: [`DPoPHandle`](DPoPHandle.md)

DPoP handle to use for requesting a sender-constrained access token.
Obtained from [getDPoPHandle](../functions/getDPoPHandle.md)

#### See

[RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)

***

### signal?

• `optional` **signal**: [`AbortSignal`](https://developer.mozilla.org/docs/Web/API/AbortSignal)

AbortSignal to abort polling. Default is that the operation will time out
after the indicated expires_in property returned by the server in
[initiateDeviceAuthorization](../functions/initiateDeviceAuthorization.md)

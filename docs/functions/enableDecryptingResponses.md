# Function: enableDecryptingResponses()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **enableDecryptingResponses**(`config`, `contentEncryptionAlgorithms`, ...`keys`): `void`

Enables the client to process encrypted ID Tokens, encrypted JWT UserInfo
responses, and encrypted JWT Introspection responses. Multiple private keys
may be provided for the decryption key selection process but only a single
one must match the process.

The following JWE Key Management Algorithms are supported

- ECDH-ES
- ECDH-ES+A128KW
- ECDH-ES+A192KW
- ECDH-ES+A256KW
- RSA-OAEP
- RSA-OAEP-256
- RSA-OAEP-384
- RSA-OAEP-512

Note: ECDH algorithms only allow P-256 or X25519 key curve to be used

The following JWE Content Encryption Algorithms are supported

- A128GCM
- A192GCM
- A256GCM
- A128CBC-HS256
- A192CBC-HS384
- A256CBC-HS512

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `config` | [`Configuration`](../classes/Configuration.md) | - |
| `contentEncryptionAlgorithms` | `string`[] | An allow list for JWE Content Encryption Algorithms identifiers |
| ...`keys` | ([`CryptoKey`](https://developer.mozilla.org/docs/Web/API/CryptoKey) \| [`DecryptionKey`](../interfaces/DecryptionKey.md))[] | Keys to enable decrypting assertions with |

## Returns

`void`

## Example

```ts
let key!: client.CryptoKey | client.DecryptionKey
let config!: client.Configuration

client.enableDecryptingResponses(config, ['A128CBC-HS256'], key)
```

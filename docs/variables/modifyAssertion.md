# Variable: modifyAssertion

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

• `const` **modifyAssertion**: *typeof* `oauth.modifyAssertion` = `oauth.modifyAssertion`

Use to mutate JWT header and payload before they are signed. Its intended use
is working around non-conform server behaviours, such as modifying JWT "aud"
(audience) claims, or otherwise changing fixed claims used by this library.

## Example

Changing the `alg: "Ed25519"` back to `alg: "EdDSA"`

```ts
let key!: client.CryptoKey | client.PrivateKey
let config!: client.Configuration
let parameters!: URLSearchParams
let keyPair!: client.CryptoKeyPair

let remapEd25519: client.ModifyAssertionOptions = {
  [client.modifyAssertion]: (header) => {
    if (header.alg === 'Ed25519') {
      header.alg = 'EdDSA'
    }
  },
}

// For JAR
client.buildAuthorizationUrlWithJAR(
  config,
  parameters,
  key,
  remapEd25519,
)

// For Private Key JWT
client.PrivateKeyJwt(key, remapEd25519)

// For DPoP
client.getDPoPHandle(config, keyPair, remapEd25519)
```

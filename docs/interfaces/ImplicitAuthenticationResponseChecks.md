# Interface: ImplicitAuthenticationResponseChecks

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

## Properties

### expectedState?

• `optional` **expectedState**: `string` \| *typeof* `skipStateCheck`

Expected value of the `state` authorization response parameter. This value
must match exactly. When `undefined` the expectation is that there is no
`state` in the authorization response.

***

### maxAge?

• `optional` **maxAge**: `number`

ID Token [\`auth\_time\`](IDToken.md#auth_time) claim value will be checked
to be present and conform to this `maxAge` value. Use of this option is
required if you sent a `max_age` parameter in the authorization request.
Default is [ClientMetadata.default\_max\_age](ClientMetadata.md#default_max_age) and falls back to not
checking the claim's value beyond it being a number when present.

# Interface: WWWAuthenticateChallengeParameters

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

WWW-Authenticate challenge auth-param dictionary with known and unknown parameter names

## Indexable

\[`parameter`: [`Lowercase`](https://www.typescriptlang.org/docs/handbook/2/template-literal-types.html#lowercasestringtype)\<`string`\>\]: `undefined` \| `string`

## Properties

### algs?

• `readonly` `optional` **algs**: `string`

A space-delimited list of supported algorithms, used in
[RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)
challenges

***

### error?

• `readonly` `optional` **error**: `string`

A machine-readable error code value

***

### error\_description?

• `readonly` `optional` **error\_description**: `string`

Human-readable ASCII text providing additional information, used to assist the client developer
in understanding the error that occurred

***

### error\_uri?

• `readonly` `optional` **error\_uri**: `string`

A URI identifying a human-readable web page with information about the error, used to provide
the client developer with additional information about the error

***

### realm?

• `readonly` `optional` **realm**: `string`

Identifies the protection space

***

### resource\_metadata?

• `readonly` `optional` **resource\_metadata**: `string`

The URL of the protected resource metadata

***

### scope?

• `readonly` `optional` **scope**: `string`

The scope necessary to access the protected resource, used with `insufficient_scope` error code

# Interface: WWWAuthenticateChallenge

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

Parsed WWW-Authenticate challenge

## Properties

### parameters

• `readonly` **parameters**: [`WWWAuthenticateChallengeParameters`](WWWAuthenticateChallengeParameters.md)

Parsed WWW-Authenticate challenge auth-param dictionary (always present but will be empty when
[token68](WWWAuthenticateChallenge.md#token68) is present)

***

### scheme

• `readonly` **scheme**: [`Lowercase`](https://www.typescriptlang.org/docs/handbook/2/template-literal-types.html#lowercasestringtype)\<`string`\>

Parsed WWW-Authenticate challenge auth-scheme

NOTE: because the value is case insensitive it is always returned lowercased

***

### token68?

• `readonly` `optional` **token68**: `string`

Parsed WWW-Authenticate challenge token68

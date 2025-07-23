# Type Alias: RecognizedTokenTypes

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

• **RecognizedTokenTypes**: [`Record`](https://www.typescriptlang.org/docs/handbook/utility-types.html#recordkeys-type)\<[`Lowercase`](https://www.typescriptlang.org/docs/handbook/2/template-literal-types.html#lowercasestringtype)\<`string`\>, (`res`, `body`) => `void`\>

A record of custom token type handlers for processing non-standard token types in OAuth 2.0 token
endpoint responses.

This allows extending the library to support non-standard token types returned by the
authorization server's token endpoint with optional specific processing.

By default, this library recognizes and handles `bearer` and `dpop` token types. When a token
endpoint response contains a different `token_type` value, you can provide custom handlers to
process these tokens appropriately. Token types other than `bearer`, `dpop`, and ones represented
in this record will be rejected as per https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1

## Examples

Allow a custom `mac` token type

```ts
let recognizedTokenTypes: oauth.RecognizedTokenTypes = {
  mac: () => {},
}
```

Allow a custom `mac` token type with additional constraints put on the token endpoint JSON
response

```ts
let recognizedTokenTypes: oauth.RecognizedTokenTypes = {
  mac: (response: Response, tokenResponse: oauth.TokenEndpointResponse) => {
    if (typeof tokenResponse.id !== 'string') {
      throw new oauth.UnsupportedOperationError('invalid "mac" token_type', {
        cause: { body: tokenResponse },
      })
    }
  },
}
```

> [!NOTE]\
> Token type names are case insensitive and will be normalized to lowercase before lookup.

## See

[RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1)

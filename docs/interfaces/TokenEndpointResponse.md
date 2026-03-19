# Interface: TokenEndpointResponse

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

## Indexable

> \[`parameter`: `string`\]: [`JsonValue`](../type-aliases/JsonValue.md) \| `undefined`

## Properties

### access\_token

• `readonly` **access\_token**: `string`

***

### token\_type

• `readonly` **token\_type**: [`Lowercase`](https://www.typescriptlang.org/docs/handbook/2/template-literal-types.html#lowercasestringtype)\<`string`\>

> [!NOTE]\
> Because the value is case insensitive it is always returned lowercased

***

### authorization\_details?

• `readonly` `optional` **authorization\_details?**: [`AuthorizationDetails`](AuthorizationDetails.md)[]

***

### expires\_in?

• `readonly` `optional` **expires\_in?**: `number`

***

### id\_token?

• `readonly` `optional` **id\_token?**: `string`

***

### refresh\_token?

• `readonly` `optional` **refresh\_token?**: `string`

***

### scope?

• `readonly` `optional` **scope?**: `string`

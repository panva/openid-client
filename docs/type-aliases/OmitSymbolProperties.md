# Type Alias: OmitSymbolProperties\<T\>

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

• **OmitSymbolProperties**\<`T`\> = `{ [K in keyof T as K extends symbol ? never : K]: T[K] }`

Removes symbol-keyed properties from a type.

## Type Parameters

| Type Parameter |
| ------ |
| `T` |

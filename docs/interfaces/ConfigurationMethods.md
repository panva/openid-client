# Interface: ConfigurationMethods

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

Public methods available on a [Configuration](../classes/Configuration.md) instance

## Methods

### clientMetadata()

▸ **clientMetadata**(): [`Readonly`](https://www.typescriptlang.org/docs/handbook/utility-types.html#readonlytype)\<[`OmitSymbolProperties`](../type-aliases/OmitSymbolProperties.md)\<[`ClientMetadata`](ClientMetadata.md)\>\>

Used to retrieve the Client Metadata

#### Returns

[`Readonly`](https://www.typescriptlang.org/docs/handbook/utility-types.html#readonlytype)\<[`OmitSymbolProperties`](../type-aliases/OmitSymbolProperties.md)\<[`ClientMetadata`](ClientMetadata.md)\>\>

***

### serverMetadata()

▸ **serverMetadata**(): [`Readonly`](https://www.typescriptlang.org/docs/handbook/utility-types.html#readonlytype)\<[`ServerMetadata`](ServerMetadata.md)\> & [`ServerMetadataHelpers`](ServerMetadataHelpers.md)

Used to retrieve the Authorization Server Metadata

#### Returns

[`Readonly`](https://www.typescriptlang.org/docs/handbook/utility-types.html#readonlytype)\<[`ServerMetadata`](ServerMetadata.md)\> & [`ServerMetadataHelpers`](ServerMetadataHelpers.md)

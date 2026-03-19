# Class: ResponseBodyError

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

Throw when a server responds with an "OAuth-style" error JSON body

## Example

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "error": "invalid_request"
}
```

## Properties

### cause

• **cause**: [`Record`](https://www.typescriptlang.org/docs/handbook/utility-types.html#recordkeys-type)\<`string`, [`JsonValue`](../type-aliases/JsonValue.md) \| `undefined`\>

The parsed JSON response body

***

### code

• **code**: `"OAUTH_RESPONSE_BODY_ERROR"`

***

### error

• **error**: `string`

Error code given in the JSON response

***

### message

• **message**: `string`

***

### name

• **name**: `string`

***

### response

• **response**: [`Response`](https://developer.mozilla.org/docs/Web/API/Response)

The "OAuth-style" error [Response](https://developer.mozilla.org/docs/Web/API/Response), its [Response.bodyUsed](https://developer.mozilla.org/docs/Web/API/Response/bodyUsed) is `true` and the JSON
body is available in [ResponseBodyError.cause](#cause)

***

### status

• **status**: `number`

HTTP Status Code of the response

***

### error\_description?

• `optional` **error\_description?**: `string`

Human-readable text providing additional information, used to assist the developer in
understanding the error that occurred, given in the JSON response

***

### stack?

• `optional` **stack?**: `string`

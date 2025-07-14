# Function: AttestationAuth()

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

▸ **AttestationAuth**(`attestation`, `clientInstanceKey`, `options`?): [`ClientAuth`](../type-aliases/ClientAuth.md)

**`attest_jwt_client_auth`** uses the HTTP request body to send only
`client_id` as `application/x-www-form-urlencoded` body parameter,
`OAuth-Client-Attestation` HTTP Header field to transmit a Client Attestation
JWT issued to the client instance by its Client Attester, and
`OAuth-Client-Attestation-PoP` HTTP Header field to transmit a Proof of
Possession (PoP) of its Client Instance Key.

This implementation will fetch the [ServerMetadata.challenge\_endpoint](../interfaces/ServerMetadata.md#challenge_endpoint)
(if one is available) once to fetch an initial `challenge` claim value before
the authenticated request is made. Afterwards it will keep track of the
latest `challenge` based on the response's
`OAuth-Client-Attestation-Challenge` HTTP Header (if one was returned).

It will also retry the request once when the `use_attestation_challenge`
error is encountered.

> [!NOTE]\
> This is an experimental feature not subject to semantic versioning
> guarantees.

## Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `attestation` | `string` | Client Attestation JWT issued to the client instance by its Client Attester. |
| `clientInstanceKey` | [`CryptoKey`](https://developer.mozilla.org/docs/Web/API/CryptoKey) | Client Instance Key |
| `options`? | [`ModifyAssertionOptions`](../interfaces/ModifyAssertionOptions.md) |  |

## Returns

[`ClientAuth`](../type-aliases/ClientAuth.md)

## Examples

Usage with a [Configuration](../classes/Configuration.md) obtained through [discovery](discovery.md)

```ts
let server!: URL
let attestation!: string
let clientInstanceKey!: client.CryptoKey
let clientId!: string
let clientMetadata!: Partial<client.ClientMetadata> | string | undefined

let config = await client.discovery(
  server,
  clientId,
  clientMetadata,
  client.AttestationAuth(attestation, clientInstanceKey),
)
```

Usage with a [Configuration](../classes/Configuration.md) instance

```ts
let server!: client.ServerMetadata
let attestation!: string
let clientInstanceKey!: client.CryptoKey
let clientId!: string
let clientMetadata!: Partial<client.ClientMetadata> | string | undefined

let config = new client.Configuration(
  server,
  clientId,
  clientMetadata,
  client.AttestationAuth(attestation, clientInstanceKey),
)
```

## See

 - [OAuth Token Endpoint Authentication Methods](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method)
 - [draft-ietf-oauth-attestation-based-client-auth-06 - OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-06.html)

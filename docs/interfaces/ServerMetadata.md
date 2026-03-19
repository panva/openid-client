# Interface: ServerMetadata

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

Authorization Server Metadata

## See

[IANA OAuth Authorization Server Metadata registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#authorization-server-metadata)

## Indexable

> \[`metadata`: `string`\]: [`JsonValue`](../type-aliases/JsonValue.md) \| `undefined`

## Properties

### issuer

• `readonly` **issuer**: `string`

Authorization server's Issuer Identifier URL.

***

### acr\_values\_supported?

• `readonly` `optional` **acr\_values\_supported?**: `string`[]

JSON array containing a list of the Authentication Context Class References that this
authorization server supports.

***

### authorization\_encryption\_alg\_values\_supported?

• `readonly` `optional` **authorization\_encryption\_alg\_values\_supported?**: `string`[]

JSON array containing a list of algorithms supported by the authorization server for
introspection response encryption (`alg` value).

***

### authorization\_encryption\_enc\_values\_supported?

• `readonly` `optional` **authorization\_encryption\_enc\_values\_supported?**: `string`[]

JSON array containing a list of algorithms supported by the authorization server for
introspection response encryption (`enc` value).

***

### authorization\_endpoint?

• `readonly` `optional` **authorization\_endpoint?**: `string`

URL of the authorization server's authorization endpoint.

***

### authorization\_response\_iss\_parameter\_supported?

• `readonly` `optional` **authorization\_response\_iss\_parameter\_supported?**: `boolean`

Boolean value indicating whether the authorization server provides the `iss` parameter in the
authorization response.

***

### authorization\_signing\_alg\_values\_supported?

• `readonly` `optional` **authorization\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of algorithms supported by the authorization server for
introspection response signing.

***

### backchannel\_authentication\_endpoint?

• `readonly` `optional` **backchannel\_authentication\_endpoint?**: `string`

CIBA Backchannel Authentication Endpoint.

***

### backchannel\_authentication\_request\_signing\_alg\_values\_supported?

• `readonly` `optional` **backchannel\_authentication\_request\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWS signing algorithms supported for validation of signed
CIBA authentication requests.

***

### backchannel\_logout\_session\_supported?

• `readonly` `optional` **backchannel\_logout\_session\_supported?**: `boolean`

Boolean value specifying whether the authorization server can pass a `sid` (session ID) Claim
in the Logout Token to identify the RP session with the OP.

***

### backchannel\_logout\_supported?

• `readonly` `optional` **backchannel\_logout\_supported?**: `boolean`

Boolean value specifying whether the authorization server supports back-channel logout.

***

### backchannel\_token\_delivery\_modes\_supported?

• `readonly` `optional` **backchannel\_token\_delivery\_modes\_supported?**: `string`[]

Supported CIBA authentication result delivery modes.

***

### backchannel\_user\_code\_parameter\_supported?

• `readonly` `optional` **backchannel\_user\_code\_parameter\_supported?**: `boolean`

Indicates whether the authorization server supports the use of the CIBA `user_code` parameter.

***

### check\_session\_iframe?

• `readonly` `optional` **check\_session\_iframe?**: `string`

URL of an authorization server iframe that supports cross-origin communications for session
state information with the RP Client, using the HTML5 postMessage API.

***

### claim\_types\_supported?

• `readonly` `optional` **claim\_types\_supported?**: `string`[]

JSON array containing a list of the Claim Types that the authorization server supports.

***

### claims\_locales\_supported?

• `readonly` `optional` **claims\_locales\_supported?**: `string`[]

Languages and scripts supported for values in Claims being returned, represented as a JSON
array of RFC 5646 language tag values.

***

### claims\_parameter\_supported?

• `readonly` `optional` **claims\_parameter\_supported?**: `boolean`

Boolean value specifying whether the authorization server supports use of the `claims`
parameter.

***

### claims\_supported?

• `readonly` `optional` **claims\_supported?**: `string`[]

JSON array containing a list of the Claim Names of the Claims that the authorization server MAY
be able to supply values for.

***

### code\_challenge\_methods\_supported?

• `readonly` `optional` **code\_challenge\_methods\_supported?**: `string`[]

PKCE code challenge methods supported by this authorization server.

***

### device\_authorization\_endpoint?

• `readonly` `optional` **device\_authorization\_endpoint?**: `string`

URL of the authorization server's device authorization endpoint.

***

### display\_values\_supported?

• `readonly` `optional` **display\_values\_supported?**: `string`[]

JSON array containing a list of the `display` parameter values that the authorization server
supports.

***

### dpop\_signing\_alg\_values\_supported?

• `readonly` `optional` **dpop\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWS algorithms supported for DPoP Proof JWTs.

***

### end\_session\_endpoint?

• `readonly` `optional` **end\_session\_endpoint?**: `string`

URL at the authorization server to which an RP can perform a redirect to request that the
End-User be logged out at the authorization server.

***

### frontchannel\_logout\_session\_supported?

• `readonly` `optional` **frontchannel\_logout\_session\_supported?**: `boolean`

Boolean value specifying whether the authorization server can pass `iss` (issuer) and `sid`
(session ID) query parameters to identify the RP session with the authorization server when the
`frontchannel_logout_uri` is used.

***

### frontchannel\_logout\_supported?

• `readonly` `optional` **frontchannel\_logout\_supported?**: `boolean`

Boolean value specifying whether the authorization server supports HTTP-based logout.

***

### grant\_types\_supported?

• `readonly` `optional` **grant\_types\_supported?**: `string`[]

JSON array containing a list of the `grant_type` values that this authorization server
supports.

***

### id\_token\_encryption\_alg\_values\_supported?

• `readonly` `optional` **id\_token\_encryption\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWE `alg` values supported by the authorization server for
the ID Token.

***

### id\_token\_encryption\_enc\_values\_supported?

• `readonly` `optional` **id\_token\_encryption\_enc\_values\_supported?**: `string`[]

JSON array containing a list of the JWE `enc` values supported by the authorization server for
the ID Token.

***

### id\_token\_signing\_alg\_values\_supported?

• `readonly` `optional` **id\_token\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWS `alg` values supported by the authorization server for
the ID Token.

***

### introspection\_encryption\_alg\_values\_supported?

• `readonly` `optional` **introspection\_encryption\_alg\_values\_supported?**: `string`[]

JSON array containing a list of algorithms supported by the authorization server for
introspection response content key encryption (`alg` value).

***

### introspection\_encryption\_enc\_values\_supported?

• `readonly` `optional` **introspection\_encryption\_enc\_values\_supported?**: `string`[]

JSON array containing a list of algorithms supported by the authorization server for
introspection response content encryption (`enc` value).

***

### introspection\_endpoint?

• `readonly` `optional` **introspection\_endpoint?**: `string`

URL of the authorization server's introspection endpoint.

***

### introspection\_endpoint\_auth\_methods\_supported?

• `readonly` `optional` **introspection\_endpoint\_auth\_methods\_supported?**: `string`[]

JSON array containing a list of client authentication methods supported by this introspection
endpoint.

***

### introspection\_endpoint\_auth\_signing\_alg\_values\_supported?

• `readonly` `optional` **introspection\_endpoint\_auth\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWS signing algorithms supported by the introspection
endpoint for the signature on the JWT used to authenticate the client at the introspection
endpoint.

***

### introspection\_signing\_alg\_values\_supported?

• `readonly` `optional` **introspection\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of algorithms supported by the authorization server for
introspection response signing.

***

### jwks\_uri?

• `readonly` `optional` **jwks\_uri?**: `string`

URL of the authorization server's JWK Set document.

***

### mtls\_endpoint\_aliases?

• `readonly` `optional` **mtls\_endpoint\_aliases?**: [`MTLSEndpointAliases`](MTLSEndpointAliases.md)

JSON object containing alternative authorization server endpoints, which a client intending to
do mutual TLS will use in preference to the conventional endpoints.

***

### op\_policy\_uri?

• `readonly` `optional` **op\_policy\_uri?**: `string`

URL that the authorization server provides to the person registering the client to read about
the authorization server's requirements on how the client can use the data provided by the
authorization server.

***

### op\_tos\_uri?

• `readonly` `optional` **op\_tos\_uri?**: `string`

URL that the authorization server provides to the person registering the client to read about
the authorization server's terms of service.

***

### protected\_resources?

• `readonly` `optional` **protected\_resources?**: `string`[]

JSON array containing a list of resource identifiers for OAuth protected resources.

***

### pushed\_authorization\_request\_endpoint?

• `readonly` `optional` **pushed\_authorization\_request\_endpoint?**: `string`

URL of the authorization server's pushed authorization request endpoint.

***

### registration\_endpoint?

• `readonly` `optional` **registration\_endpoint?**: `string`

URL of the authorization server's Dynamic Client Registration Endpoint.

***

### request\_object\_encryption\_alg\_values\_supported?

• `readonly` `optional` **request\_object\_encryption\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWE `alg` values supported by the authorization server for
Request Objects.

***

### request\_object\_encryption\_enc\_values\_supported?

• `readonly` `optional` **request\_object\_encryption\_enc\_values\_supported?**: `string`[]

JSON array containing a list of the JWE `enc` values supported by the authorization server for
Request Objects.

***

### request\_object\_signing\_alg\_values\_supported?

• `readonly` `optional` **request\_object\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWS `alg` values supported by the authorization server for
Request Objects.

***

### request\_parameter\_supported?

• `readonly` `optional` **request\_parameter\_supported?**: `boolean`

Boolean value specifying whether the authorization server supports use of the `request`
parameter.

***

### request\_uri\_parameter\_supported?

• `readonly` `optional` **request\_uri\_parameter\_supported?**: `boolean`

Boolean value specifying whether the authorization server supports use of the `request_uri`
parameter.

***

### require\_pushed\_authorization\_requests?

• `readonly` `optional` **require\_pushed\_authorization\_requests?**: `boolean`

Indicates whether the authorization server accepts authorization requests only via PAR.

***

### require\_request\_uri\_registration?

• `readonly` `optional` **require\_request\_uri\_registration?**: `boolean`

Boolean value specifying whether the authorization server requires any `request_uri` values
used to be pre-registered.

***

### require\_signed\_request\_object?

• `readonly` `optional` **require\_signed\_request\_object?**: `boolean`

Indicates where authorization request needs to be protected as Request Object and provided
through either `request` or `request_uri` parameter.

***

### response\_modes\_supported?

• `readonly` `optional` **response\_modes\_supported?**: `string`[]

JSON array containing a list of the `response_mode` values that this authorization server
supports.

***

### response\_types\_supported?

• `readonly` `optional` **response\_types\_supported?**: `string`[]

JSON array containing a list of the `response_type` values that this authorization server
supports.

***

### revocation\_endpoint?

• `readonly` `optional` **revocation\_endpoint?**: `string`

URL of the authorization server's revocation endpoint.

***

### revocation\_endpoint\_auth\_methods\_supported?

• `readonly` `optional` **revocation\_endpoint\_auth\_methods\_supported?**: `string`[]

JSON array containing a list of client authentication methods supported by this revocation
endpoint.

***

### revocation\_endpoint\_auth\_signing\_alg\_values\_supported?

• `readonly` `optional` **revocation\_endpoint\_auth\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWS signing algorithms supported by the revocation endpoint
for the signature on the JWT used to authenticate the client at the revocation endpoint.

***

### scopes\_supported?

• `readonly` `optional` **scopes\_supported?**: `string`[]

JSON array containing a list of the `scope` values that this authorization server supports.

***

### service\_documentation?

• `readonly` `optional` **service\_documentation?**: `string`

URL of a page containing human-readable information that developers might want or need to know
when using the authorization server.

***

### signed\_metadata?

• `readonly` `optional` **signed\_metadata?**: `string`

Signed JWT containing metadata values about the authorization server as claims.

***

### subject\_types\_supported?

• `readonly` `optional` **subject\_types\_supported?**: `string`[]

JSON array containing a list of the Subject Identifier types that this authorization server
supports.

***

### tls\_client\_certificate\_bound\_access\_tokens?

• `readonly` `optional` **tls\_client\_certificate\_bound\_access\_tokens?**: `boolean`

Indicates authorization server support for mutual-TLS client certificate-bound access tokens.

***

### token\_endpoint?

• `readonly` `optional` **token\_endpoint?**: `string`

URL of the authorization server's token endpoint.

***

### token\_endpoint\_auth\_methods\_supported?

• `readonly` `optional` **token\_endpoint\_auth\_methods\_supported?**: `string`[]

JSON array containing a list of client authentication methods supported by this token endpoint.

***

### token\_endpoint\_auth\_signing\_alg\_values\_supported?

• `readonly` `optional` **token\_endpoint\_auth\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWS signing algorithms supported by the token endpoint for
the signature on the JWT used to authenticate the client at the token endpoint.

***

### ui\_locales\_supported?

• `readonly` `optional` **ui\_locales\_supported?**: `string`[]

Languages and scripts supported for the user interface, represented as a JSON array of language
tag values from RFC 5646.

***

### userinfo\_encryption\_alg\_values\_supported?

• `readonly` `optional` **userinfo\_encryption\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWE `alg` values supported by the UserInfo Endpoint.

***

### userinfo\_encryption\_enc\_values\_supported?

• `readonly` `optional` **userinfo\_encryption\_enc\_values\_supported?**: `string`[]

JSON array containing a list of the JWE `enc` values supported by the UserInfo Endpoint.

***

### userinfo\_endpoint?

• `readonly` `optional` **userinfo\_endpoint?**: `string`

URL of the authorization server's UserInfo Endpoint.

***

### userinfo\_signing\_alg\_values\_supported?

• `readonly` `optional` **userinfo\_signing\_alg\_values\_supported?**: `string`[]

JSON array containing a list of the JWS `alg` values supported by the UserInfo Endpoint.

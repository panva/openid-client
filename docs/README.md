# openid-client API Documentation

**Table of Contents**

- [Issuer](#issuer)
- [Client](#client)
- [Customizing](#customizing)
- [TokenSet](#tokenset)
- [DeviceFlowHandle](#deviceflowhandle)
- [Strategy](#strategy)
- [generators](#generators)
- [errors](#errors)

## Sponsor

[<img height="65" align="left" src="https://cdn.auth0.com/blog/github-sponsorships/brand-evolution-logo-Auth0-horizontal-Indigo.png" alt="auth0-logo">][sponsor-auth0] If you want to quickly add OpenID Connect authentication to Node.js apps, feel free to check out Auth0's Node.js SDK and free plan. [Create an Auth0 account; it's free!][sponsor-auth0]<br><br>

## Support

If you or your business use openid-client, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree.

<br>

---

## Issuer

<!-- TOC Issuer START -->
- [Class: &lt;Issuer&gt;](#class-issuer)
  - [new Issuer(metadata)](#new-issuermetadata)
  - [issuer.Client](#issuerclient)
  - [issuer.FAPI1Client](#issuerfapi1client)
  - [issuer.metadata](#issuermetadata)
- [Issuer.discover(issuer)](#issuerdiscoverissuer)
- [Issuer.webfinger(input)](#issuerwebfingerinput)
<!-- TOC Issuer END -->

---

#### Class: `<Issuer>`

Encapsulates a discovered or instantiated OpenID Connect Issuer (Issuer), Identity Provider (IdP),
Authorization Server (AS) and its metadata.

```js
import { Issuer } from 'openid-client';
```

---

#### `new Issuer(metadata)`

Creates a new Issuer with the provided metadata

- `metadata`: `<Object>`
  - `issuer`: `<string>` Issuer identifier
  - `authorization_endpoint`: `<string>`
  - `token_endpoint`: `<string>`
  - `jwks_uri`: `<string>`
  - `userinfo_endpoint`: `<string>`
  - `revocation_endpoint`: `<string>`
  - `introspection_endpoint`: `<string>`
  - `end_session_endpoint`: `<string>`
  - `registration_endpoint`: `<string>`
  - `token_endpoint_auth_methods_supported`: `<string>`
  - `token_endpoint_auth_signing_alg_values_supported`: `<string>`
  - `introspection_endpoint_auth_methods_supported`: `<string>`
  - `introspection_endpoint_auth_signing_alg_values_supported`: `<string>`
  - `revocation_endpoint_auth_methods_supported`: `<string>`
  - `revocation_endpoint_auth_signing_alg_values_supported`: `<string>`
  - `request_object_signing_alg_values_supported`: `<string>`
  - `mtls_endpoint_aliases`: `<Object>`
    - `token_endpoint`: `<string>`
    - `userinfo_endpoint`: `<string>`
    - `revocation_endpoint`: `<string>`
    - `introspection_endpoint`: `<string>`
  - other metadata may be present but currently doesn't have any special handling
- Returns: `<Issuer>`

---

#### `issuer.Client`

Returns the `<Client>` class tied to this issuer.

- Returns: `<Client>`

---

#### `issuer.FAPI1Client`

Returns the `<FAPI1Client>` class tied to this issuer. `<FAPI1Client>` inherits from `<Client>` and
adds necessary [Financial-grade API Security Profile 1.0 - Part 2: Advanced][] behaviours:

- Returns: `<FAPI1Client>`

The behaviours are:
- `s_hash` presence and value checks in authorization endpoint response ID Tokens
- authorization endpoint response ID Tokens `iat` must not be too far in the past (fixed to be
  1 hour)
- Request Objects include `nbf` (with the same value as `iat`)

---

#### `issuer.metadata`

Returns metadata from the issuer's discovery document.

- Returns: `<Object>`

---

#### `Issuer.discover(issuer)`

Loads OpenID Connect 1.0 and/or OAuth 2.0 Authorization Server Metadata documents. When the
`issuer` argument contains '.well-known' only that document is loaded, otherwise performs both
openid-configuration and oauth-authorization-server requests.

**This is the recommended method of getting yourself an Issuer instance.**

- `issuer`: `<string>` Issuer Identifier or metadata URL
- Returns: `Promise<Issuer>`

---

#### `Issuer.webfinger(input)`

Performs [OpenID Provider Issuer Discovery][webfinger-discovery] based on End-User input.

- `input`: `<string>` EMAIL, URL, Hostname and Port, acct or syntax input
- Returns: `Promise<Issuer>`

---

## Client

<!-- TOC Client START -->
- [Class: &lt;Client&gt;](#class-client)
  - [new Client(metadata[, jwks[, options]])](#new-clientmetadata-jwks-options)
  - [client.authorizationUrl(parameters)](#clientauthorizationurlparameters)
  - [client.callback(redirectUri, parameters[, checks[, extras]])](#clientcallbackredirecturi-parameters-checks-extras)
  - [client.callbackParams(input)](#clientcallbackparamsinput)
  - [client.deviceAuthorization(parameters[, extras])](#clientdeviceauthorizationparameters-extras)
  - [client.endSessionUrl(parameters)](#clientendsessionurlparameters)
  - [client.grant(body[, extras])](#clientgrantbody-extras)
  - [client.introspect(token[, tokenTypeHint[, extras]])](#clientintrospecttoken-tokentypehint-extras)
  - [client.metadata](#clientmetadata)
  - [client.refresh(refreshToken[, extras])](#clientrefreshrefreshtoken-extras)
  - [client.requestObject(payload)](#clientrequestobjectpayload)
  - [client.requestResource(resourceUrl, accessToken, [, options])](#clientrequestresourceresourceurl-accesstoken-options)
  - [client.revoke(token[, tokenTypeHint[, extras]])](#clientrevoketoken-tokentypehint-extras)
  - [client.userinfo(accessToken[, options])](#clientuserinfoaccesstoken-options)
  - [client.pushedAuthorizationRequest(parameters[, extras])](#clientpushedauthorizationrequestparameters-extras)
- [Client Authentication Methods](#client-authentication-methods)
- [Client.fromUri(registrationClientUri, registrationAccessToken[, jwks[, clientOptions]])](#clientfromuriregistrationclienturi-registrationaccesstoken-jwks-clientoptions)
- [Client.register(metadata[, other])](#clientregistermetadata-other)
<!-- TOC Client END -->

---

#### Class: `<Client>`

Encapsulates a dynamically registered, discovered or instantiated OpenID Connect Client (Client),
Relying Party (RP), and its metadata, its instances hold the methods for getting an authorization
URL, consuming callbacks, triggering token endpoint grants, revoking and introspecting tokens.

```js
import { Issuer } from 'openid-client';

const issuer = await Issuer.discover('https://accounts.google.com');
const { Client } = issuer;
```

---

#### `new Client(metadata[, jwks[, options]])`

Creates a new Client with the provided metadata

- `metadata`: `<Object>`
  - `client_id`: `<string>`
  - `client_secret`: `<string>`
  - `id_token_signed_response_alg`: `<string>` **Default:** 'RS256'
  - `id_token_encrypted_response_alg`: `<string>`
  - `id_token_encrypted_response_enc`: `<string>`
  - `userinfo_signed_response_alg`: `<string>`
  - `userinfo_encrypted_response_alg`: `<string>`
  - `userinfo_encrypted_response_enc`: `<string>`
  - `redirect_uris`: `string[]`
  - `response_types`: `string[]` **Default:** '["code"]'
  - `post_logout_redirect_uris`: `string[]`
  - `default_max_age`: `<number>`
  - `require_auth_time`: `<boolean>` **Default:** 'false'
  - `request_object_signing_alg`: `<string>`
  - `request_object_encryption_alg`: `<string>`
  - `request_object_encryption_enc`: `<string>`
  - `token_endpoint_auth_method`: `<string>` **Default:** 'client_secret_basic'
  - `introspection_endpoint_auth_method`: `<string>` **Default:** same as token_endpoint_auth_method
  - `revocation_endpoint_auth_method`: `<string>` **Default:** same as token_endpoint_auth_method
  - `token_endpoint_auth_signing_alg`: `<string>`
  - `introspection_endpoint_auth_signing_alg`: `<string>`
  - `revocation_endpoint_auth_signing_alg`: `<string>`
  - `tls_client_certificate_bound_access_tokens`: `<boolean>`
  - other metadata may be present but currently doesn't have any special handling
- `jwks`: `<Object>` JWK Set formatted object with private keys used for signing client assertions
  or decrypting responses.
- `options`: `<Object>` additional options for the client
  - `additionalAuthorizedParties`: `<string>` &vert; `string[]` additional accepted values for the
    Authorized Party (`azp`) claim. **Default:** only the client's client_id value is accepted.
- Returns: `<Client>`

---

#### `client.metadata`

Returns the client's metadata.

- Returns: `<Object>`

---

#### `client.authorizationUrl(parameters)`

Returns the target authorization redirect URI to redirect End-Users to using the provided
parameters.

- `parameters`: `<Object>`
  - `redirect_uri`: `<string>` **Default:** If only a single `client.redirect_uris` member is
    present that one will be used automatically.
  - `response_type`: `<string>` **Default:** If only a single `client.response_types` member is
    present that one will be used automatically.
  - `scope`: `<string>` **Default:** 'openid'
  - any other authorization parameters may be provided (e.g. `nonce`, `state`, `login_hint`, ...)
- Returns: `<string>`

---

#### `client.endSessionUrl(parameters)`

Returns the target logout redirect URI to redirect End-Users to using the provided
parameters.

- `parameters`: `<Object>`
  - `id_token_hint`: `<string>` &vert; `<TokenSet>`
  - `client_id`: `<string>` **Default:** client's client_id
  - `post_logout_redirect_uri`: `<string>` **Default:** If only a single
    `client.post_logout_redirect_uris` member is present that one will be used automatically.
  - `state`: `<string>`
  - `logout_hint`: `<string>`
  - any other end session parameters may be provided
- Returns: `<string>`

---

#### `client.callbackParams(input)`

Returns recognized callback parameters from a provided input.

- `input`: `<string>` &vert; `<http.IncomingMessage>` &vert; `<http2.Http2ServerRequest>`
  - When input is of type string it will be parsed using `url.parse` and its query component will
    be returned
  - When input is a GET http/http2 request object its `url` property will be parsed using
    `url.parse` and its query component will be returned
  - When input is a POST http/http2 request object its `body` property will be parsed or returned
    if it is already an object. **Note: the request read stream will not be parsed, it is expected
    that you will have a body parser prior to calling this method. This parser would set the
    `req.body` property**
- Returns: `<Object>`

---

#### `client.callback(redirectUri, parameters[, checks[, extras]])`

Performs the callback for Authorization Server's authorization response.

- `redirectUri`: `<string>` redirect_uri used for the authorization request
- `parameters`: `<Object>` returned authorization response, see `client.callbackParams` if you need
  help getting them.
- `checks`: `<Object>`
  - `response_type`: `<string>` When provided the authorization response will be checked for
    presence of required parameters for a given response_type. Use of this check is recommended.
  - `state`: `<string>` When provided the authorization response's state parameter will be checked
    to be the this expected one. Use of this check is required if you sent a state parameter into an
    authorization request.
  - `jarm`: `<boolean>` When provided the authorization response must be a JARM one.
  - `nonce`: `<string>` When provided the authorization response's ID Token nonce parameter will be
    checked to be the this expected one. Use of this check is required if you sent a nonce parameter
    into an authorization request.
  - `code_verifier`: `<string>` PKCE code_verifier to be sent to the token endpoint during code
    exchange. Use of this check is required if you sent a code_challenge parameter into an
    authorization request.
  - `max_age`: `<number>` When provided the authorization response's ID Token auth_time parameter
    will be checked to be conform to the max_age value. Use of this check is required if you sent a
    max_age parameter into an authorization request. **Default:** uses client's `default_max_age`.

- `extras`: `<Object>`
  - `exchangeBody`: `<Object>` extra request body properties to be sent to the AS during code
    exchange.
  - `clientAssertionPayload`: `<Object>` extra client assertion payload parameters to be sent as
    part of a client JWT assertion. This is only used when the client's `token_endpoint_auth_method`
    is either `client_secret_jwt` or `private_key_jwt`.
  - `DPoP`: `<KeyObject>` or `<CryptoKey>` When provided the client will send a DPoP Proof JWT to the 
    Token Endpoint. The DPoP Proof JWT's algorithm is determined[^dpop-exception] automatically based
    on the type of key and the issuer metadata.
- Returns: `Promise<TokenSet>` Parsed token endpoint response as a TokenSet.

Tip: If you're using pure
OAuth 2.0 then `client.oauthCallback(redirectUri, parameters[, checks[, extras]])` is the OAuth 2.0
variant of this method, it has the same signature with the exception of checks only supporting
`code_verifier`, `state`, `response_type` and `jarm`.

---

#### `client.refresh(refreshToken[, extras])`

Performs `refresh_token` grant type exchange.

- `refreshToken`: `<string>` &vert; `<TokenSet>` Refresh Token value. When TokenSet instance is
  provided its `refresh_token` property will be used automatically.
- `extras`: `<Object>`
  - `exchangeBody`: `<Object>` extra request body properties to be sent to the AS during refresh
    token exchange.
  - `clientAssertionPayload`: `<Object>` extra client assertion payload parameters to be sent as
    part of a client JWT assertion. This is only used when the client's `token_endpoint_auth_method`
    is either `client_secret_jwt` or `private_key_jwt`.
  - `DPoP`: `<KeyObject>` or `<CryptoKey>` When provided the client will send a DPoP Proof JWT to the 
  Token Endpoint. The DPoP Proof JWT's algorithm is determined[^dpop-exception] automatically based
    on the type of key and the issuer metadata.
- Returns: `Promise<TokenSet>` Parsed token endpoint response as a TokenSet.

---

#### `client.userinfo(accessToken[, options])`

Fetches the OIDC `userinfo` response with the provided Access Token. Also handles signed and/or
encrypted userinfo responses. When TokenSet is provided as an argument the userinfo `sub` property
will also be checked to match the on in the TokenSet's ID Token.

- `accessToken`: `<string>` &vert; `<TokenSet>` Access Token value. When TokenSet instance is
  provided its `access_token` property will be used automatically.
- `options`: `<Object>`
  - `method`: `<string>` The HTTP method to use for the request 'GET' or 'POST'. **Default:** 'GET'
  - `via`: `<string>` The mechanism to use to attach the Access Token to the request. Valid values
    are `header` or `body`. **Default:** 'header'.
  - `tokenType`: `<string>` The token type as the Authorization Header scheme. **Default:** 'Bearer'
    or the `token_type` property from a passed in TokenSet.
  - `params`: `<Object>` additional parameters to send with the userinfo request (as query string
    when GET, as x-www-form-urlencoded body when POST).
  - `DPoP`: `<KeyObject>` or `<CryptoKey>` When provided the client will send a DPoP Proof JWT to the 
    Userinfo Endpoint. The DPoP Proof JWT's algorithm is determined[^dpop-exception] automatically based
    on the type of key and the issuer metadata.
- Returns: `Promise<Object>` Parsed userinfo response.

---

#### `client.requestResource(resourceUrl, accessToken[, options])`

Fetches an arbitrary resource with the provided Access Token in an Authorization header.

- `resourceUrl`: `<URL>` &vert; `<string>` Resource URL to request a response from.
- `accessToken`: `<string>` &vert; `<TokenSet>` Access Token value. When TokenSet instance is
  provided its `access_token` property will be used automatically.
- `options`: `<Object>`
  - `headers`: `<Object>` HTTP Headers to include in the request.
  - `body`: `<string>` &vert; `<Buffer>` HTTP Body to include in the request.
  - `method`: `<string>` The HTTP method to use for the request. **Default:** 'GET'
  - `tokenType`: `<string>` The token type as the Authorization Header scheme. **Default:** 'Bearer'
    or the `token_type` property from a passed in TokenSet.
  - `DPoP`: `<KeyObject>` or `<CryptoKey>` When provided the client will send a DPoP Proof JWT to the 
      Userinfo Endpoint. The DPoP Proof JWT's algorithm is determined[^dpop-exception] automatically based
    on the type of key and the issuer metadata.
- Returns: `Promise<Response>` Response is a [Got Response](https://github.com/sindresorhus/got/tree/v11.8.0#response)
  with the `body` property being a `<Buffer>`


---

#### `client.grant(body[, extras])`

Performs an arbitrary `grant_type` exchange at the `token_endpoint`.

- `body`: `<Object>`
  - `grant_type`: `<string>`
  - other properties may be provided depending on the grant in question
- `extras`: `<Object>`
  - `clientAssertionPayload`: `<Object>` extra client assertion payload parameters to be sent as
  part of a client JWT assertion. This is only used when the client's `token_endpoint_auth_method`
  is either `client_secret_jwt` or `private_key_jwt`.
  - `DPoP`: `<KeyObject>` or `<CryptoKey>` When provided the client will send a DPoP Proof JWT to the 
    Token Endpoint. The DPoP Proof JWT's algorithm is determined[^dpop-exception] automatically based
    on the type of key and the issuer metadata.
- Returns: `Promise<TokenSet>`

---

#### `client.introspect(token[, tokenTypeHint[, extras]])`

Introspects a token at the Authorization Server's `introspection_endpoint`.

- `token`: `<string>`
- `tokenTypeHint`: `<string>`
- `extras`: `<Object>`
  - `introspectBody`: `<Object>` extra request body properties to be sent to the introspection
    endpoint.
  - `clientAssertionPayload`: `<Object>` extra client assertion payload parameters to be sent as
  part of a client JWT assertion. This is only used when the client's `token_endpoint_auth_method`
  is either `client_secret_jwt` or `private_key_jwt`.
- Returns: `Promise<Object>` Parsed introspection response.

---

#### `client.revoke(token[, tokenTypeHint[, extras]])`

Revokes a token at the Authorization Server's `revocation_endpoint`.

- `token`: `<string>`
- `tokenTypeHint`: `<string>`
- `extras`: `<Object>`
  - `revokeBody`: `<Object>` extra request body properties to be sent to the revocation endpoint.
  - `clientAssertionPayload`: `<Object>` extra client assertion payload parameters to be sent as
  part of a client JWT assertion. This is only used when the client's `token_endpoint_auth_method`
  is either `client_secret_jwt` or `private_key_jwt`.
- Returns: `Promise<undefined>` Revocation responses are not parsed as per the specification.

---

#### `client.requestObject(payload)`

Creates a signed and optionally encrypted Request Object to send to the AS. Uses the client's
`request_object_signing_alg`, `request_object_encryption_alg`, `request_object_encryption_enc`
metadata for determining the algorithms to use.

- `payload`: `<Object>` Authorization request parameters and any other JWT parameters to be included
  in the Request Object.
  - `client_id`: `<string>` **Default:** client's client_id
  - `iss`: `<string>` **Default:** client's client_id
  - `aud`: `<string>` **Default:** issuer's Issuer Identifier
  - `iat`: `<number>` **Default:** now()
  - `exp`: `<number>` **Default:** now() + 300 (5 minutes from now)
  - `jti`: `<string>` **Default:** 32 random base64url encoded bytes
  - any other authorization request parameters may be included
  - any other JWT parameters like `nbf` may also be included
  - any custom request object payload properties may also be included
- Returns: `Promise<string>`

---

#### `client.deviceAuthorization(parameters[, extras])`

[RFC8628 - OAuth 2.0 Device Authorization Grant (Device Flow)](https://tools.ietf.org/html/rfc8628)

Starts a Device Authorization Request at the issuer's `device_authorization_endpoint` and returns
a handle for subsequent Device Access Token Request polling.

- `parameters`: `<Object>`
  - `client_id`: `<string>` **Default:** client's client_id
  - `scope`: `<string>` **Default:** 'openid'
  - any Device Authorization Request parameters may also be included
- `extras`: `<Object>`
  - `exchangeBody`: `<Object>` extra request body properties to be sent to the AS during the Device
    Access Token Request
  - `clientAssertionPayload`: `<Object>` extra client assertion payload parameters to be sent as
    part of a client JWT assertion. This is only used when the client's `token_endpoint_auth_method`
    is either `client_secret_jwt` or `private_key_jwt`.
  - `DPoP`: `<KeyObject>` or `<CryptoKey>` When provided the client will send a DPoP Proof JWT to the 
  Token Endpoint. The DPoP Proof JWT's algorithm is determined[^dpop-exception] automatically based
    on the type of key and the issuer metadata.
- Returns: `Promise<DeviceFlowHandle>`

---

#### `client.pushedAuthorizationRequest(parameters[, extras])`

[OAuth 2.0 Pushed Authorization Requests (PAR) - draft 06](https://tools.ietf.org/html/draft-ietf-oauth-par-06)

Performs a Pushed Authorization Request at the issuer's `pushed_authorization_request_endpoint`
with the provided parameters. The resolved object contains a `request_uri` that you will
afterwards pass to [client.authorizationUrl(parameters)](#clientauthorizationurlparameters) as the `request_uri` parameter.

The parameters sent to `pushed_authorization_request_endpoint` default to the same values
as [client.authorizationUrl(parameters)](#clientauthorizationurlparameters) unless
`request` (a Request Object) parameter e.g. from [client.requestObject(payload)](#clientrequestobjectpayload) is present.

The client will use it's `token_endpoint_auth_method` to authenticate at the `pushed_authorization_request_endpoint`.

- `parameters`: `<Object>`
  - `client_id`: `<string>` **Default:** client's client_id
  - any other request parameters may also be included
- `extras`: `<Object>`
  - `clientAssertionPayload`: `<Object>` extra client assertion payload parameters to be sent as
    part of a client JWT assertion. This is only used when the client's `token_endpoint_auth_method`
    is either `client_secret_jwt` or `private_key_jwt`.
- Returns: `Promise<Object>` Parsed Pushed Authorization Request Response with `request_uri` 
  and `expires_in` properties validated to be present and correct types.

---

#### Client Authentication Methods

Defined in [Core 1.0][client-authentication] and [RFC 8705](https://tools.ietf.org/html/rfc8705)
the following are valid values for `token_endpoint_auth_method`.

- `none` - only client_id is sent in the request body
- `client_secret_basic` (default) - client_id and client_secret is sent using the `Authorization`
  header as described in [RFC6749](https://tools.ietf.org/html/rfc6749#section-2.3.1)
- `client_secret_post` - client_id and client_secret is sent in the request body as described in
  [RFC6749](https://tools.ietf.org/html/rfc6749#section-2.3.1)
- `client_secret_jwt` - using `client_secret` as a shared symmetric secret a `client_assertion` is
  sent in the request body
- `private_key_jwt` - using the asymmetric keys provided via `jwks` a `client_assertion` is sent
  in the request body
- `tls_client_auth` and `self_signed_tls_client_auth` - sends client_id in the request body combined
  with client certificate and key configured via setting `cert` and `key` on a per-request basis
  using [`docs#customizing-http-requests`](https://github.com/panva/node-openid-client/tree/main/docs#customizing-http-requests)

Note: `*_jwt` methods resolve their signature algorithm either via the client's configured alg
(`token_endpoint_auth_signing_alg`) or any of the issuer's supported algs
(`token_endpoint_auth_signing_alg_values_supported`).

---

#### `Client.register(metadata[, other])`

Performs Dynamic Client Registration with the provided metadata at the issuer's
`registration_endpoint`.

- `metadata`: `<Object>` Client Metadata to register the new client with.
- `other`: `<Object>`
  - `jwks`: `<Object>` JWK Set formatted object with private keys used for signing client assertions
    or decrypting responses. When neither `jwks_uri` or `jwks` is present in `metadata` the key's
    public parts will be registered as `jwks`.
  - `initialAccessToken`: `<string>` Initial Access Token to use as a Bearer token during the
    registration call.
  - `additionalAuthorizedParties`: `<string>` &vert; `string[]` additional accepted values for the
    Authorized Party (`azp`) claim. **Default:** only the client's client_id value is accepted.

---

#### `Client.fromUri(registrationClientUri, registrationAccessToken[, jwks[, clientOptions]])`

Performs Dynamic Client Read Request to retrieve a Client instance.

- `registrationClientUri`: `<string>` Location of the Client Configuration Endpoint
- `registrationAccessToken`: `<string>` Registration Access Token to use as a Bearer token during
  the Client Read Request
- `jwks`: `<Object>` JWK Set formatted object with private keys used for signing client assertions
  or decrypting responses.
- `clientOptions`: `<Object>` additional options passed to the `Client` constructor
  - `additionalAuthorizedParties`: `<string>` &vert; `string[]` additional accepted values for the
    Authorized Party (`azp`) claim. **Default:** only the client's client_id value is accepted.

---

## Customizing

<!-- TOC Customizing START -->
- [Customizing HTTP requests](#customizing-http-requests)
- [Customizing individual HTTP requests](#customizing-individual-http-requests)
- [Customizing clock skew tolerance](#customizing-clock-skew-tolerance)
<!-- TOC Customizing END -->

---

#### Customizing HTTP requests

The following are default http request
[options](https://nodejs.org/api/https.html#httpsrequesturl-options-callback) that openid-client sets for all
requests.

```js
const DEFAULT_HTTP_OPTIONS = {
  headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})` },
  timeout: 3500,
};
```

You may change these global options like so:

```js
import { custom } from 'openid-client';

custom.setHttpOptionsDefaults({
  timeout: 5000,
});
```

This is meant to change global request options such as `timeout` or the default `User-Agent` header.

#### Customizing individual HTTP requests

You change options on a per-request basis by assigning a function to

- `Issuer` constructor to override the following request's options
  - discovery
  - webfinger
- `Issuer` instance to override fetching issuer's jwks_uri
- `issuer.Client` constructor to override the following request's options
  - dynamic client registration through Client Registration Endpoint
  - discovering client info through Client Read Request
- `issuer.Client` instance to override the following request's options
  - userinfo requests
  - token endpoint requests
  - introspection endpoint requests
  - revocation endpoint requests

This function will then be called before executing each and every request on the instance or constructor.

```js
import { custom } from 'openid-client';

// you can also set this on Issuer constructor, Issuer instance, or Client constructor
client[custom.http_options] = (url, options) => {
  // console.log(url);
  // console.log(options);
  return { timeout: 5000 };
}
```

The following options can be provided `agent`, `ca`, `cert`, `crl`, `headers`, `key`, `lookup`, `passphrase`, 
`pfx`, `timeout`. These are all relayed to https://nodejs.org/api/https.html#httpsrequesturl-options-callback

<details>
  <summary><em><strong>Example</strong></em> (Click to expand) providing mutual-TLS client certificate and key</summary>

```js
import { custom } from 'openid-client';
client[custom.http_options] = function (url, options) {
  // https://nodejs.org/api/tls.html#tlscreatesecurecontextoptions
  const result = {};

  result.cert = cert; // <string> | <string[]> | <Buffer> | <Buffer[]>
  result.key = key; // <string> | <string[]> | <Buffer> | <Buffer[]> | <Object[]>

  // custom CA
  // result.ca = ca; // <string> | <string[]> | <Buffer> | <Buffer[]>

  // use with .p12/.pfx files
  // result.pfx = pfx; // <string> | <string[]> | <Buffer> | <Buffer[]> | <Object[]>
  // result.passphrase = passphrase; // <string>

  // use HTTP(S)_PROXY
  // https://nodejs.org/api/http.html#httprequesturl-options-callback
  // e.g. using https://www.npmjs.com/package/proxy-agent
  // result.agent = agent;

  return result;
}
```
</details>

---

#### Customizing clock skew tolerance

It is possible the RP or OP environment has a system clock skew, which can result in the error "JWT not active yet". To set a clock tolerance (in seconds)

```js
import { custom } from 'openid-client';
client[custom.clock_tolerance] = 5; // to allow a 5 second skew
```

---

## TokenSet

<!-- TOC TokenSet START -->
- [Class: &lt;TokenSet&gt;](#class-tokenset)
  - [new TokenSet(input)](#new-tokensetinput)
  - [tokenset.expired()](#tokensetexpired)
  - [tokenset.claims()](#tokensetclaims)
<!-- TOC TokenSet END -->

---

#### Class: `<TokenSet>`

Represents a set of tokens retrieved from either authorization callback or successful token endpoint
grant call.

---

#### `new TokenSet(input)`

Creates a new TokenSet from the provided response. E.g. parsed token endpoint response, parsed
callback parameters. You only need to instantiate a TokenSet yourself if you recall it from e.g.
distributed cache storage or a database. **Note: manually constructed TokenSet instances do not
undergo any validations.**

- `input`: `<Object>`
  - `access_token`: `<string>`
  - `token_type`: `<string>`
  - `id_token`: `<string>`
  - `refresh_token`: `<string>`
  - `expires_in`: `<number>`
  - `expires_at`: `<number>` Access token expiration timestamp, represented as the number of seconds since the epoch (January 1, 1970 00:00:00 UTC).
  - `session_state`: `<string>`
  - other properties may be present and they'll be passthrough available on the TokenSet instance
- Returns: `<TokenSet>`

---

#### `tokenset.expired()`

Given that the instance has expires_at / expires_in this function returns true / false when the
access token (which expires properties are for) is beyond its lifetime.

- Returns: `<boolean>`

---

#### `tokenset.claims()`

Given that the instance has an id_token this function returns its parsed payload object. Does not
perform any validations as these were done prior to openid-client returning the tokenset in the
first place.

- Returns: `<Object>`

---

## DeviceFlowHandle

<!-- TOC DeviceFlowHandle START -->
- [Class: &lt;DeviceFlowHandle&gt;](#class-deviceflowhandle)
  - [handle.poll([options])](#handlepolloptions)
  - [handle.abort()](#handleabort)
  - [handle.user_code](#handleuser_code)
  - [handle.verification_uri](#handleverification_uri)
  - [handle.verification_uri_complete](#handleverification_uri_complete)
  - [handle.expired()](#handleexpired)
  - [handle.expires_in](#handleexpires_in)
  - [handle.device_code](#handledevice_code)
<!-- TOC DeviceFlowHandle END -->

---

#### Class: `<DeviceFlowHandle>`

The handle represents a Device Authorization Response with the `verification_uri`, `user_code` and
other defined response properties. A handle is instantiated by calling
[`client.deviceAuthorization()`](#clientdeviceauthorizationparameters-extras)

---

#### `handle.poll([options])`

This will continuously poll the token_endpoint and resolve with a TokenSet once one is received.
This will handle the defined `authorization_pending` and `slow_down` "soft" errors and continue
polling but upon any other error it will reject.

- `options`: `<Object>`
  - `signal`: `<AbortSignal>` An optional AbortSignal that can be used to abort polling. When
  if the signal is aborted the next interval in the poll will make the returned promise reject.
- Returns: `Promise<TokenSet>`

---

#### `handle.abort()`

This will abort ongoing polling. The next interval in the poll will result in a rejection.

---

#### `handle.user_code`

Returns the `user_code` Device Authorization Response parameter.

- Returns: `<string>`

---

#### `handle.verification_uri`

Returns the `verification_uri` Device Authorization Response parameter.

- Returns: `<string>`

---

#### `handle.verification_uri_complete`

Returns the `verification_uri_complete` Device Authorization Response parameter.

- Returns: `<string>`

---

#### `handle.expired()`

Returns true/false depending on whether the handle is expired or not.

- Returns: `<boolean>`

---

#### `handle.expires_in`

Returns the number of seconds until the handle expires.

- Returns: `<number>`

---

#### `handle.device_code`

Returns the `device_code` Device Authorization Response parameter.

- Returns: `<string>`

---

## Strategy

<!-- TOC Strategy START -->
- [Class: &lt;Strategy&gt;](#class-strategy)
  - [new Strategy(options, verify)](#new-strategyoptions-verify)
<!-- TOC Strategy END -->

---

#### Class: `<Strategy>`

Generic OpenID Connect [Passport](http://passportjs.org) authentication middleware strategy.

```js
import { Strategy } from 'openid-client';
```

---

#### `new Strategy(options, verify)`

Creates a new Strategy

- `options`: `<Object>`
  - `client`: `<Client>` Client instance. The strategy will use it.
  - `params`: `<Object>` Authorization Request parameters. The strategy will use these for every authorization request.
  - `passReqToCallback`: `<boolean>` Boolean specifying whether the verify function should get
    the request object as first argument instead. **Default:** 'false'
  - `usePKCE`: `<boolean>` &vert; `<string>` The PKCE method to use. When 'true' it will resolve based
    on the issuer metadata, when 'false' no PKCE will be used. **Default:** 'true'
  - `sessionKey`: `<string>` Define the property in your session which is used for storing information for the purpose of consuming the authentication response. **Default:** 'oidc:${Issuer Identifier}'
- `verify`: `<Function>` Your regular Passport
  [Verify Callback](http://www.passportjs.org/docs/configure/#verify-callback) function in which you
  verify the user from based on the data received from the AS.
  - `tokenset`: `<TokenSet>` Successful callback result TokenSet
  - `[userinfo]`: `<Object>` Optional argument, omit it when you don't want to load userinfo and
    are fine using 'tokenset.claims()' alone.
  - `done`: `<Function>`
- Returns: `<Strategy>`

Note: You can also set authorization request parameters dynamically using the `options` argument in `passport.authenticate([options])`:

```js
app.get('/protected-route', function(req, res, next) {
  if (shouldReConsent(req)) {
    passport.authenticate('oidc', { prompt: 'consent' })(req, res, next);
  }
});
```

---

## generators

<!-- TOC generators START -->
  - [generators.random([bytes])](#generatorsrandombytes)
  - [generators.state([bytes])](#generatorsrandombytes)
  - [generators.nonce([bytes])](#generatorsrandombytes)
  - [generators.codeVerifier([bytes])](#generatorsrandombytes)
  - [generators.codeChallenge(codeVerifier)](#generatorscodechallengeverifier)
<!-- TOC generators END -->

---

#### `generators.random([bytes])`

Generates random bytes and encodes them in url safe base64. This method is also aliased as
`generators.nonce`, `generators.state` and `generators.codeVerifier`

- `bytes`: `<number>` Number indicating the number of bytes to generate. **Default:** 32
- Returns: `<string>`

---

#### `generators.codeChallenge(verifier)`

Calculates the S256 PKCE code challenge for an arbitrary code verifier.

- `verifier`: `<string>` Code verifier to calculate the S256 code challenge for.
- Returns: `<string>`

---

## Errors

<!-- TOC Errors START -->
- [Class: &lt;TypeError&gt;](#class-typeerror)
- [Class: &lt;RPError&gt;](#class-rperror)
- [Class: &lt;OPError&gt;](#class-operror)
  - [error.error](#errorerror)
  - [error.error_description](#errorerror_description)
  - [error.error_uri](#errorerror_uri)
  - [error.state](#errorstate)
  - [error.scope](#errorscope)
  - [error.response](#errorresponse)
<!-- TOC Errors END -->

The following errors are expected to be thrown by openid-client runtime and have their prototypes
exported.

```js
import { errors } from 'openid-client';
// { OPError: [Function: OPError],
//   RPError: [Function: RPError] }
```

---

#### Class: `TypeError`

Thrown when unexpected argument types or their format is encountered. This is the standard built-in
[`TypeError`](https://nodejs.org/api/errors.html#errors_class_typeerror).

---

#### Class: `RPError`

Error class thrown when client-side response expectations/validations fail to pass. Depending on the
context it may or may not have additional context-based properties like `checks`, `jwt`, `params` or
`body`.

---

#### Class: `OPError`

Error class thrown when a regular OAuth 2.0 / OIDC style error is returned by the AS or an
unexpected response is sent by the OP.

---

#### `error.error`

The 'error' parameter from the AS response.

- Returns: `<string>` &vert; `<undefined>`

---

#### `error.error_description`

The 'error_description' parameter from the AS response.

- Returns: `<string>` &vert; `<undefined>`

---

#### `error.error_uri`

The 'error_uri' parameter from the AS response.

- Returns: `<string>` &vert; `<undefined>`

---

#### `error.state`

The 'state' parameter from the AS response.

- Returns: `<string>` &vert; `<undefined>`

---

#### `error.scope`

The 'scope' parameter from the AS response.

- Returns: `<string>` &vert; `<undefined>`

---

#### `error.response`

When the error is related to an http(s) request made to the OP this property will hold the pure node
request instance.

- Returns: `<http.IncomingMessage>` &vert; `<undefined>`


[sponsor-auth0]: https://a0.to/try-auth0
[support-sponsor]: https://github.com/sponsors/panva
[jose]: https://github.com/panva/jose
[webfinger-discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
[got-library]: https://github.com/sindresorhus/got/tree/v11.8.0
[client-authentication]: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
[Financial-grade API Security Profile 1.0 - Part 2: Advanced]: https://openid.net/specs/openid-financial-api-part-2-1_0.html

[^dpop-exception]: Ed25519, Ed448, and all Elliptic Curve keys have a fixed algorithm. RSA and RSA-PSS keys
look for an algorithm supported by the issuer metadata, if none is found PS256 is used as fallback.

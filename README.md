# openid-client

[![build][travis-image]][travis-url] [![dependencies][david-image]][david-url] [![codecov][codecov-image]][codecov-url] [![npm][npm-image]][npm-url] [![licence][licence-image]][licence-url]

openid-client is a server side [OpenID][openid-connect] Relying Party (RP, Client) implementation for
Node.js

**Table of Contents**

  * [Implemented specs &amp; features](#implemented-specs--features)
  * [Get started](#get-started)
  * [Usage](#usage)

## Implemented specs & features

The following client/RP features from OpenID Connect/OAuth2.0 specifications are implemented by
openid-client.

- [OpenID Connect Core 1.0 incorporating errata set 1][feature-core]
  - Authorization Callback
    - Authorization Code Flow
    - Implicit Flow
    - Hybrid Flow
  - UserInfo Request
  - Fetching Distributed Claims
  - Unpacking Aggregated Claims
  - Offline Access / Refresh Token Grant
  - Client Credentials Grant
  - Password Grant
  - Client Authentication
    - client_secret_basic
    - client_secret_post
    - client_secret_jwt
    - private_key_jwt
- [OpenID Connect Discovery 1.0 incorporating errata set 1][feature-discovery]
  - Discovery of OpenID Provider (Issuer) Metadata
  - Discovery of OpenID Provider (Issuer) Metadata via user provided inputs (see #WebFinger)
- [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1][feature-registration]
  - Dynamic Client Registration request
  - Client initialization via registration client uri
- [RFC7009 - OAuth 2.0 Token revocation][feature-revocation]
  - Client Authenticated request to token revocation
- [RFC7662 - OAuth 2.0 Token introspection][feature-introspection]
  - Client Authenticated request to token introspection

## Example
Head over to the example folder to see the library in use. This example is deployed and configured
to use an example OpenID Connect Provider [here][heroku-example]. The provider is using
[oidc-provider][oidc-provider] library.

## Get started
On the off-chance you want to manage multiple clients for multiple issuers you need to first get
an Issuer instance.

### via Discovery (recommended)
```js
const Issuer = require('openid-client').Issuer;
Issuer.discover('https://accounts.google.com') // => Promise
  .then(function (googleIssuer) {
    console.log('Discovered issuer %s', googleIssuer);
  });
```

### manually
```js
const Issuer = require('openid-client').Issuer;
const googleIssuer = new Issuer({
  issuer: 'https://accounts.google.com',
  authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
  userinfo_endpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
  jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
}); // => Issuer
console.log('Set up issuer %s', googleIssuer);
```

**Now you can create your Client.**

### manually (recommended)
You should provide the following metadata; `client_id, client_secret`. You can also provide
`id_token_signed_response_alg` (defaults to `RS256`) and `token_endpoint_auth_method` (defaults to
`client_secret_basic`);

```js
const client = new googleIssuer.Client({
  client_id: 'zELcpfANLqY7Oqas',
  client_secret: 'TQV5U29k1gHibH5bx1layBo0OSAvAbRT3UYW3EWrSYBB5swxjVfWUa1BS8lqzxG/0v9wruMcrGadany3'
}); // => Client
```

### via registration client uri
Should your oidc provider have provided you with a registration client uri and registration access
token you can also have the Client discovered.
```js
new googleIssuer.Client.fromUri(registration_client_uri, registration_access_token) // => Promise
  .then(function (client) {
    console.log('Discovered client %s', client);
  });
```

## Usage

### Getting authorization url
```js
client.authorizationUrl({
  redirect_uri: 'https://client.example.com/callback',
  scope: 'openid email',
}); // => String (URL)
```

You can also get HTML body of a self-submitting form to utilize POST to the authorization url with
`#authorizationPost` method, same signature as `#authorizationUrl`.
```js
client.authorizationPost({
  redirect_uri: 'https://client.example.com/callback',
  scope: 'openid email',
}); // => String (Valid HTML body)
```

### Processing callback
```js
client.authorizationCallback('https://client.example.com/callback', request.query) // => Promise
  .then(function (tokenSet) {
    console.log('received tokens %j', tokenSet);
  });
```

### Processing callback with state or nonce check
```js
const state = session.state;
const nonce = session.nonce;

client.authorizationCallback('https://client.example.com/callback', request.query, { state, nonce }) // => Promise
  .then(function (tokenSet) {
    console.log('received tokens %j', tokenSet);
  });
```

### Refreshing a token
```js
client.refresh(refreshToken) // => Promise
  .then(function (tokenSet) {
    console.log('refreshed tokens %j', tokenSet);
  });
```
Tip: accepts TokenSet as well as direct refresh token values;

### Revoke a token
```js
client.revoke(token, [tokenTypeHint]) // => Promise
  .then(function (response) {
    console.log('revoked token %s', token, response);
  });
```

### Introspect a token
```js
client.introspect(token, [tokenTypeHint]) // => Promise
  .then(function (response) {
    console.log('token details %j', response);
  });
```

### Fetching userinfo
```js
client.userinfo(accessToken) // => Promise
  .then(function (userinfo) {
    console.log('userinfo %j', userinfo);
  });
```
Tip: accepts TokenSet as well as direct access token values;

via POST
```js
client.userinfo(accessToken, { verb: 'post' }); // => Promise
```

auth via query
```js
client.userinfo(accessToken, { via: 'query' }); // => Promise
```

auth via body
```js
client.userinfo(accessToken, { verb: 'post', via: 'body' }); // => Promise
```

userinfo also handles (as long as you have the proper metadata configured) responses that are:
- signed
- signed and encrypted (nested JWT)
- just encrypted

### Fetching Distributed Claims
```js
let claims = {
  sub: 'userID',
  _claim_names: {
    credit_history: 'src1',
    email: 'src2',
  },
  _claim_sources: {
    src1: { endpoint: 'https://src1.example.com/claims', access_token: 'foobar' },
    src2: { endpoint: 'https://src2.example.com/claims' },
  },
};

client.fetchDistributedClaims(claims, { src2: 'bearer.for.src2' }) // => Promise
  .then(function (output) {
    console.log('claims %j', claims); // ! also modifies original input, does not create a copy
    console.log('output %j', output);
    // removes fetched names and sources and removes _claim_names and _claim_sources members if they
    // are empty
  });
  // when rejected the error will have a property 'src' with the source name it relates to
```

### Unpacking Aggregated Claims
```js
let claims = {
  sub: 'userID',
  _claim_names: {
    credit_history: 'src1',
    email: 'src2',
  },
  _claim_sources: {
    src1: { JWT: 'probably.a.jwt' },
    src2: { JWT: 'probably.another.jwt' },
  },
};

client.unpackAggregatedClaims(claims) // => Promise, autodiscovers JWT issuers, verifies signatures
  .then(function (output) {
    console.log('claims %j', claims); // ! also modifies original input, does not create a copy
    console.log('output %j', output);
    // removes fetched names and sources and removes _claim_names and _claim_sources members if they
    // are empty
  });
  // when rejected the error will have a property 'src' with the source name it relates to
```

### Custom token endpoint grants
Use when the token endpoint also supports client_credentials or password grants;

```js
client.grant({
  grant_type: 'client_credentials'
}); // => Promise

client.grant({
  grant_type: 'password',
  username: 'johndoe',
  password: 'A3ddj3w',
}); // => Promise
```

### Registering new client (via Dynamic Registration)
```js
issuer.Client.register(metadata, [keystore]) // => Promise
  .then(function (client) {
    console.log('Registered client %s, %j', client, client.metadata);
  });
```

## WebFinger discovery
```js
Issuer.webfinger(userInput) // => Promise
  .then(function (issuer) {
    console.log('Discovered issuer %s', issuer);
  });
```
Accepts, normalizes, discovers and validates the discovery of User Input using E-Mail, URL, acct,
Hostname and Port syntaxes as described in [Discovery 1.0][feature-discovery].

Uses already discovered (cached) issuers where applicable.

## Configuration

### Changing HTTP request defaults
Setting `defaultHttpOptions` on `Issuer` always merges your passed options with the default.
openid-client uses [got][got-library] for http requests with the following default request options

```js
const DEFAULT_HTTP_OPTIONS = {
  followRedirect: false,
  headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})` },
  retries: 0,
  timeout: 1500,
};
```

You can add your own headers, change the user-agent used or change the timeout setting
```js
Issuer.defaultHttpOptions = { timeout: 2500, headers: { 'X-Your-Header': '<whatever>' } };
```

Confirm your httpOptions by
```js
console.log('httpOptions %j', Issuer.defaultHttpOptions);
```

[travis-image]: https://img.shields.io/travis/panva/node-openid-client/master.svg?style=flat-square&maxAge=7200
[travis-url]: https://travis-ci.org/panva/node-openid-client
[david-image]: https://img.shields.io/david/panva/node-openid-client.svg?style=flat-square&maxAge=7200
[david-url]: https://david-dm.org/panva/node-openid-client
[codecov-image]: https://img.shields.io/codecov/c/github/panva/node-openid-client/master.svg?style=flat-square&maxAge=7200
[codecov-url]: https://codecov.io/gh/panva/node-openid-client
[npm-image]: https://img.shields.io/npm/v/openid-client.svg?style=flat-square&maxAge=7200
[npm-url]: https://www.npmjs.com/package/openid-client
[licence-image]: https://img.shields.io/github/license/panva/node-openid-client.svg?style=flat-square&maxAge=7200
[licence-url]: LICENSE.md
[openid-connect]: http://openid.net/connect/
[heroku-example]: https://tranquil-reef-95185.herokuapp.com/client
[oidc-provider]: https://github.com/panva/node-oidc-provider
[feature-core]: http://openid.net/specs/openid-connect-core-1_0.html
[feature-discovery]: http://openid.net/specs/openid-connect-discovery-1_0.html
[feature-registration]: http://openid.net/specs/openid-connect-registration-1_0.html
[feature-revocation]: https://tools.ietf.org/html/rfc7009
[feature-introspection]: https://tools.ietf.org/html/rfc7662
[got-library]: https://github.com/sindresorhus/got
[signed-userinfo]: http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

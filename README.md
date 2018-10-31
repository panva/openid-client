# openid-client

[![build][travis-image]][travis-url] [![codecov][codecov-image]][codecov-url]

openid-client is a server side [OpenID][openid-connect] Relying Party (RP, Client) implementation for
Node.js, supports [passport][passport-url].

Notice: openid-client ^2.0.x drops support for Node.js versions less than lts/boron(6.9.0) due to
Node.js lts/argon end of life on [2018-04-30](https://github.com/nodejs/Release). See the
[CHANGELOG](/CHANGELOG.md) for a complete list of deprecations and changes.

**Table of Contents**

  - [Implemented specs & features](#implemented-specs--features)
  - [Certification](#certification)
  - [Get started](#get-started)
  - [Usage](#usage)
  - [Usage with passport](#usage-with-passport)
  - [Configuration](#configuration)


## Implemented specs & features

The following client/RP features from OpenID Connect/OAuth2.0 specifications are implemented by
openid-client.

- [OpenID Connect Core 1.0][feature-core]
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
    - none
    - client_secret_basic
    - client_secret_post
    - client_secret_jwt
    - private_key_jwt
- [RFC8414 - OAuth 2.0 Authorization Server Metadata][feature-oauth-discovery] and [OpenID Connect Discovery 1.0][feature-discovery]
  - Discovery of OpenID Provider (Issuer) Metadata
  - Discovery of OpenID Provider (Issuer) Metadata via user provided inputs (see [WebFinger](#webfinger-discovery))
- [OpenID Connect Dynamic Client Registration 1.0][feature-registration]
  - Dynamic Client Registration request
  - Client initialization via registration client uri
- [RFC7009 - OAuth 2.0 Token revocation][feature-revocation]
  - Client Authenticated request to token revocation
- [RFC7662 - OAuth 2.0 Token introspection][feature-introspection]
  - Client Authenticated request to token introspection

Updates to features defined in draft or experimental specifications are released as MINOR library
versions, if you utilize these consider using the tilde ~ operator in your package.json since
breaking changes may be introduced as part of these specification updates.

## Certification
[<img width="184" height="96" align="right" src="https://cdn.jsdelivr.net/gh/panva/node-openid-client@38cf016b0837e6d4116de3780b28d222d5780bc9/OpenID_Certified.png" alt="OpenID Certification">][openid-certified-link]  
Filip Skokan has [certified][openid-certified-link] that [openid-client][npm-url]
conforms to the RP Basic, RP Implicit, RP Hybrid, RP Config, RP Dynamic and RP Form Post profiles
of the OpenID Connect™ protocol.

[![build][conformance-image]][conformance-url]


<h2>Sponsor</h2>

[<img width="65" height="65" align="left" src="https://avatars.githubusercontent.com/u/2824157?s=75&v=4" alt="auth0-logo">][sponsor-auth0] If you want to quickly add OpenID Connect authentication to Node.js apps, feel free to check out Auth0's Node.js SDK and free plan at [auth0.com/overview][sponsor-auth0].<br><br>

<h2>Support</h2>

[<img src="https://c5.patreon.com/external/logo/become_a_patron_button@2x.png" width="160" align="right">][support-patreon]
If you or your business use openid-client, please consider becoming a [Patron][support-patreon] so I can continue maintaining it and adding new features carefree. You may also donate one-time via [PayPal][support-paypal].
[<img src="https://cdn.jsdelivr.net/gh/gregoiresgt/payment-icons@183140a5ff8f39b5a19d59ebeb2c77f03c3a24d3/Assets/Payment/PayPal/Paypal@2x.png" width="100" align="right">][support-paypal]


## Get started
On the off-chance you want to manage multiple clients for multiple issuers you need to first get
an Issuer instance.

### via Discovery (recommended)
```js
const { Issuer } = require('openid-client');
Issuer.discover('https://accounts.google.com') // => Promise
  .then(function (googleIssuer) {
    console.log('Discovered issuer %s %O', googleIssuer.issuer, googleIssuer.metadata);
  });
```

### manually
```js
const { Issuer } = require('openid-client');
const googleIssuer = new Issuer({
  issuer: 'https://accounts.google.com',
  authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
  userinfo_endpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
  jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
}); // => Issuer
console.log('Set up issuer %s %O', googleIssuer.issuer, googleIssuer.metadata);
```

**Now you can create your Client.**

### manually (recommended)
You should provide at least the following metadata: `client_id`, `client_secret`, `id_token_signed_response_alg` (defaults to `RS256`) and `token_endpoint_auth_method` (defaults to `client_secret_basic`) for a basic client definition, but you may provide any IANA registered client metadata.

```js
const client = new googleIssuer.Client({
  client_id: 'zELcpfANLqY7Oqas',
  client_secret: 'TQV5U29k1gHibH5bx1layBo0OSAvAbRT3UYW3EWrSYBB5swxjVfWUa1BS8lqzxG/0v9wruMcrGadany3'
}, [keystore]); // => Client
```

`keystore` is an optional argument for instantiating a client with configured asymmetrical
ID Token or UserInfo response encryption.

### via registration client uri
Should your oidc provider have provided you with a registration client uri and registration access
token you can also have the Client discovered.
```js
googleIssuer.Client.fromUri(registration_client_uri, registration_access_token, [keystore]) // => Promise
  .then(function (client) {
    console.log('Discovered client %s %O', client.client_id, client.metadata);
  });
```

`keystore` is an optional argument for instantiating a client through registration client uri
with configured asymmetrical ID Token or UserInfo response encryption.

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
const { state, response_type } = session[authorizationRequestState];
client.authorizationCallback('https://client.example.com/callback', request.query, { state, response_type }) // => Promise
  .then(function (tokenSet) {
    console.log('received and validated tokens %j', tokenSet);
    console.log('validated id_token claims %j', tokenSet.claims);
  });
```

Aside from `state` and `response_type`, checks for `nonce` (implicit and hybrid responses) and
`max_age` are implemented. `id_token` signature and claims validation does not need to be requested,
it is done automatically.

### OP Errors - OpenIdConnectError
When the OpenID Provider returns an OIDC formatted error from either authorization callbacks or
any of the JSON responses the library will reject a given Promise with `OpenIdConnectError` instance.

The message of this error is `"${error} (${error_description})"`. However the OpenIdConnectError object
also has the following properties:

- error
- error_description
- error_uri
- state
- scope

Values are `undefined` if these were not provided in the response. Additionally, for API call
responses a `response` property is available with the response object from the used http client.

### Handling multiple response modes
When handling multiple response modes with one single pass you can use `#callbackParams`
to get the params object from the koa/express/node request object or a url string.
(http.IncomingMessage). If form_post is your response_type you need to include a body parser prior.

```js
client.callbackParams('https://client.example.com/cb?code=code'); // => { code: 'code' };
client.callbackParams('/cb?code=code'); // => { code: 'code' };

// example koa v2.x w/ koa-body
app.use(bodyParser({ patchNode: true }));
app.use(async function (ctx, next) {
  const params = client.callbackParams(ctx.request.req); // => parsed url query or body object
  // ...
});

// example express w/ bodyParser
app.use(bodyParser.urlencoded({ extended: false }));
app.use(function (req, res, next) {
  const params = client.callbackParams(req); // => parsed url query or body object
  // ...
});
```

### Refreshing a token
```js
client.refresh(refreshToken) // => Promise
  .then(function (tokenSet) {
    console.log('refreshed and validated tokens %j', tokenSet);
    console.log('refreshed id_token claims %j', tokenSet.claims);
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

with extra query/body payload
```js
client.userinfo(accessToken, { params: { fields: 'email,ids_for_business' } }); // => Promise
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

### Getting RP-Initiated Logout url

Note: Only usable with issuer's supporting OpenID Connect Session Management 1.0

```js
client.endSessionUrl({
  post_logout_redirect_uri: '...', // OPTIONAL, defaults to client.post_logout_redirect_uris[0] if there's only one
  state: '...', // RECOMMENDED
  id_token_hint: '...', // OPTIONAL, accepts the string value or tokenSet with id_token
}); // => String (URL)
```

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
Use when the token endpoint also supports additional grant types.

```js
client.grant({
  grant_type: 'client_credentials',
  scope: 'api:read',
}); // => Promise

client.grant({
  grant_type: 'password',
  username: 'johndoe',
  password: 'A3ddj3w',
  scope: 'profile',
}); // => Promise
```

### Registering new client (via Dynamic Registration)
```js
const opts = { keystore, initialAccessToken }; // both optional
issuer.Client.register(metadata, [opts]) // => opts optional, Promise
  .then(function (client) {
    console.log('Registered client %s, %O', client.client_id, client.metadata);
  });
```

### Generating a signed/encrypted Request Object
```js
client.requestObject({ max_age: 300, redirect_uri })
  .then(function (request) {
    console.log('JWT Request Object %s', request)
  });
```

This will use the client metadata `request_object_signing_alg`, `request_object_encryption_alg` and
`request_object_encryption_enc`, but you can provide the signing and/or encryption algs explicitly

```js
client.requestObject({ max_age: 300, redirect_uri }, {
  // sign: '...',
  // encrypt: {
  //   alg: '...',
  //   enc: '...',
  // }
}).then(function (request) {
  console.log('JWT Request Object %s', request)
});
```

### WebFinger discovery
```js
Issuer.webfinger(userInput) // => Promise
  .then(function (issuer) {
    console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);
  });
```
Accepts, normalizes, discovers and validates the discovery of User Input using E-Mail, URL, acct,
Hostname and Port syntaxes as described in [Discovery 1.0][feature-discovery].

Uses already discovered (cached) issuers where applicable.

### TokenSet
`authorizationCallback` and `refresh` methods on a Client return TokenSet, when assigned an
`expires_in` value a TokenSet calculates and assigns an `expires_at` with the corresponding unix
time. It also comes with few helpers.

```js
client.authorizationCallback(..., ...).then(function (tokenSet) {
  console.log('tokenSet#expires_at', tokenSet.expires_at);
  console.log('tokenSet#expires_in', tokenSet.expires_in);
  setTimeout(function () {
    console.log('tokenSet#expires_in', tokenSet.expires_in);
  }, 2000);
  console.log('tokenSet#expired()', tokenSet.expired());
  console.log('tokenSet#claims', tokenSet.claims);
});
```

## Usage with passport
Once you have a Client instance, just pass it to the Strategy constructor. Issuer is best
discovered, Client passed properties manually or via an uri (see [get-started](#get-started)).

Verify function is invoked with a TokenSet, userinfo only when requested, last argument is always
the done function which you invoke once you found your user.

```js
const { Strategy } = require('openid-client');
const params = {
  // ... any authorization request parameters go here
  // client_id defaults to client.client_id
  // redirect_uri defaults to client.redirect_uris[0]
  // response type defaults to client.response_types[0], then 'code'
  // scope defaults to 'openid'
}
const passReqToCallback = false; // optional, defaults to false, when true req is passed as a first
                                 // argument to verify fn

const usePKCE = true; // optional, defaults to false, when true the code_challenge_method will be
                      // resolved from the issuer configuration, instead of true you may provide
                      // any of the supported values directly, i.e. "S256" (recommended) or "plain"

passport.use('oidc', new Strategy({ client, [params], [passReqToCallback], [usePKCE] }, (tokenset, userinfo, done) => {
  console.log('tokenset', tokenset);
  console.log('access_token', tokenset.access_token);
  console.log('id_token', tokenset.id_token);
  console.log('claims', tokenset.claims);
  console.log('userinfo', userinfo);

  User.findOne({ id: tokenset.claims.sub }, function (err, user) {
    if (err) return done(err);
    return done(null, user);
  });
}));

// start authentication request
// options [optional], extra authentication parameters
app.get('/auth', passport.authenticate('oidc', [options]));

// authentication callback
app.get('/auth/cb', passport.authenticate('oidc', { successRedirect: '/', failureRedirect: '/login' }));
```

## Configuration

### Client Authentication explained

Configure `token_endpoint_auth_method` with one of the following. Defined in [Core 1.0][client-authentication]:

- `none` - only client_id is sent in the request body
- `client_secret_basic` (default) - client_id and client_secret is sent using the `Authorization`
  header as described in [RFC6749](https://tools.ietf.org/html/rfc6749#section-2.3.1)
- `client_secret_post` - client_id and client_secret is sent in the request body as described in
  [RFC6749](https://tools.ietf.org/html/rfc6749#section-2.3.1)
- `client_secret_jwt` - using `client_secret` as a shared symmetrical secret a `client_assertion` is
  sent in the request body
- `private_key_jwt` - using the asymmetric keys provided via `keystore` a `client_assertion` is sent
  in the request body

The configuration may differ between token, introspection and revocation endpoints. The metadata
would be:

- `token_endpoint_auth_method`
- `introspection_endpoint_auth_method`
- `revocation_endpoint_auth_method`

The other metadata names follow the same prefix convention.

Note: `*_jwt` methods resolve their algorithm either via the client's configured alg
(`token_endpoint_auth_signing_alg`) or any of the issuer's supported algs
(`token_endpoint_auth_signing_alg_values_supported`)


### Allow for system clock skew
It is possible the RP or OP environment has a system clock skew, to set a clock tolerance (in seconds)

```js
client.CLOCK_TOLERANCE = 5; // to allow a 5 second skew
```

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

### Proxy settings
Because of the lightweight nature of [got][got-library] library the client will not use
environment-defined http(s) proxies. In order to have them used you'll need to either provide your own http request
implementation using the provided `httpClient` setter or use the bundled [request][request-library]
one.

Custom implementation:
```js
/*
 * url {String}
 * options {Object}
 * options.headers {Object}
 * options.body {String|Object}
 * options.form {Boolean}
 * options.query {Object}
 * options.timeout {Number}
 * options.retries {Number}
 * options.followRedirect {Boolean}
 */

Issuer.httpClient = {
   get(url, options) {}, // return Promise
   post(url, options) {}, // return Promise
   HTTPError, // used error constructor
};
```

Bundled (and maintained + tested) request implementation after you've added [request][request-library]
to your package.json bundle:

```
npm install request@^2.0.0 --save
```

```js
Issuer.useRequest();
```


[travis-image]: https://api.travis-ci.com/panva/node-openid-client.svg?branch=master
[travis-url]: https://travis-ci.com/panva/node-openid-client
[conformance-image]: https://api.travis-ci.com/panva/openid-client-conformance-tests.svg?branch=master
[conformance-url]: https://github.com/panva/openid-client-conformance-tests
[codecov-image]: https://codecov.io/gh/panva/node-openid-client/branch/master/graph/badge.svg
[codecov-url]: https://codecov.io/gh/panva/node-openid-client
[openid-connect]: https://openid.net/connect/
[heroku-example]: https://tranquil-reef-95185.herokuapp.com/client
[oidc-provider]: https://github.com/panva/node-oidc-provider
[feature-core]: https://openid.net/specs/openid-connect-core-1_0.html
[client-authentication]: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
[feature-discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[feature-oauth-discovery]: https://tools.ietf.org/html/rfc8414
[feature-registration]: https://openid.net/specs/openid-connect-registration-1_0.html
[feature-revocation]: https://tools.ietf.org/html/rfc7009
[feature-introspection]: https://tools.ietf.org/html/rfc7662
[got-library]: https://github.com/sindresorhus/got
[request-library]: https://github.com/request/request
[signed-userinfo]: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
[openid-certified-link]: https://openid.net/certification/
[passport-url]: http://passportjs.org
[npm-url]: https://www.npmjs.com/package/openid-client
[sponsor-auth0]: https://auth0.com/overview?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=openid-client&utm_content=auth
[support-patreon]: https://www.patreon.com/panva
[support-paypal]: https://www.paypal.me/panva

# openid-client

[![build][travis-image]][travis-url] [![codecov][codecov-image]][codecov-url] [![npm][npm-image]][npm-url] [![licence][licence-image]][licence-url]

openid-client is a server side [OpenID][openid-connect] Relying Party (RP, Client) implementation for
Node.js

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
}); // => String
```

### Processing callback
```js
client.authorizationCallback('https://client.example.com/callback', request.query) // => Promise
  .then(function (tokens) {
    console.log('received tokens %j', tokens);
  });
```

### Refreshing a token
```js
client.refresh(refreshToken) // => Promise
  .then(function (tokens) {
    console.log('refreshed tokens %j', tokens);
  });
```

### Revoke a token
```js
client.revoke(token) // => Promise
  .then(function () {
    console.log('revoked token %s', token);
  });
```

### Introspect a token
```js
client.introspect(token) // => Promise
  .then(function (details) {
    console.log('token details %j', details);
  });
```

### Fetching userinfo
```js
client.userinfo(accessToken) // => Promise
  .then(function (userinfo) {
    console.log('userinfo %j', userinfo);
  });
```

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

[travis-image]: https://img.shields.io/travis/panva/node-openid-client/master.svg?style=flat-square&maxAge=7200
[travis-url]: https://travis-ci.org/panva/node-openid-client
[codecov-image]: https://img.shields.io/codecov/c/github/panva/node-openid-client/master.svg?style=flat-square&maxAge=7200
[codecov-url]: https://codecov.io/gh/panva/node-openid-client
[npm-image]: https://img.shields.io/npm/v/openid-client.svg?style=flat-square&maxAge=7200
[npm-url]: https://www.npmjs.com/package/openid-client
[licence-image]: https://img.shields.io/github/license/panva/node-openid-client.svg?style=flat-square&maxAge=7200
[licence-url]: LICENSE.md
[openid-connect]: http://openid.net/connect/
[heroku-example]: https://tranquil-reef-95185.herokuapp.com/client
[oidc-provider]: https://github.com/panva/node-oidc-provider

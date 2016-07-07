# oidc-client

[![build][travis-image]][travis-url] [![codecov][codecov-image]][codecov-url] [![npm][npm-image]][npm-url] [![licence][licence-image]][licence-url]

oidc-client is a server side [OpenID][openid-connect] Relying Party (RP, Client) implementation for
Node.js

## Get started
On the off-chance you want to manage multiple clients for multiple issuers you need to first get
a Provider.

### via Discovery
```js
const Provider = require('oidc-client').Provider;
Provider.discover('https://accounts.google.com') // => Promise
  .then(function (googleProvider) {
    console.log('Discovered issuer %s', googleProvider.issuer);
  });
```

### manually
```js
const Provider = require('oidc-client').Provider;
const googleProvider = new Provider({
  issuer: 'https://accounts.google.com',
  authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
  userinfo_endpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
  jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
}); // => Provider
console.log('Set up issuer %s', googleProvider.issuer);
```

Now you can create your Client.

### manually
You should provide the following metadata; `client_id, client_secret`. You can also provide
`id_token_signed_response_alg` (defaults to `RS256`) and `token_endpoint_auth_method` (defaults to
`client_secret_basic`);

```js
const client = new googleProvider.Client({
  client_id: 'zELcpfANLqY7Oqas',
  client_secret: 'TQV5U29k1gHibH5bx1layBo0OSAvAbRT3UYW3EWrSYBB5swxjVfWUa1BS8lqzxG/0v9wruMcrGadany3'
}) // => Client
```

### via Dynamic Registration
Should your provider support Dynamic Registration and/or provided you with a registration client uri
and registration access token you can also have the Client discovered.
```js
new googleProvider.Client.fromUri(registration_client_uri, registration_access_token) // => Promise
  .then(function (client) {
    console.log('Discovered client %s', client.client_id);
  })
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

[travis-image]: https://img.shields.io/travis/panva/node-oidc-client/master.svg?style=flat-square&maxAge=7200
[travis-url]: https://travis-ci.org/panva/node-oidc-client
[codecov-image]: https://img.shields.io/codecov/c/github/panva/node-oidc-client/master.svg?style=flat-square&maxAge=7200
[codecov-url]: https://codecov.io/gh/panva/node-oidc-client
[npm-image]: https://img.shields.io/npm/v/oidc-client.svg?style=flat-square&maxAge=7200
[npm-url]: https://www.npmjs.com/package/oidc-client
[licence-image]: https://img.shields.io/github/license/panva/node-oidc-client.svg?style=flat-square&maxAge=7200
[licence-url]: LICENSE.md
[openid-connect]: http://openid.net/connect/

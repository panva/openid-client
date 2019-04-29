# Change Log

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

# [2.5.0](https://github.com/panva/node-openid-client/compare/v2.4.5...v2.5.0) (2019-04-29)


### Bug Fixes

* key lookup cache is now working as intended ([90d2f2a](https://github.com/panva/node-openid-client/commit/90d2f2a)), closes [#162](https://github.com/panva/node-openid-client/issues/162)


### Features

* add support for azure ad v2 multitenant apps ([24486dd](https://github.com/panva/node-openid-client/commit/24486dd)), closes [/github.com/panva/node-openid-client/pull/148#issuecomment-483348258](https://github.com//github.com/panva/node-openid-client/pull/148/issues/issuecomment-483348258) [#148](https://github.com/panva/node-openid-client/issues/148)



<a name="2.4.5"></a>
## [2.4.5](https://github.com/panva/node-openid-client/compare/v2.4.4...v2.4.5) (2018-11-05)


### Bug Fixes

* upgrade min node-jose version to fix its performance in node ([e682dfc](https://github.com/panva/node-openid-client/commit/e682dfc))



<a name="2.4.4"></a>
## [2.4.4](https://github.com/panva/node-openid-client/compare/v2.4.3...v2.4.4) (2018-10-18)


### Bug Fixes

* strategy code_verifier length, removed uuid dependency ([60d0cb8...ea4a8fd](https://github.com/panva/node-openid-client/compare/60d0cb8...ea4a8fd)), closes [#131](https://github.com/panva/node-openid-client/issues/131)



<a name="2.4.3"></a>
## [2.4.3](https://github.com/panva/node-openid-client/compare/v2.4.2...v2.4.3) (2018-10-10)


### Bug Fixes

* assign Discovery 1.0 defaults when discovering with .well-known ([74b593e](https://github.com/panva/node-openid-client/commit/74b593e))



<a name="2.4.2"></a>
## [2.4.2](https://github.com/panva/node-openid-client/compare/v2.4.1...v2.4.2) (2018-09-27)


### Bug Fixes

* non-string error responses are not treated as OpenIdConnectError ([782d464](https://github.com/panva/node-openid-client/commit/782d464)), closes [#125](https://github.com/panva/node-openid-client/issues/125)



<a name="2.4.1"></a>
## [2.4.1](https://github.com/panva/node-openid-client/compare/v2.4.0...v2.4.1) (2018-09-16)


### Bug Fixes

* lts/boron unsupported syntax fix ([5289188](https://github.com/panva/node-openid-client/commit/5289188))



<a name="2.4.0"></a>
# [2.4.0](https://github.com/panva/node-openid-client/compare/v2.3.1...v2.4.0) (2018-09-16)


### Bug Fixes

* OpenIdConnectError also returns session_state ([95fae3d](https://github.com/panva/node-openid-client/commit/95fae3d))
* stop sending state on the authorisation code token grant ([c4c9e50](https://github.com/panva/node-openid-client/commit/c4c9e50))


### Features

* add RP-Initiated Logout URL helper ([7c2e030](https://github.com/panva/node-openid-client/commit/7c2e030)), closes [#116](https://github.com/panva/node-openid-client/issues/116)



<a name="2.3.1"></a>
## [2.3.1](https://github.com/panva/node-openid-client/compare/v2.3.0...v2.3.1) (2018-08-23)


### Bug Fixes

* apply safer, simpler www-authenticate parsing regex ([ffce55a](https://github.com/panva/node-openid-client/commit/ffce55a))
* only assign Discovery 1.0 defaults when Issuer is discovered ([dca60b8](https://github.com/panva/node-openid-client/commit/dca60b8))



<a name="2.3.0"></a>
# [2.3.0](https://github.com/panva/node-openid-client/compare/v2.2.1...v2.3.0) (2018-08-11)


### Features

* authorization response parameter checking based on response_type ([6e0ac57](https://github.com/panva/node-openid-client/commit/6e0ac57))
* passport strategy automatically checks response REQUIRED params ([902eeed](https://github.com/panva/node-openid-client/commit/902eeed))



# Pre standard-version Change Log
## Version 2.2.x
### Version 2.2.1
- 2018-07-10 [DIFF](https://github.com/panva/node-openid-client/compare/v2.2.0...v2.2.1)
- improved discovery support of custom .well-known suffixes
- chores - refactoring, missing tests, cleanup

### Version 2.2.0
- 2018-07-04 [DIFF](https://github.com/panva/node-openid-client/compare/v2.1.1...v2.2.0)
- added support for [RFC8414 - OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
  discovery

## Version 2.1.x
### Version 2.1.1
- 2018-06-28 [DIFF](https://github.com/panva/node-openid-client/compare/v2.1.0...v2.1.1)
- fixed handling of bearer endpoint responses with www-authenticate headers only. fixes #102

### Version 2.1.0
- 2018-05-31 [DIFF](https://github.com/panva/node-openid-client/compare/v2.0.4...v2.1.0)
- `node-jose` dependency bumped to major ^1.0.0 - fixes `A\d{3}GCMKW` symmetrical encryption support
- dependency updates

## Version 2.0.x
### Version 2.0.4
- 2018-05-25 [DIFF](https://github.com/panva/node-openid-client/compare/v2.0.3...v2.0.4)
- fixed circular when serializing OpenIdConnectError
- base64url dependency update

### Version 2.0.3
- 2018-05-15 [DIFF](https://github.com/panva/node-openid-client/compare/v2.0.2...v2.0.3)
- base64url dependency replaced

### Version 2.0.2
- 2018-05-10 [DIFF](https://github.com/panva/node-openid-client/compare/v2.0.1...v2.0.2)
- dependency tree updates

### Version 2.0.1
- 2018-04-26 [DIFF](https://github.com/panva/node-openid-client/compare/v2.0.0...v2.0.1)
- fixed `client_secret_basic` requiring the username and password tokens to be `x-www-form-urlencoded`
  according to https://tools.ietf.org/html/rfc6749#section-2.3.1
  - NOTE: Although technically a fix, this is a breaking change when used with providers that also
    don't currently follow the standard. A proper way of submitting client_id and client_secret using
    `client_secret_basic` is `Authorization: base64(formEncode(client_id):formEncode(client_secret))`.
    If your client_id and client_secret does contain special characters that need encoding this does not
    affect you. If it does, try using `client_secret_post` instead.

### Version 2.0.0
- 2018-04-12 [DIFF](https://github.com/panva/node-openid-client/compare/v1.20.0...v2.0.0)
- dropped support for Node.js v4.x due to its End-of-Life on [2018-04-30](https://github.com/nodejs/Release)
- removed deprecated `client#grantAuth`
- removed deprecated way of passing keystore directly to `Client#register`
- removed support for passing client to `OpenIDConnectStrategy` as single argument, use
  `new Strategy({ client })` instead of `new Strategy(client)`.
- fixed a bug requiring nonce to be passed for `response_type=none`

## Version 1.20.0
- 2018-03-13 [DIFF](https://github.com/panva/node-openid-client/compare/v1.19.5...v1.20.0)
- added documentation for `OpenIdConnectError`
- added `error_uri` from IdP responses to `OpenIdConnectError` instances
- fixed `OpenIdConnectError` messages to include `error_description`

## Version 1.19.x
### Version 1.19.5
- 2018-03-10 [DIFF](https://github.com/panva/node-openid-client/compare/v1.19.4...v1.19.5)
- `Issuer.discover` now parses the provided URI instead of just inspecting the string. #80

### Version 1.19.4
- 2018-01-30 [DIFF](https://github.com/panva/node-openid-client/compare/v1.19.3...v1.19.4)
- fixed edge cases of (and simplified) private id token decryption method

### Version 1.19.3
- 2018-01-22 [DIFF](https://github.com/panva/node-openid-client/compare/v1.19.2...v1.19.3)
- fix return values of `#authorizationCallback()` for `response_type=none` to resolve a TokenSet

### Version 1.19.2
- 2018-01-16 [DIFF](https://github.com/panva/node-openid-client/compare/v1.19.1...v1.19.2)
- fixed `authorizationUrl` to respect existing issuer authorization_endpoint query parameters

### Version 1.19.1
- 2018-01-15 [DIFF](https://github.com/panva/node-openid-client/compare/v1.19.0...v1.19.1)
- adjusted the passport state mismatch related error message to hint developers at a local setup
  issue

### Version 1.19.0
- 2017-12-12 [DIFF](https://github.com/panva/node-openid-client/compare/v1.18.2...v1.19.0)
- added maintained request wrapper and a simple api to use request instead of `got`

## Version 1.18.x
### Version 1.18.2
- 2017-12-05 [DIFF](https://github.com/panva/node-openid-client/compare/v1.18.1...v1.18.2)
- bumped node-jose dependency

### Version 1.18.1
- 2017-11-25 [DIFF](https://github.com/panva/node-openid-client/compare/v1.18.0...v1.18.1)
- fixed the order of several `assert.equal` calls to swap actual/expected descriptions
- added assertion error messages for passport strategy

### Version 1.18.0
- 2017-11-19 [DIFF](https://github.com/panva/node-openid-client/compare/v1.17.0...v1.18.0)
- added option for the passport strategy to use PKCE
- updated http request library `got` dependency

## Version 1.17.0
- 2017-10-31 [DIFF](https://github.com/panva/node-openid-client/compare/v1.16.0...v1.17.0)
- now uses `client_secret_post` as default for Issuer instances that do not support
  `client_secret_basic` but do signal support for `client_secret_post` in their discovery document

## Version 1.16.0
- 2017-10-13 [DIFF](https://github.com/panva/node-openid-client/compare/v1.15.0...v1.16.0)
- added `s_hash` value validation support for ID Tokens returned by authorization endpoint
- fixed edge cases where valid `_hash` but from invalid sha-length was accepted

## Version 1.15.0
- 2017-09-11 [DIFF](https://github.com/panva/node-openid-client/compare/v1.14.0...v1.15.0)
- added support for Request Objects encrypted with symmetrical keys
- fixed PBES2 encryption to use client_secret derived symmetrical key instead of its full octet value

## Version 1.14.0
- 2017-09-09 [DIFF](https://github.com/panva/node-openid-client/compare/v1.13.0...v1.14.0)
- added Passport Strategy `passReqToCallback` option, defaults to false

## Version 1.13.0
- 2017-08-24 [DIFF](https://github.com/panva/node-openid-client/compare/v1.12.1...v1.13.0)
- added an optional keystore argument to `Client#fromUri(uri, token, [keystore])` to pass a keystore
  with private asymmetrical keys
- fixed keystore check during constructor `Client#new` calls to check that only private asymmetrical
  keys are added

## Version 1.12.0
### Version 1.12.1
- 2017-08-11 [DIFF](https://github.com/panva/node-openid-client/compare/v1.12.0...v1.12.1)
- explicitly specified accepted response type via `accept: application/json` header
- added state to token_endpoint calls for servers supporting mixup mitigation

### Version 1.12.0
- 2017-07-17 [DIFF](https://github.com/panva/node-openid-client/compare/v1.11.1...v1.12.0)
- Allow session key to be specified in passport strategy options

## Version 1.11.0
### Version 1.11.1
- 2017-07-14 [DIFF](https://github.com/panva/node-openid-client/compare/v1.11.0...v1.11.1)
- relaxed #callbackParams to allow IncomingMessage lookalikes
- update internal dependencies

### Version 1.11.0
- 2017-05-19 [DIFF](https://github.com/panva/node-openid-client/compare/v1.10.0...v1.11.0)
- fixed default application_type from `['web']` to `'web'`
- added barebones `Issuer.httpClient` setter to help advanced developers in complex environments
  to change the used http request client

## Version 1.10.0
- 2017-05-04 [DIFF](https://github.com/panva/node-openid-client/compare/v1.9.0...v1.10.0)
- added pure OAuth 2.0 stripped down callback function `#oauthCallback`
- added an extra option for `#userinfo` requests to have extra params in either query or body

## Version 1.9.0
- 2017-04-30 [DIFF](https://github.com/panva/node-openid-client/compare/v1.8.2...v1.9.0)
- added introspection/revocation specific client and issuer properties. To remain backwards
  compatible they default to their token endpoint counterparts
  - issuer.revocation_endpoint_auth_methods_supported
  - issuer.introspection_endpoint_auth_methods_supported
  - issuer.revocation_endpoint_auth_signing_alg_values_supported
  - issuer.introspection_endpoint_auth_signing_alg_values_supported
  - client.revocation_endpoint_auth_method
  - client.introspection_endpoint_auth_method
  - client.revocation_endpoint_auth_signing_alg
  - client.introspection_endpoint_auth_signing_alg

## Version 1.8.0
### Version 1.8.2
- 2017-04-29 [DIFF](https://github.com/panva/node-openid-client/compare/v1.8.0...v1.8.2)
- bumped node-jose dependency to avoid github tar.gz dependencies
- adjusted token_endpoint_auth_method=none to how it should be

### Version 1.8.0
- 2017-04-07 [DIFF](https://github.com/panva/node-openid-client/compare/v1.7.2...v1.8.0)
- Issuer and Client now recognize custom properties, this is so that new Registry Contents do not
  require a new release of openid-client to be picked up. Custom properties are exposed as getters
  so long as they do not interfere with the object's Prototype and they are always available in
  `#metadata` getter.

## Version 1.7.0
### Version 1.7.2
- 2017-03-28 [DIFF](https://github.com/panva/node-openid-client/compare/v1.7.1...v1.7.2)
- added missing check for webfinger issuer location protocol

### Version 1.7.1
- 2017-03-28 [DIFF](https://github.com/panva/node-openid-client/compare/v1.6.4...v1.7.1)
- added authorizationCallback support for submitting code_verifier
- example now includes session management OP and RP frames

1.7.0 failed to publish properly, use 1.7.1 instead

## Version 1.6.0
### Version 1.6.4
- 2017-03-14 [DIFF](https://github.com/panva/node-openid-client/compare/v1.6.3...v1.6.4)
- fixed receiving (correct) empty responses from revocation endpoints (#21)

### Version 1.6.3
- 2017-03-14 [DIFF](https://github.com/panva/node-openid-client/compare/v1.6.2...v1.6.3)
- bumped minimum node-jose version to cover http://blog.intothesymmetry.com/2017/03/critical-vulnerability-in-json-web.html

### Version 1.6.2
- 2017-03-09 [DIFF](https://github.com/panva/node-openid-client/compare/v1.6.1...v1.6.2)
- fixed verify callback skipping userinfo when userinfo_endpoint is not configured (#19)
- removed mandatory checks from passport strategy, allowing i.e. implicit only OPs (#19)

### Version 1.6.1
- 2017-03-07 [DIFF](https://github.com/panva/node-openid-client/compare/v1.6.0...v1.6.1)
- fixed verify callback skipping userinfo call when arity says it should but no access token is present (#18)

### Version 1.6.0
- 2017-02-15 [DIFF](https://github.com/panva/node-openid-client/compare/v1.5.3...v1.6.0)
- added at_hash presence assertion for applicable (implicit) ID Token validation
- added c_hash presence assertion for applicable (hybrid) ID Token validation from the authorization_endpoint

## Version 1.5.0
### Version 1.5.3
- 2017-02-15 [DIFF](https://github.com/panva/node-openid-client/compare/v1.5.2...v1.5.3)
- fixed an ID Token validation for ID Token returned by Token Endpoint that includes c_hash

### Version 1.5.2
- 2017-02-01 [DIFF](https://github.com/panva/node-openid-client/compare/v1.5.1...v1.5.2)
- fixed passport strategy, have it use prototype instead of ES6 class syntax

### Version 1.5.1
- 2017-01-29 [DIFF](https://github.com/panva/node-openid-client/compare/v1.5.0...v1.5.1)
- fixed client_assertion aud claim for `_jwt` auth methods when used in introspection and revocation

### Version 1.5.0
- 2017-01-26 [DIFF](https://github.com/panva/node-openid-client/compare/v1.4.0...v1.5.0)
- added a passport.js strategy
- added missing max_age, default_max_age related functionality
  - authorizationCallback now supports max_age check
  - clients with default_max_age use this default value automatically
  - when max_age is checked auth_time claim is mandatory and must be a number
- added missing require_auth_time related functionality
  - clients with require_auth_time = true have the presence and format of auth_time claim validated
- authorizationUrl and authorizationPost now removes null and undefined values and ensures parameters
  are stringified before passed to url.format
- added client.CLOCK_TOLERANCE property, to allow for clock skew (in seconds)

## Version 1.4.0
- 2017-01-10 [DIFF](https://github.com/panva/node-openid-client/compare/v1.3.1...v1.4.0)
- deprecated passing keystore directly to Client#register, pass an object with keystore property instead
- added the option to provide InitialAccessToken value to Client#register

## Version 1.3.0
### Version 1.3.1
- 2016-12-18 [DIFF](https://github.com/panva/node-openid-client/compare/v1.3.0...v1.3.1)
- added error messages when expected response is missing

### Version 1.3.0
- 2016-12-13 [DIFF](https://github.com/panva/node-openid-client/compare/v1.2.0...v1.3.0)
- added `#requestObject` method to Client to return signed and/or encrypted Request Object

## Version 1.2.0
- 2016-12-09 [DIFF](https://github.com/panva/node-openid-client/compare/v1.1.0...v1.2.0)
- added `#claims` getter to TokenSets returned from `authorizationCallback` and `refresh`;

## Version 1.1.0
- 2016-11-23 [DIFF](https://github.com/panva/node-openid-client/compare/v1.0.2...v1.1.0)
- fixed unpacking aggregated claims with alg=none and no iss claim
- fetching distributed claims now expects a JWT response, previously expected invalid OP responses

## Version 1.0.0
### Version 1.0.2
- 2016-11-22 [DIFF](https://github.com/panva/node-openid-client/compare/v1.0.1...v1.0.2)
- fixed signed userinfo response validation in case iss, aud and similar ID Token claims are missing

### Version 1.0.1
- 2016-11-18 [DIFF](https://github.com/panva/node-openid-client/compare/v1.0.0...v1.0.1)
- Updated uuid dependency

### Version 1.0.0
RP test tools are passing, no changes required from the library, API is declared stable, hence 1.0.0
release.

- 2016-11-16 [DIFF](https://github.com/panva/node-openid-client/compare/v0.7.0...v1.0.0)
- See [1.x migration](#migrating-from-0x-to-10) to update your 0.x deployment into 1.x.

## Migrating from 0.x to 1.0

1. update your package.json file to `"^1.0.0"`
2. sit back and relax, no breaking changes

## pre 1.x changelog

    4. Major version zero (0.y.z) is for initial development. Anything may change at any time.
       The public API should not be considered stable.

    5. Version 1.0.0 defines the public API.

- https://github.com/panva/node-openid-client/compare/v0.6.0...v0.7.0
  - added: webfinger discovery
  - added: callback parameter helper for node's http.IncomingMessage
  - tested for lts/argon (4), lts/boron (6) and current stable (7)
- https://github.com/panva/node-openid-client/compare/v0.5.4...v0.6.0
  - added: handling of symmetrically encrypted responses (A...GCMKW, A...KW, PBES2-HS...+A...KW)
  - fix: state check supersedes error check, still not sure about it though
- https://github.com/panva/node-openid-client/compare/v0.5.0...v0.5.4
  - added: token_type_hint for introspection and revocation
  - fix: handle refresh w/o id_token
  - fix: ignore nonce values when refreshing w/ id_token
  - fix: validateIdToken only checks at_hash and c_hash values when TokenSet is passed in
  - fix: session_state now part of returned TokenSet
- https://github.com/panva/node-openid-client/compare/v0.4.1...v0.5.0
  - aggregated and distributed claim handling
- https://github.com/panva/node-openid-client/compare/v0.3.0...v0.4.1
  - fix: issuer with path component discovery
  - built-in signed and/or encrypted userinfo handling
  - authorizationCallback handling of implicit and hybrid responses
- https://github.com/panva/node-openid-client/compare/v0.2.0...v0.3.0
  - encrypted userinfo and idtoken response handling
- https://github.com/panva/node-openid-client/compare/v0.1.0...v0.2.0
  - httpOptions configurable on a library level
  - signed userinfo response handling

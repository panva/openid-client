# openid-client CHANGELOG

Yay for [SemVer](http://semver.org/).

**Table of Contents**

<!-- TOC START min:2 max:2 link:true update:true -->
  - [Version 1.3.0](#version-130)
  - [Version 1.2.0](#version-120)
  - [Version 1.1.0](#version-110)
  - [Version 1.0.2](#version-102)
  - [Version 1.0.1](#version-101)
  - [Version 1.0.0](#version-100)
  - [Migrating from 0.x to 1.0](#migrating-from-0x-to-10)
  - [pre 1.x changelog](#pre-1x-changelog)

<!-- TOC END -->

## Version 1.3.0
- [DIFF](https://github.com/panva/node-openid-client/compare/v1.2.0...v1.3.0)
- added `#requestObject` method to Client to return signed and/or encrypted Request Object

## Version 1.2.0
- [DIFF](https://github.com/panva/node-openid-client/compare/v1.1.0...v1.2.0)
- added `#claims` getter to TokenSets returned from `authorizationCallback` and `refresh`;

## Version 1.1.0
- [DIFF](https://github.com/panva/node-openid-client/compare/v1.0.2...v1.1.0)
- fixed unpacking aggregated claims with alg=none and no iss claim
- fetching distributed claims now expects a JWT response, previously expected invalid OP responses

## Version 1.0.2
- [DIFF](https://github.com/panva/node-openid-client/compare/v1.0.1...v1.0.2)
- fixed signed userinfo response validation in case iss, aud and similar ID Token claims are missing

## Version 1.0.1
- [DIFF](https://github.com/panva/node-openid-client/compare/v1.0.0...v1.0.1)
- Updated uuid dependency

## Version 1.0.0
RP test tools are passing, no changes required from the library, API is declared stable, hence 1.0.0
release.

- [DIFF](https://github.com/panva/node-openid-client/compare/v0.7.0...v1.0.0)
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

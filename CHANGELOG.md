Following semver, 1.0.0 will mark the first API stable release and commence of this file,
until then please use the compare views of github for reference.

- https://github.com/panva/node-openid-client/compare/v0.5.0...v0.5.2
  - fix: handle refresh w/o id_token
  - fix: ignore nonce values when refreshing w/ id_token
  - fix: validateIdToken only checks at_hash and c_hash values when TokenSet is passed in
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

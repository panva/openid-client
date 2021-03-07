# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [4.4.2](https://github.com/panva/node-openid-client/compare/v4.4.1...v4.4.2) (2021-03-07)


### Bug Fixes

* resolve discovery URIs one by one to yield consistent results ([6b18218](https://github.com/panva/node-openid-client/commit/6b18218cfa098195ec8442086221a88fa6aef654)), closes [#260](https://github.com/panva/node-openid-client/issues/260) [#267](https://github.com/panva/node-openid-client/issues/267)

## [4.4.1](https://github.com/panva/node-openid-client/compare/v4.4.0...v4.4.1) (2021-02-26)


### Bug Fixes

* hide AggregateError message stack ([3011cca](https://github.com/panva/node-openid-client/commit/3011ccabc63e670adcee432b6565d10b55554865)), closes [#336](https://github.com/panva/node-openid-client/issues/336)

## [4.4.0](https://github.com/panva/node-openid-client/compare/v4.3.0...v4.4.0) (2021-01-29)


### Features

* allow options.https.pfx for mTSL ([075cad7](https://github.com/panva/node-openid-client/commit/075cad73a28d825128e6c92d44e7dba556b6a6f4)), closes [#326](https://github.com/panva/node-openid-client/issues/326)

## [4.3.0](https://github.com/panva/node-openid-client/compare/v4.2.3...v4.3.0) (2021-01-22)


### Features

* **typescript:** add userinfo response generics ([b176b2f](https://github.com/panva/node-openid-client/commit/b176b2f9161be77082c520ab532c237380abda22))

## [4.2.3](https://github.com/panva/node-openid-client/compare/v4.2.2...v4.2.3) (2021-01-18)


### Performance

* use base64url encoding in node when available ([24ab5b4](https://github.com/panva/node-openid-client/commit/24ab5b46c688cd1dd3679fe61a9de668c87e656b))

## [4.2.2](https://github.com/panva/node-openid-client/compare/v4.2.1...v4.2.2) (2020-11-30)


### Bug Fixes

* push pkce <> response type resolution to the authenticate function ([1970af4](https://github.com/panva/node-openid-client/commit/1970af41dc0cd62d44efb1f0a48bdc2a70bcd608)), closes [#312](https://github.com/panva/node-openid-client/issues/312)

## [4.2.1](https://github.com/panva/node-openid-client/compare/v4.2.0...v4.2.1) (2020-10-27)


### Bug Fixes

* **typescript:** add state property to AuthorizationParameters ([#305](https://github.com/panva/node-openid-client/issues/305)) ([b9dfa60](https://github.com/panva/node-openid-client/commit/b9dfa6064d7823ab0bb3eed486a3a5c7ad452982)), closes [#304](https://github.com/panva/node-openid-client/issues/304)

## [4.2.0](https://github.com/panva/node-openid-client/compare/v4.1.1...v4.2.0) (2020-10-03)


### Features

* add callback extras to strategy options ([#295](https://github.com/panva/node-openid-client/issues/295)) ([b77466d](https://github.com/panva/node-openid-client/commit/b77466ddb597accdb783bad07566f28db0d2c827))

## [4.1.1](https://github.com/panva/node-openid-client/compare/v4.1.0...v4.1.1) (2020-09-14)


### Bug Fixes

* **typescript:** ts module interop issues with default export ([6ca57d0](https://github.com/panva/node-openid-client/commit/6ca57d0ef08c188c1da7f3c980b74ba3abf33966)), closes [#291](https://github.com/panva/node-openid-client/issues/291)

## [4.1.0](https://github.com/panva/node-openid-client/compare/v4.0.2...v4.1.0) (2020-09-11)


### Features

* OAuth 2.0 DPoP in various relevant API interfaces ([44a0de7](https://github.com/panva/node-openid-client/commit/44a0de7ceb62cabacd62798ac136f1c394907028))

## [4.0.2](https://github.com/panva/node-openid-client/compare/v4.0.1...v4.0.2) (2020-09-11)


### Bug Fixes

* updated request object mime-type as per draft-ietf-oauth-jwsreq-30 ([d5cc619](https://github.com/panva/node-openid-client/commit/d5cc619cbf137c42898229546e44b8f065af6e3f))

## [4.0.1](https://github.com/panva/node-openid-client/compare/v4.0.0...v4.0.1) (2020-09-10)


### Bug Fixes

* ensure minimal got version handles upcoming node version changes ([fd737a3](https://github.com/panva/node-openid-client/commit/fd737a3598c29d7069328156e06b23d08c1f50c6))

## [4.0.0](https://github.com/panva/node-openid-client/compare/v3.15.10...v4.0.0) (2020-09-09)


### ⚠ BREAKING CHANGES

* the deprecated `issuer.key()` method was removed
* due to added ESM module support Node.js version with
ESM implementation bugs are no longer supported, this only affects early
v13.x versions. The resulting Node.js semver range is
`^10.19.0 || >=12.0.0 < 13 || >=13.7.0` (also taking into account the
`got` dependency update)
* upgraded got http request library dependency from
`v9.x` to `v11.x`. If you override some of the http request options
you will most certainly have to accomodate them.
* Signed Request Object "typ" changed from `JWT` to
`oauth.authz.req+jwt`
* Encrypted Request Object "cty" changed from `JWT` to
`oauth.authz.req+jwt`
* PKCE is now used by default in the passport strategy
* `client.userinfo()` `verb` parameter was renamed to
`method`
* the deprecated `client.resource()` method was removed

### Features

* added support for ESM (ECMAScript modules) ([3ac37e8](https://github.com/panva/node-openid-client/commit/3ac37e80d66d47e9814972ed86d1323b9ee96b79))
* passport strategy will now use PKCE by default where applicable ([56f9fe7](https://github.com/panva/node-openid-client/commit/56f9fe7171ccc1bec6427d4f9bc45e419150ab4d))


### Bug Fixes

* request object type changed from 'JWT' to 'oauth.authz.req+jwt' ([641a42f](https://github.com/panva/node-openid-client/commit/641a42fdd3097289085340afab652e4b8b9f571c))


### Refactor

* remove deprecated `client.resource()` ([c0ec865](https://github.com/panva/node-openid-client/commit/c0ec8652673c7b276a7c71eb2d730eb3feb22eeb))
* remove deprecated `issuer.key()` ([5cd1ecf](https://github.com/panva/node-openid-client/commit/5cd1ecfced358c7a685d9dc29aa451a9ef13b770))
* rename `client.userinfo()` `verb` parameter to `method` ([4cb21a4](https://github.com/panva/node-openid-client/commit/4cb21a4c2aef6421fe7a0f67d45baf209989cdd4))
* upgrade got from v9.x to v11.x ([c72b5e8](https://github.com/panva/node-openid-client/commit/c72b5e812f6a94a92e008facefa72c366728d4a5))

## [3.15.10](https://github.com/panva/node-openid-client/compare/v3.15.9...v3.15.10) (2020-09-02)


### Bug Fixes

* **typescript:** add missing types ([#284](https://github.com/panva/node-openid-client/issues/284)) ([49e0ff0](https://github.com/panva/node-openid-client/commit/49e0ff0c695cabd54148bc8a83611dd4ef6ed47c))

## [3.15.9](https://github.com/panva/node-openid-client/compare/v3.15.8...v3.15.9) (2020-07-26)


### Bug Fixes

* **typescript:** max_age in AuthorizationParameters is a number ([5ce2a73](https://github.com/panva/node-openid-client/commit/5ce2a733890dba6ba2bc2f8f296a4235c0c5cdd6)), closes [#279](https://github.com/panva/node-openid-client/issues/279)



## [3.15.8](https://github.com/panva/node-openid-client/compare/v3.15.7...v3.15.8) (2020-07-17)


### Bug Fixes

* allow AAD appid including discovery URLs to be multi-tenant ([c27caab](https://github.com/panva/node-openid-client/commit/c27caab9b9df92b591c4f0491fd2ec346ff48988))



## [3.15.7](https://github.com/panva/node-openid-client/compare/v3.15.6...v3.15.7) (2020-07-16)



## [3.15.6](https://github.com/panva/node-openid-client/compare/v3.15.5...v3.15.6) (2020-07-06)


### Bug Fixes

* merge helper returns modified object, leftovers removed ([2e3339b](https://github.com/panva/node-openid-client/commit/2e3339bd82297d6e37574e007b8a443087f3291e))



## [3.15.5](https://github.com/panva/node-openid-client/compare/v3.15.4...v3.15.5) (2020-06-26)


### Bug Fixes

* regression from [#272](https://github.com/panva/node-openid-client/issues/272) ([9bff960](https://github.com/panva/node-openid-client/commit/9bff960bda42fd8af7b8569f121ca35c7f4cfae4))



## [3.15.4](https://github.com/panva/node-openid-client/compare/v3.15.3...v3.15.4) (2020-06-26)



## [3.15.3](https://github.com/panva/node-openid-client/compare/v3.15.2...v3.15.3) (2020-06-15)


### Bug Fixes

* give AAD v1 common same treatment as v2 common ([2344e00](https://github.com/panva/node-openid-client/commit/2344e006fd4086d0df8391f9ef95cce25299e45f)), closes [#269](https://github.com/panva/node-openid-client/issues/269)



## [3.15.2](https://github.com/panva/node-openid-client/compare/v3.15.1...v3.15.2) (2020-06-01)


### Bug Fixes

* allow any JSON numeric value for timestamp values ([a24a759](https://github.com/panva/node-openid-client/commit/a24a7596c038bacd5bdbfc5b8678a96e62b86fd2)), closes [#263](https://github.com/panva/node-openid-client/issues/263)



## [3.15.1](https://github.com/panva/node-openid-client/compare/v3.15.0...v3.15.1) (2020-05-12)


### Bug Fixes

* A192CBC-HS384 and A256CBC-HS512 direct encryption key derivation ([c356bbe](https://github.com/panva/node-openid-client/commit/c356bbeaba1e28b6a56534b9ba503cb536c14d57))



## [3.15.0](https://github.com/panva/node-openid-client/compare/v3.14.2...v3.15.0) (2020-04-28)


### Features

* add RPError indicators for unix timestamp comparison failures ([fe3db5c](https://github.com/panva/node-openid-client/commit/fe3db5c46a04cab024901782f202d08234b4cd96)), closes [#250](https://github.com/panva/node-openid-client/issues/250)



## [3.14.2](https://github.com/panva/node-openid-client/compare/v3.14.1...v3.14.2) (2020-04-07)


### Bug Fixes

* **typescript:** add options arg to TypeOfGenericClient ([b97b028](https://github.com/panva/node-openid-client/commit/b97b0288d5d79f25cad3d0009212878c5d42a2e0))



## [3.14.1](https://github.com/panva/node-openid-client/compare/v3.14.0...v3.14.1) (2020-03-21)


### Bug Fixes

* assert refresh_token grant ID Token sub to equal previous ([23f3f9f](https://github.com/panva/node-openid-client/commit/23f3f9fcb88c157cf9bbfa7cc2444e07f0cedc18))



## [3.14.0](https://github.com/panva/node-openid-client/compare/v3.13.0...v3.14.0) (2020-02-28)


### Features

* support additional authorized parties ([c9268ce](https://github.com/panva/node-openid-client/commit/c9268ce24c0080729652d7ba67a7f313227dc815)), closes [#231](https://github.com/panva/node-openid-client/issues/231)



## [3.13.0](https://github.com/panva/node-openid-client/compare/v3.12.2...v3.13.0) (2020-02-18)


### Features

* add support for RSA-OAEP-384 and RSA-OAEP-512 JWE algorithms ([6c696e9](https://github.com/panva/node-openid-client/commit/6c696e98202af2a358fde72bd0718c7dff7f3a96))



## [3.12.2](https://github.com/panva/node-openid-client/compare/v3.12.1...v3.12.2) (2020-01-30)


### Bug Fixes

* ensure jose version that handles ECDH-ES for larger key sizes right ([e91001a](https://github.com/panva/node-openid-client/commit/e91001a30e0c429ef5bb49e0fda58a54f765c346))



## [3.12.1](https://github.com/panva/node-openid-client/compare/v3.12.0...v3.12.1) (2020-01-25)


### Bug Fixes

* allow multiple keys to match when selecting encryption key for request object ([fa3fa67](https://github.com/panva/node-openid-client/commit/fa3fa677709f4e229c6356896731416feff71509))



## [3.12.0](https://github.com/panva/node-openid-client/compare/v3.11.0...v3.12.0) (2020-01-23)


### Bug Fixes

* allow omitting the `*_enc` attributes (default 'A128CBC-HS256') ([6567c73](https://github.com/panva/node-openid-client/commit/6567c73996ba247d1bd46796d37a32ffa93d74a5))


### Features

* new API for fetching arbitrary resources with the access token ([c981ed6](https://github.com/panva/node-openid-client/commit/c981ed68e5cb0a53f064eb27604d8790ef3dac91)), closes [#222](https://github.com/panva/node-openid-client/issues/222)



## [3.11.0](https://github.com/panva/node-openid-client/compare/v3.10.1...v3.11.0) (2020-01-10)


### Bug Fixes

* **typescript:** allow 'id_token token' as a response type ([61c486c](https://github.com/panva/node-openid-client/commit/61c486c2b800c9299f4eaf3649711c39a6e5ce57))


### Features

* detect self-issued OP and validate ID Token accordingly ([c5d3158](https://github.com/panva/node-openid-client/commit/c5d315826a767d1479509931eddb5ae6e3b99532)), closes [#220](https://github.com/panva/node-openid-client/issues/220) [#221](https://github.com/panva/node-openid-client/issues/221)



## [3.10.1](https://github.com/panva/node-openid-client/compare/v3.10.0...v3.10.1) (2020-01-07)


### Bug Fixes

* allow duplicate "kid" values in issuer's jwks_uri (sigh) ([8840fb6](https://github.com/panva/node-openid-client/commit/8840fb6e9cb2b3f8e6396b596ff90f8f080e7f7a))



## [3.10.0](https://github.com/panva/node-openid-client/compare/v3.9.2...v3.10.0) (2019-12-27)


### Bug Fixes

* enabled full JWT validation on distributed and aggregated claims ([d95e31b](https://github.com/panva/node-openid-client/commit/d95e31bf33bf3dc9a90e420a6dc90bbfd964d885))


### Features

* allow consuming JARM responses (jwt response mode) ([dd4aae9](https://github.com/panva/node-openid-client/commit/dd4aae92eafbdde5ac11c2d7d422d150ceed45da))



## [3.9.2](https://github.com/panva/node-openid-client/compare/v3.9.1...v3.9.2) (2019-12-17)


### Bug Fixes

* skip validating iat is in the past ([0791001](https://github.com/panva/node-openid-client/commit/0791001a6e0244ac3fbde8b9e6cf206d97f82fbe))



## [3.9.1](https://github.com/panva/node-openid-client/compare/v3.9.0...v3.9.1) (2019-12-15)


### Bug Fixes

* remove check for nonce presence in params ([cac46fb](https://github.com/panva/node-openid-client/commit/cac46fb1846c853f6c519beddd5ab5bdaf0770b1))



## [3.9.0](https://github.com/panva/node-openid-client/compare/v3.8.4...v3.9.0) (2019-12-06)


### Bug Fixes

* check for mTLS request options during token_endpoint calls ([269569f](https://github.com/panva/node-openid-client/commit/269569fbb08139694589f1b27bda690b8d8474fe))
* **typescript:** complete http options ([3997687](https://github.com/panva/node-openid-client/commit/3997687cc68bf76bc92ac143c5e5fe3b9cbd3914))


### Features

* added API for fetching any resource ([ae242a5](https://github.com/panva/node-openid-client/commit/ae242a5c058386a3607af4a662dbf696938bc6f1))
* added issuer.FAPIClient for FAPI RW integrations ([ab88aa5](https://github.com/panva/node-openid-client/commit/ab88aa590fb5a853ddbd8273a713bf142a9f5049))



## [3.8.4](https://github.com/panva/node-openid-client/compare/v3.8.3...v3.8.4) (2019-11-26)


### Bug Fixes

* use shake256(m, 114) for Ed448 ID Token _hash claims ([80311c8](https://github.com/panva/node-openid-client/commit/80311c89273d9e2577dc694f1ac91a00944cc026))



## [3.8.3](https://github.com/panva/node-openid-client/compare/v3.8.2...v3.8.3) (2019-11-14)



## [3.8.2](https://github.com/panva/node-openid-client/compare/v3.8.1...v3.8.2) (2019-11-10)


### Bug Fixes

* assert jwks is present for private_key_jwk first ([c1f875c](https://github.com/panva/node-openid-client/commit/c1f875c0c4a472b2dc424bc9de21a9cbdc8ca8ad))



## [3.8.1](https://github.com/panva/node-openid-client/compare/v3.8.0...v3.8.1) (2019-11-07)


### Bug Fixes

* use sha512 for Ed25519 and shake256 for Ed448 ID Token _hash claims ([31f7a04](https://github.com/panva/node-openid-client/commit/31f7a040c289e7fd389a0083803f2998bf62b660))



## [3.8.0](https://github.com/panva/node-openid-client/compare/v3.7.4...v3.8.0) (2019-11-07)


### Features

* allow tokenType for userinfo to use as authorization header scheme ([4eaa75f](https://github.com/panva/node-openid-client/commit/4eaa75f714a744f9e712615dedc6702f4f9b7a64))



## [3.7.4](https://github.com/panva/node-openid-client/compare/v3.7.3...v3.7.4) (2019-10-24)


### Bug Fixes

* allow distributed claims to be missing from the response ([48d6633](https://github.com/panva/node-openid-client/commit/48d6633af2bb5d724c2fee2628fdfc871324bb94)), closes [#197](https://github.com/panva/node-openid-client/issues/197)



## [3.7.3](https://github.com/panva/node-openid-client/compare/v3.7.2...v3.7.3) (2019-10-01)


### Bug Fixes

* use updated jose package ([1f3a251](https://github.com/panva/node-openid-client/commit/1f3a251))



## [3.7.2](https://github.com/panva/node-openid-client/compare/v3.7.1...v3.7.2) (2019-09-13)


### Bug Fixes

* **typescript:** add missing Strategy interface properties ([c0d59c4](https://github.com/panva/node-openid-client/commit/c0d59c4)), closes [#189](https://github.com/panva/node-openid-client/issues/189)



## [3.7.1](https://github.com/panva/node-openid-client/compare/v3.7.0...v3.7.1) (2019-09-09)


### Bug Fixes

* **typescript:** remove the need for @types/got dependency ([e5a50d7](https://github.com/panva/node-openid-client/commit/e5a50d7))



## [3.7.0](https://github.com/panva/node-openid-client/compare/v3.6.2...v3.7.0) (2019-09-09)


### Bug Fixes

* assert client_secret is present when required, require client_id, etc ([82855a5](https://github.com/panva/node-openid-client/commit/82855a5))


### Features

* Add Typescript definitions ([#184](https://github.com/panva/node-openid-client/issues/184)) ([c37130b](https://github.com/panva/node-openid-client/commit/c37130b))
* allow clientAssertionPayload to overwrite default payload ([28c8964](https://github.com/panva/node-openid-client/commit/28c8964))



## [3.6.2](https://github.com/panva/node-openid-client/compare/v3.6.1...v3.6.2) (2019-09-03)


### Bug Fixes

* device authorization request always pushes the client_id to body ([6fbf125](https://github.com/panva/node-openid-client/commit/6fbf125))



## [3.6.1](https://github.com/panva/node-openid-client/compare/v3.6.0...v3.6.1) (2019-08-24)


### Bug Fixes

* ignore runtime unsupported or malformed issuer jwks ([f08b8be](https://github.com/panva/node-openid-client/commit/f08b8be))



## [3.6.0](https://github.com/panva/node-openid-client/compare/v3.5.0...v3.6.0) (2019-08-24)


### Features

* add RFC8628 - OAuth 2.0 Device Authorization Grant (Device Flow) support ([adb4b76](https://github.com/panva/node-openid-client/commit/adb4b76))
* allow multiple resource parameters in authorization requests ([dfdd8cb](https://github.com/panva/node-openid-client/commit/dfdd8cb))



## [3.5.0](https://github.com/panva/node-openid-client/compare/v3.4.0...v3.5.0) (2019-08-22)


### Features

* added Node.js lts/dubnium support for runtime supported features ([54788c2](https://github.com/panva/node-openid-client/commit/54788c2))



## [3.4.0](https://github.com/panva/node-openid-client/compare/v3.3.0...v3.4.0) (2019-08-13)


### Features

* electron v6.x runtime support ([65ec619](https://github.com/panva/node-openid-client/commit/65ec619))



## [3.3.0](https://github.com/panva/node-openid-client/compare/v3.2.3...v3.3.0) (2019-08-02)


### Features

* option to change http options globally ([a1e0a3f](https://github.com/panva/node-openid-client/commit/a1e0a3f))



## [3.2.3](https://github.com/panva/node-openid-client/compare/v3.2.2...v3.2.3) (2019-07-18)


### Bug Fixes

* **strategy:** do not modify the params argument, clone it instead ([4731d29](https://github.com/panva/node-openid-client/commit/4731d29)), closes [#177](https://github.com/panva/node-openid-client/issues/177)



## [3.2.2](https://github.com/panva/node-openid-client/compare/v3.2.1...v3.2.2) (2019-07-12)


### Bug Fixes

* give AAD v2 organizations and consumers same treatment as common ([4891b5b](https://github.com/panva/node-openid-client/commit/4891b5b)), closes [#175](https://github.com/panva/node-openid-client/issues/175)



## [3.2.1](https://github.com/panva/node-openid-client/compare/v3.2.0...v3.2.1) (2019-07-10)


### Bug Fixes

* plug reported lodash vulnerability ([b690dac](https://github.com/panva/node-openid-client/commit/b690dac))



## [3.2.0](https://github.com/panva/node-openid-client/compare/v3.1.2...v3.2.0) (2019-06-27)


### Features

* feat: added support for direct symmetric key encryption alg (dir) ([f1b4282](https://github.com/panva/node-openid-client/commit/f1b4282))



## [3.1.2](https://github.com/panva/node-openid-client/compare/v3.1.1...v3.1.2) (2019-06-21)


### Bug Fixes

* ensure runtime @panva/jose dependency ^1.3.0 ([d992deb](https://github.com/panva/node-openid-client/commit/d992deb))



## [3.1.1](https://github.com/panva/node-openid-client/compare/v3.1.0...v3.1.1) (2019-05-15)


### Bug Fixes

* passport strategy runtime authenticate parameters regression ([36e741e](https://github.com/panva/node-openid-client/commit/36e741e)), closes [#167](https://github.com/panva/node-openid-client/issues/167)



## [3.1.0](https://github.com/panva/node-openid-client/compare/v3.0.0...v3.1.0) (2019-05-13)


### Features

* add helpers for generating secure random values & PKCE challenges ([44f1865](https://github.com/panva/node-openid-client/commit/44f1865))



## [3.0.0](https://github.com/panva/node-openid-client/compare/v2.5.0...v3.0.0) (2019-05-11)


### Bug Fixes

* authorizationParams no longer requires nonce for `response_type=token`
* issuer's auth signing algs presence is now asserted if client is missing the relevant metadata property
* unintended (client|issuer).metadata[property] reassignment is no longer possible
* refreshed encrypted ID Tokens are now properly decrypted
* userinfo_endpoint presence on an issuer is now asserted during userinfo function call
* PBES2 symmetric encryption and decryption now correctly uses the `client_secret` value rather then
its SHA digest
* Accept header is now correctly set for all requests
* clients configured to receive signed and/or encrypted userinfo endpoints will now correctly reject
a response that isn't proper `application/jwt`


### Features

* **Typed Errors** - openid-client now has unique errors for HTTP transport related errors, OP/AS
returned errors and RP(client-side) assertions.
* **common configuration issues are now gracefully handled.** I feel like many developers may be
setting properties like `redirect_uri` or `response_type` on a client instance. I sympathize and
openid-client will now take these common mistakes and accomodate.
* **QoL** `#client.authorizationParams()` will now attempt to resolve the `redirect_uri` and
`response_type` from your client's metadata. If there's only one listed, it will be used
automatically. If there's more, you must continue providing it explicitly.
* **per-request http request options helper function** HTTP request options can now be modified on
a per request basis for the different classes or their instances. This now allows each request's
options to be altered on-demand with e.g. client mutual-TLS certificates or implementing work
arounds for specific AS quirks.
* **mutual-TLS client authentication** is now supported through the above mentioned helper for both
client-authentication and proof-of-possession purposes.
* **custom request bodies** Where the above per-request helper falls short is providing extra
token endpoint exchange parameters like `resource` to authorization code or refresh token exchange,
you can now pass those in the actual client methods.
* **custom client assertion payloads** You can now pass extra claims to the client authenticated
calls e.g. token, introspect, revoke.
* **request objects are now set to be one-time use** Generated Request Objects are secure by default
they include iat, exp and jti claims so that OPs have a way to make them one-time use depending on
their policy.
* **EdDSA support** OKP JSON Web Keys and EdDSA signing and verification is now supported.


### BREAKING CHANGES
* openid-client now uses `@panva/jose` for all things JOSE. As a result of this the minimum required
node version is v12.0.0 and the client will now only function in node.js environments.
* `Issuer.defaultHttpOptions` getter and setter were removed. See documentation customization
section for its replacement.
* `client.CLOCK_TOLERANCE` client property was removed. See documentation customization  section for
its replacement.
* `client.authorizationCallback()` has been renamed to `client.callback()`
* `tokenset.claims` getter is now a function `tokenset.claims()`
* `useRequest` and `useGot` methods were removed, with the maintenance mode and inevitable
deprecation of the `request` module i've decided to only support got as an http request library.
* Instead of passing jose library keystore instances with private keys the API now
expects a JWKS formatted object. `keystore` options argument properties are now called just `jwks`.
* `response_type=code` is no longer defaulted to in `#client.authorizationUrl()` if your client
instance has multiple `response_types` members.
* Strict `===` equality operator is now used for assertions, while unlikely the breaking change is
that should some ID Token claims be correct values but incorrect type, these will start failing now.
* `#client.revoke()` no longer returns or in any way processes the response body as per spec
requirements.
* All http(s) responses are now strictly checked for the expected http response status code.
* All http(s) requests now assert that an absolute URL is being requested.
* Passport Strategy will now fail when userinfo is requested via the verify callback arity but no
access token is returned from the OP.



## [2.5.0](https://github.com/panva/node-openid-client/compare/v2.4.5...v2.5.0) (2019-04-29)


### Bug Fixes

* key lookup cache is now working as intended ([90d2f2a](https://github.com/panva/node-openid-client/commit/90d2f2a)), closes [#162](https://github.com/panva/node-openid-client/issues/162)


### Features

* add support for azure ad v2 multitenant apps ([24486dd](https://github.com/panva/node-openid-client/commit/24486dd)), closes [#148](https://github.com/panva/node-openid-client/issues/148)



## [2.4.5](https://github.com/panva/node-openid-client/compare/v2.4.4...v2.4.5) (2018-11-05)


### Bug Fixes

* upgrade min node-jose version to fix its performance in node ([e682dfc](https://github.com/panva/node-openid-client/commit/e682dfc))



## [2.4.4](https://github.com/panva/node-openid-client/compare/v2.4.3...v2.4.4) (2018-10-18)


### Bug Fixes

* strategy code_verifier length, removed uuid dependency ([60d0cb8...ea4a8fd](https://github.com/panva/node-openid-client/compare/60d0cb8...ea4a8fd)), closes [#131](https://github.com/panva/node-openid-client/issues/131)



## [2.4.3](https://github.com/panva/node-openid-client/compare/v2.4.2...v2.4.3) (2018-10-10)


### Bug Fixes

* assign Discovery 1.0 defaults when discovering with .well-known ([74b593e](https://github.com/panva/node-openid-client/commit/74b593e))



## [2.4.2](https://github.com/panva/node-openid-client/compare/v2.4.1...v2.4.2) (2018-09-27)


### Bug Fixes

* non-string error responses are not treated as OpenIdConnectError ([782d464](https://github.com/panva/node-openid-client/commit/782d464)), closes [#125](https://github.com/panva/node-openid-client/issues/125)



## [2.4.1](https://github.com/panva/node-openid-client/compare/v2.4.0...v2.4.1) (2018-09-16)


### Bug Fixes

* lts/boron unsupported syntax fix ([5289188](https://github.com/panva/node-openid-client/commit/5289188))



## [2.4.0](https://github.com/panva/node-openid-client/compare/v2.3.1...v2.4.0) (2018-09-16)


### Bug Fixes

* OpenIdConnectError also returns session_state ([95fae3d](https://github.com/panva/node-openid-client/commit/95fae3d))
* stop sending state on the authorisation code token grant ([c4c9e50](https://github.com/panva/node-openid-client/commit/c4c9e50))


### Features

* add RP-Initiated Logout URL helper ([7c2e030](https://github.com/panva/node-openid-client/commit/7c2e030)), closes [#116](https://github.com/panva/node-openid-client/issues/116)



## [2.3.1](https://github.com/panva/node-openid-client/compare/v2.3.0...v2.3.1) (2018-08-23)


### Bug Fixes

* apply safer, simpler www-authenticate parsing regex ([ffce55a](https://github.com/panva/node-openid-client/commit/ffce55a))
* only assign Discovery 1.0 defaults when Issuer is discovered ([dca60b8](https://github.com/panva/node-openid-client/commit/dca60b8))



## [2.3.0](https://github.com/panva/node-openid-client/compare/v2.2.1...v2.3.0) (2018-08-11)


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

# openid-client API Reference

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

## You are probably looking for this

| Name | Description |
| ------ | ------ |
| [authorizationCodeGrant](functions/authorizationCodeGrant.md) | Processes an authorization response and performs the Authorization Code Grant. |
| [buildAuthorizationUrl](functions/buildAuthorizationUrl.md) | Builds an authorization request URL. |
| [ClientMetadata](interfaces/ClientMetadata.md) | Client metadata that affects openid-client behavior. |
| [discovery](functions/discovery.md) | Discovers authorization server metadata and creates a client configuration. |
| [ServerMetadata](interfaces/ServerMetadata.md) | Metadata describing an OAuth 2.0 authorization server. |

## Configuration

| Name | Description |
| ------ | ------ |
| [Configuration](classes/Configuration.md) | Represents an authorization server and its client configuration. |
| [discovery](functions/discovery.md) | Discovers authorization server metadata and creates a client configuration. |

## Grants

| Function | Description |
| ------ | ------ |
| [authorizationCodeGrant](functions/authorizationCodeGrant.md) | Processes an authorization response and performs the Authorization Code Grant. |
| [clientCredentialsGrant](functions/clientCredentialsGrant.md) | Performs an OAuth 2.0 Client Credentials Grant. |
| [genericGrantRequest](functions/genericGrantRequest.md) | Performs an arbitrary OAuth grant request. |
| [initiateBackchannelAuthentication](functions/initiateBackchannelAuthentication.md) | Initiates a Client-Initiated Backchannel Authentication request. |
| [initiateDeviceAuthorization](functions/initiateDeviceAuthorization.md) | Initiates an OAuth 2.0 Device Authorization Grant. |
| [pollBackchannelAuthenticationGrant](functions/pollBackchannelAuthenticationGrant.md) | Polls until a Client-Initiated Backchannel Authentication Grant completes. |
| [pollDeviceAuthorizationGrant](functions/pollDeviceAuthorizationGrant.md) | Polls until an OAuth 2.0 Device Authorization Grant completes. |
| [refreshTokenGrant](functions/refreshTokenGrant.md) | Performs an OAuth 2.0 Refresh Token Grant. |

## Advanced Configuration

| Function | Description |
| ------ | ------ |
| [~~allowInsecureRequests~~](functions/allowInsecureRequests.md) | By default the module only allows interactions with HTTPS endpoints. This removes that restriction. |
| [dynamicClientRegistration](functions/dynamicClientRegistration.md) | Discovers an authorization server and dynamically registers a client. |
| [enableDecryptingResponses](functions/enableDecryptingResponses.md) | Enables processing of encrypted authorization server responses. |
| [enableDetachedSignatureResponseChecks](functions/enableDetachedSignatureResponseChecks.md) | Enables FAPI 1.0 Advanced detached-signature response validation. |
| [enableNonRepudiationChecks](functions/enableNonRepudiationChecks.md) | Enables JWS signature validation for processed JWT responses. |
| [getJwksCache](functions/getJwksCache.md) | Exports the JSON Web Key Set cache used for signature validation. |
| [setJwksCache](functions/setJwksCache.md) | Imports an externally managed JSON Web Key Set cache. |
| [useCodeIdTokenResponseType](functions/useCodeIdTokenResponseType.md) | Configures the client to use the OpenID Connect Hybrid Flow. |
| [useIdTokenResponseType](functions/useIdTokenResponseType.md) | Configures the client to use the OpenID Connect Implicit Flow. |
| [useJwtResponseMode](functions/useJwtResponseMode.md) | Configures the client to use JWT Secured Authorization Response Mode (JARM). |

## Client Authentication Methods

| Function | Description |
| ------ | ------ |
| [ClientSecretBasic](functions/ClientSecretBasic.md) | Creates a `client_secret_basic` client authentication method. |
| [ClientSecretJwt](functions/ClientSecretJwt.md) | Creates a `client_secret_jwt` client authentication method. |
| [ClientSecretPost](functions/ClientSecretPost.md) | Creates a `client_secret_post` client authentication method. |
| [None](functions/None.md) | Creates a `none` client authentication method. |
| [PrivateKeyJwt](functions/PrivateKeyJwt.md) | Creates a `private_key_jwt` client authentication method. |
| [TlsClientAuth](functions/TlsClientAuth.md) | Creates a `tls_client_auth` client authentication method. |

## Errors

| Class | Description |
| ------ | ------ |
| [AuthorizationResponseError](classes/AuthorizationResponseError.md) | Thrown when an OAuth 2.0 Authorization Error Response is encountered. |
| [ClientError](classes/ClientError.md) | An error raised by openid-client. |
| [ResponseBodyError](classes/ResponseBodyError.md) | Thrown when a server returns an OAuth-style error in a JSON response body. |
| [WWWAuthenticateChallengeError](classes/WWWAuthenticateChallengeError.md) | Thrown when a server response contains one or more parseable `WWW-Authenticate` challenges. |

## Authorization Request

| Function | Description |
| ------ | ------ |
| [buildAuthorizationUrl](functions/buildAuthorizationUrl.md) | Builds an authorization request URL. |
| [buildAuthorizationUrlWithJAR](functions/buildAuthorizationUrlWithJAR.md) | Builds an authorization request URL using a JWT Secured Authorization Request (JAR). |
| [buildAuthorizationUrlWithPAR](functions/buildAuthorizationUrlWithPAR.md) | Builds an authorization request URL using Pushed Authorization Requests (PAR). |
| [calculatePKCECodeChallenge](functions/calculatePKCECodeChallenge.md) | Calculates an S256 PKCE `code_challenge` from a `code_verifier`. |
| [randomNonce](functions/randomNonce.md) | Generates a random OpenID Connect `nonce` value. |
| [randomState](functions/randomState.md) | Generates a random OAuth 2.0 `state` value. |

## DPoP

| Function | Description |
| ------ | ------ |
| [getDPoPHandle](functions/getDPoPHandle.md) | Creates a DPoP handle for sender-constrained token requests. |
| [randomDPoPKeyPair](functions/randomDPoPKeyPair.md) | Generates an asymmetric key pair for signing DPoP proofs. |

## Dynamic Client Registration (DCR)

| Function | Description |
| ------ | ------ |
| [dynamicClientRegistration](functions/dynamicClientRegistration.md) | Discovers an authorization server and dynamically registers a client. |

## OpenID Connect 1.0

| Function | Description |
| ------ | ------ |
| [authorizationCodeGrant](functions/authorizationCodeGrant.md) | Processes an authorization response and performs the Authorization Code Grant. |
| [buildEndSessionUrl](functions/buildEndSessionUrl.md) | Builds an RP-Initiated Logout URL. |
| [discovery](functions/discovery.md) | Discovers authorization server metadata and creates a client configuration. |
| [fetchUserInfo](functions/fetchUserInfo.md) | Fetches and parses OpenID Connect UserInfo claims. |
| [implicitAuthentication](functions/implicitAuthentication.md) | Validates an OpenID Connect Implicit Flow response. |

## PKCE

| Function | Description |
| ------ | ------ |
| [authorizationCodeGrant](functions/authorizationCodeGrant.md) | Processes an authorization response and performs the Authorization Code Grant. |
| [calculatePKCECodeChallenge](functions/calculatePKCECodeChallenge.md) | Calculates an S256 PKCE `code_challenge` from a `code_verifier`. |
| [randomPKCECodeVerifier](functions/randomPKCECodeVerifier.md) | Generates a random PKCE `code_verifier` value. |

## Protected Resource Requests

| Function | Description |
| ------ | ------ |
| [fetchProtectedResource](functions/fetchProtectedResource.md) | Fetches an arbitrary OAuth 2.0 protected resource. |
| [fetchUserInfo](functions/fetchUserInfo.md) | Fetches and parses OpenID Connect UserInfo claims. |

## Token Management

| Function | Description |
| ------ | ------ |
| [tokenIntrospection](functions/tokenIntrospection.md) | Retrieves the status and metadata of an OAuth 2.0 token. |
| [tokenRevocation](functions/tokenRevocation.md) | Requests revocation of an OAuth 2.0 token. |

## Interfaces

| Interface | Description |
| ------ | ------ |
| [AuthorizationCodeGrantChecks](interfaces/AuthorizationCodeGrantChecks.md) | Expected values and validation checks for an Authorization Code Grant response. |
| [AuthorizationCodeGrantOptions](interfaces/AuthorizationCodeGrantOptions.md) | Options for performing an Authorization Code Grant. |
| [AuthorizationDetails](interfaces/AuthorizationDetails.md) | An entry in an OAuth 2.0 Rich Authorization Requests `authorization_details` array. |
| [BackchannelAuthenticationGrantPollOptions](interfaces/BackchannelAuthenticationGrantPollOptions.md) | Options for polling a Client-Initiated Backchannel Authentication Grant. |
| [BackchannelAuthenticationResponse](interfaces/BackchannelAuthenticationResponse.md) | A parsed successful Client-Initiated Backchannel Authentication response. |
| [ConfigurationMethods](interfaces/ConfigurationMethods.md) | Methods exposed by a [Configuration](classes/Configuration.md) instance. |
| [ConfigurationProperties](interfaces/ConfigurationProperties.md) | Configurable properties exposed by a [Configuration](classes/Configuration.md) instance. |
| [ConfirmationClaims](interfaces/ConfirmationClaims.md) | Proof-of-possession confirmation (`cnf`) claims associated with a token. |
| [CryptoKeyPair](interfaces/CryptoKeyPair.md) | An asymmetric public and private `CryptoKey` pair. |
| [CustomFetchOptions](interfaces/CustomFetchOptions.md) | Options passed to a custom HTTP request implementation. |
| [DecryptionKey](interfaces/DecryptionKey.md) | An asymmetric private key and optional JOSE metadata used to decrypt responses. |
| [DeviceAuthorizationGrantPollOptions](interfaces/DeviceAuthorizationGrantPollOptions.md) | Options for polling an OAuth 2.0 Device Authorization Grant. |
| [DeviceAuthorizationResponse](interfaces/DeviceAuthorizationResponse.md) | A parsed successful OAuth 2.0 Device Authorization Response. |
| [DiscoveryRequestOptions](interfaces/DiscoveryRequestOptions.md) | Options for authorization server metadata discovery. |
| [DPoPHandle](interfaces/DPoPHandle.md) | A DPoP proof-generation and nonce-management handle returned by [getDPoPHandle](functions/getDPoPHandle.md). |
| [DPoPOptions](interfaces/DPoPOptions.md) | Options for making DPoP-bound requests. |
| [DynamicClientRegistrationRequestOptions](interfaces/DynamicClientRegistrationRequestOptions.md) | Options for Dynamic Client Registration requests. |
| [ExportedJWKSCache](interfaces/ExportedJWKSCache.md) | A JSON Web Key Set cache value suitable for external persistence. |
| [GenerateKeyPairOptions](interfaces/GenerateKeyPairOptions.md) | Options for generating an asymmetric signing key pair. |
| [IDToken](interfaces/IDToken.md) | Claims from a validated OpenID Connect ID Token. |
| [ImplicitAuthenticationResponseChecks](interfaces/ImplicitAuthenticationResponseChecks.md) | Expected values and validation checks for an OpenID Connect Implicit Flow response. |
| [IntrospectionResponse](interfaces/IntrospectionResponse.md) | A parsed successful OAuth 2.0 Token Introspection response. |
| [JWKS](interfaces/JWKS.md) | A JSON Web Key Set. |
| [ModifyAssertionFunction](interfaces/ModifyAssertionFunction.md) | A callback that mutates a JWT assertion header and claims immediately before signing. |
| [ModifyAssertionOptions](interfaces/ModifyAssertionOptions.md) | Options for customizing a JWT assertion immediately before signing. |
| [MTLSEndpointAliases](interfaces/MTLSEndpointAliases.md) | Authorization server endpoint aliases used for mutual TLS. |
| [PrivateKey](interfaces/PrivateKey.md) | An asymmetric private key with an optional JWK Key ID for JOSE headers. |
| [ServerMetadataHelpers](interfaces/ServerMetadataHelpers.md) | Helpers for querying authorization server capabilities. |
| [TokenEndpointResponse](interfaces/TokenEndpointResponse.md) | A parsed successful OAuth 2.0 token endpoint response. |
| [TokenEndpointResponseHelpers](interfaces/TokenEndpointResponseHelpers.md) | Helpers attached to a parsed [TokenEndpointResponse](interfaces/TokenEndpointResponse.md). |
| [UserInfoAddress](interfaces/UserInfoAddress.md) | The structured `address` claim in an OpenID Connect UserInfo response. |
| [UserInfoResponse](interfaces/UserInfoResponse.md) | Claims from a parsed OpenID Connect UserInfo response. |
| [WWWAuthenticateChallenge](interfaces/WWWAuthenticateChallenge.md) | A parsed `WWW-Authenticate` challenge. |
| [WWWAuthenticateChallengeParameters](interfaces/WWWAuthenticateChallengeParameters.md) | Known and extension authentication parameters from a `WWW-Authenticate` challenge. |

## Type Aliases

| Type Alias | Description |
| ------ | ------ |
| [ClientAuth](type-aliases/ClientAuth.md) | A function that applies client authentication to an authorization server request. |
| [CryptoKey](type-aliases/CryptoKey.md) | A Web Cryptography key as declared by the host runtime. |
| [CustomFetch](type-aliases/CustomFetch.md) | A Fetch API-compatible function used for outbound HTTP requests. |
| [FetchBody](type-aliases/FetchBody.md) | A request body supported by openid-client's Fetch API integration. |
| [JsonArray](type-aliases/JsonArray.md) | A JSON array. |
| [JsonObject](type-aliases/JsonObject.md) | A JSON object. |
| [JsonPrimitive](type-aliases/JsonPrimitive.md) | A JSON primitive value. |
| [JsonValue](type-aliases/JsonValue.md) | Any JSON-compatible value. |
| [JWK](type-aliases/JWK.md) | A JSON Web Key with standard JOSE and supported extension parameters. |
| [JWSAlgorithm](type-aliases/JWSAlgorithm.md) | A supported JWS `alg` identifier for digital signature validation. |
| [OmitSymbolProperties](type-aliases/OmitSymbolProperties.md) | Removes symbol-keyed properties from a type. |

## Variables

| Variable | Description |
| ------ | ------ |
| [clockSkew](variables/clockSkew.md) | Adjusts the current time used by protocol validations. |
| [clockTolerance](variables/clockTolerance.md) | Sets the allowed clock tolerance for JWT timestamp claim validation. |
| [customFetch](variables/customFetch.md) | Overrides the Fetch API implementation used for outbound HTTP requests. |
| [modifyAssertion](variables/modifyAssertion.md) | Provides a hook for mutating JWT headers and claims immediately before signing. |
| [~~skipStateCheck~~](variables/skipStateCheck.md) | Skips authorization response `state` validation. |
| [~~skipSubjectCheck~~](variables/skipSubjectCheck.md) | Skips UserInfo `sub` claim validation. |

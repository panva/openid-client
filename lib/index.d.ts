/// <reference types="@panva/jose" />
/// <reference types="node" />

/**
 * @see https://github.com/panva/node-openid-client/blob/master/docs/README.md
 */
declare module 'openid-client' {
  import { JWKS } from '@panva/jose'
  import { IncomingMessage } from 'http'
  import { Http2ServerRequest } from 'http2'

  /**
   * @see https://medium.com/@darutk/diagrams-of-all-the-openid-connect-flows-6968e3990660
   */
  enum AuthResponseType {
    CODE = 'code',
    TOKEN = 'token',
    ID_TOKEN = 'id_token',
  }

  /**
   * @see https://github.com/panva/node-openid-client/blob/master/docs/README.md#client-authentication-methods
   */
  enum TokenAuthMethod {
    BASIC = 'client_secret_basic',
    POST = 'client_secret_post',
    CLIENT_SECRET_JWT = 'client_secret_jwt',
    PRIVATE_KEY_JWT = 'private_key_jwt',
    TLS_CLIENT_AUTH = 'tls_client_auth'
  }

  /**
   * @see https://github.com/panva/node-openid-client/blob/master/docs/README.md#new-clientmetadata-jwks
   */
  export interface IClientMetadata {
    client_id: string
    client_secret?: string
    id_token_signed_response_alg?: string
    id_token_encrypted_response_alg?: string
    id_token_encrypted_response_enc?: string
    userinfo_signed_response_alg?: string
    userinfo_encrypted_response_alg?: string
    userinfo_encrypted_response_enc?: string
    redirect_uris?: string[]
    response_types?: AuthResponseType[]
    post_logout_redirect_uris?: string[]
    default_max_age?: number
    require_auth_time?: boolean
    request_object_signing_alg?: string
    request_object_encryption_alg?: string
    request_object_encryption_enc?: string
    token_endpoint_auth_method?: TokenAuthMethod
    introspection_endpoint_auth_method?: TokenAuthMethod
    revocation_endpoint_auth_method?: TokenAuthMethod
    token_endpoint_auth_signing_alg?: string
    introspection_endpoint_auth_signing_alg?: string
    revocation_endpoint_auth_signing_alg?: string
    tls_client_certificate_bound_access_tokens?: boolean

    [key: string]: any
  }

  export interface IAuthorizationUrlParams {
    redirect_uri?: string
    response_type?: string
    scope?: string,
    [key: string]: any
  }

  export interface IEndSessionUrlParams {
    id_token_hint?: TokenType
    post_logout_redirect_uri?: string
    state?: string
  }

  export type CallbackParamsType = {
    state?: string
    response_type?: string
    nonce?: string
    code_verifier?: string
    [key: string]: any
  }

  export type TokenType = string | TokenSet

  export interface ICallbackChecks {
    /**
     * When provided the authorization response will be checked for presence of required parameters for a
     * given response_type. Use of this check is recommended.
     */
    response_type?: string
    /**
     * When provided the authorization response's state parameter will be checked to be the this expected one.
     * Use of this check is required if you sent a state parameter into an authorization request.
     */
    state?: string
    /**
     * PKCE code_verifier to be sent to the token endpoint during code exchange. Use of this check is required
     * if you sent a code_challenge parameter into an authorization request.
     */
    code_verifier?: string
  }

  export interface IExtendedCallbackChecks extends ICallbackChecks {
    /**
     * When provided the authorization response's ID Token auth_time parameter will be checked to be conform to the
     * max_age value. Use of this check is required if you sent a max_age parameter into an authorization request.
     */
    max_age?: number
    /**
     * When provided the authorization response's ID Token nonce parameter will be checked to be the this expected
     * one. Use of this check is required if you sent a nonce parameter into an authorization request.
     */
    nonce?: string
  }

  export interface ICallbackExtras {
    /**
     * extra request body properties to be sent to the AS during code exchange.
     */
    exchangeBody?: object
    /**
     * extra client assertion payload parameters to be sent as part of a client JWT assertion. This is only used
     * when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
     */
    clientAssertionPayload?: object
  }

  export interface IRefreshExtras {
    /**
     * extra request body properties to be sent to the AS during refresh token exchange.
     */
    exchangeBody?: object
    /**
     * extra client assertion payload parameters to be sent as part of a client JWT assertion.
     * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
     */
    clientAssertionPayload?: object
  }

  export interface IGrantBody {
    grant_type: string
    [key: string]: any
  }

  export interface IGrantExtras {
    /**
     * extra client assertion payload parameters to be sent as part of a client JWT assertion.
     * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
     */
    clientAssertionPayload?: object
  }

  export interface IIntrospectExtras {
    /**
     * extra request body properties to be sent to the introspection endpoint.
     */
    introspectBody?: object
    /**
     * extra client assertion payload parameters to be sent as part of a client JWT assertion.
     * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
     */
    clientAssertionPayload: object
  }

  export interface IRevokeExtras {
    /**
     * extra request body properties to be sent to the revocation endpoint.
     */
    revokeBody?: object
    /**
     * extra client assertion payload parameters to be sent as part of a client JWT assertion.
     * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
     */
    clientAssertionPayload?: object
  }

  export interface IRequestObjectPayload {
    client_id?: string
    iss?: string
    aud?: string
    iat?: number
    exp?: number
    jti?: string
    [key: string]: any
  }

  export interface IRegisterOther {
    /**
     * JWK Set formatted object with private keys used for signing client assertions or decrypting responses.
     * When neither jwks_uri or jwks is present in metadata the key's public parts will be registered as jwks.
     */
    jwks?: object
    /**
     * Initial Access Token to use as a Bearer token during the registration call.
     */
    initialAccessToken?: string
  }

  export interface IDeviceAuthParameters {
    client_id?: string
    scope?: string
    [key: string]: any
  }

  export interface IDeviceAuthExtras {
    /**
     * extra request body properties to be sent to the AS during the Device Access Token Request
     */
    exchangeBody?: object
    /**
     * extra client assertion payload parameters to be sent as part of a client JWT assertion.
     * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
     */
    clientAssertionPayload?: object
  }

  /**
   * Encapsulates a dynamically registered, discovered or instantiated OpenID Connect Client (Client),
   * Relying Party (RP), and its metadata, its instances hold the methods for getting an authorization URL,
   * consuming callbacks, triggering token endpoint grants, revoking and introspecting tokens.
   */
  export interface IClient {
    metadata?: IClientMetadata

    /**
     * Returns the target authorization redirect URI to redirect End-Users to using the provided parameters.
     */
    authorizationUrl (parameters?: IAuthorizationUrlParams): string

    /**
     * Returns the target logout redirect URI to redirect End-Users to using the provided parameters.
     * @param parameters
     */
    endSessionUrl (parameters?: IEndSessionUrlParams): string

    /**
     * Returns recognized callback parameters from a provided input.
     *
     * - When input is of type string it will be parsed using url.parse and its query component will be returned
     * - When input is a GET http/http2 request object its url property will be parsed using url.parse and its
     * query component will be returned
     * - When input is a POST http/http2 request object its body property will be parsed or returned if it is already
     * an object. Note: the request read stream will not be parsed, it is expected that you will have a body parser
     * prior to calling this method. This parser would set the req.body property
     */
    callbackParams (input: string | IncomingMessage | Http2ServerRequest): CallbackParamsType

    /**
     * Performs the callback for Authorization Server's authorization response.
     * @param redirectUri redirect_uri used for the authorization request
     * @param parameters returned authorization response, see client.callbackParams if you need help getting them.
     * @param checks
     * @param extras
     */
    callback(redirectUri: string, parameters: CallbackParamsType, checks?: IExtendedCallbackChecks, extras?: ICallbackExtras) : Promise<TokenSet>

    /**
     * Pure OAuth 2.0 version of callback().
     * @param redirectUri
     * @param parameters
     * @param checks
     * @param extras
     */
    oauthCallback(redirectUri: string, parameters: CallbackParamsType, checks?: ICallbackChecks, extras?: ICallbackExtras) : Promise<TokenSet>

    /**
     * Performs refresh_token grant type exchange.
     * @param refreshToken Refresh Token value. When TokenSet instance is provided its refresh_token property
     * will be used automatically.
     * @param extras
     */
    refresh(refreshToken: TokenType, extras?: IRefreshExtras) : Promise<TokenSet>

    /**
     * Fetches the OIDC userinfo response with the provided Access Token. Also handles signed and/or
     * encrypted userinfo responses. When TokenSet is provided as an argument the userinfo sub property
     * will also be checked to match the on in the TokenSet's ID Token.
     *
     * @param accessToken Access Token value. When TokenSet instance is provided its access_token property
     * will be used automatically.
     */
    userinfo(accessToken: TokenType) : Promise<object>

    /**
     * Performs an arbitrary grant_type exchange at the token_endpoint.
     */
    grant(body: IGrantBody, extras?: IGrantExtras) : Promise<TokenSet>

    /**
     * Introspects a token at the Authorization Server's introspection_endpoint.
     */
    introspect(token: string, tokenTypeHint?: string, extras?: IIntrospectExtras) : Promise<object>

    /**
     * Revokes a token at the Authorization Server's revocation_endpoint.
     */
    revoke(token, tokenTypeHint?: string, extras?: IRevokeExtras) : Promise<void>

    /**
     * Creates a signed and optionally encrypted Request Object to send to the AS. Uses the client's
     * request_object_signing_alg, request_object_encryption_alg, request_object_encryption_enc metadata for
     * determining the algorithms to use.
     */
    requestObject(payload: IRequestObjectPayload): Promise<string>

    /**
     * Starts a Device Authorization Request at the issuer's device_authorization_endpoint and returns a handle
     * for subsequent Device Access Token Request polling.
     */
    deviceAuthorization(parameters?: IDeviceAuthParameters, extras?: IDeviceAuthExtras): Promise<IDeviceFlowHandle>

    [key: string]: any
  }

  export class Client implements IClient {
    constructor (metadata: IClientMetadata, jwks?: object)

    metadata: IClientMetadata
    authorizationUrl (parameters?: IAuthorizationUrlParams): string
    endSessionUrl (parameters?: IEndSessionUrlParams): string
    callbackParams (input: string | IncomingMessage | Http2ServerRequest): CallbackParamsType
    callback(redirectUri: string, parameters: CallbackParamsType, checks?: IExtendedCallbackChecks, extras?: ICallbackExtras) : Promise<TokenSet>
    oauthCallback(redirectUri: string, parameters: CallbackParamsType, checks?: ICallbackChecks, extras?: ICallbackExtras) : Promise<TokenSet>
    refresh(refreshToken: TokenType, extras?: IRefreshExtras) : Promise<TokenSet>
    userinfo(accessToken: TokenType) : Promise<object>
    grant(body: IGrantBody, extras?: IGrantExtras) : Promise<TokenSet>
    introspect(token: string, tokenTypeHint?: string, extras?: IIntrospectExtras) : Promise<object>
    revoke(token, tokenTypeHint?: string, extras?: IRevokeExtras) : Promise<void>
    requestObject(payload: IRequestObjectPayload): Promise<string>
    deviceAuthorization(parameters?: IDeviceAuthParameters, extras?: IDeviceAuthExtras): Promise<IDeviceFlowHandle>
    static register(metadata: object, other?: IRegisterOther): Promise<IClient>
    static fromUri(registrationClientUri: string, registrationAccessToken: string, jwks?: object): Promise<IClient>
  }

  export interface IDeviceFlowHandleParams {
    client: IClient
    exchangeBody: object
    clientAssertionPayload: object
    response: string
    maxAge: number
  }

  export interface IDeviceFlowHandle {
    poll() : Promise<TokenSet>
    expired() : boolean
    expires_at: number
    client: IClient
    maxAge: number
    exchangeBody: object
    clientAssertionPayload: object
    response: string
    interval: number
    user_code: string
    device_code: string
    verification_uri: string
    verification_uri_complete: string
    expires_in: number
  }

  export class DeviceFlowHandle implements IDeviceFlowHandle {
    constructor (params : IDeviceFlowHandleParams)
    poll() : Promise<TokenSet>
    expired() : boolean
    // tslint:disable-next-line:variable-name
    expires_at: number
    client: IClient
    maxAge: number
    exchangeBody: object
    clientAssertionPayload: object
    response: string
    interval: number
    // tslint:disable-next-line:variable-name
    user_code: string
    // tslint:disable-next-line:variable-name
    device_code: string
    // tslint:disable-next-line:variable-name
    verification_uri: string
    // tslint:disable-next-line:variable-name
    verification_uri_complete: string
    // tslint:disable-next-line:variable-name
    expires_in: number
  }

  export interface IIssuerMetadata {
    issuer: string
    authorization_endpoint: string
    token_endpoint: string
    jwks_uri: string
    userinfo_endpoint: string
    revocation_endpoint: string
    end_session_endpoint: string
    registration_endpoint: string
    token_endpoint_auth_methods_supported: string
    token_endpoint_auth_signing_alg_values_supported: string
    introspection_endpoint_auth_methods_supported: string
    introspection_endpoint_auth_signing_alg_values_supported: string
    revocation_endpoint_auth_methods_supported: string
    revocation_endpoint_auth_signing_alg_values_supported: string
    request_object_signing_alg_values_supported: string
    mtls_endpoint_aliases: IMetadataMtlsEndpointAliases

    [key: string]: any
  }

  export interface IMetadataMtlsEndpointAliases {
    token_endpoint: string
    userinfo_endpoint: string
    revocation_endpoint: string
    introspection_endpoint: string
  }

  /**
   * Encapsulates a discovered or instantiated OpenID Connect Issuer (Issuer), Identity Provider (IdP),
   * Authorization Server (AS) and its metadata.
   */
  export interface IIssuer {
    /**
     * Returns the <Client> class tied to this issuer.
     */
    Client: { new (metadata: IClientMetadata, jwks?: object) }

    /**
     * Returns metadata from the issuer's discovery document.
     */
    metadata?: IIssuerMetadata

    /**
     * Returns the issuer's jwks_uri keys as a @panva/jose parsed JWKS.Keystore.
     * @param forceReload
     */
    keystore (forceReload?: boolean): Promise<JWKS.KeyStore>

    [key: string]: any
  }

  export class Issuer implements IIssuer {
    constructor (metadata: IIssuerMetadata)
    Client: typeof Client
    metadata: IIssuerMetadata
    keystore (forceReload?: boolean): Promise<JWKS.KeyStore>

    /**
     * Loads OpenID Connect 1.0 and/or OAuth 2.0 Authorization Server Metadata documents.
     * When the issuer argument contains '.well-known' only that document is loaded, otherwise
     * performs both openid-configuration and oauth-authorization-server requests.
     * @param issuer Issuer Identifier or metadata URL
     */
    static discover (issuer: string): Promise<Issuer>

    /**
     * Performs OpenID Provider Issuer Discovery based on End-User input.
     * @param input EMAIL, URL, Hostname and Port, acct or syntax input
     */
    static webfinger (input: string): Promise<Issuer>
  }

  export interface ITokenSetParams {
    /**
     * The raw access token in JWT format
     */
    access_token?: string
    /**
     * Usually "Bearer"
     */
    token_type?: string
    /**
     * The raw id token in JWT format
     */
    id_token?: string
    /**
     * Refresh token, opaque string value
     */
    refresh_token?: string
    /**
     * space-separated scope(s) used for the authentication request
     */
    scope?: string
    expires_in?: number
    expires_at?: number
    /**
     * State value passed in the authentication request
     */
    session_state?: string | object

    [key: string]: any
  }

  /**
   * Creates a new TokenSet from the provided response. E.g. parsed token endpoint response, parsed callback
   * parameters. You only need to instantiate a TokenSet yourself if you recall it from e.g. distributed cache
   * storage or a database. Note: manually constructed TokenSet instances do not undergo any validations.
   */
  export class TokenSet implements ITokenSetParams {
    // tslint:disable-next-line:variable-name
    access_token?: string
    // tslint:disable-next-line:variable-name
    token_type?: string
    // tslint:disable-next-line:variable-name
    id_token?: string
    // tslint:disable-next-line:variable-name
    refresh_token?: string
    // tslint:disable-next-line:variable-name
    expires_in?: number
    // tslint:disable-next-line:variable-name
    expires_at?: number
    // tslint:disable-next-line:variable-name
    session_state?: string | object
    scope?: string

    constructor (input?: ITokenSetParams)

    /**
     * Given that the instance has expires_at / expires_in this function returns true / false when the
     * access token (which expires properties are for) is beyond its lifetime.
     */
    expired(): boolean

    /**
     * Given that the instance has an id_token this function returns its parsed payload object.
     * Does not perform any validations as these were done prior to openid-client returning the
     * tokenset in the first place.
     */
    claims(): object

    [key: string]: any
  }
}

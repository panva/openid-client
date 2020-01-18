/// <reference types="node" />
// TypeScript Version: 3.6

/* tslint:disable:strict-export-declare-modifiers */

/**
 * @see https://github.com/panva/node-openid-client/blob/master/docs/README.md
 */
import * as http from 'http';
import * as https from 'https';
import * as http2 from 'http2';
import * as tls from 'tls';

import { GotOptions, GotPromise } from 'got';
import { URL } from 'url';
import { JWKS, JSONWebKeySet } from 'jose';

export type HttpOptions = GotOptions<string | null>;
export type RetryFunction = (retry: number, error: Error) => number;
export type CustomHttpOptionsProvider = (options: HttpOptions) => HttpOptions;
export type TokenTypeHint = 'access_token' | 'refresh_token' | string;

/**
 * @see https://github.com/panva/node-openid-client/blob/master/lib/index.js
 */
export const custom: {
  setHttpOptionsDefaults(params: HttpOptions): undefined;
  readonly http_options: unique symbol;
  readonly clock_tolerance: unique symbol;
};

/**
 * @see https://medium.com/@darutk/diagrams-of-all-the-openid-connect-flows-6968e3990660
 */
export type ResponseType = 'code' | 'id_token' | 'code id_token' | 'id_token token' | 'code token' | 'code id_token token' | 'none';
/**
 * @see https://github.com/panva/node-openid-client/blob/master/docs/README.md#client-authentication-methods
 */
export type ClientAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'tls_client_auth' | 'self_signed_tls_client_auth' | 'none';

/**
 * @see https://github.com/panva/node-openid-client/blob/master/docs/README.md#new-clientmetadata-jwks
 */
export interface ClientMetadata {
  // important
  client_id: string;
  id_token_signed_response_alg?: string;
  token_endpoint_auth_method?: ClientAuthMethod;
  client_secret?: string;
  redirect_uris?: string[];
  response_types?: ResponseType[];
  post_logout_redirect_uris?: string[];
  default_max_age?: number;
  require_auth_time?: boolean;
  tls_client_certificate_bound_access_tokens?: boolean;
  request_object_signing_alg?: string;

  // less important
  id_token_encrypted_response_alg?: string;
  id_token_encrypted_response_enc?: string;
  introspection_endpoint_auth_method?: ClientAuthMethod;
  introspection_endpoint_auth_signing_alg?: string;
  request_object_encryption_alg?: string;
  request_object_encryption_enc?: string;
  revocation_endpoint_auth_method?: ClientAuthMethod;
  revocation_endpoint_auth_signing_alg?: string;
  token_endpoint_auth_signing_alg?: string;
  userinfo_encrypted_response_alg?: string;
  userinfo_encrypted_response_enc?: string;
  userinfo_signed_response_alg?: string;
  authorization_encrypted_response_alg?: string;
  authorization_encrypted_response_enc?: string;
  authorization_signed_response_alg?: string;

  [key: string]: unknown;
}

export interface ClaimsParameterMember {
  essential?: boolean;
  value?: string;
  values?: string[];

  [key: string]: unknown;
}

export interface AuthorizationParameters {
  acr_values?: string;
  audience?: string;
  claims?: string | {
    id_token?: {
      [key: string]: null | ClaimsParameterMember
    }
    userinfo?: {
      [key: string]: null | ClaimsParameterMember
    }
  };
  claims_locales?: string;
  client_id?: string;
  code_challenge_method?: string;
  code_challenge?: string;
  display?: string;
  id_token_hint?: string;
  login_hint?: string;
  max_age?: string;
  nonce?: string;
  prompt?: string;
  redirect_uri?: string;
  registration?: string;
  request_uri?: string;
  request?: string;
  resource?: string | string[];
  response_mode?: string;
  response_type?: string;
  scope?: string;
  ui_locales?: string;

  [key: string]: unknown;
}

export interface EndSessionParameters {
  id_token_hint?: TokenSet | string;
  post_logout_redirect_uri?: string;
  state?: string;

  [key: string]: unknown;
}

export interface CallbackParamsType {
  access_token?: string;
  code?: string;
  error?: string;
  error_description?: string;
  error_uri?: string;
  expires_in?: string;
  id_token?: string;
  state?: string;
  token_type?: string;
  session_state?: string;
  response?: string;

  [key: string]: unknown;
}

export interface OAuthCallbackChecks {
  /**
   * When provided the authorization response will be checked for presence of required parameters for a
   * given response_type. Use of this check is recommended.
   */
  response_type?: string;
  /**
   * When provided the authorization response's state parameter will be checked to be the this expected one.
   * Use of this check is required if you sent a state parameter into an authorization request.
   */
  state?: string;
  /**
   * PKCE code_verifier to be sent to the token endpoint during code exchange. Use of this check is required
   * if you sent a code_challenge parameter into an authorization request.
   */
  code_verifier?: string;
  /**
   * This must be set to true when requesting JARM responses.
   */
  jarm?: boolean;
}

export interface OpenIDCallbackChecks extends OAuthCallbackChecks {
  /**
   * When provided the authorization response's ID Token auth_time parameter will be checked to be conform to the
   * max_age value. Use of this check is required if you sent a max_age parameter into an authorization request.
   */
  max_age?: number;
  /**
   * When provided the authorization response's ID Token nonce parameter will be checked to be the this expected
   * one. Use of this check is required if you sent a nonce parameter into an authorization request.
   */
  nonce?: string;
}

export interface CallbackExtras {
  /**
   * extra request body properties to be sent to the AS during code exchange.
   */
  exchangeBody?: object;
  /**
   * extra client assertion payload parameters to be sent as part of a client JWT assertion. This is only used
   * when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
   */
  clientAssertionPayload?: object;
}

export interface RefreshExtras {
  /**
   * extra request body properties to be sent to the AS during refresh token exchange.
   */
  exchangeBody?: object;
  /**
   * extra client assertion payload parameters to be sent as part of a client JWT assertion.
   * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
   */
  clientAssertionPayload?: object;
}

export interface GrantBody {
  grant_type: string;

  [key: string]: unknown;
}

export interface GrantExtras {
  /**
   * extra client assertion payload parameters to be sent as part of a client JWT assertion.
   * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
   */
  clientAssertionPayload?: object;
}

export interface IntrospectExtras {
  /**
   * extra request body properties to be sent to the introspection endpoint.
   */
  introspectBody?: object;
  /**
   * extra client assertion payload parameters to be sent as part of a client JWT assertion.
   * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
   */
  clientAssertionPayload?: object;
}

export interface RevokeExtras {
  /**
   * extra request body properties to be sent to the revocation endpoint.
   */
  revokeBody?: object;
  /**
   * extra client assertion payload parameters to be sent as part of a client JWT assertion.
   * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
   */
  clientAssertionPayload?: object;
}

export interface RequestObjectPayload extends AuthorizationParameters {
  client_id?: string;
  iss?: string;
  aud?: string;
  iat?: number;
  exp?: number;
  jti?: string;

  [key: string]: unknown;
}

export interface RegisterOther {
  /**
   * JWK Set formatted object with private keys used for signing client assertions or decrypting responses.
   * When neither jwks_uri or jwks is present in metadata the key's public parts will be registered as jwks.
   */
  jwks?: JSONWebKeySet;
  /**
   * Initial Access Token to use as a Bearer token during the registration call.
   */
  initialAccessToken?: string;
}

export interface DeviceAuthorizationParameters {
  client_id?: string;
  scope?: string;

  [key: string]: unknown;
}

export interface DeviceAuthorizationExtras {
  /**
   * extra request body properties to be sent to the AS during the Device Access Token Request
   */
  exchangeBody?: object;
  /**
   * extra client assertion payload parameters to be sent as part of a client JWT assertion.
   * This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt.
   */
  clientAssertionPayload?: object;
}

export interface UserinfoResponse {
  sub: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  updated_at?: number;
  address?: {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;

    [key: string]: unknown;
  };

  [key: string]: unknown;
}

export interface IntrospectionResponse {
  active: boolean;
  client_id?: string;
  exp?: number;
  iat?: number;
  sid?: string;
  iss?: string;
  jti?: string;
  username?: string;
  aud?: string | string[];
  scope: string;
  token_type?: string;
  cnf?: {
    'x5t#S256'?: string;

    [key: string]: unknown;
  };

  [key: string]: unknown;
}

/**
 * Encapsulates a dynamically registered, discovered or instantiated OpenID Connect Client (Client),
 * Relying Party (RP), and its metadata, its instances hold the methods for getting an authorization URL,
 * consuming callbacks, triggering token endpoint grants, revoking and introspecting tokens.
 */
export class Client {
  constructor(metadata: ClientMetadata, jwks?: JSONWebKeySet);
  [custom.http_options]: CustomHttpOptionsProvider;
  [custom.clock_tolerance]: number;
  metadata: ClientMetadata;

  /**
   * Returns the target authorization redirect URI to redirect End-Users to using the provided parameters.
   * @param parameters Authorization Request parameters
   */
  authorizationUrl(parameters?: AuthorizationParameters): string;

  /**
   * Returns the target logout redirect URI to redirect End-Users to using the provided parameters.
   * @param parameters RP-Initiated Logout Request parameters
   */
  endSessionUrl(parameters?: EndSessionParameters): string;

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
  callbackParams(input: string | http.IncomingMessage | http2.Http2ServerRequest): CallbackParamsType;

  /**
   * Performs the callback for Authorization Server's authorization response.
   * @param redirectUri redirect_uri used for the authorization request
   * @param parameters returned authorization response, see client.callbackParams if you need help getting them.
   * @param checks checks to perform on the Authorization Response
   * @param extras add extra parameters to the Token Endpoint Request and/or Client Authentication JWT Assertion
   */
  callback(redirectUri: string | undefined, parameters: CallbackParamsType, checks?: OpenIDCallbackChecks, extras?: CallbackExtras): Promise<TokenSet>;

  /**
   * Pure OAuth 2.0 version of callback().
   * @param redirectUri redirect_uri used for the authorization request
   * @param parameters returned authorization response, see client.callbackParams if you need help getting them.
   * @param checks checks to perform on the Authorization Response
   * @param extras add extra parameters to the Token Endpoint Request and/or Client Authentication JWT Assertion
   */
  oauthCallback(redirectUri: string | undefined, parameters: CallbackParamsType, checks?: OAuthCallbackChecks, extras?: CallbackExtras): Promise<TokenSet>;

  /**
   * Performs refresh_token grant type exchange.
   * @param refreshToken Refresh Token value. When TokenSet instance is provided its refresh_token property
   * will be used automatically.
   * @param extras Add extra parameters to the Token Endpoint Request and/or Client Authentication JWT Assertion
   */
  refresh(refreshToken: TokenSet | string, extras?: RefreshExtras): Promise<TokenSet>;

  /**
   * Fetches the OIDC userinfo response with the provided Access Token. Also handles signed and/or
   * encrypted userinfo responses. When TokenSet is provided as an argument the userinfo sub property
   * will also be checked to match the on in the TokenSet's ID Token.
   *
   * @param accessToken Access Token value. When TokenSet instance is provided its access_token property
   * will be used automatically.
   * @param options Options for the UserInfo request.
   */
  userinfo(accessToken: TokenSet | string, options?: { verb?: 'GET' | 'POST', via?: 'header' | 'body' | 'query', tokenType?: string, params?: object }): Promise<UserinfoResponse>;

  /**
   * @deprecated in favor of client.requestResource
   */
  resource(resourceUrl: string, accessToken: TokenSet | string, options?: { headers?: object, verb?: 'GET' | 'POST', via?: 'header' | 'body' | 'query', tokenType?: string }): GotPromise<Buffer>;

  /**
   * Fetches an arbitrary resource with the provided Access Token in an Authorization header.
   *
   * @param resourceUrl Resource URL to request a response from.
   * @param accessToken Access Token value. When TokenSet instance is provided its access_token property
   * will be used automatically.
   * @param options Options for the request.
   */
  requestResource(resourceUrl: string | URL, accessToken: TokenSet | string, options?: {
    headers?: object
    body: string | Buffer
    method?: 'GET' | 'POST' | 'PUT' | 'HEAD' | 'DELETE' | 'OPTIONS' | 'TRACE'
    tokenType?: string
  }): GotPromise<Buffer>;

  /**
   * Performs an arbitrary grant_type exchange at the token_endpoint.
   */
  grant(body: GrantBody, extras?: GrantExtras): Promise<TokenSet>;

  /**
   * Introspects a token at the Authorization Server's introspection_endpoint.
   */
  introspect(token: string, tokenTypeHint?: TokenTypeHint, extras?: IntrospectExtras): Promise<IntrospectionResponse>;

  /**
   * Revokes a token at the Authorization Server's revocation_endpoint.
   */
  revoke(token: string, tokenTypeHint?: TokenTypeHint, extras?: RevokeExtras): Promise<undefined>;

  /**
   * Creates a signed and optionally encrypted Request Object to send to the AS. Uses the client's
   * request_object_signing_alg, request_object_encryption_alg, request_object_encryption_enc metadata for
   * determining the algorithms to use.
   */
  requestObject(payload: RequestObjectPayload): Promise<string>;

  /**
   * Starts a Device Authorization Request at the issuer's device_authorization_endpoint and returns a handle
   * for subsequent Device Access Token Request polling.
   */
  deviceAuthorization(parameters?: DeviceAuthorizationParameters, extras?: DeviceAuthorizationExtras): Promise<DeviceFlowHandle<Client>>;
  static register(metadata: object, other?: RegisterOther): Promise<Client>;
  static fromUri(registrationClientUri: string, registrationAccessToken: string, jwks?: JSONWebKeySet): Promise<Client>;
  static [custom.http_options]: CustomHttpOptionsProvider;

  [key: string]: unknown;
}

export class DeviceFlowHandle<TClient extends Client> { // tslint:disable-line:no-unnecessary-generics
  poll(): Promise<TokenSet>;
  expired(): boolean;
  expires_at: number;
  client: TClient;
  user_code: string;
  device_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
}

export interface IssuerMetadata {
  issuer: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  jwks_uri?: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  end_session_endpoint?: string;
  registration_endpoint?: string;
  token_endpoint_auth_methods_supported?: string[];
  token_endpoint_auth_signing_alg_values_supported?: string[];
  introspection_endpoint_auth_methods_supported?: string[];
  introspection_endpoint_auth_signing_alg_values_supported?: string[];
  revocation_endpoint_auth_methods_supported?: string[];
  revocation_endpoint_auth_signing_alg_values_supported?: string[];
  request_object_signing_alg_values_supported?: string[];
  mtls_endpoint_aliases?: MtlsEndpointAliases;

  [key: string]: unknown;
}

export interface MtlsEndpointAliases {
  token_endpoint?: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  device_authorization_endpoint?: string;
}

// https://stackoverflow.com/questions/40249906/using-a-generic-type-argument-with-typeof-t
// https://stackoverflow.com/questions/39622778/what-is-new-in-typescript
// https://github.com/Microsoft/TypeScript/issues/204
export interface TypeOfGenericClient<TClient extends Client> {
  new (metadata: ClientMetadata, jwks?: JSONWebKeySet): TClient;
  [custom.http_options]: CustomHttpOptionsProvider;
  [custom.clock_tolerance]: number;
}

/**
 * Encapsulates a discovered or instantiated OpenID Connect Issuer (Issuer), Identity Provider (IdP),
 * Authorization Server (AS) and its metadata.
 */
export class Issuer<TClient extends Client> { // tslint:disable-line:no-unnecessary-generics
  constructor(metadata: IssuerMetadata);

  /**
   * Returns the <Client> class tied to this issuer.
   */
  Client: TypeOfGenericClient<TClient>;

  /**
   * Returns the <FAPIClient> class tied to this issuer.
   */
  FAPIClient: TypeOfGenericClient<TClient>;

  /**
   * Returns metadata from the issuer's discovery document.
   */
  metadata: IssuerMetadata;
  [custom.http_options]: CustomHttpOptionsProvider;

  /**
   * Returns the issuer's jwks_uri keys as a `jose` parsed JWKS.Keystore.
   * @param forceReload forces a reload of the issuer's jwks_uri
   */
  keystore(forceReload?: boolean): Promise<JWKS.KeyStore>;

  /**
   * Loads OpenID Connect 1.0 and/or OAuth 2.0 Authorization Server Metadata documents.
   * When the issuer argument contains '.well-known' only that document is loaded, otherwise
   * performs both openid-configuration and oauth-authorization-server requests.
   * @param issuer Issuer Identifier or metadata URL
   */
  static discover(issuer: string): Promise<Issuer<Client>>;

  /**
   * Performs OpenID Provider Issuer Discovery based on End-User input.
   * @param input EMAIL, URL, Hostname and Port, acct or syntax input
   */
  static webfinger(input: string): Promise<Issuer<Client>>;

  static [custom.http_options]: CustomHttpOptionsProvider;

  [key: string]: unknown;
}

export interface TokenSetParameters {
  /**
   * The raw access token in JWT format
   */
  access_token?: string;
  /**
   * Usually "Bearer"
   */
  token_type?: string;
  /**
   * The raw id token in JWT format
   */
  id_token?: string;
  /**
   * Refresh token, opaque string value
   */
  refresh_token?: string;
  /**
   * space-separated scope(s) used for the authentication request
   */
  scope?: string;

  /**
   * When the token set was received the expires_at field was calculated based on current timestamp
   * and the expires_in. When recalling a TokenSet instance just the expires_at should be passed in.
   */
  expires_at?: number;
  /**
   * State value passed in the authentication request
   */
  session_state?: string;

  [key: string]: unknown;
}

export interface IdTokenClaims extends UserinfoResponse {
  acr?: string;
  amr?: string[];
  at_hash?: string;
  aud: string | string[];
  auth_time?: number;
  azp?: string;
  c_hash?: string;
  exp: number;
  iat: number;
  iss: string;
  nonce?: string;
  s_hash?: string;
  sub: string;

  [key: string]: unknown;
}

/**
 * Creates a new TokenSet from the provided response. E.g. parsed token endpoint response, parsed callback
 * parameters. You only need to instantiate a TokenSet yourself if you recall it from e.g. distributed cache
 * storage or a database. Note: manually constructed TokenSet instances do not undergo any validations.
 */
export class TokenSet implements TokenSetParameters {
  access_token?: string;
  token_type?: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  expires_at?: number;
  session_state?: string;
  scope?: string;

  constructor(input?: TokenSetParameters);

  /**
   * Given that the instance has expires_at / expires_in this function returns true / false when the
   * access token (which expires properties are for) is beyond its lifetime.
   */
  expired(): boolean;

  /**
   * Given that the instance has an id_token this function returns its parsed payload object.
   * Does not perform any validations as these were done prior to openid-client returning the
   * tokenset in the first place.
   */
  claims(): IdTokenClaims;

  [key: string]: unknown;
}

export type StrategyVerifyCallbackUserInfo<TUser> = (tokenset: TokenSet, userinfo: UserinfoResponse, done: (err: any, user?: TUser) => void) => void;
export type StrategyVerifyCallback<TUser> = (tokenset: TokenSet, done: (err: any, user?: TUser) => void) => void;
export type StrategyVerifyCallbackReqUserInfo<TUser> = (req: http.IncomingMessage, tokenset: TokenSet, userinfo: UserinfoResponse, done: (err: any, user?: TUser) => void) => void;
export type StrategyVerifyCallbackReq<TUser> = (req: http.IncomingMessage, tokenset: TokenSet, done: (err: any, user?: TUser) => void) => void;

export interface StrategyOptions<TClient extends Client> {
  client: TClient;
  /**
   * Authorization Request parameters. The strategy will use these.
   */
  params?: AuthorizationParameters;
  /**
   * Boolean specifying whether the verify function should get the request object as first argument instead.
   * Default: 'false'
   */
  passReqToCallback?: boolean;
  /**
   * The PKCE method to use. When 'true' it will resolve based on the issuer metadata, when 'false' no PKCE will be
   * used. Default: 'false'
   */
  usePKCE?: boolean | string;
  /**
   * The PKCE method to use. When 'true' it will resolve based on the issuer metadata, when 'false' no PKCE will be
   * used. Default: 'false'
   */
  sessionKey?: string;
}

// tslint:disable-next-line:no-unnecessary-class
export class Strategy<TUser, TClient extends Client> { // tslint:disable-line:no-unnecessary-generics
  constructor(options: StrategyOptions<TClient>, verify: StrategyVerifyCallback<TUser> | StrategyVerifyCallbackUserInfo<TUser> |
    StrategyVerifyCallbackReq<TUser> | StrategyVerifyCallbackReqUserInfo<TUser>)

  authenticate(req: any, options?: any): void;
  success(user: any, info?: any): void;
  fail(challenge: any, status: number): void;
  fail(status: number): void;
  redirect(url: string, status?: number): void;
  pass(): void;
  error(err: Error): void;
}

/**
 * @see https://github.com/panva/node-openid-client/blob/master/lib/helpers/generators.js
 */
export namespace generators {
  /**
   * Generates random bytes and encodes them in url safe base64.
   * @param bytes Number indicating the number of bytes to generate. Default: 32
   */
  function random(bytes?: number): string;

  /**
   * Generates random bytes and encodes them in url safe base64.
   * @param bytes Number indicating the number of bytes to generate. Default: 32
   */
  function state(bytes?: number): string;

  /**
   * Generates random bytes and encodes them in url safe base64.
   * @param bytes Number indicating the number of bytes to generate. Default: 32
   */
  function nonce(bytes?: number): string;

  /**
   * Generates random bytes and encodes them in url safe base64.
   * @param bytes Number indicating the number of bytes to generate. Default: 32
   */
  function codeVerifier(bytes?: number): string;
  /**
   * Calculates the S256 PKCE code challenge for an arbitrary code verifier.
   * Encodes in url safe base64.
   * @param verifier Code verifier to calculate the S256 code challenge for
   */
  function codeChallenge(verifier: string): string;
}

/**
 * @see https://github.com/panva/node-openid-client/blob/master/lib/errors.js
 */
export namespace errors {
  /**
   * Error class thrown when a regular OAuth 2.0 / OIDC style error is returned by the AS or an
   * unexpected response is sent by the OP.
   */
  class OPError extends Error {
    /**
     * The 'error_description' parameter from the AS response.
     */
    error_description?: string;
    /**
     * The 'error' parameter from the AS response.
     */
    error?: string;
    /**
     * The 'error_uri' parameter from the AS response.
     */
    error_uri?: string;
    /**
     * The 'state' parameter from the AS response.
     */
    state?: string;
    /**
     * The 'scope' parameter from the AS response.
     */
    scope?: string;
    /**
     * The 'session_state' parameter from the AS response.
     */
    session_state?: string;

    /**
     * When the error is related to an http(s) request this propetty will hold the  response object
     * from got.
     */
    response?: any;
  }

  /**
   * Error class thrown when client-side response expectations/validations fail to pass.
   * Depending on the context it may or may not have additional context-based properties like
   * checks, jwt, params or body.
   */
  class RPError extends Error {
    jwt?: string;
    checks?: object;
    params?: object;
    body?: object;
    /**
     * When the error is related to an http(s) request this propetty will hold the response object
     * from got.
     */
    response?: any;
  }
}

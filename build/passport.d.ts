import * as client from './index.js';
import type * as express from 'express';
import type passport from 'passport';
export type VerifyFunction = (
/**
 * Parsed Token Endpoint Response returned by the authorization server with
 * attached helpers.
 */
tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers, verified: passport.AuthenticateCallback) => void;
export type VerifyFunctionWithRequest = (req: express.Request, 
/**
 * Parsed Token Endpoint Response returned by the authorization server with
 * attached helpers.
 */
tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers, verified: passport.AuthenticateCallback) => void;
export interface AuthenticateOptions extends passport.AuthenticateOptions {
    /**
     * OAuth 2.0 Resource Indicator(s) to use for the request either for the
     * authorization request or token endpoint request, depending on whether it's
     * part of {@link Strategy.authenticate} options during the initial redirect or
     * callback phase.
     *
     * This is a request-specific override for {@link StrategyOptions.resource}.
     */
    resource?: string | string[];
    /**
     * Login Hint to use for the authorization request. It is ignored for token
     * endpoint requests.
     */
    loginHint?: string;
    /**
     * ID Token Hint to use for the authorization request. It is ignored for token
     * endpoint requests.
     */
    idTokenHint?: string;
    /**
     * OAuth 2.0 Rich Authorization Requests to use for the authorization request.
     * It is ignored for token endpoint requests.
     *
     * This is a request-specific override for
     * {@link StrategyOptions.authorizationDetails}.
     */
    authorizationDetails?: client.AuthorizationDetails | client.AuthorizationDetails[];
    /**
     * OpenID Connect prompt. This will be used as the `prompt` authorization
     * request parameter unless specified through other means.
     */
    prompt?: string;
    /**
     * OAuth 2.0 scope to use for the authorization request. It is ignored for
     * token endpoint requests.
     *
     * This is a request-specific override for {@link StrategyOptions.scope}.
     */
    scope?: string | string[];
    /**
     * The state option is ignored by this strategy.
     *
     * @deprecated
     */
    state?: never;
    /**
     * OAuth 2.0 redirect_uri to use for the request either for the authorization
     * request or token endpoint request, depending on whether it's part of
     * {@link Strategy.authenticate} options during the initial redirect or
     * callback phase.
     *
     * This is a request-specific override for {@link StrategyOptions.callbackURL}.
     *
     * Note: The option is called "callbackURL" to keep some continuity and
     * familiarity with other oauth-based strategies in the passport ecosystem,
     * namely "passport-oauth2".
     */
    callbackURL?: URL | string;
}
/**
 * Retrieve an openid-client DPoPHandle for a given request.
 */
export type getDPoPHandle = (req: express.Request) => Promise<client.DPoPHandle | undefined> | client.DPoPHandle | undefined;
interface StrategyOptionsBase {
    /**
     * Openid-client Configuration instance.
     */
    config: client.Configuration;
    /**
     * Name of the strategy, default is the host component of the authorization
     * server's issuer identifier.
     */
    name?: string;
    /**
     * Property in the session to use for storing the authorization request state,
     * default is the host component of the authorization server's issuer
     * identifier.
     */
    sessionKey?: string;
    /**
     * Function used to retrieve an openid-client DPoPHandle for a given request,
     * when provided the strategy will use DPoP where applicable.
     */
    DPoP?: getDPoPHandle;
    /**
     * An absolute URL to which the authorization server will redirect the user
     * after obtaining authorization. The {@link !URL} instance's `href` will be
     * used as the `redirect_uri` authorization request and token endpoint request
     * parameters. When string is provided it will be internally casted to a
     * {@link URL} instance.
     */
    callbackURL?: URL | string;
    /**
     * OAuth 2.0 Authorization Request Scope. This will be used as the `scope`
     * authorization request parameter unless specified through other means.
     */
    scope?: string;
    /**
     * OAuth 2.0 Rich Authorization Request(s). This will be used as the
     * `authorization_details` authorization request parameter unless specified
     * through other means.
     */
    authorizationDetails?: client.AuthorizationDetails | client.AuthorizationDetails[];
    /**
     * OAuth 2.0 Resource Indicator(s). This will be used as the `resource`
     * authorization request parameter unless specified through other means.
     */
    resource?: string | string[];
    /**
     * Whether the strategy will use PAR. Default is `false`.
     */
    usePAR?: boolean;
    /**
     * Whether the strategy will use JAR. Its value can be a private key to sign
     * with or an array with the private key and a modify assertion function that
     * will be used to modify the request object before it is signed. Default is
     * `false`.
     */
    useJAR?: false | client.CryptoKey | client.PrivateKey | [client.CryptoKey | client.PrivateKey, client.ModifyAssertionFunction];
    /**
     * Whether the verify function should get the `req` as first argument instead.
     * Default is `false`.
     */
    passReqToCallback?: boolean;
}
export interface StrategyOptions extends StrategyOptionsBase {
    passReqToCallback?: false;
}
export interface StrategyOptionsWithRequest extends StrategyOptionsBase {
    passReqToCallback: true;
}
export declare class Strategy implements passport.Strategy {
    /**
     * Name of the strategy
     */
    readonly name: string;
    constructor(options: StrategyOptions, verify: VerifyFunction);
    constructor(options: StrategyOptionsWithRequest, verify: VerifyFunctionWithRequest);
    /**
     * [Strategy method] Return additional authorization request parameters.
     *
     * This method is intended to be overloaded if additional parameters need to
     * be included an authorization request are needed.
     *
     * By default this method takes care of adding the corresponding authorization
     * endpoint parameters when
     * {@link AuthenticateOptions.authorizationDetails authorizationDetails},
     * {@link AuthenticateOptions.idTokenHint idTokenHint},
     * {@link AuthenticateOptions.loginHint loginHint},
     * {@link AuthenticateOptions.prompt prompt},
     * {@link AuthenticateOptions.resource resource}, or
     * {@link AuthenticateOptions.scope scope} properties of
     * {@link AuthenticateOptions} are used.
     *
     * @param req
     * @param options This is the value originally passed to
     *   `passport.authenticate()` as its `options` argument.
     */
    authorizationRequestParams<TOptions extends AuthenticateOptions>(req: express.Request, options: TOptions): URLSearchParams | Record<string, string> | undefined;
    /**
     * [Strategy method] Return additional token endpoint request parameters.
     *
     * This method is intended to be overloaded if additional parameters to be
     * included in the authorization code grant token endpoint request are
     * needed.
     *
     * By default this method takes care of adding the `resource` token endpoint
     * parameters when {@link AuthenticateOptions.resource} is used.
     *
     * @param req
     * @param options This is the value originally passed to
     *   `passport.authenticate()` as its `options` argument.
     */
    authorizationCodeGrantParameters<TOptions extends AuthenticateOptions>(req: express.Request, options: TOptions): URLSearchParams | Record<string, string> | undefined;
    /**
     * [Strategy method] Return the current request URL.
     *
     * This method is intended to be overloaded if its return value does not match
     * the actual URL the authorization server redirected the user to.
     *
     * - Its `searchParams` are used as the authorization response parameters when
     *   the authorization response request is a GET.
     * - Its resulting `href` value (after stripping its `searchParams` and `hash`)
     *   is used as the `redirect_uri` authorization code grant token endpoint
     *   parameter unless {@link AuthenticateOptions.callbackURL}, or
     *   {@link StrategyOptionsBase.callbackURL} are used in which case those are
     *   used as the `redirect_uri` parameter instead.
     *
     * Default is
     *
     * ```ts
     * function currentUrl(req: express.Request): URL {
     *   return new URL(
     *     `${req.protocol}://${req.host}${req.originalUrl ?? req.url}`,
     *   )
     * }
     * ```
     *
     * When behind a reverse proxy it assumes common proxy headers are in use and
     * that
     * {@link https://expressjs.com/en/guide/behind-proxies.html Express (behind proxies docs)},
     * or
     * {@link https://fastify.dev/docs/latest/Reference/Server/#trustproxy Fastify (trustProxy docs)}
     * are properly configured to trust them.
     */
    currentUrl(req: express.Request): URL;
    /**
     * [Strategy method] Determine whether to initiate an authorization request.
     *
     * This method is intended to be overloaded if custom logic for determining
     * whether to initiate an authorization request or process an authorization
     * response.
     *
     * By default, this method returns `true` when the request method is GET and
     * the current URL does not contain `code`, `error`, or `response` query
     * parameters, indicating that this is an initial authorization request rather
     * than a callback from the authorization server.
     *
     * @param req
     * @param currentUrl The current request URL as determined by
     *   {@link Strategy.currentUrl}
     * @param options This is the value originally passed to
     *   `passport.authenticate()` as its `options` argument.
     */
    shouldInitiateAuthRequest<TOptions extends AuthenticateOptions>(req: express.Request, currentUrl: URL, options: TOptions): boolean;
    /**
     * [Passport method] Authenticate the request.
     */
    authenticate<TOptions extends AuthenticateOptions>(this: passport.StrategyCreated<Strategy, Strategy & passport.StrategyCreatedStatic>, req: express.Request, options: TOptions): void;
}
export {};

import * as client from './index.js'

import type * as express from 'express'
import type passport from 'passport'

export type VerifyFunction = (
  /**
   * Parsed Token Endpoint Response returned by the authorization server with
   * attached helpers.
   */
  tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers,
  verified: passport.AuthenticateCallback,
) => void

export type VerifyFunctionWithRequest = (
  req: express.Request,
  /**
   * Parsed Token Endpoint Response returned by the authorization server with
   * attached helpers.
   */
  tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers,
  verified: passport.AuthenticateCallback,
) => void

export interface AuthenticateOptions extends passport.AuthenticateOptions {
  /**
   * OAuth 2.0 Resource Indicator(s) to use for the request either for the
   * authorization request or token endpoint request, depending on whether it's
   * part of {@link Strategy.authenticate} options during the initial redirect or
   * callback phase.
   *
   * This is a request-specific override for {@link StrategyOptions.resource}.
   */
  resource?: string | string[]

  /**
   * Login Hint to use for the authorization request. It is ignored for token
   * endpoint requests.
   */
  loginHint?: string

  /**
   * ID Token Hint to use for the authorization request. It is ignored for token
   * endpoint requests.
   */
  idTokenHint?: string

  /**
   * OAuth 2.0 Rich Authorization Requests to use for the authorization request.
   * It is ignored for token endpoint requests.
   *
   * This is a request-specific override for
   * {@link StrategyOptions.authorizationDetails}.
   */
  authorizationDetails?:
    | client.AuthorizationDetails
    | client.AuthorizationDetails[]

  /**
   * OpenID Connect prompt. This will be used as the `prompt` authorization
   * request parameter unless specified through other means.
   */
  prompt?: string

  /**
   * OAuth 2.0 scope to use for the authorization request. It is ignored for
   * token endpoint requests.
   *
   * This is a request-specific override for {@link StrategyOptions.scope}.
   */
  scope?: string | string[]

  /**
   * The state option is ignored by this strategy.
   *
   * @deprecated
   */
  state?: never

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
  callbackURL?: URL | string
}

/**
 * Retrieve an openid-client DPoPHandle for a given request.
 */
export type getDPoPHandle = (
  req: express.Request,
) => Promise<client.DPoPHandle | undefined> | client.DPoPHandle | undefined

interface StrategyOptionsBase {
  /**
   * Openid-client Configuration instance.
   */
  config: client.Configuration

  /**
   * Name of the strategy, default is the host component of the authorization
   * server's issuer identifier.
   */
  name?: string

  /**
   * Property in the session to use for storing the authorization request state,
   * default is the host component of the authorization server's issuer
   * identifier.
   */
  sessionKey?: string

  /**
   * Function used to retrieve an openid-client DPoPHandle for a given request,
   * when provided the strategy will use DPoP where applicable.
   */
  DPoP?: getDPoPHandle

  /**
   * An absolute URL to which the authorization server will redirect the user
   * after obtaining authorization. The {@link !URL} instance's `href` will be
   * used as the `redirect_uri` authorization request and token endpoint request
   * parameters. When string is provided it will be internally casted to a
   * {@link URL} instance.
   */
  callbackURL?: URL | string

  /**
   * OAuth 2.0 Authorization Request Scope. This will be used as the `scope`
   * authorization request parameter unless specified through other means.
   */
  scope?: string

  /**
   * OAuth 2.0 Rich Authorization Request(s). This will be used as the
   * `authorization_details` authorization request parameter unless specified
   * through other means.
   */
  authorizationDetails?:
    | client.AuthorizationDetails
    | client.AuthorizationDetails[]

  /**
   * OAuth 2.0 Resource Indicator(s). This will be used as the `resource`
   * authorization request parameter unless specified through other means.
   */
  resource?: string | string[]

  /**
   * Whether the strategy will use PAR. Default is `false`.
   */
  usePAR?: boolean

  /**
   * Whether the strategy will use JAR. Its value can be a private key to sign
   * with or an array with the private key and a modify assertion function that
   * will be used to modify the request object before it is signed. Default is
   * `false`.
   */
  useJAR?:
    | false
    | client.CryptoKey
    | client.PrivateKey
    | [client.CryptoKey | client.PrivateKey, client.ModifyAssertionFunction]

  /**
   * Whether the verify function should get the `req` as first argument instead.
   * Default is `false`.
   */
  passReqToCallback?: boolean
}

export interface StrategyOptions extends StrategyOptionsBase {
  passReqToCallback?: false
}
export interface StrategyOptionsWithRequest extends StrategyOptionsBase {
  passReqToCallback: true
}

function setResource(params: URLSearchParams, resource: string | string[]) {
  if (Array.isArray(resource)) {
    for (const value of resource) {
      params.append('resource', value)
    }
  } else {
    params.set('resource', resource)
  }
}

function setAuthorizationDetails(
  params: URLSearchParams,
  authorizationDetails:
    | client.AuthorizationDetails
    | client.AuthorizationDetails[],
) {
  if (Array.isArray(authorizationDetails)) {
    params.set('authorization_details', JSON.stringify(authorizationDetails))
  } else {
    params.set('authorization_details', JSON.stringify([authorizationDetails]))
  }
}

/**
 * Taken from express@5 req.host implementation to get around the fact that
 * req.host in express@4 is not the host but hostname. Catches errors stemming
 * from possibly not using express and returns req.host for compatibility with
 * e.g. fastify-express.
 */
function host(req: express.Request): string | undefined {
  try {
    const trust = req.app.get('trust proxy fn')
    let val = req.get('x-forwarded-host')

    if (!val || !trust(req.socket.remoteAddress, 0)) {
      val = req.get('host')
    } else if (val.indexOf(',') !== -1) {
      val = val.substring(0, val.indexOf(',')).trimRight()
    }

    return val || undefined
  } catch {
    return req.host
  }
}

export class Strategy implements passport.Strategy {
  /**
   * Name of the strategy
   */
  readonly name: string
  /**
   * @internal
   */
  _config: StrategyOptionsBase['config']
  /**
   * @internal
   */
  _verify: VerifyFunction | VerifyFunctionWithRequest
  /**
   * @internal
   */
  _callbackURL: Exclude<StrategyOptionsBase['callbackURL'], string>
  /**
   * @internal
   */
  _sessionKey: NonNullable<StrategyOptionsBase['sessionKey']>
  /**
   * @internal
   */
  _passReqToCallback: StrategyOptionsBase['passReqToCallback']
  /**
   * @internal
   */
  _usePAR: StrategyOptionsBase['usePAR']
  /**
   * @internal
   */
  _useJAR: StrategyOptionsBase['useJAR']
  /**
   * @internal
   */
  _DPoP: StrategyOptionsBase['DPoP']
  /**
   * @internal
   */
  _scope: StrategyOptionsBase['scope']
  /**
   * @internal
   */
  _resource: StrategyOptionsBase['resource']
  /**
   * @internal
   */
  _authorizationDetails: StrategyOptionsBase['authorizationDetails']

  constructor(options: StrategyOptions, verify: VerifyFunction)
  constructor(
    options: StrategyOptionsWithRequest,
    verify: VerifyFunctionWithRequest,
  )
  constructor(
    options: StrategyOptions | StrategyOptionsWithRequest,
    verify: VerifyFunction | VerifyFunctionWithRequest,
  ) {
    if (!(options?.config instanceof client.Configuration)) {
      throw new TypeError()
    }

    if (typeof verify !== 'function') {
      throw new TypeError()
    }

    const { host } = new URL(options.config.serverMetadata().issuer)

    this.name = options.name ?? host
    this._sessionKey = options.sessionKey ?? host
    this._DPoP = options.DPoP
    this._config = options.config
    this._scope = options.scope
    this._useJAR = options.useJAR
    this._usePAR = options.usePAR
    this._verify = verify
    if (options.callbackURL) {
      this._callbackURL = new URL(options.callbackURL)
    }
    this._passReqToCallback = options.passReqToCallback
    this._resource = options.resource
    this._authorizationDetails = options.authorizationDetails
  }

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
  authorizationRequestParams<TOptions extends AuthenticateOptions>(
    // @ts-ignore
    req: express.Request,
    options: TOptions,
  ): URLSearchParams | Record<string, string> | undefined {
    let params = new URLSearchParams()

    if (options?.scope) {
      if (Array.isArray(options?.scope) && options.scope.length) {
        params.set('scope', options.scope.join(' '))
      } else if (typeof options?.scope === 'string' && options.scope.length) {
        params.set('scope', options.scope)
      }
    }

    if (options?.prompt) {
      params.set('prompt', options.prompt)
    }

    if (options?.loginHint) {
      params.set('login_hint', options.loginHint)
    }

    if (options?.idTokenHint) {
      params.set('id_token_hint', options.idTokenHint)
    }

    if (options?.resource) {
      setResource(params, options.resource)
    }

    if (options?.authorizationDetails) {
      setAuthorizationDetails(params, options.authorizationDetails)
    }

    if (options?.callbackURL) {
      params.set('redirect_uri', new URL(options.callbackURL).href)
    }

    return params
  }

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
  authorizationCodeGrantParameters<TOptions extends AuthenticateOptions>(
    // @ts-ignore
    req: express.Request,
    options: TOptions,
  ): URLSearchParams | Record<string, string> | undefined {
    let params = new URLSearchParams()

    if (options?.resource) {
      setResource(params, options.resource)
    }

    return params
  }

  /**
   * @private
   *
   * @internal
   */
  async authorizationRequest<TOptions extends AuthenticateOptions>(
    this: passport.StrategyCreated<
      Strategy,
      Strategy & passport.StrategyCreatedStatic
    >,
    req: express.Request,
    options: TOptions,
  ): Promise<void> {
    try {
      let redirectTo = client.buildAuthorizationUrl(
        this._config,
        new URLSearchParams(this.authorizationRequestParams(req, options)),
      )

      if (redirectTo.searchParams.get('response_type')?.includes('id_token')) {
        redirectTo.searchParams.set('nonce', client.randomNonce())

        if (!redirectTo.searchParams.has('response_mode')) {
          redirectTo.searchParams.set('response_mode', 'form_post')
        }
      }

      const codeVerifier = client.randomPKCECodeVerifier()
      const code_challenge =
        await client.calculatePKCECodeChallenge(codeVerifier)
      redirectTo.searchParams.set('code_challenge', code_challenge)
      redirectTo.searchParams.set('code_challenge_method', 'S256')

      if (
        !this._config.serverMetadata().supportsPKCE() &&
        !redirectTo.searchParams.has('nonce')
      ) {
        redirectTo.searchParams.set('state', client.randomState())
      }

      if (this._callbackURL && !redirectTo.searchParams.has('redirect_uri')) {
        redirectTo.searchParams.set('redirect_uri', this._callbackURL.href)
      }

      if (this._scope && !redirectTo.searchParams.has('scope')) {
        redirectTo.searchParams.set('scope', this._scope)
      }

      if (this._resource && !redirectTo.searchParams.has('resource')) {
        setResource(redirectTo.searchParams, this._resource)
      }

      if (
        this._authorizationDetails &&
        !redirectTo.searchParams.has('authorization_details')
      ) {
        setAuthorizationDetails(
          redirectTo.searchParams,
          this._authorizationDetails,
        )
      }

      const DPoP = await this._DPoP?.(req)

      if (DPoP && !redirectTo.searchParams.has('dpop_jkt')) {
        redirectTo.searchParams.set(
          'dpop_jkt',
          await DPoP.calculateThumbprint(),
        )
      }

      const sessionKey = this._sessionKey
      const stateData: StateData = { code_verifier: codeVerifier }

      let nonce: string | null
      if ((nonce = redirectTo.searchParams.get('nonce'))) {
        stateData.nonce = nonce
      }
      let state: string | null
      if ((state = redirectTo.searchParams.get('state'))) {
        stateData.state = state
      }
      let max_age: string | null
      if ((max_age = redirectTo.searchParams.get('max_age'))) {
        stateData.max_age = parseInt(max_age, 10)
      }

      ;(req as any).session[sessionKey] = stateData

      if (this._useJAR) {
        let key: client.CryptoKey | client.PrivateKey
        let modifyAssertion: client.ModifyAssertionFunction | undefined
        if (Array.isArray(this._useJAR)) {
          ;[key, modifyAssertion] = this._useJAR
        } else {
          key = this._useJAR
        }
        redirectTo = await client.buildAuthorizationUrlWithJAR(
          this._config,
          redirectTo.searchParams,
          key,
          { [client.modifyAssertion]: modifyAssertion },
        )
      }

      if (this._usePAR) {
        redirectTo = await client.buildAuthorizationUrlWithPAR(
          this._config,
          redirectTo.searchParams,
          { DPoP },
        )
      }

      return this.redirect(redirectTo.href)
    } catch (err) {
      return this.error(err)
    }
  }

  /**
   * @private
   *
   * @internal
   */
  async authorizationCodeGrant<TOptions extends AuthenticateOptions>(
    this: passport.StrategyCreated<
      Strategy,
      Strategy & passport.StrategyCreatedStatic
    >,
    req: express.Request,
    currentUrl: URL,
    options: TOptions,
  ): Promise<void> {
    try {
      const sessionKey = this._sessionKey
      const stateData: StateData = (req as any).session[sessionKey]

      if (!stateData?.code_verifier) {
        return this.fail({
          message: 'Unable to verify authorization request state',
        })
      }

      if (options.callbackURL || this._callbackURL) {
        const _currentUrl = new URL(options.callbackURL! || this._callbackURL!)
        for (const [k, v] of currentUrl.searchParams.entries()) {
          _currentUrl.searchParams.append(k, v)
        }
        currentUrl = _currentUrl
      }

      let input: URL | Request = currentUrl
      if (req.method === 'POST') {
        input = new Request(currentUrl.href, {
          method: 'POST',
          headers: Object.entries(req.headersDistinct).reduce(
            (acc, [key, values]) => {
              for (const value of values!) {
                acc.append(key, value)
              }
              return acc
            },
            new Headers(),
          ),
          // @ts-ignore
          body: req,
          duplex: 'half',
        })
      }

      const tokens = await client.authorizationCodeGrant(
        this._config,
        input,
        {
          pkceCodeVerifier: stateData.code_verifier,
          expectedNonce: stateData.nonce,
          expectedState: stateData.state,
          maxAge: stateData.max_age,
        },
        this.authorizationCodeGrantParameters(req, options),
        { DPoP: await this._DPoP?.(req) },
      )

      const verified: passport.AuthenticateCallback = (err, user, info) => {
        if (err) return this.error(err)
        if (!user) return this.fail(info)
        return this.success(user)
      }

      if (options.passReqToCallback ?? this._passReqToCallback) {
        return (this._verify as VerifyFunctionWithRequest)(
          req,
          tokens,
          verified,
        )
      }

      return (this._verify as VerifyFunction)(tokens, verified)
    } catch (err) {
      if (
        err instanceof client.AuthorizationResponseError &&
        err.error === 'access_denied'
      ) {
        return this.fail({
          message: err.error_description || err.error,
          ...Object.fromEntries(err.cause.entries()),
        })
      }
      return this.error(err)
    }
  }

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
  currentUrl(req: express.Request): URL {
    return new URL(
      `${req.protocol}://${host(req)}${req.originalUrl ?? req.url}`,
    )
  }

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
  shouldInitiateAuthRequest<TOptions extends AuthenticateOptions>(
    req: express.Request,
    currentUrl: URL,
    // @ts-ignore
    options: TOptions,
  ): boolean {
    return (
      req.method === 'GET' &&
      !currentUrl.searchParams.has('code') &&
      !currentUrl.searchParams.has('error') &&
      !currentUrl.searchParams.has('response')
    )
  }

  /**
   * [Passport method] Authenticate the request.
   */
  authenticate<TOptions extends AuthenticateOptions>(
    this: passport.StrategyCreated<
      Strategy,
      Strategy & passport.StrategyCreatedStatic
    >,
    req: express.Request,
    options: TOptions,
  ): void {
    if (!(req as any).session) {
      return this.error(
        new Error(
          'OAuth 2.0 authentication requires session support. Did you forget to use express-session middleware?',
        ),
      )
    }

    const currentUrl = this.currentUrl(req)

    if (this.shouldInitiateAuthRequest(req, currentUrl, options)) {
      Strategy.prototype.authorizationRequest.call(this, req, options)
    } else {
      Strategy.prototype.authorizationCodeGrant.call(
        this,
        req,
        currentUrl,
        options,
      )
    }
  }
}

interface StateData {
  nonce?: string
  state?: string
  max_age?: number
  code_verifier: string
}

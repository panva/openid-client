import * as client from './index.js'

import type { PrivateKey } from 'oauth4webapi'
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
   * URL to which the authorization server will redirect the user after
   * obtaining authorization. This will be used as the `redirect_uri`
   * authorization request parameter unless specified elsewhere.
   */
  callbackURL?: string
  /**
   * Authorization Request Scope. This will be used as the `scope` authorization
   * request parameter unless specified elsewhere.
   */
  scope?: string
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
    | PrivateKey
    | [client.CryptoKey | PrivateKey, client.ModifyAssertionFunction]
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

export class Strategy implements passport.Strategy {
  /**
   * Name of the strategy
   */
  readonly name: string
  /**
   * @internal
   */
  _config: client.Configuration
  /**
   * @internal
   */
  _verify: VerifyFunction | VerifyFunctionWithRequest
  /**
   * @internal
   */
  _callbackURL?: string
  /**
   * @internal
   */
  _sessionKey: string
  /**
   * @internal
   */
  _passReqToCallback?: boolean
  /**
   * @internal
   */
  _proxy?: boolean
  /**
   * @internal
   */
  _usePAR?: boolean
  /**
   * @internal
   */
  _useJAR?: StrategyOptionsBase['useJAR']
  /**
   * @internal
   */
  _DPoP?: StrategyOptionsBase['DPoP']
  /**
   * @internal
   */
  _scope?: string

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
    this._callbackURL = options.callbackURL
    this._passReqToCallback = options.passReqToCallback
  }

  // prettier-ignore
  /**
   * Return extra parameters to be included an authorization request.
   */
  authorizationRequestParams<
    TOptions extends
      passport.AuthenticateOptions = passport.AuthenticateOptions,
  >(
    // @ts-ignore
    req: express.Request, options: TOptions,
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

    return params
  }

  // prettier-ignore
  /**
   * Return extra parameters to be included in the authorization code grant
   * token endpoint request.
   */
  authorizationCodeGrantParameters<
    TOptions extends
      passport.AuthenticateOptions = passport.AuthenticateOptions,
  >(
    // @ts-ignore
    req: express.Request, options: TOptions,
  ): URLSearchParams | Record<string, string> | undefined {
    return {}
  }

  /**
   * @internal
   */
  async authorizationRequest<
    TOptions extends
      passport.AuthenticateOptions = passport.AuthenticateOptions,
  >(
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
        redirectTo.searchParams.set('redirect_uri', this._callbackURL)
      }

      if (this._scope && !redirectTo.searchParams.has('scope')) {
        redirectTo.searchParams.set('scope', this._scope)
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
   * @internal
   */
  async authorizationCodeGrant<
    TOptions extends
      passport.AuthenticateOptions = passport.AuthenticateOptions,
  >(
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
   * Return the current request URL.
   *
   * - Its `searchParams` are used as the authorization response parameters when
   *   the response type used by the client is `code`
   * - Its value stripped of `searchParams` and `hash` is used as the
   *   `redirect_uri` authorization code grant token endpoint parameter
   *
   * This function may need to be overridden by users if its return value does
   * not match the actual URL the authorization server redirected the user to.
   */
  currentUrl(req: express.Request): URL {
    return new URL(`${req.protocol}://${req.host}${req.originalUrl ?? req.url}`)
  }

  /**
   * Authenticate request.
   */
  authenticate<
    TOptions extends
      passport.AuthenticateOptions = passport.AuthenticateOptions,
  >(
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

    if (
      (req.method === 'GET' && currentUrl.searchParams.size === 0) ||
      (currentUrl.searchParams.size === 1 && currentUrl.searchParams.has('iss'))
    ) {
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

/* eslint-disable no-underscore-dangle */

const util = require('util');
const crypto = require('crypto');
const url = require('url');
const assert = require('assert');

const base64url = require('base64url');
const _ = require('lodash');

const OpenIdConnectError = require('./open_id_connect_error');
const Client = require('./client');
const random = require('./util/random');

function verified(err, user, info = {}) {
  if (err) {
    this.error(err);
  } else if (!user) {
    this.fail(info);
  } else {
    this.success(user, info);
  }
}

/**
 * @name constructor
 * @api public
 */
function OpenIDConnectStrategy({
  client,
  params = {},
  passReqToCallback = false,
  sessionKey,
  usePKCE = false,
} = {}, verify) {
  assert(client instanceof Client, 'client must be an instance of openid-client Client');
  assert.equal(typeof verify, 'function', 'verify must be a function');

  assert(client.issuer && client.issuer.issuer, 'client must have an issuer with an identifier');

  this._client = client;
  this._issuer = client.issuer;
  this._verify = verify;
  this._passReqToCallback = passReqToCallback;
  this._usePKCE = usePKCE;
  this._key = sessionKey || `oidc:${url.parse(this._issuer.issuer).hostname}`;
  this._params = params;

  if (this._usePKCE === true) {
    const supportedMethods = this._issuer.code_challenge_methods_supported;
    assert(Array.isArray(supportedMethods), 'code_challenge_methods_supported is not properly set on issuer');
    assert(supportedMethods.length, 'issuer code_challenge_methods_supported is empty');
    if (supportedMethods.includes('S256')) {
      this._usePKCE = 'S256';
    } else if (supportedMethods.includes('plain')) {
      this._usePKCE = 'plain';
    } else {
      throw new Error('neither S256 or plain code_challenge_method is supported by the issuer');
    }
  } else if (typeof this._usePKCE === 'string') {
    assert(['plain', 'S256'].includes(this._usePKCE), `${this._usePKCE} is not valid/implemented PKCE code_challenge_method`);
  }

  this.name = url.parse(client.issuer.issuer).hostname;

  if (!params.response_type) params.response_type = _.get(client, 'response_types[0]', 'code');
  if (!params.redirect_uri) params.redirect_uri = _.get(client, 'redirect_uris[0]'); // TODO: only default if there's one
  if (!params.scope) params.scope = 'openid';
}

OpenIDConnectStrategy.prototype.authenticate = function authenticate(req, options) {
  const client = this._client;
  try {
    if (!req.session) {
      throw new Error('authentication requires session support when using state, max_age or nonce');
    }
    const reqParams = client.callbackParams(req);
    const sessionKey = this._key;

    /* start authentication request */
    if (_.isEmpty(reqParams)) {
      // provide options object with extra authentication parameters
      const params = _.defaults({}, options, this._params, {
        state: random(),
      });

      if (!params.nonce && params.response_type.includes('id_token')) {
        params.nonce = random();
      }

      req.session[sessionKey] = _.pick(params, 'nonce', 'state', 'max_age', 'response_type');

      if (this._usePKCE) {
        const verifier = random();
        req.session[sessionKey].code_verifier = verifier;

        switch (this._usePKCE) { // eslint-disable-line default-case
          case 'S256':
            params.code_challenge = base64url.encode(crypto.createHash('sha256').update(verifier).digest());
            params.code_challenge_method = 'S256';
            break;
          case 'plain':
            params.code_challenge = verifier;
            break;
        }
      }

      this.redirect(client.authorizationUrl(params));
      return;
    }
    /* end authentication request */

    /* start authentication response */

    const session = req.session[sessionKey];
    if (_.isEmpty(session)) {
      this.error(new Error(util.format(
        `did not find expected authorization request details in session, req.session["${sessionKey}"] is %j`,
        session
      )));
      return;
    }

    const {
      state, nonce, max_age: maxAge, code_verifier: codeVerifier, response_type: responseType,
    } = session;

    try {
      delete req.session[sessionKey];
    } catch (err) {}

    const opts = _.defaults({}, options, {
      redirect_uri: this._params.redirect_uri,
    });

    const checks = {
      state,
      nonce,
      max_age: maxAge,
      code_verifier: codeVerifier,
      response_type: responseType,
    };

    let callback = client.authorizationCallback(opts.redirect_uri, reqParams, checks)
      .then((tokenset) => {
        const result = { tokenset };
        return result;
      });

    const passReq = this._passReqToCallback;
    const loadUserinfo = this._verify.length > (passReq ? 3 : 2) && client.issuer.userinfo_endpoint;

    if (loadUserinfo) {
      callback = callback.then((result) => {
        if (result.tokenset.access_token) {
          const userinfoRequest = client.userinfo(result.tokenset);
          return userinfoRequest.then((userinfo) => {
            result.userinfo = userinfo;
            return result;
          });
        }

        return result;
      });
    }

    callback.then((result) => {
      const args = [result.tokenset, verified.bind(this)];

      if (loadUserinfo) args.splice(1, 0, result.userinfo);
      if (passReq) args.unshift(req);

      this._verify(...args);
    }).catch((error) => {
      if (error instanceof OpenIdConnectError
            && error.error !== 'server_error'
            && !error.error.startsWith('invalid')) {
        this.fail(error);
      } else {
        this.error(error);
      }
    });
    /* end authentication response */
  } catch (err) {
    this.error(err);
  }
};

module.exports = OpenIDConnectStrategy;

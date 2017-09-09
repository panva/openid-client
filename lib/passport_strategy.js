'use strict';

/* eslint-disable no-underscore-dangle */

const _ = require('lodash');
const uuid = require('uuid');
const url = require('url');
const assert = require('assert');
const OpenIdConnectError = require('./open_id_connect_error');
const Client = require('./client');

function verified(err, user, info) {
  const add = info || {};
  if (err) {
    this.error(err);
  } else if (!user) {
    this.fail(add);
  } else {
    this.success(user, add);
  }
}

/**
 * @name constructor
 * @api public
 */
function OpenIDConnectStrategy(options, verify) {
  const opts = (() => {
    if (options instanceof Client) return { client: options };
    return options;
  })();

  const client = opts.client;

  assert.equal(client instanceof Client, true);
  assert.equal(typeof verify, 'function');

  assert(client.issuer && client.issuer.issuer, 'client must have an issuer with an identifier');

  this._client = client;
  this._issuer = client.issuer;
  this._verify = verify;
  this._passReqToCallback = opts.passReqToCallback;
  this._key = opts.sessionKey || `oidc:${url.parse(this._issuer.issuer).hostname}`;
  this._params = opts.params || {};
  const params = this._params;

  this.name = url.parse(client.issuer.issuer).hostname;

  if (!params.response_type) params.response_type = _.get(client, 'response_types[0]', 'code');
  if (!params.redirect_uri) params.redirect_uri = _.get(client, 'redirect_uris[0]');
  if (!params.scope) params.scope = 'openid';
}

OpenIDConnectStrategy.prototype.authenticate = function authenticate(req, options) {
  const client = this._client;
  try {
    if (!req.session) throw new Error('authentication requires session support when using state, max_age or nonce');
    const reqParams = client.callbackParams(req);
    const sessionKey = this._key;

    /* start authentication request */
    if (_.isEmpty(reqParams)) {
      // provide options object with extra authentication parameters
      const opts = _.defaults({}, options, this._params, {
        state: uuid(),
      });

      if (!opts.nonce && opts.response_type.includes('id_token')) {
        opts.nonce = uuid();
      }

      req.session[sessionKey] = _.pick(opts, 'nonce', 'state', 'max_age');
      this.redirect(client.authorizationUrl(opts));
      return;
    }
    /* end authentication request */

    /* start authentication response */
    const session = req.session[sessionKey];
    const state = _.get(session, 'state');
    const maxAge = _.get(session, 'max_age');
    const nonce = _.get(session, 'nonce');

    try {
      delete req.session[sessionKey];
    } catch (err) {}

    const opts = _.defaults({}, options, {
      redirect_uri: this._params.redirect_uri,
    });

    const checks = { state, nonce, max_age: maxAge };
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

      this._verify.apply(this, args);
    }).catch((error) => {
      if (error instanceof OpenIdConnectError &&
            error.error !== 'server_error' &&
            !error.error.startsWith('invalid')) {
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

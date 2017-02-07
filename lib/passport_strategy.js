'use strict';

/* eslint-disable no-underscore-dangle */

const _ = require('lodash');
const uuid = require('uuid');
const url = require('url');
const assert = require('assert');
const OpenIdConnectError = require('./open_id_connect_error');
const Client = require('./client');

const MANDATORY = ['authorization_endpoint', 'jwks_uri', 'token_endpoint', 'userinfo_endpoint'];

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

function OpenIDConnectStrategy(options, verify) {
  const opts = (() => {
    if (options instanceof Client) return { client: options };
    return options;
  })();

  const client = opts.client;

  assert.equal(client instanceof Client, true);
  assert.equal(typeof verify, 'function');

  assert(client.issuer && client.issuer.issuer, 'client must have an issuer with an identifier');
  MANDATORY.forEach((prop) => {
    assert(client.issuer[prop], `client's issuer must have ${prop} configured`);
  });

  this._client = client;
  this._issuer = client.issuer;
  this._verify = verify;
  this._params = opts.params || {};
  const params = this._params;

  this.name = url.parse(client.issuer.issuer).hostname;

  if (!params.response_type) params.response_type = _.get(client, 'response_types[0]', 'code');
  if (!params.redirect_uri) params.redirect_uri = _.get(client, 'redirect_uris[0]');
  if (!params.scope) params.scope = 'openid';
}

OpenIDConnectStrategy.prototype.authenticate = function authenticate(req, options) {
  const client = this._client;
  const issuer = this._issuer;
  try {
    if (!req.session) throw new Error('authentication requires session support when using state, max_age or nonce');
    const reqParams = client.callbackParams(req);
    const sessionKey = `oidc:${url.parse(issuer.issuer).hostname}`;

    /* start authentication request */
    if (_.isEmpty(reqParams)) {
      // provide options objecti with extra authentication parameters
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

    if (req.session) delete req.session[sessionKey];

    const opts = _.defaults({}, options, {
      redirect_uri: this._params.redirect_uri,
    });

    const checks = { state, nonce, max_age: maxAge };
    let callback = client.authorizationCallback(opts.redirect_uri, reqParams, checks)
      .then((tokenset) => {
        const result = { tokenset };
        return result;
      });

    const loadUserinfo = this._verify.length > 2;

    if (loadUserinfo) {
      callback = callback.then((result) => {
        const userinfoRequest = client.userinfo(result.tokenset);
        return userinfoRequest.then((userinfo) => {
          result.userinfo = userinfo;
          return result;
        });
      });
    }

    callback.then((result) => {
      if (result.userinfo) {
        this._verify(result.tokenset, result.userinfo, verified.bind(this));
      } else {
        this._verify(result.tokenset, verified.bind(this));
      }
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

'use strict';

const _ = require('lodash');
const uuid = require('uuid');
const url = require('url');
const assert = require('assert');
const OpenIdConnectError = require('./open_id_connect_error');
const Client = require('./client');

class OpenIDConnectStrategy {
  constructor(options, verify) {
    const opts = (() => {
      if (options instanceof Client) return { client: options };
      return options;
    })();

    const client = opts.client;

    assert.equal(client instanceof Client, true);
    assert.equal(typeof verify, 'function');

    assert(client.issuer.issuer);
    assert(client.issuer.authorization_endpoint);
    assert(client.issuer.jwks_uri);
    assert(client.issuer.token_endpoint);
    assert(client.issuer.userinfo_endpoint);

    this.client = client;
    this.issuer = client.issuer;
    this.verify = verify;
    this.name = url.parse(client.issuer.issuer).hostname;

    this.response_type = opts.response_type || _.get(client, 'response_types[0]', 'code');
    this.redirect_uri = opts.redirect_uri || _.get(client, 'redirect_uris[0]');

    this.scope = (() => {
      if (Array.isArray(opts.scope)) {
        return opts.scope.join(' ');
      }
      return opts.scope ? String(opts.scope) : 'openid';
    })();
  }

  authenticate(req) {
    const params = this.client.callbackParams(req);
    const sessionKey = `oidc:${url.parse(this.issuer.issuer).hostname}`;
    const redirectUri = this.redirect_uri;

    if (_.isEmpty(params)) { // start authentication request
      const opts = {
        scope: this.scope,
        response_type: this.response_type,
        redirect_uri: redirectUri,
        state: uuid(),
        nonce: uuid(),
      };

      req.session[sessionKey] = _.pick(opts, 'nonce', 'state');
      this.redirect(this.client.authorizationUrl(opts));
      return;
    }

    const { nonce, state } = req.session[sessionKey] || {};
    delete req.session[sessionKey];

    let callback = this.client.authorizationCallback(redirectUri, params, { state, nonce })
      .then((tokenset) => {
        const result = { tokenset };
        return result;
      });

    const loadUserinfo = this.verify.length > 2;
    const verified = (err, user, info = {}) => {
      if (err) {
        this.error(err);
      } else if (!user) {
        this.fail(info);
      } else {
        this.success(user, info);
      }
    };

    if (loadUserinfo) {
      callback = callback.then((result) => {
        const userinfoRequest = this.client.userinfo(result.tokenset);
        return userinfoRequest.then((userinfo) => {
          result.userinfo = userinfo;
          return result;
        });
      });
    }

    callback.then((result) => {
      if (result.userinfo) {
        this.verify(result.tokenset, result.userinfo, verified);
      } else {
        this.verify(result.tokenset, verified);
      }
    }).catch((error) => {
      if (error instanceof OpenIdConnectError && error.error !== 'server_error') {
        this.fail(error);
      } else {
        this.error(error);
      }
    });
  }
}

module.exports = OpenIDConnectStrategy;

'use strict';

const util = require('util');
const assert = require('assert');
const jose = require('node-jose');
const base64url = require('base64url');
const url = require('url');
const { merge, defaults, pick, forEach } = require('lodash');

const TokenSet = require('./token_set');
const tokenHash = require('./token_hash');

const {
  USER_AGENT,
  CLIENT_METADATA,
  CLIENT_DEFAULTS,
} = require('./consts');

const debug = require('debug')('oidc:client');

const got = require('got');
const map = new WeakMap();

function instance(ctx) {
  if (!map.has(ctx)) map.set(ctx, {});
  return map.get(ctx);
}

class BaseClient {
  constructor(metadata) {
    forEach(defaults(pick(metadata, CLIENT_METADATA), CLIENT_DEFAULTS), (value, key) => {
      instance(this)[key] = value;
    });
  }

  authorizationUrl(params) {
    const query = defaults(params, {
      client_id: this.client_id,
      scope: 'openid',
      response_type: 'code',
    });

    if (typeof query.claims === 'object') {
      query.claims = JSON.stringify(query.claims, ['id_token', 'userinfo']);
    }

    return url.format(defaults({
      search: null,
      query,
    }, url.parse(this.provider.authorization_endpoint)));
  }

  authorizationCallback(redirectUri, params) {
    if (params.error) {
      return Promise.reject(pick(params, 'error', 'error_description', 'state'));
    }

    return this.grant({
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: redirectUri,
    }).then(tokenset => this.validateIdToken(tokenset));
  }

  validateIdToken(token) {
    let idToken = token;

    if (idToken instanceof TokenSet) {
      if (!idToken.id_token) {
        throw new Error('id_token not present in TokenSet');
      }

      idToken = idToken.id_token;
    }

    const now = Math.ceil(Date.now() / 1000);
    const parts = idToken.split('.');
    const header = parts[0];
    const payload = parts[1];
    const headerObject = JSON.parse(base64url.decode(header));
    const payloadObject = JSON.parse(base64url.decode(payload));

    const verifyPresence = (prop) => {
      if (payloadObject[prop] === undefined) {
        throw new Error(`missing required JWT property ${prop}`);
      }
    };

    assert.equal(this.id_token_signed_response_alg, headerObject.alg, 'unexpected algorithm used');

    ['iss', 'sub', 'aud', 'exp', 'iat'].forEach(verifyPresence);
    assert.equal(this.provider.issuer, payloadObject.iss, 'unexpected iss value');

    assert(typeof payloadObject.iat === 'number', 'iat is not a number');
    assert(payloadObject.iat <= now, 'id_token issued in the future');

    if (payloadObject.nbf !== undefined) {
      assert(typeof payloadObject.nbf === 'number', 'nbf is not a number');
      assert(payloadObject.nbf <= now, 'id_token not active yet');
    }

    assert(typeof payloadObject.exp === 'number', 'exp is not a number');
    assert(now < payloadObject.exp, 'id_token expired');

    if (payloadObject.azp !== undefined) {
      assert.equal(this.client_id, payloadObject.azp, 'azp must be the client_id');
    }

    if (!Array.isArray(payloadObject.aud)) {
      payloadObject.aud = [payloadObject.aud];
    } else if (payloadObject.aud.length > 1 && !payloadObject.azp) {
      throw new Error('missing required JWT property azp');
    }

    assert(payloadObject.aud.indexOf(this.client_id) !== -1, 'aud is missing the client_id');

    if (payloadObject.at_hash && token.access_token) {
      assert.equal(payloadObject.at_hash, tokenHash(token.access_token, headerObject.alg),
        'at_hash mismatch');
    }

    if (payloadObject.c_hash && token.code) {
      assert.equal(payloadObject.at_hash, tokenHash(token.code, headerObject.alg), 'c_hash mismatch');
    }

    return this.provider.key(headerObject)
      .then(key => jose.JWS.createVerify(key).verify(idToken))
      .then(() => token);
  }

  // implicitCallback(params, verify) {
  //   if (params.error) {
  //     return Promise.reject(pick(params, 'error', 'error_description', 'state'));
  //   }
  // }

  refresh(refreshToken) {
    let token = refreshToken;

    if (token instanceof TokenSet) {
      if (!token.refresh_token) {
        return Promise.reject(new Error('refresh_token not present in TokenSet'));
      }
      token = token.refresh_token;
    }

    return this.grant({
      grant_type: 'refresh_token',
      refresh_token: String(token),
    }).then(tokenset => this.validateIdToken(tokenset));
  }

  grant(body) {
    const auth = this.grantAuth();
    debug('client %s %s grant request started', this.client_id, body.grant_type);

    return got.post(this.provider.token_endpoint, merge({
      body,
      retries: 0,
      followRedirect: false,
      headers: {
        'User-Agent': USER_AGENT,
      },
    }, auth)).then((response) => new TokenSet(JSON.parse(response.body)), (err) => {
      debug('client %s grant request failed (%s > %s)', this.client_id, err.name, err.message);
      throw err;
    });
  }

  grantAuth() {
    switch (this.token_endpoint_auth_method) {
      case 'client_secret_post':
        return {
          body: {
            client_id: this.client_id,
            client_secret: this.client_secret,
          },
        };
      default: {
        const value = new Buffer(`${this.client_id}:${this.client_secret}`).toString('base64');
        return {
          headers: {
            Authorization: `Basic ${value}`,
          },
        };
      }
    }
  }

  inspect() {
    return util.format('Client <%s>', this.client_id);
  }

  static fromUri(uri, token) {
    debug('fetching client from %s', uri);

    return got.get(uri, {
      retries: 0,
      followRedirect: false,
      headers: {
        Authorization: `Bearer ${token}`,
        'User-Agent': USER_AGENT,
      },
    }).then((response) => new this(JSON.parse(response.body)), (err) => {
      debug('%s request failed (%s > %s)', uri, err.name, err.message);
      throw err;
    });
  }
}

CLIENT_METADATA.forEach((prop) => {
  Object.defineProperty(BaseClient.prototype, prop, {
    get() {
      return instance(this)[prop];
    },
  });
});

module.exports = BaseClient;

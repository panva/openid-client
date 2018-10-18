const util = require('util');
const assert = require('assert');
const stdhttp = require('http');
const crypto = require('crypto');
const querystring = require('querystring');
const url = require('url');

const jose = require('node-jose');
const base64url = require('base64url');
const _ = require('lodash');
const tokenHash = require('oidc-token-hash');

const errorHandlerFactory = require('./helpers/error_handler');
const expectResponseWithBody = require('./helpers/expect_response');
const TokenSet = require('./token_set');
const OpenIdConnectError = require('./open_id_connect_error');
const now = require('./util/unix_timestamp');
const { CALLBACK_PROPERTIES, CLIENT_DEFAULTS, JWT_CONTENT } = require('./helpers/consts');
const issuerRegistry = require('./issuer_registry');
const forEach = require('./util/for_each');
const random = require('./util/random');

const errorHandler = errorHandlerFactory();
const bearerErrorHandler = errorHandlerFactory({ bearerEndpoint: true });

const map = new WeakMap();
const format = 'compact';

function formUrlEncode(value) {
  return encodeURIComponent(value).replace(/%20/g, '+');
}

function bearer(token) {
  return `Bearer ${token}`;
}

function instance(ctx) {
  if (!map.has(ctx)) map.set(ctx, { metadata: {} });
  return map.get(ctx);
}

function cleanUpClaims(claims) {
  if (_.isEmpty(claims._claim_names)) delete claims._claim_names;
  if (_.isEmpty(claims._claim_sources)) delete claims._claim_sources;
  return claims;
}

function assignClaim(target, source, sourceName) {
  return (inSource, claim) => {
    if (inSource === sourceName) {
      assert(source[claim] !== undefined, `expected claim "${claim}" in "${sourceName}"`);
      target[claim] = source[claim];
      delete target._claim_names[claim];
    }
  };
}

function getFromJWT(jwt, position, claim) {
  assert.equal(typeof jwt, 'string', 'invalid JWT type, expected a string');
  const parts = jwt.split('.');
  assert.equal(parts.length, 3, 'invalid JWT format, expected three parts');
  const parsed = JSON.parse(base64url.decode(parts[position]));
  return typeof claim === 'undefined' ? parsed : parsed[claim];
}

function getSub(jwt) {
  return getFromJWT(jwt, 1, 'sub');
}

function getIss(jwt) {
  return getFromJWT(jwt, 1, 'iss');
}

function getHeader(jwt) {
  return getFromJWT(jwt, 0);
}

function getPayload(jwt) {
  return getFromJWT(jwt, 1);
}

function assignErrSrc(sourceName) {
  return (err) => {
    err.src = sourceName;
    throw err;
  };
}

function authorizationParams(params) {
  assert(_.isPlainObject(params), 'pass a plain object as the first argument');

  const authParams = Object.assign(
    { client_id: this.client_id, scope: 'openid', response_type: 'code' },
    params
  );

  // TODO: default redirect_uris if there's one

  forEach(authParams, (value, key) => {
    if (value === null || value === undefined) {
      delete authParams[key];
    } else if (key === 'claims' && typeof value === 'object') {
      authParams[key] = JSON.stringify(value);
    } else if (typeof value !== 'string') {
      authParams[key] = String(value);
    }
  });

  assert(
    ['none', 'code'].includes(authParams.response_type) || authParams.nonce,
    'nonce MUST be provided for implicit and hybrid flows'
  );

  return authParams;
}

function claimJWT(jwt) {
  try {
    const iss = getIss(jwt);
    const keyDef = getHeader(jwt);
    assert(keyDef.alg, 'claim source is missing JWT header alg property');

    if (keyDef.alg === 'none') return Promise.resolve(getPayload(jwt));

    const getKey = (() => {
      if (!iss || iss === this.issuer.issuer) {
        return this.issuer.key(keyDef);
      }
      if (issuerRegistry.has(iss)) {
        return issuerRegistry.get(iss).key(keyDef);
      }
      return this.issuer.constructor.discover(iss).then(issuer => issuer.key(keyDef));
    })();

    return getKey
      .then(key => jose.JWS.createVerify(key).verify(jwt))
      .then(result => JSON.parse(result.payload));
  } catch (error) {
    return Promise.reject(error);
  }
}

function checkStore(keystore) {
  assert(jose.JWK.isKeyStore(keystore), 'keystore must be an instance of jose.JWK.KeyStore');
  assert(keystore.all().every((key) => {
    if (key.kty === 'RSA' || key.kty === 'EC') {
      try { key.toPEM(true); } catch (err) { return false; }
      return true;
    }
    return false;
  }), 'keystore must only contain private EC or RSA keys');
}

// if an OP doesnt support client_secret_basic but supports client_secret_post, use it instead
// this is in place to take care of most common pitfalls when first using discovered Issuers without
// the support for default values defined by Discovery 1.0
function checkBasicSupport(client, metadata, properties) {
  try {
    const supported = client.issuer.token_endpoint_auth_methods_supported;
    if (!supported.includes(properties.token_endpoint_auth_method)) {
      if (supported.includes('client_secret_post')) {
        properties.token_endpoint_auth_method = 'client_secret_post';
      }
    }
  } catch (err) {}
}

function getDefaultsForEndpoint(endpoint, issuer, properties) {
  if (!issuer[`${endpoint}_endpoint`]) return;

  const tokenEndpointAuthMethod = properties.token_endpoint_auth_method;
  const tokenEndpointAuthSigningAlg = properties.token_endpoint_auth_signing_alg;

  const eam = `${endpoint}_endpoint_auth_method`;
  const easa = `${endpoint}_endpoint_auth_signing_alg`;

  if (properties[eam] === undefined && properties[easa] === undefined) {
    if (tokenEndpointAuthMethod !== undefined) {
      properties[eam] = tokenEndpointAuthMethod;
    }
    if (tokenEndpointAuthSigningAlg !== undefined) {
      properties[easa] = tokenEndpointAuthSigningAlg;
    }
  }
}

function assertSigningAlgValuesSupport(endpoint, issuer, properties) {
  if (!issuer[`${endpoint}_endpoint`]) return;

  const eam = `${endpoint}_endpoint_auth_method`;
  const easa = `${endpoint}_endpoint_auth_signing_alg`;
  const easavs = `${endpoint}_endpoint_auth_signing_alg_values_supported`;

  if (properties[eam] && properties[eam].endsWith('_jwt') && !properties[easa]) {
    assert(issuer[easavs], `${easavs} must be configured on the issuer if ${easa} is not defined on a client`);
  }
}

function assertIssuerConfiguration(issuer, endpoint) {
  assert(issuer[endpoint], `${endpoint} must be configured on the issuer`);
}

class Client {
  /**
   * @name constructor
   * @api public
   */
  constructor(metadata = {}, keystore) {
    const properties = Object.assign({}, CLIENT_DEFAULTS, metadata);

    if (!metadata.token_endpoint_auth_method) { // if no explicit value was provided
      checkBasicSupport(this, metadata, properties);
    }

    assertSigningAlgValuesSupport('token', this.issuer, properties);

    ['introspection', 'revocation'].forEach((endpoint) => {
      getDefaultsForEndpoint(endpoint, this.issuer, properties);
      assertSigningAlgValuesSupport(endpoint, this.issuer, properties);
    });

    forEach(properties, (value, key) => {
      instance(this).metadata[key] = value;
      if (!this[key]) {
        Object.defineProperty(this, key, {
          get() { return instance(this).metadata[key]; },
        });
      }
    });

    if (keystore !== undefined) {
      checkStore.call(this, keystore);
      instance(this).keystore = keystore;
    }

    this.CLOCK_TOLERANCE = 0;
  }

  /**
   * @name authorizationUrl
   * @api public
   */
  authorizationUrl(params) {
    assertIssuerConfiguration(this.issuer, 'authorization_endpoint');
    const target = url.parse(this.issuer.authorization_endpoint, true);
    target.search = null;
    Object.assign(target.query, authorizationParams.call(this, params));
    return url.format(target);
  }

  /**
   * @name authorizationPost
   * @api public
   */
  authorizationPost(params) {
    const inputs = authorizationParams.call(this, params);
    const formInputs = Object.keys(inputs)
      .map(name => `<input type="hidden" name="${name}" value="${inputs[name]}"/>`).join('\n');

    return `<!DOCTYPE html>
<head>
  <title>Requesting Authorization</title>
</head>
<body onload="javascript:document.forms[0].submit()">
  <form method="post" action="${this.issuer.authorization_endpoint}">
    ${formInputs}
  </form>
</body>
</html>`;
  }

  /**
   * @name endSessionUrl
   * @api public
   */
  endSessionUrl(params = {}) {
    assertIssuerConfiguration(this.issuer, 'end_session_endpoint');

    const {
      0: postLogout,
      length,
    } = this.post_logout_redirect_uris || [];

    const {
      post_logout_redirect_uri = length === 1 ? postLogout : undefined,
    } = params;

    let hint = params.id_token_hint;

    if (hint instanceof TokenSet) {
      assert(hint.id_token, 'id_token not present in TokenSet');
      hint = hint.id_token;
    }

    const target = url.parse(this.issuer.end_session_endpoint, true);
    target.search = null;
    target.query = Object.assign(params, target.query, {
      post_logout_redirect_uri,
      id_token_hint: hint,
    });
    forEach(target.query, (value, key) => {
      if (value === null || value === undefined) {
        delete target.query[key];
      }
    });
    return url.format(target);
  }

  /**
   * @name callbackParams
   * @api public
   */
  callbackParams(input) { // eslint-disable-line class-methods-use-this
    const isIncomingMessage = input instanceof stdhttp.IncomingMessage
      || (input && input.method && input.url);
    const isString = typeof input === 'string';

    assert(
      isString || isIncomingMessage,
      '#callbackParams only accepts string urls, http.IncomingMessage or a lookalike'
    );

    let uri;
    if (isIncomingMessage) {
      const msg = input;

      switch (msg.method) {
        case 'GET':
          uri = msg.url;
          break;
        case 'POST':
          assert(msg.body, 'incoming message body missing, include a body parser prior to this call');
          switch (typeof msg.body) {
            case 'object':
            case 'string':
              if (Buffer.isBuffer(msg.body)) {
                return querystring.parse(msg.body.toString('utf-8'));
              }
              if (typeof msg.body === 'string') {
                return querystring.parse(msg.body);
              }

              return msg.body;
            default:
              throw new Error('invalid IncomingMessage body object');
          }
        default:
          throw new Error('invalid IncomingMessage method');
      }
    } else {
      uri = input;
    }

    return _.pick(url.parse(uri, true).query, CALLBACK_PROPERTIES);
  }

  /**
   * @name authorizationCallback
   * @api public
   */
  authorizationCallback(redirectUri, parameters, checks = {}) {
    const params = _.pick(parameters, CALLBACK_PROPERTIES);

    if (this.default_max_age && !checks.max_age) checks.max_age = this.default_max_age;

    if (!params.state && checks.state) {
      return Promise.reject(new Error('state missing from the response'));
    }

    if (params.state && !checks.state) {
      return Promise.reject(new Error('checks.state argument is missing'));
    }

    if (checks.state !== params.state) {
      return Promise.reject(new Error('state mismatch'));
    }

    if (params.error) {
      return Promise.reject(new OpenIdConnectError(params));
    }

    const RESPONSE_TYPE_REQUIRED_PARAMS = {
      code: ['code'],
      id_token: ['id_token'],
      token: ['access_token', 'token_type'],
    };

    if (checks.response_type) {
      for (const type of checks.response_type.split(' ')) { // eslint-disable-line no-restricted-syntax
        if (type === 'none') {
          if (params.code || params.id_token || params.access_token) {
            return Promise.reject(new Error('unexpected params encountered for "none" response'));
          }
        } else {
          for (const param of RESPONSE_TYPE_REQUIRED_PARAMS[type]) { // eslint-disable-line no-restricted-syntax, max-len
            if (!params[param]) {
              return Promise.reject(new Error(`${param} missing from response`));
            }
          }
        }
      }
    }

    let promise;

    if (params.id_token) {
      promise = Promise.resolve(new TokenSet(params))
        .then(tokenset => this.decryptIdToken(tokenset))
        .then(tokenset => this.validateIdToken(tokenset, checks.nonce, 'authorization', checks.max_age, checks.state));
    }

    if (params.code) {
      const grantCall = () => this.grant({
        grant_type: 'authorization_code',
        code: params.code,
        redirect_uri: redirectUri,
        code_verifier: checks.code_verifier,
      })
        .then(tokenset => this.decryptIdToken(tokenset))
        .then(tokenset => this.validateIdToken(tokenset, checks.nonce, 'token', checks.max_age))
        .then((tokenset) => {
          if (params.session_state) tokenset.session_state = params.session_state;
          return tokenset;
        });

      if (promise) {
        promise = promise.then(grantCall);
      } else {
        return grantCall();
      }
    }

    return promise || Promise.resolve(new TokenSet(params));
  }

  /**
   * @name oauthCallback
   * @api public
   */
  oauthCallback(redirectUri, parameters, checks = {}) {
    const params = _.pick(parameters, CALLBACK_PROPERTIES);

    if (!params.state && checks.state) {
      return Promise.reject(new Error('state missing from the response'));
    }

    if (params.state && !checks.state) {
      return Promise.reject(new Error('checks.state argument is missing'));
    }

    if (checks.state !== params.state) {
      return Promise.reject(new Error('state mismatch'));
    }

    if (params.error) {
      return Promise.reject(new OpenIdConnectError(params));
    }

    const RESPONSE_TYPE_REQUIRED_PARAMS = {
      code: ['code'],
      token: ['access_token', 'token_type'],
    };

    if (checks.response_type) {
      for (const type of checks.response_type.split(' ')) { // eslint-disable-line no-restricted-syntax
        if (type === 'none') {
          if (params.code || params.id_token || params.access_token) {
            return Promise.reject(new Error('unexpected params encountered for "none" response'));
          }
        }

        if (RESPONSE_TYPE_REQUIRED_PARAMS[type]) {
          for (const param of RESPONSE_TYPE_REQUIRED_PARAMS[type]) { // eslint-disable-line no-restricted-syntax, max-len
            if (!params[param]) {
              return Promise.reject(new Error(`${param} missing from response`));
            }
          }
        }
      }
    }

    if (params.code) {
      return this.grant({
        grant_type: 'authorization_code',
        code: params.code,
        redirect_uri: redirectUri,
        code_verifier: checks.code_verifier,
      });
    }

    return Promise.resolve(new TokenSet(params));
  }

  /**
   * @name decryptIdToken
   * @api private
   */
  decryptIdToken(token, use) {
    if (!use) use = 'id_token'; // eslint-disable-line no-param-reassign

    if (!this[`${use}_encrypted_response_alg`]) {
      return Promise.resolve(token);
    }

    let idToken = token;

    if (idToken instanceof TokenSet) {
      assert(idToken.id_token, 'id_token not present in TokenSet');
      idToken = idToken.id_token;
    }

    const expectedAlg = this[`${use}_encrypted_response_alg`];
    const expectedEnc = this[`${use}_encrypted_response_enc`];

    const header = JSON.parse(base64url.decode(idToken.split('.')[0]));

    assert.equal(header.alg, expectedAlg, 'unexpected alg received');
    assert.equal(header.enc, expectedEnc, 'unexpected enc received');

    const keystoreOrSecret = expectedAlg.match(/^(RSA|ECDH)/)
      ? Promise.resolve(instance(this).keystore) : this.joseSecret(expectedAlg);

    return keystoreOrSecret.then(keyOrStore => jose.JWE.createDecrypt(keyOrStore).decrypt(idToken)
      .then((result) => {
        if (token instanceof TokenSet) {
          Object.defineProperty(token, 'encrypted_id_token', { value: token.id_token }); // TODO: deprecated
          token.id_token = result.payload.toString('utf8');
          return token;
        }
        return result.payload.toString('utf8');
      }));
  }

  /**
   * @name validateIdToken
   * @api private
   */
  validateIdToken(tokenSet, nonce, returnedBy, maxAge, state) {
    let idToken = tokenSet;

    const expectedAlg = (() => {
      if (returnedBy === 'userinfo') return this.userinfo_signed_response_alg;
      return this.id_token_signed_response_alg;
    })();

    const isTokenSet = idToken instanceof TokenSet;

    if (isTokenSet) {
      assert(idToken.id_token, 'id_token not present in TokenSet');
      idToken = idToken.id_token;
    }

    idToken = String(idToken);

    const timestamp = now();
    const parts = idToken.split('.');
    const header = JSON.parse(base64url.decode(parts[0]));
    const payload = JSON.parse(base64url.decode(parts[1]));

    const verifyPresence = (prop) => {
      if (payload[prop] === undefined) {
        throw new Error(`missing required JWT property ${prop}`);
      }
    };

    assert.equal(header.alg, expectedAlg, 'unexpected algorithm received');

    if (returnedBy !== 'userinfo') {
      ['iss', 'sub', 'aud', 'exp', 'iat'].forEach(verifyPresence);
    }

    if (payload.iss !== undefined) {
      assert.equal(payload.iss, this.issuer.issuer, 'unexpected iss value');
    }

    if (payload.iat !== undefined) {
      assert.equal(typeof payload.iat, 'number', 'iat is not a number');
      assert(payload.iat <= timestamp + this.CLOCK_TOLERANCE, 'id_token issued in the future');
    }

    if (payload.nbf !== undefined) {
      assert.equal(typeof payload.nbf, 'number', 'nbf is not a number');
      assert(payload.nbf <= timestamp + this.CLOCK_TOLERANCE, 'id_token not active yet');
    }

    if (maxAge || (maxAge !== null && this.require_auth_time)) {
      assert(payload.auth_time, 'missing required JWT property auth_time');
      assert.equal(typeof payload.auth_time, 'number', 'auth_time is not a number');
    }

    if (maxAge) {
      assert(payload.auth_time + maxAge >= timestamp - this.CLOCK_TOLERANCE, 'too much time has elapsed since the last End-User authentication');
    }

    if (nonce !== null && (payload.nonce || nonce !== undefined)) {
      assert.equal(payload.nonce, nonce, 'nonce mismatch');
    }

    if (payload.exp !== undefined) {
      assert.equal(typeof payload.exp, 'number', 'exp is not a number');
      assert(timestamp - this.CLOCK_TOLERANCE < payload.exp, 'id_token expired');
    }

    if (payload.aud !== undefined) {
      if (!Array.isArray(payload.aud)) {
        payload.aud = [payload.aud];
      } else if (payload.aud.length > 1 && !payload.azp) {
        throw new Error('missing required JWT property azp');
      }
    }

    if (payload.azp !== undefined) {
      assert.equal(payload.azp, this.client_id, 'azp must be the client_id');
    }

    if (payload.aud !== undefined) {
      assert(payload.aud.includes(this.client_id), 'aud is missing the client_id');
    }

    if (returnedBy === 'authorization') {
      assert(payload.at_hash || !tokenSet.access_token, 'missing required property at_hash');
      assert(payload.c_hash || !tokenSet.code, 'missing required property c_hash');

      if (payload.s_hash) {
        assert(state, 'cannot verify s_hash, state not provided');
        assert(tokenHash(payload.s_hash, state, header.alg), 's_hash mismatch');
      }
    }

    if (tokenSet.access_token && payload.at_hash !== undefined) {
      assert(tokenHash(payload.at_hash, tokenSet.access_token, header.alg), 'at_hash mismatch');
    }

    if (tokenSet.code && payload.c_hash !== undefined) {
      assert(tokenHash(payload.c_hash, tokenSet.code, header.alg), 'c_hash mismatch');
    }

    if (header.alg === 'none') {
      return Promise.resolve(tokenSet);
    }

    return (header.alg.startsWith('HS') ? this.joseSecret() : this.issuer.key(header))
      .then(key => jose.JWS.createVerify(key).verify(idToken).catch(() => {
        throw new Error('invalid signature');
      }))
      .then(() => tokenSet);
  }

  /**
   * @name refresh
   * @api public
   */
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
    })
      .then((tokenset) => {
        if (!tokenset.id_token) {
          return tokenset;
        }
        return this.decryptIdToken(tokenset)
          .then(() => this.validateIdToken(tokenset, null, 'token', null));
      });
  }

  /**
   * @name userinfo
   * @api public
   */
  userinfo(accessToken, options) {
    let token = accessToken;
    const opts = _.merge({
      verb: 'get',
      via: 'header',
    }, options);

    if (token instanceof TokenSet) {
      if (!token.access_token) {
        return Promise.reject(new Error('access_token not present in TokenSet'));
      }
      token = token.access_token;
    }

    const verb = String(opts.verb).toLowerCase();
    let httpOptions;

    switch (opts.via) {
      case 'query':
        assert.equal(verb, 'get', 'providers should only parse query strings for GET requests');
        httpOptions = { query: { access_token: token } };
        break;
      case 'body':
        assert.equal(verb, 'post', 'can only send body on POST');
        httpOptions = { form: true, body: { access_token: token } };
        break;
      default:
        httpOptions = { headers: { Authorization: bearer(token) } };
    }

    if (opts.params) {
      if (verb === 'post') {
        _.defaultsDeep(httpOptions, { body: opts.params });
      } else {
        _.defaultsDeep(httpOptions, { query: opts.params });
      }
    }

    const { issuer } = this;
    return this.httpClient[verb](issuer.userinfo_endpoint, issuer.httpOptions(httpOptions))
      .then(expectResponseWithBody(200))
      .then((response) => {
        if (JWT_CONTENT.exec(response.headers['content-type'])) {
          return Promise.resolve(response.body)
            .then(jwt => this.decryptIdToken(jwt, 'userinfo'))
            .then((jwt) => {
              if (!this.userinfo_signed_response_alg) return JSON.parse(jwt);
              return this.validateIdToken(jwt, null, 'userinfo', null)
                .then(valid => JSON.parse(base64url.decode(valid.split('.')[1])));
            });
        }

        return JSON.parse(response.body);
      })
      .then((parsed) => {
        if (accessToken.id_token) {
          assert.equal(parsed.sub, getSub(accessToken.id_token), 'userinfo sub mismatch');
        }

        return parsed;
      })
      .catch(bearerErrorHandler.bind(this));
  }

  /**
   * @name derivedKey
   * @api private
   */
  derivedKey(len) {
    const cacheKey = `${len}_key`;
    if (instance(this)[cacheKey]) {
      return Promise.resolve(instance(this)[cacheKey]);
    }

    const derivedBuffer = crypto.createHash('sha256')
      .update(this.client_secret)
      .digest()
      .slice(0, len / 8);

    return jose.JWK.asKey({ k: base64url.encode(derivedBuffer), kty: 'oct' }).then((key) => {
      instance(this)[cacheKey] = key;
      return key;
    });
  }

  /**
   * @name joseSecret
   * @api private
   */
  joseSecret(alg) {
    if (String(alg).match(/^(?:A|PBES2.+)(\d{3})(GCM)?KW$/)) {
      return this.derivedKey(parseInt(RegExp.$1, 10));
    }

    if (instance(this).jose_secret) {
      return Promise.resolve(instance(this).jose_secret);
    }

    return jose.JWK.asKey({ k: base64url.encode(this.client_secret), kty: 'oct' }).then((key) => {
      instance(this).jose_secret = key;
      return key;
    });
  }

  /**
   * @name grant
   * @api public
   */
  grant(body) {
    assertIssuerConfiguration(this.issuer, 'token_endpoint');
    return this.authenticatedPost('token', { body: _.omitBy(body, _.isUndefined) })
      .then(expectResponseWithBody(200))
      .then(response => new TokenSet(JSON.parse(response.body)));
  }

  /**
   * @name revoke
   * @api public
   */
  revoke(token, hint) {
    assertIssuerConfiguration(this.issuer, 'revocation_endpoint');
    assert(!hint || typeof hint === 'string', 'hint must be a string');

    const body = { token };
    if (hint) body.token_type_hint = hint;
    return this.authenticatedPost('revocation', { body })
      .then((response) => {
        if (response.body) {
          return JSON.parse(response.body);
        }
        return {};
      });
  }

  /**
   * @name introspect
   * @api public
   */
  introspect(token, hint) {
    assertIssuerConfiguration(this.issuer, 'introspection_endpoint');
    assert(!hint || typeof hint === 'string', 'hint must be a string');

    const body = { token };
    if (hint) body.token_type_hint = hint;
    return this.authenticatedPost('introspection', { body })
      .then(expectResponseWithBody(200))
      .then(response => JSON.parse(response.body));
  }

  /**
   * @name fetchDistributedClaims
   * @api public
   */
  fetchDistributedClaims(claims, tokens = {}) {
    const distributedSources = _.pickBy(claims._claim_sources, def => !!def.endpoint);

    return Promise.all(_.map(distributedSources, (def, sourceName) => {
      const opts = {
        headers: { Authorization: bearer(def.access_token || tokens[sourceName]) },
      };

      return this.httpClient.get(def.endpoint, this.issuer.httpOptions(opts))
        .then(response => claimJWT.call(this, response.body), bearerErrorHandler.bind(this))
        .then((data) => {
          delete claims._claim_sources[sourceName];
          forEach(claims._claim_names, assignClaim(claims, data, sourceName));
        }).catch(assignErrSrc(sourceName));
    })).then(() => cleanUpClaims(claims));
  }

  /**
   * @name unpackAggregatedClaims
   * @api public
   */
  unpackAggregatedClaims(claims) {
    const aggregatedSources = _.pickBy(claims._claim_sources, def => !!def.JWT);

    return Promise.all(_.map(aggregatedSources, (def, sourceName) => {
      const decoded = claimJWT.call(this, def.JWT);

      return decoded.then((data) => {
        delete claims._claim_sources[sourceName];
        forEach(claims._claim_names, assignClaim(claims, data, sourceName));
      }).catch(assignErrSrc(sourceName));
    })).then(() => cleanUpClaims(claims));
  }

  /**
   * @name authenticatedPost
   * @api private
   */
  authenticatedPost(endpoint, httpOptions) {
    return Promise.resolve(this.authFor(endpoint))
      .then((auth) => {
        const opts = this.issuer.httpOptions(_.merge(httpOptions, auth, { form: true }));
        return this.httpClient.post(this.issuer[`${endpoint}_endpoint`], opts);
      })
      .catch(errorHandler.bind(this));
  }

  /**
   * @name createSign
   * @api private
   */
  createSign(endpoint = 'token') {
    let alg = this[`${endpoint}_endpoint_auth_signing_alg`];
    switch (this[`${endpoint}_endpoint_auth_method`]) {
      case 'client_secret_jwt':
        return this.joseSecret().then((key) => {
          if (!alg) {
            alg = _.find(
              this.issuer[`${endpoint}_endpoint_auth_signing_alg_values_supported`],
              signAlg => key.algorithms('sign').includes(signAlg)
            );
          }

          return jose.JWS.createSign({
            fields: { alg, typ: 'JWT' },
            format,
          }, { key, reference: false });
        });
      case 'private_key_jwt': {
        if (!alg) {
          const algs = new Set();
          instance(this).keystore.all().forEach((key) => {
            key.algorithms('sign').forEach(algs.add.bind(algs));
          });

          alg = _.find(
            this.issuer[`${endpoint}_endpoint_auth_signing_alg_values_supported`],
            signAlg => algs.has(signAlg)
          );
        }

        const key = instance(this).keystore.get({ alg, use: 'sig' });
        assert(key, 'no valid key found');

        return Promise.resolve(jose.JWS.createSign({
          fields: { alg, typ: 'JWT' },
          format,
        }, { key, reference: true }));
      }
      /* istanbul ignore next */
      default:
        throw new Error('createSign only works for _jwt token auth methods');
    }
  }

  /**
   * @name authFor
   * @api private
   */
  authFor(endpoint = 'token') {
    const authMethod = this[`${endpoint}_endpoint_auth_method`];
    switch (authMethod) {
      case 'none':
        return {
          body: {
            client_id: this.client_id,
          },
        };
      case 'client_secret_post':
        return {
          body: {
            client_id: this.client_id,
            client_secret: this.client_secret,
          },
        };
      case 'private_key_jwt':
      case 'client_secret_jwt': {
        const timestamp = now();
        return this.createSign(endpoint).then(sign => sign.update(JSON.stringify({
          iat: timestamp,
          exp: timestamp + 60,
          jti: random(),
          iss: this.client_id,
          sub: this.client_id,
          aud: this.issuer[`${endpoint}_endpoint`],
        })).final().then((client_assertion) => { // eslint-disable-line camelcase, arrow-body-style
          return {
            body: {
              client_assertion,
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            },
          };
        }));
      }
      default: {
        const encoded = `${formUrlEncode(this.client_id)}:${formUrlEncode(this.client_secret)}`;
        const value = Buffer.from(encoded).toString('base64');
        return { headers: { Authorization: `Basic ${value}` } };
      }
    }
  }

  /**
   * @name inspect
   * @api public
   */
  inspect() {
    return util.format('Client <%s>', this.client_id);
  }

  /**
   * @name register
   * @api public
   */
  static register(properties, { initialAccessToken, keystore } = {}) {
    assertIssuerConfiguration(this.issuer, 'registration_endpoint');

    if (keystore !== undefined && !(properties.jwks || properties.jwks_uri)) {
      checkStore.call(this, keystore);
      properties.jwks = keystore.toJSON();
    }

    const headers = { 'Content-Type': 'application/json' };

    if (initialAccessToken) headers.Authorization = bearer(initialAccessToken);

    return this.httpClient.post(this.issuer.registration_endpoint, this.issuer.httpOptions({
      headers,
      body: JSON.stringify(properties),
    }))
      .then(expectResponseWithBody(201))
      .then(response => new this(JSON.parse(response.body), keystore))
      .catch(bearerErrorHandler.bind(this));
  }

  get metadata() {
    return instance(this).metadata;
  }

  /**
   * @name fromUri
   * @api public
   */
  static fromUri(uri, token, keystore) {
    return this.httpClient.get(uri, this.issuer.httpOptions({
      headers: { Authorization: bearer(token) },
    }))
      .then(expectResponseWithBody(200))
      .then(
        response => new this(JSON.parse(response.body), keystore), bearerErrorHandler.bind(this)
      );
  }

  /**
   * @name requestObject
   * @api public
   */
  requestObject(request = {}, algorithms = {}) {
    assert(_.isPlainObject(request), 'pass a plain object as the first argument');

    _.defaults(algorithms, {
      sign: this.request_object_signing_alg,
      encrypt: {
        alg: this.request_object_encryption_alg,
        enc: this.request_object_encryption_enc,
      },
    }, {
      sign: 'none',
    });

    const signed = (() => {
      const alg = algorithms.sign;
      const header = { alg, typ: 'JWT' };
      const payload = JSON.stringify(_.defaults({}, request, {
        iss: this.client_id,
        aud: this.issuer.issuer,
        client_id: this.client_id,
      }));

      if (alg === 'none') {
        return Promise.resolve([
          base64url.encode(JSON.stringify(header)),
          base64url.encode(payload),
          '',
        ].join('.'));
      }

      const symmetrical = alg.startsWith('HS');

      const getKey = (() => {
        if (symmetrical) return this.joseSecret();
        const { keystore } = instance(this);

        assert(keystore, `no keystore present for client, cannot sign using ${alg}`);
        const key = keystore.get({ alg, use: 'sig' });
        assert(key, `no key to sign with found for ${alg}`);
        return Promise.resolve(key);
      })();

      return getKey
        .then(key => jose.JWS.createSign({
          fields: header,
          format,
        }, { key, reference: !symmetrical }))
        .then(sign => sign.update(payload).final());
    })();

    if (!algorithms.encrypt.alg) return signed;
    const fields = { alg: algorithms.encrypt.alg, enc: algorithms.encrypt.enc, cty: 'JWT' };

    let keystoreOrSecret;
    if (fields.alg.match(/^(RSA|ECDH)/)) {
      keystoreOrSecret = this.issuer.key({
        alg: fields.alg,
        enc: fields.enc,
        use: 'enc',
      }, true);
    } else {
      keystoreOrSecret = this.joseSecret(fields.alg);
    }

    /* eslint-disable arrow-body-style */
    return keystoreOrSecret.then((key) => {
      return signed.then((cleartext) => {
        return jose.JWE.createEncrypt({ format, fields }, { key, reference: key.kty !== 'oct' })
          .update(cleartext)
          .final();
      });
    });
    /* eslint-enable arrow-body-style */
  }

  get httpClient() {
    return this.issuer.httpClient;
  }

  static get httpClient() {
    return this.issuer.httpClient;
  }
}

module.exports = Client;

const assert = require('assert');
const util = require('util');
const url = require('url');

const jose = require('node-jose');
const _ = require('lodash');
const pAny = require('p-any');
const LRU = require('lru-cache');
const objectHash = require('object-hash');

const http = require('./helpers/http');
const httpRequest = require('./helpers/http_request');
const errorHandler = require('./helpers/error_handler')();
const getClient = require('./client');
const registry = require('./issuer_registry');
const expectResponseWithBody = require('./helpers/expect_response');
const webfingerNormalize = require('./util/webfinger_normalize');
const forEach = require('./util/for_each');
const {
  DEFAULT_HTTP_OPTIONS, ISSUER_DEFAULTS, OIDC_DISCOVERY,
  OAUTH2_DISCOVERY, WEBFINGER, REL, AAD_MULTITENANT_DISCOVERY,
} = require('./helpers/consts');

const privateProps = new WeakMap();

let defaultHttpOptions = _.clone(DEFAULT_HTTP_OPTIONS);
let httpClient;

function instance(ctx) {
  if (!privateProps.has(ctx)) privateProps.set(ctx, { metadata: {} });
  return privateProps.get(ctx);
}

const AAD_MULTITENANT = Symbol('AAD_MULTITENANT');

class Issuer {
  /**
   * @name constructor
   * @api public
   */
  constructor(meta = {}) {
    const aadIssValidation = meta[AAD_MULTITENANT];
    delete meta[AAD_MULTITENANT];

    ['introspection', 'revocation'].forEach((endpoint) => {
      // e.g. defaults introspection_endpoint to token_introspection_endpoint value
      if (
        meta[`${endpoint}_endpoint`] === undefined
        && meta[`token_${endpoint}_endpoint`] !== undefined
      ) {
        meta[`${endpoint}_endpoint`] = meta[`token_${endpoint}_endpoint`];
        delete meta[`token_${endpoint}_endpoint`];
      }

      // if intro/revocation endpoint auth specific meta is missing use the token ones if they
      // are defined
      if (
        meta[`${endpoint}_endpoint`]
        && meta[`${endpoint}_endpoint_auth_methods_supported`] === undefined
        && meta[`${endpoint}_endpoint_auth_signing_alg_values_supported`] === undefined
      ) {
        if (meta.token_endpoint_auth_methods_supported) {
          meta[`${endpoint}_endpoint_auth_methods_supported`] = meta.token_endpoint_auth_methods_supported;
        }
        if (meta.token_endpoint_auth_signing_alg_values_supported) {
          meta[`${endpoint}_endpoint_auth_signing_alg_values_supported`] = meta.token_endpoint_auth_signing_alg_values_supported;
        }
      }
    });

    forEach(meta, (value, key) => {
      instance(this).metadata[key] = value;
      if (!this[key]) {
        Object.defineProperty(this, key, {
          get() { return instance(this).metadata[key]; },
        });
      }
    });

    instance(this).cache = new LRU({ max: 100 });

    registry.set(this.issuer, this);

    Object.defineProperty(this, 'Client', {
      value: getClient(this, aadIssValidation),
    });
  }

  /**
   * @name inspect
   * @api public
   */
  inspect() {
    return util.format('Issuer <%s>', this.issuer);
  }

  /**
   * @name keystore
   * @api private
   */
  keystore(reload) {
    if (!this.jwks_uri) return Promise.reject(new Error('jwks_uri must be configured'));

    const { keystore, cache } = instance(this);

    if (reload || !keystore) {
      cache.reset();
      return this.httpClient.get(this.jwks_uri, this.httpOptions())
        .then(expectResponseWithBody(200))
        .then(response => JSON.parse(response.body))
        .then(jwks => jose.JWK.asKeyStore(jwks))
        .then((joseKeyStore) => {
          cache.set('throttle', true, 60 * 1000);
          instance(this).keystore = joseKeyStore;
          return joseKeyStore;
        })
        .catch(errorHandler.bind(this));
    }

    return Promise.resolve(keystore);
  }

  /**
   * @name key
   * @api private
   */
  key({
    kid, kty, alg, use, key_ops: ops,
  }, allowMulti = false) {
    const { cache } = instance(this);

    const def = {
      kid, kty, alg, use, key_ops: ops,
    };

    const defHash = objectHash(def, {
      algorithm: 'sha256',
      ignoreUnknown: true,
      unorderedArrays: true,
      unorderedSets: true,
    });

    // refresh keystore on every unknown key but also only upto once every minute
    const freshJwksUri = cache.get(defHash) || cache.get('throttle');

    return this.keystore(!freshJwksUri)
      .then(store => store.all(def))
      .then((keys) => {
        assert(keys.length, 'no valid key found');
        if (!allowMulti) {
          assert.equal(keys.length, 1, 'multiple matching keys, kid must be provided');
          cache.set(defHash, true);
        }
        return keys[0];
      });
  }

  /**
   * @name metadata
   * @api public
   */
  get metadata() {
    return instance(this).metadata;
  }

  /**
   * @name webfinger
   * @api public
   */
  static webfinger(input) {
    const resource = webfingerNormalize(input);
    const { host } = url.parse(resource);
    const query = { resource, rel: REL };
    const opts = { query, followRedirect: true };
    const webfingerUrl = `https://${host}${WEBFINGER}`;

    return this.httpClient.get(webfingerUrl, this.httpOptions(opts))
      .then(expectResponseWithBody(200))
      .then(response => JSON.parse(response.body))
      .then((body) => {
        const location = _.find(body.links, link => typeof link === 'object' && link.rel === REL && link.href);
        assert(location, 'no issuer found in webfinger');
        assert(typeof location.href === 'string' && location.href.startsWith('https://'), 'invalid issuer location');
        const expectedIssuer = location.href;
        if (registry.has(expectedIssuer)) return registry.get(expectedIssuer);

        return this.discover(expectedIssuer).then((issuer) => {
          try {
            assert.equal(issuer.issuer, expectedIssuer, 'discovered issuer mismatch');
          } catch (err) {
            registry.delete(issuer.issuer);
            throw err;
          }
          return issuer;
        });
      });
  }

  /**
   * @name discover
   * @api public
   */
  static discover(uri) {
    const parsed = url.parse(uri);

    if (parsed.pathname.includes('/.well-known/')) {
      return this.httpClient.get(uri, this.httpOptions())
        .then(expectResponseWithBody(200))
        .then(({ body }) => new Issuer(Object.assign(
          {},
          ISSUER_DEFAULTS,
          JSON.parse(body),
          { [AAD_MULTITENANT]: uri === AAD_MULTITENANT_DISCOVERY }
        )))
        .catch(errorHandler.bind(this));
    }

    const uris = [];
    if (parsed.pathname === '/') {
      uris.push(`${OAUTH2_DISCOVERY}`);
    } else {
      uris.push(`${OAUTH2_DISCOVERY}${parsed.pathname}`);
    }
    if (parsed.pathname.endsWith('/')) {
      uris.push(`${parsed.pathname}${OIDC_DISCOVERY.substring(1)}`);
    } else {
      uris.push(`${parsed.pathname}${OIDC_DISCOVERY}`);
    }

    return pAny(uris.map((pathname) => {
      const wellKnownUri = url.format(Object.assign({}, parsed, { pathname }));
      return this.httpClient.get(wellKnownUri, this.httpOptions())
        .then(expectResponseWithBody(200))
        .then(({ body }) => new Issuer(Object.assign(
          {},
          ISSUER_DEFAULTS,
          JSON.parse(body),
          { [AAD_MULTITENANT]: wellKnownUri === AAD_MULTITENANT_DISCOVERY }
        )));
    }))
      .catch((err) => {
        if (err instanceof pAny.AggregateError) {
          for (const el of err) { // eslint-disable-line no-restricted-syntax
            if (el instanceof this.httpClient.HTTPError) throw el;
            if (el.message.startsWith('expected 200 OK with body, got ')) throw el;
            if (el instanceof SyntaxError) throw el;
          }
        }
        throw err;
      })
      .catch(errorHandler.bind(this));
  }

  static useGot() {
    this.httpClient = http;
  }

  static useRequest() {
    this.httpClient = httpRequest();
  }

  get httpClient() {
    return this.constructor.httpClient;
  }

  static get httpClient() {
    return httpClient;
  }

  static set httpClient(client) {
    assert.equal(typeof client.get, 'function', 'client.get must be a function');
    assert.equal(typeof client.post, 'function', 'client.post must be a function');
    assert(client.HTTPError, 'client.HTTPError must be a constructor');
    httpClient = client;
  }

  /**
   * @name httpOptions
   * @api public
   */
  httpOptions(...args) {
    return this.constructor.httpOptions(...args);
  }

  /**
   * @name httpOptions
   * @api public
   */
  static httpOptions(values) {
    return _.merge({}, this.defaultHttpOptions, values);
  }

  /**
   * @name defaultHttpOptions
   * @api public
   */
  static get defaultHttpOptions() {
    return defaultHttpOptions;
  }

  /**
   * @name defaultHttpOptions=
   * @api public
   */
  static set defaultHttpOptions(value) {
    defaultHttpOptions = _.merge({}, DEFAULT_HTTP_OPTIONS, value);
  }
}

Issuer.useGot();

module.exports = Issuer;

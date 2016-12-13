'use strict';

const jose = require('node-jose');
const assert = require('assert');
const util = require('util');
const url = require('url');
const _ = require('lodash');
const LRU = require('lru-cache');
const got = require('got');

const DEFAULT_HTTP_OPTIONS = require('./consts').DEFAULT_HTTP_OPTIONS;
const ISSUER_DEFAULTS = require('./consts').ISSUER_DEFAULTS;
const ISSUER_METADATA = require('./consts').ISSUER_METADATA;
const DISCOVERY = require('./consts').DISCOVERY;
const WEBFINGER = require('./consts').WEBFINGER;
const REL = require('./consts').REL;

const gotErrorHandler = require('./got_error_handler');
const BaseClient = require('./client');
const registry = require('./issuer_registry');
const webfingerNormalize = require('./webfinger_normalize');

const privateProps = new WeakMap();

let defaultHttpOptions = _.clone(DEFAULT_HTTP_OPTIONS);

function instance(ctx) {
  if (!privateProps.has(ctx)) privateProps.set(ctx, {});
  return privateProps.get(ctx);
}

function stripTrailingSlash(uri) {
  if (uri && uri.endsWith('/')) {
    return uri.slice(0, -1);
  }
  return uri;
}

class Issuer {
  constructor(metadata) {
    _.forEach(_.defaults(_.pick(metadata, ISSUER_METADATA), ISSUER_DEFAULTS), (value, key) => {
      instance(this)[key] = value;
    });

    instance(this).cache = new LRU({ max: 100 });

    registry.set(this.issuer, this);

    const self = this;

    Object.defineProperty(this, 'Client', {
      value: class Client extends BaseClient {
        static get issuer() {
          return self;
        }

        get issuer() {
          return this.constructor.issuer;
        }
      },
    });
  }

  inspect() {
    return util.format('Issuer <%s>', this.issuer);
  }

  keystore(reload) {
    const keystore = instance(this).keystore;
    const lookupCache = instance(this).cache;

    if (reload || !keystore) {
      lookupCache.reset();
      return got(this.jwks_uri, this.httpOptions())
      .then(response => JSON.parse(response.body), gotErrorHandler)
      .then(jwks => jose.JWK.asKeyStore(jwks))
      .then((joseKeyStore) => {
        lookupCache.set('throttle', true, 60 * 1000);
        instance(this).keystore = joseKeyStore;
        return joseKeyStore;
      });
    }

    return Promise.resolve(keystore);
  }

  key(def, allowMulti) {
    const lookupCache = instance(this).cache;

    // refresh keystore on every unknown key but also only upto once every minute
    const freshJwksUri = lookupCache.get(def) || lookupCache.get('throttle');

    return this.keystore(!freshJwksUri)
      .then(store => store.all(def))
      .then((keys) => {
        assert(keys.length, 'no valid key found');
        if (!allowMulti) {
          assert.equal(keys.length, 1, 'multiple matching keys, kid must be provided');
          lookupCache.set(def, true);
        }
        return keys[0];
      });
  }

  get metadata() {
    return _.omitBy(_.pick(this, ISSUER_METADATA), _.isUndefined);
  }

  static webfinger(input) {
    const resource = webfingerNormalize(input);
    const host = url.parse(resource).host;
    const query = { resource, rel: REL };
    const opts = { query, followRedirect: true };

    return got(`https://${host}${WEBFINGER}`, this.httpOptions(opts))
      .then(response => JSON.parse(response.body))
      .then((body) => {
        const foo = _.find(body.links, link => typeof link === 'object' && link.rel === REL && link.href);
        assert(foo, 'no issuer found in webfinger');
        const expectedIssuer = foo.href;
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

  static discover(uri) {
    uri = stripTrailingSlash(uri); // eslint-disable-line no-param-reassign
    const isWellKnown = uri.endsWith(DISCOVERY);
    const wellKnownUri = isWellKnown ? uri : `${uri}${DISCOVERY}`;

    return got(wellKnownUri, this.httpOptions())
      .then(response => new this(JSON.parse(response.body)), gotErrorHandler);
  }

  httpOptions() {
    return this.constructor.httpOptions.apply(this.constructor, arguments); // eslint-disable-line prefer-rest-params, max-len
  }

  static httpOptions(values) {
    return _.merge({}, this.defaultHttpOptions, values);
  }

  static get defaultHttpOptions() {
    return defaultHttpOptions;
  }

  static set defaultHttpOptions(value) {
    defaultHttpOptions = _.merge({}, DEFAULT_HTTP_OPTIONS, value);
  }

}

ISSUER_METADATA.forEach((prop) => {
  Object.defineProperty(Issuer.prototype, prop, {
    get() {
      return instance(this)[prop];
    },
  });
});

module.exports = Issuer;

'use strict';

const url = require('url');
const jose = require('node-jose');
const util = require('util');
const _ = require('lodash');
const LRU = require('lru-cache');
const got = require('got');

const DEFAULT_HTTP_OPTIONS = require('./consts').DEFAULT_HTTP_OPTIONS;
const ISSUER_DEFAULTS = require('./consts').ISSUER_DEFAULTS;
const ISSUER_METADATA = require('./consts').ISSUER_METADATA;
const WELL_KNOWN = require('./consts').WELL_KNOWN;

const gotErrorHandler = require('./got_error_handler');
const BaseClient = require('./base_client');

const map = new WeakMap();

let defaultHttpOptions = _.clone(DEFAULT_HTTP_OPTIONS);

function instance(ctx) {
  if (!map.has(ctx)) map.set(ctx, {});
  return map.get(ctx);
}

class Issuer {
  constructor(metadata) {
    _.forEach(_.defaults(_.pick(metadata, ISSUER_METADATA), ISSUER_DEFAULTS), (value, key) => {
      instance(this)[key] = value;
    });

    instance(this).cache = new LRU({ max: 100 });

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
      return got.get(this.jwks_uri, this.httpOptions())
      .then(response => JSON.parse(response.body), gotErrorHandler)
      .then(jwks => jose.JWK.asKeyStore(jwks))
      .then(joseKeyStore => {
        lookupCache.set('throttle', true, 60 * 1000);
        instance(this).keystore = joseKeyStore;
        return joseKeyStore;
      });
    }

    return Promise.resolve(keystore);
  }

  key(def) {
    const lookupCache = instance(this).cache;

    // refresh keystore on every unknown key but also only upto once every minute
    const freshJwksUri = lookupCache.get(def) || lookupCache.get('throttle');

    return this.keystore(!freshJwksUri)
      .then(store => store.get(def))
      .then(key => {
        lookupCache.set(def, true);
        return key;
      });
  }

  get metadata() {
    return _.omitBy(_.pick(this, ISSUER_METADATA), _.isUndefined);
  }

  static discover(uri) {
    const isWellKnown = uri.endsWith(WELL_KNOWN);
    const wellKnownUri = isWellKnown ? uri : url.resolve(uri, WELL_KNOWN);

    return got.get(wellKnownUri, this.httpOptions())
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

ISSUER_METADATA.forEach(prop => {
  Object.defineProperty(Issuer.prototype, prop, {
    get() {
      return instance(this)[prop];
    },
  });
});

module.exports = Issuer;

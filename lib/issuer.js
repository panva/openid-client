'use strict';

const url = require('url');
const jose = require('node-jose');
const util = require('util');
const _ = require('lodash');

const isStandardError = require('./is_standard_error');
const OpenIdConnectError = require('./open_id_connect_error');

const USER_AGENT = require('./consts').USER_AGENT;
const WELL_KNOWN = require('./consts').WELL_KNOWN;
const ISSUER_METADATA = require('./consts').ISSUER_METADATA;
const ISSUER_DEFAULTS = require('./consts').ISSUER_DEFAULTS;

const BaseClient = require('./base_client');

const got = require('got');
const map = new WeakMap();

const DEFAULT_HTTP_OPTIONS = {
  followRedirect: false,
  headers: { 'User-Agent': USER_AGENT },
  retries: 0,
  timeout: 1500,
};
Object.freeze(DEFAULT_HTTP_OPTIONS);

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

  keystore() {
    return got.get(this.jwks_uri, this.httpOptions())
      .then(response => JSON.parse(response.body), err => {
        if (isStandardError(err)) throw new OpenIdConnectError(err.response.body);
        throw err;
      })
      .then(jwks => jose.JWK.asKeyStore(jwks));
  }

  key(def) {
    return this.keystore().then(store => store.get(def));
  }

  get metadata() {
    return _.omitBy(_.pick(this, ISSUER_METADATA), _.isUndefined);
  }

  static discover(uri) {
    const isWellKnown = uri.endsWith(WELL_KNOWN);
    const wellKnownUri = isWellKnown ? uri : url.resolve(uri, WELL_KNOWN);

    return got.get(wellKnownUri, this.httpOptions())
      .then(response => new this(JSON.parse(response.body)), err => {
        if (isStandardError(err)) throw new OpenIdConnectError(err.response.body);
        throw err;
      });
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

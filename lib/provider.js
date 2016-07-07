'use strict';

const url = require('url');
const jose = require('node-jose');
const util = require('util');
const { defaults, pick, forEach } = require('lodash');

const {
  USER_AGENT,
  WELL_KNOWN,
  PROVIDER_METADATA,
  PROVIDER_DEFAULTS,
} = require('./consts');

const BaseClient = require('./base_client');

const debug = require('debug')('oidc:provider');

const got = require('got');
const map = new WeakMap();

function instance(ctx) {
  if (!map.has(ctx)) map.set(ctx, {});
  return map.get(ctx);
}

class Provider {
  constructor(metadata) {
    forEach(defaults(pick(metadata, PROVIDER_METADATA), PROVIDER_DEFAULTS), (value, key) => {
      instance(this)[key] = value;
    });

    const self = this;

    Object.defineProperty(this, 'Client', {
      value: class Client extends BaseClient {
        static get provider() {
          return self;
        }

        get provider() {
          return this.constructor.provider;
        }
      },
    });
  }

  inspect() {
    return util.format('Provider <%s>', this.issuer);
  }

  keyStore() {
    debug('%s request started', this.jwks_uri);

    return got.get(this.jwks_uri)
    .then(response => JSON.parse(response.body), err => {
      debug('%s request failed (%s > %s)', this.provider.jwks_uri, err.name, err.message);
      throw err;
    })
    .then(jwks => jose.JWK.asKeyStore(jwks));
  }

  key(def) {
    return this.keyStore().then(store => store.get(def));
  }

  static discover(uri) {
    const isWellKnown = uri.endsWith(WELL_KNOWN);
    const wellKnownUri = isWellKnown ? uri : url.resolve(uri, WELL_KNOWN);

    debug('discovering configuration from %s', wellKnownUri);

    return got.get(wellKnownUri, {
      retries: 0,
      followRedirect: false,
      headers: {
        'User-Agent': USER_AGENT,
      },
    }).then(response => new this(JSON.parse(response.body)), err => {
      debug('%s discovery failed (%s > %s)', wellKnownUri, err.name, err.message);
      throw err;
    });
  }
}

PROVIDER_METADATA.forEach(prop => {
  Object.defineProperty(Provider.prototype, prop, {
    get() {
      return instance(this)[prop];
    },
  });
});

module.exports = Provider;

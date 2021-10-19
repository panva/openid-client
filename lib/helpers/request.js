const assert = require('assert');
const querystring = require('querystring');
const http = require('http');
const https = require('https');
const { once } = require('events');

const CacheableLookup = require('cacheable-lookup');
const QuickLRU = require('quick-lru');

const pkg = require('../../package.json');
const { RPError } = require('../errors');

const pick = require('./pick');
const { deep: defaultsDeep } = require('./defaults');
const { HTTP_OPTIONS } = require('./consts');

let DEFAULT_HTTP_OPTIONS;

const cacheable = new CacheableLookup({
  cache: new QuickLRU({ maxSize: 1000 }),
});
const allowed = [
  'agent',
  'ca',
  'cert',
  'crl',
  'headers',
  'key',
  'lookup',
  'passphrase',
  'pfx',
  'timeout',
];

const setDefaults = (props, options) => {
  // eslint-disable-next-line max-len
  DEFAULT_HTTP_OPTIONS = defaultsDeep({}, props.length ? pick(options, ...props) : options, DEFAULT_HTTP_OPTIONS);
};

setDefaults([], {
  headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})` },
  timeout: 3500,
  lookup: cacheable.lookup,
});

module.exports = async function request(options, { accessToken, mTLS = false, DPoP } = {}) {
  let url;
  try {
    url = new URL(options.url);
    delete options.url;
    assert(/^(https?:)$/.test(url.protocol));
  } catch (err) {
    throw new TypeError('only valid absolute URLs can be requested');
  }
  const optsFn = this[HTTP_OPTIONS];
  let opts = options;

  if (DPoP && 'dpopProof' in this) {
    opts.headers = opts.headers || {};
    opts.headers.DPoP = this.dpopProof({
      htu: url,
      htm: options.method,
    }, DPoP, accessToken);
  }

  let userOptions;
  if (optsFn) {
    userOptions = pick(
      optsFn.call(this, url, defaultsDeep({}, opts, DEFAULT_HTTP_OPTIONS)),
      ...allowed,
    );
  }
  opts = defaultsDeep({}, userOptions, opts, DEFAULT_HTTP_OPTIONS);

  if (mTLS && (!opts.pfx && !(opts.key && opts.cert))) {
    throw new TypeError('mutual-TLS certificate and key not set');
  }

  if (opts.searchParams) {
    // eslint-disable-next-line no-restricted-syntax
    for (const [key, value] of Object.entries(opts.searchParams)) {
      url.searchParams.delete(key);
      url.searchParams.set(key, value);
    }
  }

  let responseType;
  let form;
  let json;
  let body;
  ({
    // eslint-disable-next-line prefer-const
    form, responseType, json, body, ...opts
  } = opts);

  // eslint-disable-next-line no-restricted-syntax
  for (const [key, value] of Object.entries(opts.headers || {})) {
    if (value === undefined) {
      delete opts.headers[key];
    }
  }

  let response;
  const req = (url.protocol === 'https:' ? https.request : http.request)(url, opts);
  return (async () => {
    // if (GET (and other && form, json, body)) throw;
    if (json) {
      req.removeHeader('content-type');
      req.setHeader('content-type', 'application/json');
      req.write(JSON.stringify(json));
    } else if (form) {
      req.removeHeader('content-type');
      req.setHeader('content-type', 'application/x-www-form-urlencoded');
      req.write(querystring.stringify(form));
    } else if (body) {
      req.write(body);
    }

    req.end();

    [response] = await Promise.race([once(req, 'response'), once(req, 'timeout')]);

    // timeout reached
    if (!response) {
      req.destroy();
      throw new RPError(`outgoing request timed out after ${opts.timeout}ms`);
    }

    const parts = [];
    // eslint-disable-next-line no-restricted-syntax
    for await (const part of response) {
      parts.push(part);
    }

    if (parts.length) {
      switch (responseType) {
        case 'json': {
          Object.defineProperty(response, 'body', {
            get() {
              let value = Buffer.concat(parts);
              try {
                value = JSON.parse(value);
              } catch (err) {
                Object.defineProperty(err, 'response', response);
                throw err;
              } finally {
                Object.defineProperty(response, 'body', { value, configurable: true });
              }
              return value;
            },
            configurable: true,
          });
          break;
        }
        case undefined:
        case 'buffer': {
          Object.defineProperty(response, 'body', {
            get() {
              const value = Buffer.concat(parts);
              Object.defineProperty(response, 'body', { value, configurable: true });
              return value;
            },
            configurable: true,
          });
          break;
        }
        default:
          throw new TypeError('unsupported responseType request option');
      }
    }

    return response;
  })().catch((err) => {
    Object.defineProperty(err, 'response', response);
    throw err;
  });
};

module.exports.setDefaults = setDefaults.bind(undefined, allowed);

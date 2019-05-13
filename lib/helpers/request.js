const got = require('got');
const { defaultsDeep } = require('lodash');

const pkg = require('../../package.json');

const isAbsoluteUrl = require('./is_absolute_url');
const { HTTP_OPTIONS } = require('./consts');

const USER_AGENT = `${pkg.name}/${pkg.version} (${pkg.homepage})`;

const DEFAULT_HTTP_OPTIONS = {
  followRedirect: false,
  headers: { 'User-Agent': USER_AGENT },
  retry: 0,
  timeout: 2500,
  throwHttpErrors: false,
};

module.exports = function request(options, { mTLS = false } = {}) {
  const { url } = options;
  isAbsoluteUrl(url);
  const optsFn = this[HTTP_OPTIONS];
  let opts;
  if (optsFn) {
    opts = optsFn.call(this, defaultsDeep(options, DEFAULT_HTTP_OPTIONS));
  } else {
    opts = defaultsDeep(options, DEFAULT_HTTP_OPTIONS);
  }

  if (mTLS && (!opts.key || !opts.cert)) {
    throw new TypeError('mutual-TLS certificate and key not set');
  }
  return got(opts);
};

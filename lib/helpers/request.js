const Got = require('got');
const defaultsDeep = require('lodash/defaultsDeep');

const pkg = require('../../package.json');

const isAbsoluteUrl = require('./is_absolute_url');
const { HTTP_OPTIONS } = require('./consts');

let DEFAULT_HTTP_OPTIONS;
let got;

const setDefaults = (options) => {
  DEFAULT_HTTP_OPTIONS = defaultsDeep(options, DEFAULT_HTTP_OPTIONS);
  got = Got.extend(DEFAULT_HTTP_OPTIONS);
};

setDefaults({
  followRedirect: false,
  headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})` },
  retry: 0,
  timeout: 2500,
  throwHttpErrors: false,
});

module.exports = function request(options, { mTLS = false } = {}) {
  const { url } = options;
  isAbsoluteUrl(url);
  const optsFn = this[HTTP_OPTIONS];
  let opts;
  if (optsFn) {
    opts = optsFn.call(this, defaultsDeep(options, DEFAULT_HTTP_OPTIONS));
  } else {
    opts = options;
  }

  if (mTLS && (!opts.key || !opts.cert)) {
    throw new TypeError('mutual-TLS certificate and key not set');
  }
  return got(opts);
};

module.exports.setDefaults = setDefaults;

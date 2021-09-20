const Got = require('got');

const pkg = require('../../package.json');

const { deep: defaultsDeep } = require('./defaults');
const isAbsoluteUrl = require('./is_absolute_url');
const { HTTP_OPTIONS } = require('./consts');

let DEFAULT_HTTP_OPTIONS;
let got;

const setDefaults = (options) => {
  DEFAULT_HTTP_OPTIONS = defaultsDeep({}, options, DEFAULT_HTTP_OPTIONS);
  got = Got.extend(DEFAULT_HTTP_OPTIONS);
};

setDefaults({
  followRedirect: false,
  headers: { 'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})` },
  retry: 0,
  timeout: 3500,
  throwHttpErrors: false,
});

module.exports = async function request(options, { accessToken, mTLS = false, DPoP } = {}) {
  const { url } = options;
  isAbsoluteUrl(url);
  const optsFn = this[HTTP_OPTIONS];
  let opts = options;

  if (DPoP && 'dpopProof' in this) {
    opts.headers = opts.headers || {};
    opts.headers.DPoP = this.dpopProof({
      htu: url,
      htm: options.method,
    }, DPoP, accessToken);
  }

  if (optsFn) {
    opts = optsFn.call(this, defaultsDeep({}, opts, DEFAULT_HTTP_OPTIONS));
  }

  if (
    mTLS
    && (
      (!opts.key || !opts.cert)
      && (!opts.https || !((opts.https.key && opts.https.certificate) || opts.https.pfx))
    )
  ) {
    throw new TypeError('mutual-TLS certificate and key not set');
  }

  return got(opts);
};

module.exports.setDefaults = setDefaults;

const { merge } = require('lodash');
const jose = require('@panva/jose');

const { assertIssuerConfiguration } = require('./assert');
const { random } = require('./generators');
const now = require('./unix_timestamp');
const request = require('./request');
const instance = require('./weak_cache');

const formUrlEncode = value => encodeURIComponent(value).replace(/%20/g, '+');

async function clientAssertion(endpoint, payload) {
  let alg = this[`${endpoint}_endpoint_auth_signing_alg`];
  if (!alg) {
    assertIssuerConfiguration(this.issuer, `${endpoint}_endpoint_auth_signing_alg_values_supported`);
  }

  if (this[`${endpoint}_endpoint_auth_method`] === 'client_secret_jwt') {
    const key = await this.joseSecret();

    if (!alg) {
      const supported = this.issuer[`${endpoint}_endpoint_auth_signing_alg_values_supported`];
      alg = Array.isArray(supported) && supported.find(signAlg => key.algorithms('sign').has(signAlg));
    }

    return jose.JWS.sign(payload, key, { alg, typ: 'JWT' });
  }

  if (!alg) {
    const algs = new Set();

    instance(this).get('keystore').all().forEach((key) => {
      key.algorithms('sign').forEach(Set.prototype.add.bind(algs));
    });

    const supported = this.issuer[`${endpoint}_endpoint_auth_signing_alg_values_supported`];
    alg = Array.isArray(supported) && supported.find(signAlg => algs.has(signAlg));
  }

  const key = instance(this).get('keystore').get({ alg, use: 'sig' });
  if (!key) {
    throw new TypeError(`no key found in client jwks to sign a client assertion with using alg ${alg}`);
  }
  return jose.JWS.sign(payload, key, { alg, typ: 'JWT', kid: key.kid });
}

async function authFor(endpoint, { clientAssertionPayload } = {}) {
  const authMethod = this[`${endpoint}_endpoint_auth_method`];
  switch (authMethod) {
    case 'self_signed_tls_client_auth':
    case 'tls_client_auth':
    case 'none':
      return { body: { client_id: this.client_id } };
    case 'client_secret_post':
      return { body: { client_id: this.client_id, client_secret: this.client_secret } };
    case 'private_key_jwt':
    case 'client_secret_jwt': {
      const timestamp = now();
      const assertion = await clientAssertion.call(this, endpoint, {
        ...clientAssertionPayload,
        iat: timestamp,
        exp: timestamp + 60,
        jti: random(),
        iss: this.client_id,
        sub: this.client_id,
        aud: this.issuer[`${endpoint}_endpoint`],
      });

      return {
        body: {
          client_id: this.client_id,
          client_assertion: assertion,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        },
      };
    }
    default: { // client_secret_basic
      // This is correct behaviour, see https://tools.ietf.org/html/rfc6749#section-2.3.1 and the
      // related appendix. (also https://github.com/panva/node-openid-client/pull/91)
      // > The client identifier is encoded using the
      // > "application/x-www-form-urlencoded" encoding algorithm per
      // > Appendix B, and the encoded value is used as the username; the client
      // > password is encoded using the same algorithm and used as the
      // > password.
      const encoded = `${formUrlEncode(this.client_id)}:${formUrlEncode(this.client_secret)}`;
      const value = Buffer.from(encoded).toString('base64');
      return { headers: { Authorization: `Basic ${value}` } };
    }
  }
}

function resolveResponseType() {
  const { length, 0: value } = this.response_types;

  if (length === 1) {
    return value;
  }

  return undefined;
}

function resolveRedirectUri() {
  const { length, 0: value } = this.redirect_uris || [];

  if (length === 1) {
    return value;
  }

  return undefined;
}

async function authenticatedPost(endpoint, opts, { clientAssertionPayload } = {}) {
  const auth = await authFor.call(this, endpoint, { clientAssertionPayload });
  const requestOpts = merge(opts, auth, { form: true });

  const mTLS = this[`${endpoint}_endpoint_auth_method`].includes('tls_client_auth');

  let targetUrl;
  if (mTLS) {
    try {
      targetUrl = this.issuer.mtls_endpoint_aliases[`${endpoint}_endpoint`];
    } catch (err) {}
  }

  targetUrl = targetUrl || this.issuer[`${endpoint}_endpoint`];

  return request.call(this, {
    ...requestOpts,
    method: 'POST',
    url: targetUrl,
  }, { mTLS });
}

module.exports = {
  resolveResponseType,
  resolveRedirectUri,
  authFor,
  authenticatedPost,
};

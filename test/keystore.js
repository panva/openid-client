const jose = require('jose');
const crypto = require('crypto');
const base64url = require('../lib/helpers/base64url');

module.exports = class KeyStore {
  constructor({ keys } = {}) {
    this.keys = keys || [];
  }

  async generate(kty, crvOrSize, { alg, kid, use } = {}) {
    let kp;
    if (kty !== 'oct' && alg) {
      kp = await jose.generateKeyPair(alg);
    } else {
      switch (kty) {
        case 'EC': {
          switch (crvOrSize) {
            case undefined:
            case 'P-256':
              kp = await jose.generateKeyPair('ES256', { extractable: true });
              break;
            case 'P-384':
              kp = await jose.generateKeyPair('ES384', { extractable: true });
              break;
            case 'P-521':
              kp = await jose.generateKeyPair('ES512', { extractable: true });
              break;
            case 'secp256k1':
              kp = await jose.generateKeyPair('ES256K', { extractable: true });
              break;
          }
          break;
        }
        case 'oct': {
          const secret = crypto.randomBytes((crvOrSize || 256) >> 3);
          const jwk = {
            kty: 'oct',
            use: use,
            alg,
            k: base64url.encode(secret),
          };
          jwk.kid = kid || (await jose.calculateJwkThumbprint(jwk));
          this.keys.push(jwk);
          return;
        }
        case 'RSA': {
          kp = await jose.generateKeyPair('RS256', { modulusLength: crvOrSize, extractable: true });
          break;
        }
        case 'OKP': {
          switch (crvOrSize) {
            case undefined:
            case 'Ed25519':
            case 'Ed448':
              kp = await jose.generateKeyPair('EdDSA', { crv: crvOrSize, extractable: true });
              break;
            case 'X25519':
            case 'X448':
              kp = await jose.generateKeyPair('ECDH-ES', { crv: crvOrSize, extractable: true });
              break;
          }
          break;
        }
      }
    }
    const jwk = {
      ...(await jose.exportJWK(kp.privateKey)),
      kid,
    };
    jwk.kid || (jwk.kid = await jose.calculateJwkThumbprint(jwk));
    if (use) jwk.use = use;
    this.keys.push(jwk);
  }

  get(query) {
    if (!query) {
      return this.keys[0];
    }
    const { kty } = query || {};
    return this.keys.find((jwk) => {
      return jwk.kty === kty;
    });
  }

  toJWKS(includePrivate) {
    if (includePrivate) {
      return { keys: this.keys };
    }

    return {
      keys: this.keys.map((privateKey) => {
        const { k, d, dp, dq, p, q, qi, ...jwk } = privateKey;
        return jwk;
      }),
    };
  }
};

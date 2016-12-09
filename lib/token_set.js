'use strict';

const now = require('./unix_timestamp');
const base64url = require('base64url');

const decodedClaims = new WeakMap();

class TokenSet {
  constructor(values) {
    Object.assign(this, values);
  }

  set expires_in(value) { // eslint-disable-line camelcase
    this.expires_at = now() + Number(value);
  }

  get expires_in() { // eslint-disable-line camelcase
    return Math.max.apply(null, [this.expires_at - now(), 0]);
  }

  expired() {
    return this.expires_in === 0;
  }

  get claims() {
    if (decodedClaims.has(this)) return decodedClaims.get(this);
    if (!this.id_token) throw new Error('id_token not present in TokenSet');

    const decoded = JSON.parse(base64url.decode(this.id_token.split('.')[1]));
    decodedClaims.set(this, decoded);
    return decoded;
  }
}

module.exports = TokenSet;

'use strict';

class TokenSet {
  constructor(values) {
    Object.assign(this, values);
  }

  set expires_in(value) { // eslint-disable-line camelcase
    const now = new Date() / 1000 | 0;
    this.expires_at = now + Number(value);
  }

  get expires_in() { // eslint-disable-line camelcase
    const now = new Date() / 1000 | 0;
    return Math.max.apply(null, [this.expires_at - now, 0]);
  }

  expired() {
    return this.expires_in === 0;
  }
}

module.exports = TokenSet;

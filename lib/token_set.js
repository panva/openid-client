const base64url = require('base64url');

const now = require('./helpers/unix_timestamp');

class TokenSet {
  /**
   * @name constructor
   * @api public
   */
  constructor(values) {
    Object.assign(this, values);
  }

  /**
   * @name expires_in=
   * @api public
   */
  set expires_in(value) { // eslint-disable-line camelcase
    this.expires_at = now() + Number(value);
  }

  /**
   * @name expires_in
   * @api public
   */
  get expires_in() { // eslint-disable-line camelcase
    return Math.max.apply(null, [this.expires_at - now(), 0]);
  }

  /**
   * @name expired
   * @api public
   */
  expired() {
    return this.expires_in === 0;
  }

  /**
   * @name claims
   * @api public
   */
  claims() {
    if (!this.id_token) {
      throw new TypeError('id_token not present in TokenSet');
    }

    return JSON.parse(base64url.decode(this.id_token.split('.')[1]));
  }
}

module.exports = TokenSet;

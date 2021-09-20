const { createHash, randomBytes } = require('crypto');

const base64url = require('./base64url');

const random = (bytes = 32) => base64url.encode(randomBytes(bytes));
const sha256 = (input) => base64url.encode(createHash('sha256').update(input).digest());

module.exports = {
  random,
  state: random,
  nonce: random,
  codeVerifier: random,
  sha256,
  codeChallenge: sha256,
};

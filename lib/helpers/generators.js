const { createHash, randomBytes } = require('crypto');

const { encode: base64url } = require('base64url');

const random = (bytes = 32) => base64url(randomBytes(bytes));

module.exports = {
  random,
  state: random,
  nonce: random,
  codeVerifier: random,
  codeChallenge: (codeVerifier) => base64url(createHash('sha256').update(codeVerifier).digest()),
};

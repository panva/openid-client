const { randomBytes } = require('crypto');

const base64url = require('base64url');

module.exports = (bytes = 32) => base64url(randomBytes(bytes));

const { STATUS_CODES } = require('http');
const { format } = require('util');

const { OPError } = require('../errors');

const REGEXP = /(\w+)=("[^"]*")/g;
const throwAuthenticateErrors = (response) => {
  const params = {};
  try {
    while ((REGEXP.exec(response.headers['www-authenticate'])) !== null) {
      if (RegExp.$1 && RegExp.$2) {
        params[RegExp.$1] = RegExp.$2.slice(1, -1);
      }
    }
  } catch (err) {}

  if (params.error) {
    throw new OPError(params, response);
  }
};
const isStandardBodyError = (response) => {
  try {
    if (typeof response.body !== 'object') {
      response.body = JSON.parse(response.body);
    }
    return typeof response.body.error === 'string' && response.body.error.length;
  } catch (err) {}

  return false;
};

function processResponse(response, { statusCode = 200, body = true, bearer = false } = {}) {
  if (response.statusCode !== statusCode) {
    if (bearer) {
      throwAuthenticateErrors(response);
    }

    if (isStandardBodyError(response)) {
      throw new OPError(response.body, response);
    }

    throw new OPError({
      error: format('expected %i %s, got: %i %s', statusCode, STATUS_CODES[statusCode], response.statusCode, STATUS_CODES[response.statusCode]),
    }, response);
  }

  if (body && !response.body) {
    throw new OPError({
      error: format('expected %i %s with body but no body was returned', statusCode, STATUS_CODES[statusCode]),
    }, response);
  }

  return response.body;
}


module.exports = processResponse;

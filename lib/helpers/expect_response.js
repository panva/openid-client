const assert = require('assert');
const { STATUS_CODES } = require('http');

const { memoize } = require('lodash');

module.exports = memoize(statusCode => function expectResponseWithBody(response) {
  assert(
    response.body,
    `expected ${statusCode} ${STATUS_CODES[statusCode]} with body, got ${response.statusCode} ${STATUS_CODES[response.statusCode]} without one`
  );
  return response;
});

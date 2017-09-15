'use strict';

const assert = require('assert');
const STATUS_CODES = require('http').STATUS_CODES;

module.exports = function generateExpectResponseBody(statusCode) {
  return function expectResponseBody(response) {
    assert(
      response.body,
      `expected ${statusCode} ${STATUS_CODES[statusCode]} with body, got ${response.statusCode} ${STATUS_CODES[response.statusCode]} without one`
    );
    return response;
  };
};

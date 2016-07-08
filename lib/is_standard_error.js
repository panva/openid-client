'use strict';

const got = require('got');

module.exports = function isStandardError(error) {
  if (error instanceof got.HTTPError) {
    try {
      error.response.body = JSON.parse(error.response.body);
      return !!error.response.body.error;
    } catch (err) {}
  }

  return false;
};

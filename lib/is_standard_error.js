'use strict';

const http = require('./http');

module.exports = function isStandardError(error) {
  if (error instanceof http.HTTPError) {
    try {
      error.response.body = JSON.parse(error.response.body);
      return !!error.response.body.error;
    } catch (err) {}
  }

  return false;
};

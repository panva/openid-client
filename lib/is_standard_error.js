'use strict';

module.exports = function isStandardError(error) {
  if (error instanceof this.httpClient.HTTPError) {
    try {
      error.response.body = JSON.parse(error.response.body);
      return !!error.response.body.error;
    } catch (err) {}
  }

  return false;
};

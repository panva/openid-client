'use strict';

const createErrorClass = require('create-error-class');

module.exports = createErrorClass('OpenIdConnectError', function stdError(body, response) {
  if (response) {
    Object.defineProperty(this, 'response', {
      value: response,
    });
  }
  Object.assign(this, {
    message: `${body.error} (${body.error_description})`,
    error: body.error,
    error_description: body.error_description,
    error_uri: body.error_uri,
    state: body.state,
    scope: body.scope,
  });
});

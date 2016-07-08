'use strict';

const createErrorClass = require('create-error-class');

module.exports = createErrorClass('OpenIdConnectError', function stdError(response) {
  Object.assign(this, {
    message: response.error,
    error: response.error,
    error_description: response.error_description,
    state: response.state,
    scope: response.scope,
  });
});

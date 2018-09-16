/* eslint-disable camelcase */

class OpenIdConnectError extends Error {
  constructor({
    error_description,
    error,
    error_uri,
    session_state,
    state,
    scope,
  }, response) {
    super(!error_description ? error : `${error} (${error_description})`);
    Error.captureStackTrace(this, this.constructor);

    Object.assign(
      this,
      { error },
      (error_description && { error_description }),
      (error_uri && { error_uri }),
      (state && { state }),
      (scope && { scope }),
      (session_state && { session_state })
    );

    Object.defineProperty(this, 'response', {
      value: response,
    });
  }
}

Object.defineProperty(OpenIdConnectError.prototype, 'name', {
  enumerable: false,
  configurable: true,
  value: 'OpenIdConnectError',
  writable: true,
});

module.exports = OpenIdConnectError;

/* eslint-disable camelcase */

/* istanbul ignore next */
function responseInspect() {
  return {
    body: this.body,
    url: this.url,
    statusCode: this.statusCode,
    headers: this.headers,
  };
}

module.exports = class OpenIdConnectError extends Error {
  constructor({
    error_description,
    error,
    error_uri,
    state,
    scope,
  }, response) {
    super(!error_description ? error : `${error} (${error_description})`);
    Error.captureStackTrace(this, this.constructor);

    Object.assign(
      this,
      { error, name: this.constructor.name },
      (error_description && { error_description }),
      (error_uri && { error_uri }),
      (state && { state }),
      (scope && { scope }),
      (response && (response.inspect = responseInspect) && { response })
    );
  }
};

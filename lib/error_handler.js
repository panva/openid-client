const isStandardError = require('./is_standard_error');
const OpenIdConnectError = require('./open_id_connect_error');

module.exports = function requestErrorHandler(err) {
  if (isStandardError.call(this, err)) {
    throw new OpenIdConnectError(err.response.body, err.response);
  }

  throw err;
};

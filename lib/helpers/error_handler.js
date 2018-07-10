const OpenIdConnectError = require('../open_id_connect_error');

const isStandardBodyError = require('./is_standard_body_error');
const checkIfBearerHeaderOnlyError = require('./is_bearer_header_only_error');

module.exports = ({ bearerEndpoint = false } = {}) => function requestErrorHandler(err) {
  if (bearerEndpoint) {
    const [isBearerHeaderOnlyError, params] = checkIfBearerHeaderOnlyError.call(this, err);

    if (isBearerHeaderOnlyError) {
      throw new OpenIdConnectError(params, err.response);
    }
  }

  if (isStandardBodyError.call(this, err)) {
    throw new OpenIdConnectError(err.response.body, err.response);
  }

  throw err;
};

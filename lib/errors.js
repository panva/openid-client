/* eslint-disable camelcase */
const { format } = require('util');

const assign = require('lodash/assign');
const makeError = require('make-error');

function OPError({
  error_description,
  error,
  error_uri,
  session_state,
  state,
  scope,
}, response) {
  OPError.super.call(this, !error_description ? error : `${error} (${error_description})`);

  assign(
    this,
    { error },
    (error_description && { error_description }),
    (error_uri && { error_uri }),
    (state && { state }),
    (scope && { scope }),
    (session_state && { session_state }),
  );

  if (response) {
    Object.defineProperty(this, 'response', {
      value: response,
    });
  }
}

makeError(OPError);

function RPError(...args) {
  if (typeof args[0] === 'string') {
    RPError.super.call(this, format(...args));
  } else {
    const {
      message, printf, response, ...rest
    } = args[0];
    if (printf) {
      RPError.super.call(this, format(...printf));
    } else {
      RPError.super.call(this, message);
    }
    assign(this, rest);
    if (response) {
      Object.defineProperty(this, 'response', {
        value: response,
      });
    }
  }
}

makeError(RPError);

module.exports = {
  OPError,
  RPError,
};

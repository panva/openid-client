const Issuer = require('./issuer');
const { OPError, RPError } = require('./errors');
const Strategy = require('./passport_strategy');
const TokenSet = require('./token_set');
const { CLOCK_TOLERANCE, HTTP_OPTIONS } = require('./helpers/consts');
const generators = require('./helpers/generators');
const { setDefaults, resetDefaults } = require('./helpers/request');

module.exports = {
  Issuer,
  Strategy,
  TokenSet,
  errors: {
    OPError,
    RPError,
  },
  custom: {
    setHttpOptionsDefaults: setDefaults,
    resetHttpOptionsDefaults: resetDefaults,
    http_options: HTTP_OPTIONS,
    clock_tolerance: CLOCK_TOLERANCE,
  },
  generators,
};

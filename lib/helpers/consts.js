const OIDC_DISCOVERY = '/.well-known/openid-configuration';
const OAUTH2_DISCOVERY = '/.well-known/oauth-authorization-server';
const WEBFINGER = '/.well-known/webfinger';
const REL = 'http://openid.net/specs/connect/1.0/issuer';
const AAD_MULTITENANT_DISCOVERY = new Set([
  `https://login.microsoftonline.com/common/v2.0${OIDC_DISCOVERY}`,
  `https://login.microsoftonline.com/organizations/v2.0${OIDC_DISCOVERY}`,
  `https://login.microsoftonline.com/consumers/v2.0${OIDC_DISCOVERY}`,
]);

const CLIENT_DEFAULTS = {
  grant_types: ['authorization_code'],
  id_token_signed_response_alg: 'RS256',
  response_types: ['code'],
  token_endpoint_auth_method: 'client_secret_basic',
};

const ISSUER_DEFAULTS = {
  claim_types_supported: ['normal'],
  claims_parameter_supported: false,
  grant_types_supported: ['authorization_code', 'implicit'],
  request_parameter_supported: false,
  request_uri_parameter_supported: true,
  require_request_uri_registration: false,
  response_modes_supported: ['query', 'fragment'],
  token_endpoint_auth_methods_supported: ['client_secret_basic'],
};

const CALLBACK_PROPERTIES = [
  'access_token',
  'code',
  'error',
  'error_description',
  'error_uri',
  'expires_in',
  'id_token',
  'state',
  'token_type',
  'session_state',
];

const JWT_CONTENT = /^application\/jwt/;

const HTTP_OPTIONS = Symbol('openid-client.custom.http-options');
const CLOCK_TOLERANCE = Symbol('openid-client.custom.clock-tolerance');

module.exports = {
  AAD_MULTITENANT_DISCOVERY,
  CALLBACK_PROPERTIES,
  CLIENT_DEFAULTS,
  CLOCK_TOLERANCE,
  HTTP_OPTIONS,
  ISSUER_DEFAULTS,
  JWT_CONTENT,
  OAUTH2_DISCOVERY,
  OIDC_DISCOVERY,
  REL,
  WEBFINGER,
};

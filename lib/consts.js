const pkg = require('../package.json');

const USER_AGENT = `${pkg.name}/${pkg.version} (${pkg.homepage})`;

const DISCOVERY = '/.well-known/openid-configuration';
const WEBFINGER = '/.well-known/webfinger';
const REL = 'http://openid.net/specs/connect/1.0/issuer';

const ISSUER_METADATA = [
  'acr_values_supported',
  'authorization_endpoint',
  'check_session_iframe',
  'claims_parameter_supported',
  'claims_supported',
  'claim_types_supported',
  'end_session_endpoint',
  'grant_types_supported',
  'id_token_encryption_alg_values_supported',
  'id_token_encryption_enc_values_supported',
  'id_token_signing_alg_values_supported',
  'issuer',
  'jwks_uri',
  'registration_endpoint',
  'request_object_encryption_alg_values_supported',
  'request_object_encryption_enc_values_supported',
  'request_object_signing_alg_values_supported',
  'request_parameter_supported',
  'request_uri_parameter_supported',
  'require_request_uri_registration',
  'response_modes_supported',
  'response_types_supported',
  'scopes_supported',
  'subject_types_supported',
  'token_endpoint',
  'token_endpoint_auth_methods_supported',
  'token_endpoint_auth_signing_alg_values_supported',
  'token_introspection_endpoint',
  'introspection_endpoint',
  'token_revocation_endpoint',
  'revocation_endpoint',
  'userinfo_encryption_alg_values_supported',
  'userinfo_encryption_enc_values_supported',
  'userinfo_endpoint',
  'userinfo_signing_alg_values_supported',
];

const CLIENT_METADATA = [
  'application_type',
  'client_id',
  'client_name',
  'client_secret',
  'client_secret_expires_at',
  'client_uri',
  'contacts',
  'default_acr_values',
  'default_max_age',
  'grant_types',
  'id_token_encrypted_response_alg',
  'id_token_encrypted_response_enc',
  'id_token_signed_response_alg',
  'initiate_login_uri',
  'jwks',
  'jwks_uri',
  'logo_uri',
  'policy_uri',
  'post_logout_redirect_uris',
  'redirect_uris',
  'registration_access_token',
  'registration_client_uri',
  'request_object_encryption_alg',
  'request_object_encryption_enc',
  'request_object_signing_alg',
  'request_uris',
  'require_auth_time',
  'response_types',
  'sector_identifier_uri',
  'subject_type',
  'token_endpoint_auth_method',
  'token_endpoint_auth_signing_alg',
  'tos_uri',
  'userinfo_encrypted_response_alg',
  'userinfo_encrypted_response_enc',
  'userinfo_signed_response_alg',
];

const ISSUER_DEFAULTS = {
  claims_parameter_supported: false,
  grant_types_supported: ['authorization_code', 'implicit'],
  request_parameter_supported: false,
  request_uri_parameter_supported: true,
  require_request_uri_registration: false,
  response_modes_supported: ['query', 'fragment'],
  token_endpoint_auth_methods_supported: ['client_secret_basic'],
};

const CLIENT_DEFAULTS = {
  application_type: ['web'],
  grant_types: ['authorization_code'],
  id_token_signed_response_alg: 'RS256',
  response_types: ['code'],
  token_endpoint_auth_method: 'client_secret_basic',
};

const CALLBACK_PROPERTIES = [
  'access_token',
  'code',
  'error',
  'error_description',
  'expires_in',
  'id_token',
  'state',
  'token_type',
  'session_state',
];

const DEFAULT_HTTP_OPTIONS = {
  followRedirect: false,
  headers: { 'User-Agent': USER_AGENT },
  retries: 0,
  timeout: 1500,
};

const JWT_CONTENT = /^application\/jwt/;

module.exports.CALLBACK_PROPERTIES = CALLBACK_PROPERTIES;
module.exports.CLIENT_DEFAULTS = CLIENT_DEFAULTS;
module.exports.CLIENT_METADATA = CLIENT_METADATA;
module.exports.DEFAULT_HTTP_OPTIONS = DEFAULT_HTTP_OPTIONS;
module.exports.ISSUER_DEFAULTS = ISSUER_DEFAULTS;
module.exports.ISSUER_METADATA = ISSUER_METADATA;
module.exports.JWT_CONTENT = JWT_CONTENT;
module.exports.USER_AGENT = USER_AGENT;
module.exports.DISCOVERY = DISCOVERY;
module.exports.REL = REL;
module.exports.WEBFINGER = WEBFINGER;

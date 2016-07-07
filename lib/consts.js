const pkg = require('../package.json');

const USER_AGENT = `${pkg.name}/${pkg.version} (${pkg.homepage})`;

const WELL_KNOWN = '/.well-known/openid-configuration';

const PROVIDER_METADATA = [
  'acr_values_supported',
  'authorization_endpoint',
  'claims_parameter_supported',
  'claims_supported',
  'grant_types_supported',
  'id_token_signing_alg_values_supported',
  'issuer',
  'jwks_uri',
  'registration_endpoint',
  'request_object_signing_alg_values_supported',
  'request_parameter_supported',
  'request_uri_parameter_supported',
  'response_modes_supported',
  'response_types_supported',
  'scopes_supported',
  'subject_types_supported',
  'token_endpoint',
  'token_endpoint_auth_methods_supported',
  'token_endpoint_auth_signing_alg_values_supported',
  'token_introspection_endpoint',
  'token_revocation_endpoint',
  'userinfo_endpoint',
  'userinfo_signing_alg_values_supported',
  'id_token_encryption_alg_values_supported',
  'id_token_encryption_enc_values_supported',
  'userinfo_encryption_alg_values_supported',
  'userinfo_encryption_enc_values_supported',
  'request_object_encryption_alg_values_supported',
  'request_object_encryption_enc_values_supported',
  'check_session_iframe',
  'end_session_endpoint',
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

const PROVIDER_DEFAULTS = {
  response_modes_supported: ['query', 'fragment'],
  grant_types_supported: ['authorization_code', 'implicit'],
  token_endpoint_auth_methods_supported: ['client_secret_basic'],
  claims_parameter_supported: false,
  request_parameter_supported: false,
  request_uri_parameter_supported: true,
  require_request_uri_registration: false,
};

const CLIENT_DEFAULTS = {
  response_types: ['code'],
  grant_types: ['authorization_code'],
  application_type: ['web'],
  id_token_signed_response_alg: 'RS256',
  token_endpoint_auth_method: 'client_secret_basic',
};

module.exports.WELL_KNOWN = WELL_KNOWN;
module.exports.PROVIDER_DEFAULTS = PROVIDER_DEFAULTS;
module.exports.PROVIDER_METADATA = PROVIDER_METADATA;
module.exports.CLIENT_DEFAULTS = CLIENT_DEFAULTS;
module.exports.CLIENT_METADATA = CLIENT_METADATA;
module.exports.USER_AGENT = USER_AGENT;

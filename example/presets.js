module.exports = {
  basic: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
    },
    keystore: undefined,
    authorization_params: {
      scope: 'openid phone',
    },
  },
  with_refresh: {
    registration: {
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    },
    keystore: undefined,
    authorization_params: {
      scope: 'openid phone offline_access',
      prompt: 'consent',
    },
  },
  implicit: {
    registration: {
      grant_types: ['implicit'],
      response_types: ['id_token token'],
    },
    keystore: undefined,
    authorization_params: {
      scope: 'openid',
      response_type: 'id_token token',
      response_mode: 'form_post',
      claims: { id_token: { email_verified: null } },
    },
  },
  hybrid: {
    registration: {
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code id_token'],
    },
    keystore: undefined,
    authorization_params: {
      scope: 'openid',
      response_type: 'code id_token',
      response_mode: 'form_post',
    },
  },
  auth_private_key_jwt: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'ES256',
    },
    keystore: ['EC', 'P-256'],
  },
  auth_client_secret_jwt: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_jwt',
      token_endpoint_auth_signing_alg: 'HS512',
    },
  },
  id_token_encrypted: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      id_token_encrypted_response_alg: 'RSA1_5',
    },
    keystore: ['RSA', 2048],
  },
  userinfo_signed: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      userinfo_signed_response_alg: 'RS256',
    },
  },
  userinfo_signed_encrypted: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      userinfo_encrypted_response_alg: 'ECDH-ES+A128KW',
      userinfo_signed_response_alg: 'RS256',
    },
    keystore: ['EC', 'P-256'],
  },
  userinfo_not_signed_but_encrypted: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      userinfo_encrypted_response_alg: 'ECDH-ES+A128KW',
    },
    keystore: ['EC', 'P-256'],
  },
  symmetric_key_enc_sig: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      userinfo_encrypted_response_alg: 'PBES2-HS512+A256KW',
      userinfo_signed_response_alg: 'HS512',
      id_token_encrypted_response_alg: 'PBES2-HS512+A256KW',
      id_token_signed_response_alg: 'HS512',
    },
    keystore: undefined,
  },
};

module.exports = {
  basic: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
    },
    keystore: null,
    authorization_params: {
      scope: 'openid phone',
    },
  },
  with_refresh: {
    registration: {
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    },
    keystore: null,
    authorization_params: {
      scope: 'openid phone offline_access',
      prompt: 'consent',
    },
  },
  pairwise: {
    registration: {
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      subject_type: 'pairwise',
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
  userinfo_encrypted: {
    registration: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      userinfo_encrypted_response_alg: 'ECDH-ES+A128KW',
    },
    keystore: ['EC', 'P-256'],
  },
};

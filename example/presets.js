module.exports = {
  basic: {},
  with_refresh: {
    registration: {
      grant_types: ['authorization_code', 'refresh_token'],
    },
    authorization_params: {
      scope: 'openid profile email address phone offline_access',
      prompt: 'consent',
    },
  },
  implicit: {
    registration: {
      grant_types: ['implicit'],
      response_types: ['id_token token'],
    },
  },
  hybrid: {
    registration: {
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code id_token'],
    },
  },
  auth_private_key_jwt: {
    registration: {
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'ES256',
    },
    keystore: ['EC', 'P-256'],
  },
  auth_client_secret_jwt: {
    registration: {
      token_endpoint_auth_method: 'client_secret_jwt',
      token_endpoint_auth_signing_alg: 'HS512',
    },
  },
  id_token_encrypted: {
    registration: {
      id_token_encrypted_response_alg: 'RSA1_5',
    },
    keystore: ['RSA', 2048],
  },
  userinfo_signed: {
    registration: {
      userinfo_signed_response_alg: 'RS256',
    },
  },
  userinfo_signed_encrypted: {
    registration: {
      userinfo_encrypted_response_alg: 'ECDH-ES+A128KW',
      userinfo_signed_response_alg: 'RS256',
    },
    keystore: ['EC', 'P-256'],
  },
  userinfo_not_signed_but_encrypted: {
    registration: {
      userinfo_encrypted_response_alg: 'ECDH-ES+A128KW',
    },
    keystore: ['EC', 'P-256'],
  },
  symmetric_key_enc_sig: {
    registration: {
      userinfo_encrypted_response_alg: 'PBES2-HS512+A256KW',
      userinfo_signed_response_alg: 'HS512',
      id_token_encrypted_response_alg: 'PBES2-HS512+A256KW',
      id_token_signed_response_alg: 'HS512',
    },
  },
};

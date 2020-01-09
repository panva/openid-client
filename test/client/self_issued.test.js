const { expect } = require('chai');
const nock = require('nock');
const timekeeper = require('timekeeper');
const jose = require('jose');

const { Issuer } = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('Validating Self-Issued OP responses', () => {
  afterEach(timekeeper.reset);
  afterEach(nock.cleanAll);

  before(function () {
    const issuer = new Issuer({
      authorization_endpoint: 'openid:',
      issuer: 'https://self-issued.me',
      scopes_supported: ['openid', 'profile', 'email', 'address', 'phone'],
      response_types_supported: ['id_token'],
      subject_types_supported: ['pairwise'],
      id_token_signing_alg_values_supported: ['RS256'],
      request_object_signing_alg_values_supported: ['none', 'RS256'],
      registration_endpoint: 'https://self-issued.me/registration/1.0/',
    });

    const client = new issuer.Client({
      client_id: 'https://rp.example.com/cb',
      response_types: ['id_token'],
      token_endpoint_auth_method: 'none',
      id_token_signed_response_alg: 'ES256',
    });

    Object.assign(this, { issuer, client });
  });

  const idToken = (claims = {}) => {
    const jwk = jose.JWK.generateSync('EC');
    return jose.JWT.sign({
      sub_jwk: jwk.toJWK(),
      sub: jwk.thumbprint,
      ...claims,
    }, jwk, { expiresIn: '2h', issuer: 'https://self-issued.me', audience: 'https://rp.example.com/cb' });
  };

  describe('consuming an ID Token response', () => {
    it('consumes a self-issued response', function () {
      const { client } = this;
      return client.callback(undefined, { id_token: idToken() });
    });

    it('expects sub_jwk to be in the ID Token claims', function () {
      const { client } = this;
      return client.callback(undefined, { id_token: idToken({ sub_jwk: undefined }) })
        .then(fail, (err) => {
          expect(err.name).to.equal('RPError');
          expect(err.message).to.equal('missing required JWT property sub_jwk');
          expect(err).to.have.property('jwt');
        });
    });

    it('expects sub_jwk to be a public JWK', function () {
      const { client } = this;
      return client.callback(undefined, { id_token: idToken({ sub_jwk: 'foobar' }) })
        .then(fail, (err) => {
          expect(err.name).to.equal('RPError');
          expect(err.message).to.equal('failed to use sub_jwk claim as an asymmetric JSON Web Key');
          expect(err).to.have.property('jwt');
        });
    });

    it('expects sub to be the thumbprint of the sub_jwk', function () {
      const { client } = this;
      return client.callback(undefined, { id_token: idToken({ sub: 'foo' }) })
        .then(fail, (err) => {
          expect(err.name).to.equal('RPError');
          expect(err.message).to.equal('failed to match the subject with sub_jwk');
          expect(err).to.have.property('jwt');
        });
    });
  });
});

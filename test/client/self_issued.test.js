const { expect } = require('chai');
const nock = require('nock');
const timekeeper = require('timekeeper');
const jose = require('jose');

const { Issuer } = require('../../lib');

const fail = () => {
  throw new Error('expected promise to be rejected');
};

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

  async function idToken(claims = {}) {
    const kp = await jose.generateKeyPair('ES256', { extractable: true });
    const jwk = await jose.exportJWK(kp.publicKey);
    const sub = await jose.calculateJwkThumbprint(jwk);
    return await new jose.SignJWT({
      sub_jwk: jwk,
      sub,
      ...claims,
    })
      .setIssuedAt()
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer('https://self-issued.me')
      .setAudience('https://rp.example.com/cb')
      .setExpirationTime('2h')
      .sign(kp.privateKey);
  }

  describe('consuming an ID Token response', () => {
    it('consumes a self-issued response', async function () {
      const { client } = this;
      return client.callback(undefined, { id_token: await idToken() });
    });

    it('expects sub_jwk to be in the ID Token claims', async function () {
      const { client } = this;
      return client
        .callback(undefined, { id_token: await idToken({ sub_jwk: undefined }) })
        .then(fail, (err) => {
          expect(err.name).to.equal('RPError');
          expect(err.message).to.equal('missing required JWT property sub_jwk');
          expect(err).to.have.property('jwt');
        });
    });

    it('expects sub_jwk to be a public JWK', async function () {
      const { client } = this;
      return client
        .callback(undefined, { id_token: await idToken({ sub_jwk: 'foobar' }) })
        .then(fail, (err) => {
          expect(err.name).to.equal('RPError');
          expect(err.message).to.equal('failed to use sub_jwk claim as an asymmetric JSON Web Key');
          expect(err).to.have.property('jwt');
        });
    });

    it('expects sub to be the thumbprint of the sub_jwk', async function () {
      const { client } = this;
      return client
        .callback(undefined, { id_token: await idToken({ sub: 'foo' }) })
        .then(fail, (err) => {
          expect(err.name).to.equal('RPError');
          expect(err.message).to.equal('failed to match the subject with sub_jwk');
          expect(err).to.have.property('jwt');
        });
    });
  });
});

const { expect } = require('chai');
const nock = require('nock');

const Issuer = require('../../lib/issuer');
const clientInternal = require('../../lib/helpers/client');
const KeyStore = require('../keystore');

async function noKidJWKS() {
  const store = new KeyStore();
  await store.generate('EC');
  const jwks = store.toJWKS(true);
  delete jwks.keys[0].kid;
  expect(jwks.keys[0].kid).to.be.undefined;
  return jwks;
}

describe('no implicit Key IDs (kid)', function () {
  afterEach(nock.cleanAll);

  it('is not added to client assertions', async () => {
    const issuer = new Issuer();
    const jwks = await noKidJWKS();
    const client = new issuer.Client(
      {
        client_id: 'identifier',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
      },
      jwks,
    );

    const {
      form: { client_assertion: jwt },
    } = await clientInternal.authFor.call(client, 'token');

    const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64'));
    expect(header).to.have.property('alg', 'ES256');
    expect(header).not.to.have.property('kid');
  });

  it('is not added to request objects', async () => {
    const issuer = new Issuer();
    const jwks = await noKidJWKS();
    const client = new issuer.Client(
      {
        client_id: 'identifier',
        request_object_signing_alg: 'ES256',
      },
      jwks,
    );

    const jwt = await client.requestObject();

    const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64'));
    expect(header).to.have.property('alg', 'ES256');
    expect(header).not.to.have.property('kid');
  });

  it('is not added to dynamic registration requests', async () => {
    const issuer = new Issuer({
      registration_endpoint: 'https://op.example.com/client/registration',
    });

    nock('https://op.example.com')
      .filteringRequestBody(function (body) {
        const payload = JSON.parse(body);
        expect(payload).to.have.nested.property('jwks.keys').that.is.an('array');
        expect(payload.jwks.keys[0]).to.be.an('object').with.property('kty');
        expect(payload.jwks.keys[0]).not.to.have.property('kid');
      })
      .post('/client/registration', () => true) // to make sure filteringRequestBody works
      .reply(201, {
        client_id: 'identifier',
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: {}, // ignore
      });

    await issuer.Client.register(
      {
        token_endpoint_auth_method: 'private_key_jwt',
      },
      { jwks: await noKidJWKS() },
    );

    expect(nock.isDone()).to.be.true;
  });
});

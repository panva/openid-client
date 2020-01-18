const { expect } = require('chai');
const jose = require('jose');
const sinon = require('sinon');
const nock = require('nock');

const { Issuer, custom } = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };
const issuer = new Issuer({
  registration_endpoint: 'https://op.example.com/client/registration',
});

describe('Client#register', () => {
  afterEach(nock.cleanAll);

  it('asserts the issuer has a registration endpoint', function () {
    const issuer = new Issuer({}); // eslint-disable-line no-shadow
    return issuer.Client.register().then(fail, ({ message }) => {
      expect(message).to.eql('registration_endpoint must be configured on the issuer');
    });
  });

  it('accepts and assigns the registered metadata', function () {
    nock('https://op.example.com')
      .post('/client/registration')
      .reply(201, {
        client_id: 'identifier',
        client_secret: 'secure',
      });

    return issuer.Client.register({}).then(function (client) {
      expect(client).to.be.instanceof(issuer.Client);
      expect(client).to.have.property('client_id', 'identifier');
      expect(client).to.have.property('client_secret', 'secure');
    });
  });

  it('is rejected with OPError upon oidc error', function () {
    nock('https://op.example.com')
      .post('/client/registration')
      .reply(500, {
        error: 'server_error',
        error_description: 'bad things are happening',
      });

    return issuer.Client.register({})
      .then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error).to.have.property('error', 'server_error');
        expect(error).to.have.property('error_description', 'bad things are happening');
      });
  });

  it('is rejected with OPError upon oidc error in www-authenticate header', function () {
    nock('https://op.example.com')
      .post('/client/registration')
      .reply(401, 'Unauthorized', {
        'WWW-Authenticate': 'Bearer error="invalid_token", error_description="bad things are happening"',
      });

    return issuer.Client.register({})
      .then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error).to.have.property('error', 'invalid_token');
        expect(error).to.have.property('error_description', 'bad things are happening');
      });
  });

  it('is rejected with when non 200 is returned', function () {
    nock('https://op.example.com')
      .post('/client/registration')
      .reply(500, 'Internal Server Error');

    return issuer.Client.register({})
      .then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error.message).to.eql('expected 201 Created, got: 500 Internal Server Error');
        expect(error).to.have.property('response');
      });
  });

  it('is rejected with JSON.parse error upon invalid response', function () {
    nock('https://op.example.com')
      .post('/client/registration')
      .reply(201, '{"notavalid"}');

    return issuer.Client.register({})
      .then(fail, function (error) {
        expect(error.name).to.eql('ParseError');
        expect(error.message).to.eql('Unexpected token } in JSON at position 12 in "https://op.example.com/client/registration": \n{"notavalid"}...');
        expect(error).to.have.property('response');
      });
  });

  describe('with keystore (as option)', function () {
    it('enriches the registration with jwks if not provided (or jwks_uri)', function () {
      const keystore = new jose.JWKS.KeyStore();

      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(JSON.parse(body)).to.eql({
            jwks: keystore.toJWKS(),
          });
        })
        .post('/client/registration', () => true) // to make sure filteringRequestBody works
        .reply(201, {
          client_id: 'identifier',
          client_secret: 'secure',
        });

      return keystore.generate('EC', 'P-256').then(() => issuer.Client.register({}, { jwks: keystore.toJWKS(true) }));
    });

    it('ignores the keystore during registration if jwks is provided', function () {
      const keystore = new jose.JWKS.KeyStore();

      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(JSON.parse(body)).to.eql({
            jwks: 'whatever',
          });
        })
        .post('/client/registration', () => true) // to make sure filteringRequestBody works
        .reply(201, {
          client_id: 'identifier',
          client_secret: 'secure',
        });

      return keystore.generate('EC', 'P-256').then(() => issuer.Client.register({
        jwks: 'whatever',
      }, { keystore }));
    });

    it('ignores the keystore during registration if jwks_uri is provided', function () {
      const keystore = new jose.JWKS.KeyStore();

      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(JSON.parse(body)).to.eql({
            jwks_uri: 'https://rp.example.com/certs',
          });
        })
        .post('/client/registration', () => true) // to make sure filteringRequestBody works
        .reply(201, {
          client_id: 'identifier',
          client_secret: 'secure',
        });

      return keystore.generate('EC', 'P-256').then(() => issuer.Client.register({
        jwks_uri: 'https://rp.example.com/certs',
      }, { keystore }));
    });

    [{}, [], 'not a keystore', 2, true, false].forEach(function (notkeystore) {
      it(`validates it is a keystore (${typeof notkeystore} ${JSON.stringify(notkeystore)})`, function () {
        return issuer.Client.register({}, { jwks: notkeystore })
          .then(fail, ({ message }) => {
            expect(message).to.eql('jwks must be a JSON Web Key Set formatted object');
          });
      });
    });

    it('does not accept oct keys', function () {
      const keystore = new jose.JWKS.KeyStore();

      return keystore.generate('oct', 32).then(() => {
        return issuer.Client.register({}, { jwks: keystore.toJWKS(true) })
          .then(fail, ({ message }) => {
            expect(message).to.eql('jwks must only contain private keys');
          });
      });
    });

    it('does not accept public keys', function () {
      const jwk = {
        kty: 'EC',
        kid: 'MFZeG102dQiqbANoaMlW_Jmf7fOZmtRsHt77JFhTpF0',
        crv: 'P-256',
        x: 'FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4',
        y: '_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4',
      };

      return issuer.Client.register({}, { jwks: { keys: [jwk] } })
        .then(fail, ({ message }) => {
          expect(message).to.eql('jwks must only contain private keys');
        });
    });
  });

  describe('with initialAccessToken (as option)', function () {
    it('Uses the initialAccessToken in a Bearer authorization scheme', function () {
      nock('https://op.example.com')
        .matchHeader('authorization', 'Bearer foobar')
        .post('/client/registration')
        .reply(201, {
          client_id: 'identifier',
          client_secret: 'secure',
        });

      return issuer.Client.register({}, { initialAccessToken: 'foobar' });
    });
  });

  describe('HTTP_OPTIONS', () => {
    afterEach(() => {
      delete issuer.Client[custom.http_options];
    });

    it('allows for http options to be defined for issuer.Client.register calls', async () => {
      const httpOptions = sinon.stub().callsFake((opts) => {
        opts.headers.custom = 'foo';
        return opts;
      });
      issuer.Client[custom.http_options] = httpOptions;

      nock('https://op.example.com')
        .post('/client/registration')
        .matchHeader('custom', 'foo')
        .reply(201, {
          client_id: 'identifier',
          client_secret: 'secure',
        });

      await issuer.Client.register({});

      expect(nock.isDone()).to.be.true;
      sinon.assert.callCount(httpOptions, 1);
    });
  });
});

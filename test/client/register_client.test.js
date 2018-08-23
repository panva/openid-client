const { expect } = require('chai');
const jose = require('node-jose');
const nock = require('nock');

const Issuer = require('../../lib/issuer');

const fail = () => { throw new Error('expected promise to be rejected'); };
const issuer = new Issuer({
  registration_endpoint: 'https://op.example.com/client/registration',
});

['useGot', 'useRequest'].forEach((httpProvider) => {
  describe(`Client#register - using ${httpProvider.substring(3).toLowerCase()}`, function () {
    before(function () {
      Issuer[httpProvider]();
    });

    afterEach(nock.cleanAll);

    it('asserts the issuer has a registration endpoint', function () {
      const issuer = new Issuer({}); // eslint-disable-line no-shadow
      expect(function () {
        issuer.Client.register();
      }).to.throw('registration_endpoint must be configured on the issuer');
    });

    it('accepts and assigns the discovered metadata', function () {
      nock('https://op.example.com')
        .post('/client/registration')
        .reply(200, {
          client_id: 'identifier',
          client_secret: 'secure',
        });

      return issuer.Client.register({}).then(function (client) {
        expect(client).to.be.instanceof(issuer.Client);
        expect(client).to.have.property('client_id', 'identifier');
        expect(client).to.have.property('client_secret', 'secure');
      });
    });

    it('is rejected with OpenIdConnectError upon oidc error', function () {
      nock('https://op.example.com')
        .post('/client/registration')
        .reply(500, {
          error: 'server_error',
          error_description: 'bad things are happening',
        });

      return issuer.Client.register({})
        .then(fail, function (error) {
          expect(error.name).to.equal('OpenIdConnectError');
          expect(error).to.have.property('error', 'server_error');
          expect(error).to.have.property('error_description', 'bad things are happening');
        });
    });

    it('is rejected with OpenIdConnectError upon oidc error in www-authenticate header', function () {
      nock('https://op.example.com')
        .post('/client/registration')
        .reply(401, 'Unauthorized', {
          'WWW-Authenticate': 'Bearer error="invalid_token", error_description="bad things are happening"',
        });

      return issuer.Client.register({})
        .then(fail, function (error) {
          expect(error.name).to.equal('OpenIdConnectError');
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
          expect(error).to.be.an.instanceof(issuer.httpClient.HTTPError);
        });
    });

    it('is rejected with JSON.parse error upon invalid response', function () {
      nock('https://op.example.com')
        .post('/client/registration')
        .reply(200, '{"notavalid"}');

      return issuer.Client.register({})
        .then(fail, function (error) {
          expect(error).to.be.an.instanceof(SyntaxError);
          expect(error).to.have.property('message').matches(/Unexpected token/);
        });
    });

    context('with keystore (as option)', function () {
      it('enriches the registration with jwks if not provided (or jwks_uri)', function () {
        const keystore = jose.JWK.createKeyStore();

        nock('https://op.example.com')
          .filteringRequestBody(function (body) {
            expect(JSON.parse(body)).to.eql({
              jwks: keystore.toJSON(),
            });
          })
          .post('/client/registration')
          .reply(200, {
            client_id: 'identifier',
            client_secret: 'secure',
          });

        return keystore.generate('EC', 'P-256').then(() => issuer.Client.register({}, { keystore }));
      });

      it('ignores the keystore during registration if jwks is provided', function () {
        const keystore = jose.JWK.createKeyStore();

        nock('https://op.example.com')
          .filteringRequestBody(function (body) {
            expect(JSON.parse(body)).to.eql({
              jwks: 'whatever',
            });
          })
          .post('/client/registration')
          .reply(200, {
            client_id: 'identifier',
            client_secret: 'secure',
          });

        return keystore.generate('EC', 'P-256').then(() => issuer.Client.register({
          jwks: 'whatever',
        }, { keystore }));
      });

      it('ignores the keystore during registration if jwks_uri is provided', function () {
        const keystore = jose.JWK.createKeyStore();

        nock('https://op.example.com')
          .filteringRequestBody(function (body) {
            expect(JSON.parse(body)).to.eql({
              jwks_uri: 'https://rp.example.com/certs',
            });
          })
          .post('/client/registration')
          .reply(200, {
            client_id: 'identifier',
            client_secret: 'secure',
          });

        return keystore.generate('EC', 'P-256').then(() => issuer.Client.register({
          jwks_uri: 'https://rp.example.com/certs',
        }, { keystore }));
      });

      it('validates it is a keystore', function () {
        [{}, [], 'not a keystore', 2, true, false].forEach(function (notkeystore) {
          expect(function () {
            issuer.Client.register({}, { keystore: notkeystore });
          }).to.throw('keystore must be an instance of jose.JWK.KeyStore');
        });
      });

      it('does not accept oct keys', function () {
        const keystore = jose.JWK.createKeyStore();

        return keystore.generate('oct', 32).then(() => {
          expect(function () {
            issuer.Client.register({}, { keystore });
          }).to.throw('keystore must only contain private EC or RSA keys');
        });
      });

      it('does not accept public keys', function () {
        return jose.JWK.asKey({
          kty: 'EC',
          kid: 'MFZeG102dQiqbANoaMlW_Jmf7fOZmtRsHt77JFhTpF0',
          crv: 'P-256',
          x: 'FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4',
          y: '_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4',
        }).then((key) => {
          expect(function () {
            issuer.Client.register({}, { keystore: key.keystore });
          }).to.throw('keystore must only contain private EC or RSA keys');
        });
      });
    });

    context('with initialAccessToken (as option)', function () {
      it('Uses the initialAccessToken in a Bearer authorization scheme', function () {
        nock('https://op.example.com')
          .matchHeader('authorization', 'Bearer foobar')
          .post('/client/registration')
          .reply(200, {
            client_id: 'identifier',
            client_secret: 'secure',
          });

        return issuer.Client.register({}, { initialAccessToken: 'foobar' });
      });
    });
  });
});

'use strict';

const Issuer = require('../../lib').Issuer;
const expect = require('chai').expect;
const nock = require('nock');

const fail = () => { throw new Error('expected promise to be rejected'); };
const issuer = new Issuer();

describe('Client#fromUri()', function () {
  it('accepts and assigns the discovered metadata', function () {
    nock('https://op.example.com')
      .get('/client/identifier')
      .reply(200, {
        client_id: 'identifier',
        client_secret: 'secure',
      });

    return issuer.Client.fromUri('https://op.example.com/client/identifier').then(function (client) {
      expect(client).to.have.property('client_id', 'identifier');
      expect(client).to.have.property('client_secret', 'secure');
    });
  });

  it('is rejected with OpenIdConnectError upon oidc error', function () {
    nock('https://op.example.com')
      .get('/client/identifier')
      .reply(500, {
        error: 'server_error',
        error_description: 'bad things are happening',
      });

    return issuer.Client.fromUri('https://op.example.com/client/identifier')
      .then(fail, function (error) {
        expect(error).to.have.property('message', 'server_error');
      });
  });

  it('is rejected with when non 200 is returned', function () {
    nock('https://op.example.com')
      .get('/client/identifier')
      .reply(500, 'Internal Server Error');

    return issuer.Client.fromUri('https://op.example.com/client/identifier')
      .then(fail, function (error) {
        expect(error).to.be.an.instanceof(issuer.httpClient.HTTPError);
      });
  });

  it('is rejected with JSON.parse error upon invalid response', function () {
    nock('https://op.example.com')
      .get('/client/identifier')
      .reply(200, '{"notavalid"}');

    return issuer.Client.fromUri('https://op.example.com/client/identifier')
      .then(fail, function (error) {
        expect(error).to.be.an.instanceof(SyntaxError);
        expect(error).to.have.property('message').matches(/Unexpected token/);
      });
  });
});

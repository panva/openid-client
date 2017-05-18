'use strict';

const Issuer = require('../../lib').Issuer;
const expect = require('chai').expect;
const nock = require('nock');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('Issuer#discover()', function () {
  it('accepts and assigns the discovered metadata', function () {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        authorization_endpoint: 'https://op.example.com/o/oauth2/v2/auth',
        issuer: 'https://op.example.com',
        jwks_uri: 'https://op.example.com/oauth2/v3/certs',
        token_endpoint: 'https://op.example.com/oauth2/v4/token',
        userinfo_endpoint: 'https://op.example.com/oauth2/v3/userinfo',
      });

    return Issuer.discover('https://op.example.com/.well-known/openid-configuration').then(function (issuer) {
      expect(issuer).to.have.property('authorization_endpoint', 'https://op.example.com/o/oauth2/v2/auth');
      expect(issuer).to.have.property('issuer', 'https://op.example.com');
      expect(issuer).to.have.property('jwks_uri', 'https://op.example.com/oauth2/v3/certs');
      expect(issuer).to.have.property('token_endpoint', 'https://op.example.com/oauth2/v4/token');
      expect(issuer).to.have.property('userinfo_endpoint', 'https://op.example.com/oauth2/v3/userinfo');
    });
  });

  it('can be discovered by ommiting the well-known part', function () {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        issuer: 'https://op.example.com',
      });

    return Issuer.discover('https://op.example.com').then(function (issuer) {
      expect(issuer).to.have.property('issuer', 'https://op.example.com');
    });
  });

  it('discovering issuers with path components', function () {
    nock('https://op.example.com')
      .get('/oidc/.well-known/openid-configuration')
      .reply(200, {
        issuer: 'https://op.example.com/oidc',
      });

    return Issuer.discover('https://op.example.com/oidc/').then(function (issuer) {
      expect(issuer).to.have.property('issuer', 'https://op.example.com/oidc');
    });
  });

  it('is rejected with OpenIdConnectError upon oidc error', function () {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(500, {
        error: 'server_error',
        error_description: 'bad things are happening',
      });

    return Issuer.discover('https://op.example.com')
      .then(fail, function (error) {
        expect(error).to.have.property('message', 'server_error');
      });
  });

  it('is rejected with when non 200 is returned', function () {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(500, 'Internal Server Error');

    return Issuer.discover('https://op.example.com')
      .then(fail, function (error) {
        expect(error).to.be.an.instanceof(Issuer.httpClient.HTTPError);
      });
  });

  it('is rejected with JSON.parse error upon invalid response', function () {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, '{"notavalid"}');

    return Issuer.discover('https://op.example.com')
      .then(fail, function (error) {
        expect(error).to.be.an.instanceof(SyntaxError);
        expect(error).to.have.property('message').matches(/Unexpected token/);
      });
  });

  it('is rejected when no body is returned', function () {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(301);

    return Issuer.discover('https://op.example.com')
      .then(fail, function (error) {
        expect(error).to.have.property('message', 'expected 200 OK with body, got 301 Moved Permanently without one');
      });
  });
});

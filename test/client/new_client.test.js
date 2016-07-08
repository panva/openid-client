'use strict';

const Issuer = require('../../lib/issuer');
const Client = require('../../lib/base_client');
const expect = require('chai').expect;

describe('new Client()', function () {
  it('accepts the recognized metadata', function () {
    let client;

    expect(function () {
      client = new Client({
        client_id: 'identifier',
        client_secret: 'secure',
      });
    }).not.to.throw();

    expect(client).to.have.property('client_id', 'identifier');
    expect(client).to.have.property('client_secret', 'secure');
  });

  it('ignores unrecognized metadata', function () {
    const client = new Client({
      client_id: 'identifier',
      client_secret: 'secure',
      unrecognized: 'http://',
    });

    expect(client).not.to.have.property('unrecognized');
  });

  it('assigns defaults to some properties', function () {
    const client = new Client({ client_id: 'identifier' });

    expect(client).to.have.property('application_type').eql(['web']);
    expect(client).to.have.property('client_id', 'identifier');
    expect(client).to.have.property('grant_types').eql(['authorization_code']);
    expect(client).to.have.property('id_token_signed_response_alg', 'RS256');
    expect(client).to.have.property('response_types').eql(['code']);
    expect(client).to.have.property('token_endpoint_auth_method', 'client_secret_basic');
  });

  context('with keystore', function () {
    it('validates it is a keystore', function () {
      [{}, [], 'not a keystore', 2, true, false].forEach(function () {
        expect(function () {
          new Client({}, 'not a keystore'); // eslint-disable-line no-new
        }).to.throw('keystore must be an instance of jose.JWK.KeyStore');
      });
    });
  });

  context('with token_endpoint_auth_method =~ _jwt', function () {
    it('validates the issuer has supported algs announced', function () {
      expect(function () {
        const issuer = new Issuer();
        new issuer.Client({ // eslint-disable-line no-new
          token_endpoint_auth_method: '_jwt',
        });
      }).to.throw(
        'token_endpoint_auth_signing_alg_values_supported must be provided on the issuer');
    });
  });
});

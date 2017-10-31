'use strict';

const Issuer = require('../../lib/issuer');
const Client = require('../../lib/client');
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

  it('assigns defaults to some properties', function () {
    const client = new Client({ client_id: 'identifier' });

    expect(client).to.have.property('application_type').eql('web');
    expect(client).to.have.property('client_id', 'identifier');
    expect(client).to.have.property('grant_types').eql(['authorization_code']);
    expect(client).to.have.property('id_token_signed_response_alg', 'RS256');
    expect(client).to.have.property('response_types').eql(['code']);
    expect(client).to.have.property('token_endpoint_auth_method', 'client_secret_basic');
  });

  context('with keystore', function () {
    it('validates it is a keystore', function () {
      [{}, [], 'not a keystore', 2, true, false].forEach(function (notkeystore) {
        expect(function () {
          new Client({}, notkeystore); // eslint-disable-line no-new
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
      }).to.throw('token_endpoint_auth_signing_alg_values_supported must be provided on the issuer');
    });
  });

  it('is able to discover custom or non-recognized properties', function () {
    const client = new Client({
      client_id: 'identifier',
      foo: 'bar',
    });
    expect(client).to.have.property('foo', 'bar');
  });

  it('custom properties do not interfere with the prototype', function () {
    const client = new Client({
      issuer: 'https://op.example.com',
      userinfo: 'foobar',
      metadata: 'foobar',
    });

    expect(client).to.have.property('userinfo').that.is.a('function'); // not a string
    expect(client).to.have.property('metadata').that.is.an('object'); // not a string
    expect(client.metadata).to.have.property('metadata', 'foobar');
    expect(client.metadata).to.have.property('userinfo', 'foobar');
  });

  context('dynamic registration defaults not supported by issuer', function () {
    it('token_endpoint_auth_method vs. token_endpoint_auth_methods_supported', function () {
      const issuer = new Issuer({
        issuer: 'https://op.example.com',
        token_endpoint_auth_methods_supported: ['client_secret_post', 'private_key_jwt'],
      });
      const client = new issuer.Client({
        client_id: 'client',
      });

      expect(client.token_endpoint_auth_method).to.equal('client_secret_post');
    });
  });
});

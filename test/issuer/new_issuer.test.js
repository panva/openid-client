'use strict';

const Issuer = require('../../lib').Issuer;
const expect = require('chai').expect;

describe('new Issuer()', function () {
  it('accepts the recognized metadata', function () {
    let issuer;
    expect(function () {
      issuer = new Issuer({
        issuer: 'https://accounts.google.com',
        authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
        token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
        userinfo_endpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
        jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
      });
    }).not.to.throw();

    expect(issuer).to.have.property('authorization_endpoint', 'https://accounts.google.com/o/oauth2/v2/auth');
    expect(issuer).to.have.property('issuer', 'https://accounts.google.com');
    expect(issuer).to.have.property('jwks_uri', 'https://www.googleapis.com/oauth2/v3/certs');
    expect(issuer).to.have.property('token_endpoint', 'https://www.googleapis.com/oauth2/v4/token');
    expect(issuer).to.have.property('userinfo_endpoint', 'https://www.googleapis.com/oauth2/v3/userinfo');
  });

  it('assigns defaults to some properties', function () {
    const issuer = new Issuer();

    expect(issuer).to.have.property('claims_parameter_supported', false);
    expect(issuer).to.have.property('grant_types_supported')
      .to.eql(['authorization_code', 'implicit']);
    expect(issuer).to.have.property('request_parameter_supported', false);
    expect(issuer).to.have.property('request_uri_parameter_supported', true);
    expect(issuer).to.have.property('require_request_uri_registration', false);
    expect(issuer).to.have.property('response_modes_supported').to.eql(['query', 'fragment']);
    expect(issuer).to.have.property('token_endpoint_auth_methods_supported')
      .to.eql(['client_secret_basic']);
  });

  it('is able to discover custom or non-recognized properties', function () {
    const issuer = new Issuer({
      issuer: 'https://op.example.com',
      foo: 'bar',
    });
    expect(issuer).to.have.property('issuer', 'https://op.example.com');
    expect(issuer).to.have.property('foo', 'bar');
  });

  it('custom properties do not interfere with the prototype', function () {
    const issuer = new Issuer({
      issuer: 'https://op.example.com',
      key: 'foobar',
      metadata: 'foobar',
    });

    expect(issuer).to.have.property('issuer', 'https://op.example.com');
    expect(issuer).to.have.property('key').that.is.a('function'); // not a string
    expect(issuer).to.have.property('metadata').that.is.an('object'); // not a string
    expect(issuer.metadata).to.have.property('metadata', 'foobar');
    expect(issuer.metadata).to.have.property('key', 'foobar');
  });
});

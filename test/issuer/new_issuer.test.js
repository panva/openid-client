const { expect } = require('chai');

const { Issuer } = require('../../lib');

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

  it('does not assign Discovery 1.0 defaults when instantiating manually', function () {
    const issuer = new Issuer();

    expect(issuer).not.to.have.property('claims_parameter_supported');
    expect(issuer).not.to.have.property('grant_types_supported');
    expect(issuer).not.to.have.property('request_parameter_supported');
    expect(issuer).not.to.have.property('request_uri_parameter_supported');
    expect(issuer).not.to.have.property('require_request_uri_registration');
    expect(issuer).not.to.have.property('response_modes_supported');
    expect(issuer).not.to.have.property('token_endpoint_auth_methods_supported');
  });

  ['introspection', 'revocation'].forEach((endpoint) => {
    it(`assigns ${endpoint}_endpoint from token_${endpoint}_endpoint and removes it`, function () {
      const issuer = new Issuer({
        [`token_${endpoint}_endpoint`]: `https://op.example.com/token/${endpoint}`,
      });

      expect(issuer).to.have.property(`${endpoint}_endpoint`, `https://op.example.com/token/${endpoint}`);
      expect(issuer).not.to.have.property(`token_${endpoint}_endpoint`);
    });

    it(`assigns ${endpoint} auth method meta from token if both are not defined`, function () {
      const issuer = new Issuer({
        token_endpoint: 'https://op.example.com/token',
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'client_secret_jwt'],
        token_endpoint_auth_signing_alg_values_supported: ['RS256', 'HS256'],
        [`${endpoint}_endpoint`]: `https://op.example.com/token/${endpoint}`,
      });

      expect(issuer).to.have.property(`${endpoint}_endpoint_auth_methods_supported`).and.eql(['client_secret_basic', 'client_secret_post', 'client_secret_jwt']);
      expect(issuer).to.have.property(`${endpoint}_endpoint_auth_signing_alg_values_supported`).and.eql(['RS256', 'HS256']);
    });
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

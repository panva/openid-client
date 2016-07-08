'use strict';

const Issuer = require('../../lib').Issuer;
const expect = require('chai').expect;

describe('Issuer', function () {
  it('#inspect', function () {
    const issuer = new Issuer({ issuer: 'https://op.example.com' });
    expect(issuer.inspect()).to.equal('Issuer <https://op.example.com>');
  });

  it('#metadata returns a copy of the issuers metadata', function () {
    const issuer = new Issuer({ issuer: 'https://op.example.com' });
    const expected = {
      claims_parameter_supported: false,
      grant_types_supported: ['authorization_code', 'implicit'],
      issuer: 'https://op.example.com',
      request_parameter_supported: false,
      request_uri_parameter_supported: true,
      require_request_uri_registration: false,
      response_modes_supported: ['query', 'fragment'],
      token_endpoint_auth_methods_supported: ['client_secret_basic'],
    };
    expect(issuer.metadata).not.to.equal(expected);
    expect(issuer.metadata).to.eql(expected);
  });
});

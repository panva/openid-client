const { expect } = require('chai');

const { Issuer } = require('../../lib');

describe('Issuer#defaultHttpOptions', function () {
  it('does not follow redirects', function () {
    expect(Issuer.defaultHttpOptions).to.have.property('followRedirect', false);
  });

  it('includes a user-agent by default', function () {
    expect(Issuer.defaultHttpOptions).to.have.nested.property('headers.User-Agent')
      .to.match(/^openid-client/);
  });

  it('does not retry', function () {
    expect(Issuer.defaultHttpOptions).to.have.property('retries', 0);
  });

  it('has a rather graceous timeout', function () {
    expect(Issuer.defaultHttpOptions).to.have.property('timeout', 1500);
  });
});

describe('Issuer#defaultHttpOptions=', function () {
  before(function () {
    this.defaultHttpOptions = Issuer.defaultHttpOptions;
  });

  afterEach(function () {
    Issuer.defaultHttpOptions = this.defaultHttpOptions;
  });

  it('can be set to follow redirects', function () {
    Issuer.defaultHttpOptions = { followRedirect: true };
    expect(Issuer.defaultHttpOptions).to.have.property('followRedirect', true);
  });

  it('can be set to send more headers by default', function () {
    Issuer.defaultHttpOptions = { headers: { 'X-Meta-Id': 'meta meta' } };
    expect(Issuer.defaultHttpOptions).to.have.nested.property('headers.User-Agent')
      .to.match(/^openid-client/);
    expect(Issuer.defaultHttpOptions).to.have.nested.property('headers.X-Meta-Id', 'meta meta');
  });

  it('can overwrite the timeout', function () {
    Issuer.defaultHttpOptions = { timeout: 2500 };
    expect(Issuer.defaultHttpOptions).to.have.property('timeout', 2500);
  });
});

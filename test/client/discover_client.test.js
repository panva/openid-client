const { expect } = require('chai');
const sinon = require('sinon');
const nock = require('nock');

const { Issuer, custom } = require('../../lib');

const fail = () => {
  throw new Error('expected promise to be rejected');
};
const issuer = new Issuer();

describe('Client#fromUri()', () => {
  it('accepts and assigns the discovered metadata', function () {
    nock('https://op.example.com')
      .matchHeader('Accept', 'application/json')
      .get('/client/identifier')
      .reply(200, {
        client_id: 'identifier',
        client_secret: 'secure',
      });

    return issuer.Client.fromUri('https://op.example.com/client/identifier').then(function (
      client,
    ) {
      expect(client).to.have.property('client_id', 'identifier');
      expect(client).to.have.property('client_secret', 'secure');
    });
  });

  it('is rejected with OPError upon oidc error', function () {
    nock('https://op.example.com').get('/client/identifier').reply(500, {
      error: 'server_error',
      error_description: 'bad things are happening',
    });

    return issuer.Client.fromUri('https://op.example.com/client/identifier').then(
      fail,
      function (error) {
        expect(error.name).to.equal('OPError');
        expect(error).to.have.property('error', 'server_error');
        expect(error).to.have.property('error_description', 'bad things are happening');
      },
    );
  });

  it('is rejected with OPError upon oidc error in www-authenticate header', function () {
    nock('https://op.example.com').get('/client/identifier').reply(401, 'Unauthorized', {
      'WWW-Authenticate':
        'Bearer error="invalid_token", error_description="bad things are happening"',
    });

    return issuer.Client.fromUri('https://op.example.com/client/identifier').then(
      fail,
      function (error) {
        expect(error.name).to.equal('OPError');
        expect(error).to.have.property('error', 'invalid_token');
        expect(error).to.have.property('error_description', 'bad things are happening');
      },
    );
  });

  it('is rejected with when non 200 is returned', function () {
    nock('https://op.example.com').get('/client/identifier').reply(500, 'Internal Server Error');

    return issuer.Client.fromUri('https://op.example.com/client/identifier').then(
      fail,
      function (error) {
        expect(error.name).to.equal('OPError');
        expect(error.message).to.eql('expected 200 OK, got: 500 Internal Server Error');
        expect(error).to.have.property('response');
      },
    );
  });

  it('is rejected with JSON.parse error upon invalid response', function () {
    nock('https://op.example.com').get('/client/identifier').reply(200, '{"notavalid"}');

    return issuer.Client.fromUri('https://op.example.com/client/identifier').then(
      fail,
      function (error) {
        expect(error.message).to.match(/in JSON at position 12/);
        expect(error).to.have.property('response');
      },
    );
  });

  describe('HTTP_OPTIONS', () => {
    afterEach(() => {
      delete issuer.Client[custom.http_options];
    });

    it('allows for http options to be defined for issuer.Client.fromUri calls', async () => {
      const httpOptions = sinon.stub().callsFake(() => ({ headers: { custom: 'foo' } }));
      issuer.Client[custom.http_options] = httpOptions;

      nock('https://op.example.com')
        .get('/client/identifier')
        .matchHeader('custom', 'foo')
        .reply(200, {
          client_id: 'identifier',
          client_secret: 'secure',
        });

      await issuer.Client.fromUri('https://op.example.com/client/identifier');

      expect(nock.isDone()).to.be.true;
      sinon.assert.callCount(httpOptions, 1);
    });
  });
});

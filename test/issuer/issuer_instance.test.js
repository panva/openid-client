'use strict';

const Issuer = require('../../lib').Issuer;
const expect = require('chai').expect;
const LRU = require('lru-cache');
const nock = require('nock');
const sinon = require('sinon');
const jose = require('node-jose');

const fail = () => { throw new Error('expected promise to be rejected'); };

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

  describe('key storage behavior', function () {
    before(function () {
      this.keystore = jose.JWK.createKeyStore();
      return this.keystore.generate('RSA', 512);
    });

    before(function () {
      this.issuer = new Issuer({
        issuer: 'https://op.example.com',
        jwks_uri: 'https://op.example.com/certs',
      });
    });

    before(function () {
      nock('https://op.example.com')
        .get('/certs')
        .reply(200, this.keystore.toJSON());

      return this.issuer.key();
    });

    after(nock.cleanAll);
    afterEach(function () {
      if (LRU.prototype.restore) LRU.prototype.restore();
    });

    it('does not refetch immidiately', function () {
      nock.cleanAll();
      return this.issuer.key();
    });

    it('fetches if asked to', function () {
      nock.cleanAll();

      // force a fail to fetch to check it tries to load
      return this.issuer.keystore(true).then(fail, () => {
        nock('https://op.example.com')
          .get('/certs')
          .reply(200, this.keystore.toJSON());

        return this.issuer.keystore(true).then(() => {
          expect(nock.isDone()).to.be.true;
        });
      });
    });

    it('asks to fetch if the keystore is stale and new key definition is requested', function () {
      sinon.stub(LRU.prototype, 'get').returns(undefined);
      return this.issuer.key({ kid: 'yeah' }).then(fail, () => {
        nock('https://op.example.com')
          .get('/certs')
          .reply(200, this.keystore.toJSON());

        return this.issuer.key({ kid: 'yeah' }).then(() => {
          expect(nock.isDone()).to.be.true;
        });
      });
    });
  });
});

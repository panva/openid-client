const { expect } = require('chai');
const LRU = require('lru-cache');
const nock = require('nock');
const sinon = require('sinon');
const jose = require('jose');

const { Issuer, custom } = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('Issuer', () => {
  describe('key storage behavior (using queryKeyStore)', function () {
    it('requires jwks_uri to be configured', function () {
      const issuer = new Issuer();

      return issuer.keystore().then(fail, (err) => {
        expect(err.message).to.equal('jwks_uri must be configured on the issuer');
      });
    });

    before(function () {
      this.keystore = new jose.JWKS.KeyStore();
      return this.keystore.generate('RSA');
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
        .reply(200, this.keystore.toJWKS());

      return this.issuer.keystore();
    });

    after(nock.cleanAll);
    afterEach(function () {
      if (LRU.prototype.get.restore) LRU.prototype.get.restore();
    });

    it('does not refetch immidiately', function () {
      nock.cleanAll();
      return this.issuer.queryKeyStore({});
    });

    it('fetches if asked to', function () {
      nock.cleanAll();

      // force a fail to fetch to check it tries to load
      return this.issuer.keystore(true).then(fail, () => {
        nock('https://op.example.com')
          .get('/certs')
          .reply(200, this.keystore.toJWKS());

        return this.issuer.keystore(true).then(() => {
          expect(nock.isDone()).to.be.true;
        });
      });
    });

    it('asks to fetch if the keystore is stale and new key definition is requested', function () {
      sinon.stub(LRU.prototype, 'get').returns(undefined);
      return this.issuer.queryKeyStore({ kid: 'yeah' }).then(fail, () => {
        nock('https://op.example.com')
          .get('/certs')
          .reply(200, this.keystore.toJWKS());

        return this.issuer.queryKeyStore({ kid: 'yeah' }).then(fail, () => {
          expect(nock.isDone()).to.be.true;
        });
      });
    });

    it('rejects when no matching key is found', function () {
      return this.issuer.queryKeyStore({ kid: 'noway' }).then(fail, (err) => {
        expect(err.message).to.equal('no valid key found in issuer\'s jwks_uri for key parameters {"kid":"noway"}');
      });
    });

    it('requires a kid is provided in definition if more keys are in the storage', function () {
      sinon.stub(LRU.prototype, 'get').returns(undefined);
      return this.keystore.generate('RSA').then(() => {
        nock('https://op.example.com')
          .get('/certs')
          .reply(200, this.keystore.toJWKS());

        return this.issuer.queryKeyStore({ alg: 'RS256' }).then(fail, (err) => {
          expect(nock.isDone()).to.be.true;
          expect(err.message).to.equal('multiple matching keys found in issuer\'s jwks_uri for key parameters {"alg":"RS256"}, kid must be provided in this case');
        });
      });
    });

    it('multiple keys can match the JWT header', function () {
      sinon.stub(LRU.prototype, 'get').returns(undefined);
      const { kid } = this.keystore.get({ kty: 'RSA' });
      return this.keystore.generate('RSA', undefined, { kid }).then(() => {
        nock('https://op.example.com')
          .get('/certs')
          .reply(200, this.keystore.toJWKS());

        return this.issuer.queryKeyStore({ alg: 'RS256', kid });
      });
    });

    describe('HTTP_OPTIONS', () => {
      afterEach(function () {
        delete this.issuer[custom.http_options];
      });

      it('allows for http options to be defined for issuer.keystore calls', async function () {
        nock.cleanAll();

        nock('https://op.example.com')
          .matchHeader('custom', 'foo')
          .get('/certs')
          .reply(200, this.keystore.toJWKS());

        const httpOptions = sinon.stub().callsFake((opts) => {
          opts.headers.custom = 'foo';
          return opts;
        });
        this.issuer[custom.http_options] = httpOptions;

        await this.issuer.keystore(true);

        expect(nock.isDone()).to.be.true;
        sinon.assert.callCount(httpOptions, 1);
      });
    });
  });
});

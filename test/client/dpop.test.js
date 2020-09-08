const crypto = require('crypto');

const { expect } = require('chai');
const nock = require('nock');
const jose = require('jose');

const { Issuer, custom } = require('../../lib');

const issuer = new Issuer({
  issuer: 'https://op.example.com',
  userinfo_endpoint: 'https://op.example.com/me',
  token_endpoint: 'https://op.example.com/token',
  introspection_endpoint: 'https://op.example.com/token/introspect',
  revocation_endpoint: 'https://op.example.com/token/revoke',
  device_authorization_endpoint: 'https://op.example.com/device',
  dpop_signing_alg_values_supported: ['PS512', 'PS384', 'PS256'],
});

const jwk = jose.JWK.generateSync('RSA');

describe('DPoP', () => {
  beforeEach(function () {
    this.client = new issuer.Client({
      client_id: 'client',
      token_endpoint_auth_method: 'none',
    });
    this.client[custom.http_options] = (opts) => {
      this.httpOpts = opts;
      return opts;
    };
  });

  afterEach(function () {
    delete this.httpOpts;
  });

  describe('dpopProof', () => {
    it('must be passed a payload object', function () {
      expect(() => this.client.dpopProof('foo')).to.throw('payload must be a plain object');
    });

    it('must be passed a private key', function () {
      const msg = '"DPoP" option must be an asymmetric private key to sign the DPoP Proof JWT with';
      expect(() => this.client.dpopProof({}, 'foo')).to.throw(msg);
      expect(() => this.client.dpopProof({}, Buffer.from('foo'))).to.throw(msg);
      expect(() => this.client.dpopProof({}, jose.JWK.generateSync('oct').toJWK(true))).to.throw(msg);
      expect(() => this.client.dpopProof({}, jose.JWK.generateSync('EC').toJWK())).to.throw(msg);
      expect(() => this.client.dpopProof({}, jose.JWK.generateSync('EC').toPEM())).to.throw(msg);
    });

    it('DPoP Proof JWT', function () {
      const proof = this.client.dpopProof({
        htu: 'foo',
        htm: 'bar',
        baz: true,
      }, jose.JWK.generateSync('RSA', 2048));
      const decoded = jose.JWT.decode(proof, { complete: true });
      expect(decoded).to.have.nested.property('header.typ', 'dpop+jwt');
      expect(decoded).to.have.nested.property('payload.iat');
      expect(decoded).to.have.nested.property('payload.jti');
      expect(decoded).to.have.nested.property('payload.htu', 'foo');
      expect(decoded).to.have.nested.property('payload.htm', 'bar');
      expect(decoded).to.have.nested.property('payload.baz', true);
      expect(decoded).to.have.nested.property('header.jwk').that.has.keys('kty', 'e', 'n');

      expect(
        jose.JWT.decode(
          this.client.dpopProof({}, jose.JWK.generateSync('EC')),
          { complete: true },
        ),
      ).to.have.nested.property('header.jwk').that.has.keys('kty', 'crv', 'x', 'y');

      if ('sign' in crypto) {
        expect(
          jose.JWT.decode(
            this.client.dpopProof({}, jose.JWK.generateSync('OKP')),
            { complete: true },
          ),
        ).to.have.nested.property('header.jwk').that.has.keys('kty', 'crv', 'x');
      }
    });

    it('key.alg is used if present', function () {
      const proof = this.client.dpopProof({}, jose.JWK.generateSync('RSA', 2048, { alg: 'PS384' }));
      expect(jose.JWT.decode(proof, { complete: true })).to.have.nested.property('header.alg', 'PS384');
    });

    it('else this.issuer.dpop_signing_alg_values_supported is used', function () {
      const proof = this.client.dpopProof({}, jose.JWK.generateSync('RSA', 2048));
      expect(jose.JWT.decode(proof, { complete: true })).to.have.nested.property('header.alg', 'PS512');
    });

    it('else key.algorithms("sign")[0] is used', function () {
      const proof = this.client.dpopProof({}, jose.JWK.generateSync('EC'));
      expect(jose.JWT.decode(proof, { complete: true })).to.have.nested.property('header.alg', 'ES256');
    });
  });

  it('is enabled for userinfo', async function () {
    nock('https://op.example.com')
      .get('/me').reply(200, { sub: 'foo' });

    await this.client.userinfo('foo', { DPoP: jwk });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for requestResource', async function () {
    nock('https://rs.example.com')
      .post('/resource').reply(200, { sub: 'foo' });

    await this.client.requestResource('https://rs.example.com/resource', 'foo', { DPoP: jwk, method: 'POST' });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for grant', async function () {
    nock('https://op.example.com')
      .post('/token').reply(200, { access_token: 'foo' });

    await this.client.grant({ grant_type: 'foo' }, { DPoP: jwk });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for refresh', async function () {
    nock('https://op.example.com')
      .post('/token').reply(200, { access_token: 'foo' });

    await this.client.refresh('foo', { DPoP: jwk });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for oauthCallback', async function () {
    nock('https://op.example.com')
      .post('/token').reply(200, { access_token: 'foo' });

    await this.client.oauthCallback('foo', { code: 'foo' }, {}, { DPoP: jwk });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for callback', async function () {
    nock('https://op.example.com')
      .post('/token').reply(200, { access_token: 'foo' });

    try {
      await this.client.callback('foo', { code: 'foo' }, {}, { DPoP: jwk });
    } catch (err) {}

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for deviceAuthorization', async function () {
    nock('https://op.example.com')
      .post('/device').reply(200, {
        expires_in: 60,
        device_code: 'foo',
        user_code: 'foo',
        verification_uri: 'foo',
        interval: 1,
      });

    const handle = await this.client.deviceAuthorization({}, { DPoP: jwk });

    expect(this.httpOpts).not.to.have.nested.property('headers.DPoP');

    nock('https://op.example.com')
      .post('/token').reply(200, { access_token: 'foo' });

    await handle.poll();

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });
});

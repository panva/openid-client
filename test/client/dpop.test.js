const { isUndefined } = require('util');

const { expect } = require('chai');
const nock = require('nock');
const jose = require('jose');

const {
  Issuer,
  custom,
  errors: { OPError },
} = require('../../lib');

const issuer = new Issuer({
  issuer: 'https://op.example.com',
  userinfo_endpoint: 'https://op.example.com/me',
  token_endpoint: 'https://op.example.com/token',
  introspection_endpoint: 'https://op.example.com/token/introspect',
  revocation_endpoint: 'https://op.example.com/token/revoke',
  device_authorization_endpoint: 'https://op.example.com/device',
  dpop_signing_alg_values_supported: ['PS512', 'PS384'],
});

const fail = () => {
  throw new Error('expected promise to be rejected');
};

describe('DPoP', () => {
  beforeEach(function () {
    this.client = new issuer.Client({
      client_id: 'client',
      token_endpoint_auth_method: 'none',
    });
    this.client[custom.http_options] = (url, opts) => {
      this.httpOpts = opts;
      return opts;
    };
  });

  afterEach(function () {
    delete this.httpOpts;
  });

  describe('dpopProof', () => {
    it('must be passed a payload object', function () {
      return this.client.dpopProof('foo').then(fail, (err) => {
        expect(err.message).to.eql('payload must be a plain object');
      });
    });

    if (jose.cryptoRuntime === 'node:crypto') {
      it('DPoP Private Key can be passed also as valid createPrivateKey input', async function () {
        if (parseInt(process.versions.node, 10) >= 16) {
          const jwk = await jose.exportJWK(
            (
              await jose.generateKeyPair('ES256', { extractable: true })
            ).privateKey,
          );
          await this.client.dpopProof({}, { format: 'jwk', key: jwk });
        }

        {
          const pem = await jose.exportPKCS8(
            (
              await jose.generateKeyPair('ES256', { extractable: true })
            ).privateKey,
          );
          await this.client.dpopProof({}, pem);
          await this.client.dpopProof({}, { key: pem, format: 'pem' });
        }

        {
          const der = (
            await jose.generateKeyPair('ES256', { extractable: true })
          ).privateKey.export({
            format: 'der',
            type: 'pkcs8',
          });
          await this.client.dpopProof({}, { key: der, format: 'der', type: 'pkcs8' });
        }

        {
          const der = (
            await jose.generateKeyPair('ES256', { extractable: true })
          ).privateKey.export({
            format: 'der',
            type: 'sec1',
          });
          await this.client.dpopProof({}, { key: der, format: 'der', type: 'sec1' });
        }

        {
          const der = (
            await jose.generateKeyPair('RS256', { extractable: true })
          ).privateKey.export({
            format: 'der',
            type: 'pkcs1',
          });
          await this.client.dpopProof({}, { key: der, format: 'der', type: 'pkcs1' });
        }
      });
    }

    it('DPoP Proof JWT w/o ath', async function () {
      const proof = await this.client.dpopProof(
        {
          htu: 'foo',
          htm: 'bar',
          baz: true,
        },
        (
          await jose.generateKeyPair('RS256', { extractable: true })
        ).privateKey,
      );
      const header = jose.decodeProtectedHeader(proof);
      const payload = jose.decodeJwt(proof);
      expect(header).to.have.property('jwk').that.has.keys('kty', 'e', 'n');
      expect(header).to.have.property('typ', 'dpop+jwt');
      expect(payload).to.have.property('iat');
      expect(payload).to.have.property('jti');
      expect(payload).to.have.property('htu', 'foo');
      expect(payload).to.have.property('htm', 'bar');
      expect(payload).to.have.property('baz', true);

      expect(
        jose.decodeProtectedHeader(
          await this.client.dpopProof(
            {},
            (
              await jose.generateKeyPair('ES256', { extractable: true })
            ).privateKey,
          ),
          { complete: true },
        ),
      )
        .to.have.property('jwk')
        .that.has.keys('kty', 'crv', 'x', 'y');

      expect(
        jose.decodeProtectedHeader(
          await this.client.dpopProof(
            {},
            (
              await jose.generateKeyPair('EdDSA', { extractable: true })
            ).privateKey,
          ),
        ),
      )
        .to.have.property('jwk')
        .that.has.keys('kty', 'crv', 'x');
    });

    it('DPoP Proof JWT w/ ath', async function () {
      const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
      const proof = await this.client.dpopProof(
        {
          htu: 'foo',
          htm: 'bar',
        },
        privateKey,
        'foo',
      );
      const payload = jose.decodeJwt(proof);
      expect(payload).to.have.property('ath', 'LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564');
    });

    if (jose.cryptoRuntime === 'node:crypto') {
      it('else this.issuer.dpop_signing_alg_values_supported is used', async function () {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose.generateKeyPair('RS256', { extractable: true })
          ).privateKey,
        );
        // 256 is not supported by the issuer, next one in line is PS384
        expect(jose.decodeProtectedHeader(proof)).to.have.property('alg', 'PS384');
      });
    }

    it('unless the key dictates an algorithm', async function () {
      {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose.generateKeyPair('EdDSA', { extractable: true })
          ).privateKey,
        );
        expect(jose.decodeProtectedHeader(proof)).to.have.property('alg', 'EdDSA');
      }

      if (!('electron' in process.versions) && jose.cryptoRuntime === 'node:crypto') {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose.generateKeyPair('EdDSA', { crv: 'Ed448' })
          ).privateKey,
        );
        expect(jose.decodeProtectedHeader(proof)).to.have.property('alg', 'EdDSA');
      }

      {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose.generateKeyPair('ES256', { extractable: true })
          ).privateKey,
        );
        expect(jose.decodeProtectedHeader(proof)).to.have.property('alg', 'ES256');
      }

      if (!('electron' in process.versions) && jose.cryptoRuntime === 'node:crypto') {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose.generateKeyPair('ES256K', { extractable: true })
          ).privateKey,
        );
        expect(jose.decodeProtectedHeader(proof)).to.have.property('alg', 'ES256K');
      }

      {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose.generateKeyPair('ES384', { extractable: true })
          ).privateKey,
        );
        expect(jose.decodeProtectedHeader(proof)).to.have.property('alg', 'ES384');
      }

      {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose.generateKeyPair('ES512', { extractable: true })
          ).privateKey,
        );
        expect(jose.decodeProtectedHeader(proof)).to.have.property('alg', 'ES512');
      }
    });
  });

  it('is enabled for userinfo', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });

    nock('https://op.example.com').get('/me').reply(200, { sub: 'foo' });

    await this.client.userinfo('foo', { DPoP: privateKey });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');

    const proof = this.httpOpts.headers.DPoP;
    const proofJWT = jose.decodeJwt(proof);
    expect(proofJWT).to.have.property('ath');
  });

  it('handles DPoP nonce in userinfo', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });

    nock('https://op.example.com')
      .get('/me')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.be.undefined;
        return true;
      })
      .reply(401, undefined, {
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
        'DPoP-Nonce': 'eyJ7S_zG.eyJH0-Z.HX4w-7v',
      })
      .get('/me')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { sub: 'foo' })
      .get('/me')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { sub: 'foo' })
      .get('/me')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(400, undefined, {
        'WWW-Authenticate': 'DPoP error="invalid_dpop_proof"',
      });

    await this.client.userinfo('foo', { DPoP: privateKey });
    await this.client.userinfo('foo', { DPoP: privateKey });
    return this.client.userinfo('foo', { DPoP: privateKey }).then(fail, (err) => {
      expect(err).to.be.an.instanceOf(OPError);
      expect(err.error).to.eql('invalid_dpop_proof');
    });
  });

  it('handles DPoP nonce in grant', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });

    nock('https://op.example.com')
      .post('/token')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.be.undefined;
        return true;
      })
      .reply(
        400,
        { error: 'use_dpop_nonce' },
        {
          'DPoP-Nonce': 'eyJ7S_zG.eyJH0-Z.HX4w-7v',
        },
      )
      .post('/token')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { access_token: 'foo' })
      .post('/token')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { access_token: 'foo' })
      .post('/token')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(400, { error: 'invalid_dpop_proof' });

    await this.client.grant({ grant_type: 'client_credentials' }, { DPoP: privateKey });
    await this.client.grant({ grant_type: 'client_credentials' }, { DPoP: privateKey });
    return this.client
      .grant({ grant_type: 'client_credentials' }, { DPoP: privateKey })
      .then(fail, (err) => {
        expect(err).to.be.an.instanceOf(OPError);
        expect(err.error).to.eql('invalid_dpop_proof');
      });
  });

  it('handles DPoP nonce in requestResource', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
    nock('https://rs.example.com')
      .get('/resource')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.be.undefined;
        return true;
      })
      .reply(401, undefined, {
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
        'DPoP-Nonce': 'eyJ7S_zG.eyJH0-Z.HX4w-7v',
      })
      .get('/resource')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { sub: 'foo' })
      .get('/resource')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { sub: 'foo' })
      .get('/resource')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose.decodeJwt(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(400, undefined, {
        'WWW-Authenticate': 'DPoP error="invalid_dpop_proof"',
      });

    await this.client.requestResource('https://rs.example.com/resource', 'foo', {
      DPoP: privateKey,
    });
    await this.client.requestResource('https://rs.example.com/resource', 'foo', {
      DPoP: privateKey,
    });
    return this.client
      .requestResource('https://rs.example.com/resource', 'foo', {
        DPoP: privateKey,
      })
      .then((response) => {
        expect(response.statusCode).to.eql(400);
      });
  });

  it('is enabled for requestResource', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
    nock('https://rs.example.com')
      .matchHeader('Transfer-Encoding', isUndefined)
      .matchHeader('Content-Length', isUndefined)
      .post('/resource')
      .reply(200, { sub: 'foo' });

    await this.client.requestResource('https://rs.example.com/resource', 'foo', {
      DPoP: privateKey,
      method: 'POST',
    });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');

    const proof = this.httpOpts.headers.DPoP;
    const proofJWT = jose.decodeJwt(proof);
    expect(proofJWT).to.have.property('ath');
  });

  it('is enabled for grant', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
    nock('https://op.example.com').post('/token').reply(200, { access_token: 'foo' });

    await this.client.grant({ grant_type: 'foo' }, { DPoP: privateKey });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for refresh', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
    nock('https://op.example.com').post('/token').reply(200, { access_token: 'foo' });

    await this.client.refresh('foo', { DPoP: privateKey });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for oauthCallback', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
    nock('https://op.example.com').post('/token').reply(200, { access_token: 'foo' });

    await this.client.oauthCallback('foo', { code: 'foo' }, {}, { DPoP: privateKey });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for callback', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
    nock('https://op.example.com').post('/token').reply(200, { access_token: 'foo' });

    try {
      await this.client.callback('foo', { code: 'foo' }, {}, { DPoP: privateKey });
    } catch (err) {}

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for deviceAuthorization', async function () {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
    nock('https://op.example.com').post('/device').reply(200, {
      expires_in: 60,
      device_code: 'foo',
      user_code: 'foo',
      verification_uri: 'foo',
      interval: 1,
    });

    const handle = await this.client.deviceAuthorization({}, { DPoP: privateKey });

    expect(this.httpOpts).not.to.have.nested.property('headers.DPoP');

    nock('https://op.example.com').post('/token').reply(200, { access_token: 'foo' });

    await handle.poll();

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });
});

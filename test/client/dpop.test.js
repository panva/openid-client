const { isUndefined } = require('util');

const { expect } = require('chai');
const nock = require('nock');
const jose2 = require('jose2');

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

const privateKey = jose2.JWK.generateSync('EC').keyObject;

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

    it('DPoP Private Key can be passed also as valid createPrivateKey input', async function () {
      if (parseInt(process.versions.node, 10) >= 16) {
        const jwk = (await jose2.JWK.generate('EC')).toJWK(true);
        await this.client.dpopProof({}, { format: 'jwk', key: jwk });
      }

      {
        const pem = (await jose2.JWK.generate('EC')).toPEM(true);
        await this.client.dpopProof({}, pem);
        await this.client.dpopProof({}, { key: pem, format: 'pem' });
      }

      {
        const der = (await jose2.JWK.generate('EC')).keyObject.export({
          format: 'der',
          type: 'pkcs8',
        });
        await this.client.dpopProof({}, { key: der, format: 'der', type: 'pkcs8' });
      }

      {
        const der = (await jose2.JWK.generate('EC')).keyObject.export({
          format: 'der',
          type: 'sec1',
        });
        await this.client.dpopProof({}, { key: der, format: 'der', type: 'sec1' });
      }

      {
        const der = (await jose2.JWK.generate('RSA')).keyObject.export({
          format: 'der',
          type: 'pkcs1',
        });
        await this.client.dpopProof({}, { key: der, format: 'der', type: 'pkcs1' });
      }
    });

    it('DPoP Proof JWT w/o ath', async function () {
      const proof = await this.client.dpopProof(
        {
          htu: 'foo',
          htm: 'bar',
          baz: true,
        },
        (
          await jose2.JWK.generate('RSA')
        ).keyObject,
      );
      const decoded = jose2.JWT.decode(proof, { complete: true });
      expect(decoded).to.have.nested.property('header.typ', 'dpop+jwt');
      expect(decoded).to.have.nested.property('payload.iat');
      expect(decoded).to.have.nested.property('payload.jti');
      expect(decoded).to.have.nested.property('payload.htu', 'foo');
      expect(decoded).to.have.nested.property('payload.htm', 'bar');
      expect(decoded).to.have.nested.property('payload.baz', true);
      expect(decoded).to.have.nested.property('header.jwk').that.has.keys('kty', 'e', 'n');

      expect(
        jose2.JWT.decode(
          await this.client.dpopProof({}, (await jose2.JWK.generate('EC')).keyObject),
          { complete: true },
        ),
      )
        .to.have.nested.property('header.jwk')
        .that.has.keys('kty', 'crv', 'x', 'y');

      expect(
        jose2.JWT.decode(
          await this.client.dpopProof({}, (await jose2.JWK.generate('OKP')).keyObject),
          { complete: true },
        ),
      )
        .to.have.nested.property('header.jwk')
        .that.has.keys('kty', 'crv', 'x');
    });

    it('DPoP Proof JWT w/ ath', async function () {
      const proof = await this.client.dpopProof(
        {
          htu: 'foo',
          htm: 'bar',
        },
        (
          await jose2.JWK.generate('EC')
        ).keyObject,
        'foo',
      );
      const decoded = jose2.JWT.decode(proof, { complete: true });
      expect(decoded).to.have.nested.property(
        'payload.ath',
        'LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564',
      );
    });

    it('else this.issuer.dpop_signing_alg_values_supported is used', async function () {
      const proof = await this.client.dpopProof(
        {},
        (
          await jose2.JWK.generate('RSA', 2048)
        ).keyObject,
      );
      // 256 is not supported by the issuer, next one in line is PS384
      expect(jose2.JWT.decode(proof, { complete: true })).to.have.nested.property(
        'header.alg',
        'PS384',
      );
    });

    it('unless the key dictates an algorithm', async function () {
      {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose2.JWK.generate('OKP', 'Ed25519')
          ).keyObject,
        );
        expect(jose2.JWT.decode(proof, { complete: true })).to.have.nested.property(
          'header.alg',
          'EdDSA',
        );
      }

      if (!('electron' in process.versions)) {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose2.JWK.generate('OKP', 'Ed448')
          ).keyObject,
        );
        expect(jose2.JWT.decode(proof, { complete: true })).to.have.nested.property(
          'header.alg',
          'EdDSA',
        );
      }

      {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose2.JWK.generate('EC', 'P-256')
          ).keyObject,
        );
        expect(jose2.JWT.decode(proof, { complete: true })).to.have.nested.property(
          'header.alg',
          'ES256',
        );
      }

      if (!('electron' in process.versions)) {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose2.JWK.generate('EC', 'secp256k1')
          ).keyObject,
        );
        expect(jose2.JWT.decode(proof, { complete: true })).to.have.nested.property(
          'header.alg',
          'ES256K',
        );
      }

      {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose2.JWK.generate('EC', 'P-384')
          ).keyObject,
        );
        expect(jose2.JWT.decode(proof, { complete: true })).to.have.nested.property(
          'header.alg',
          'ES384',
        );
      }

      {
        const proof = await this.client.dpopProof(
          {},
          (
            await jose2.JWK.generate('EC', 'P-521')
          ).keyObject,
        );
        expect(jose2.JWT.decode(proof, { complete: true })).to.have.nested.property(
          'header.alg',
          'ES512',
        );
      }
    });
  });

  it('is enabled for userinfo', async function () {
    nock('https://op.example.com').get('/me').reply(200, { sub: 'foo' });

    await this.client.userinfo('foo', { DPoP: privateKey });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');

    const proof = this.httpOpts.headers.DPoP;
    const proofJWT = jose2.JWT.decode(proof, { complete: true });
    expect(proofJWT).to.have.nested.property('payload.ath');
  });

  it('handles DPoP nonce in userinfo', async function () {
    nock('https://op.example.com')
      .get('/me')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
        expect(nonce).to.be.undefined;
        return true;
      })
      .reply(401, undefined, {
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
        'DPoP-Nonce': 'eyJ7S_zG.eyJH0-Z.HX4w-7v',
      })
      .get('/me')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { sub: 'foo' })
      .get('/me')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { sub: 'foo' })
      .get('/me')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
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
    nock('https://op.example.com')
      .post('/token')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
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
        const { nonce } = jose2.JWT.decode(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { access_token: 'foo' })
      .post('/token')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { access_token: 'foo' })
      .post('/token')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
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
    nock('https://rs.example.com')
      .get('/resource')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
        expect(nonce).to.be.undefined;
        return true;
      })
      .reply(401, undefined, {
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
        'DPoP-Nonce': 'eyJ7S_zG.eyJH0-Z.HX4w-7v',
      })
      .get('/resource')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { sub: 'foo' })
      .get('/resource')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
        expect(nonce).to.eq('eyJ7S_zG.eyJH0-Z.HX4w-7v');
        return true;
      })
      .reply(200, { sub: 'foo' })
      .get('/resource')
      .matchHeader('DPoP', (proof) => {
        const { nonce } = jose2.JWT.decode(proof);
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
    const proofJWT = jose2.JWT.decode(proof, { complete: true });
    expect(proofJWT).to.have.nested.property('payload.ath');
  });

  it('is enabled for grant', async function () {
    nock('https://op.example.com').post('/token').reply(200, { access_token: 'foo' });

    await this.client.grant({ grant_type: 'foo' }, { DPoP: privateKey });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for refresh', async function () {
    nock('https://op.example.com').post('/token').reply(200, { access_token: 'foo' });

    await this.client.refresh('foo', { DPoP: privateKey });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for oauthCallback', async function () {
    nock('https://op.example.com').post('/token').reply(200, { access_token: 'foo' });

    await this.client.oauthCallback('foo', { code: 'foo' }, {}, { DPoP: privateKey });

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for callback', async function () {
    nock('https://op.example.com').post('/token').reply(200, { access_token: 'foo' });

    try {
      await this.client.callback('foo', { code: 'foo' }, {}, { DPoP: privateKey });
    } catch (err) {}

    expect(this.httpOpts).to.have.nested.property('headers.DPoP');
  });

  it('is enabled for deviceAuthorization', async function () {
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

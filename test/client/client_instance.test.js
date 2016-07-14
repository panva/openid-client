'use strict';

const Issuer = require('../../lib').Issuer;
const _ = require('lodash');
const expect = require('chai').expect;
const BaseClient = require('../../lib/base_client');
const url = require('url');
const querystring = require('querystring');
const base64url = require('base64url');
const nock = require('nock');
const sinon = require('sinon');
const OpenIdConnectError = require('../../lib/open_id_connect_error');
const TokenSet = require('../../lib/token_set');
const got = require('got');
const jose = require('node-jose');
const noop = () => {};
const fail = () => {
  throw new Error('expected promise to be rejected');
};
const now = () => Date.now() / 1000 | 0;

describe('Client', function () {
  afterEach(nock.cleanAll);

  describe('#authorizationUrl', function () {
    before(function () {
      const issuer = new Issuer({
        authorization_endpoint: 'https://op.example.com/auth',
      });
      this.client = new issuer.Client({
        client_id: 'identifier',
      });
    });

    it('returns a string with the url with some basic defaults', function () {
      expect(url.parse(this.client.authorizationUrl({
        redirect_uri: 'https://rp.example.com/cb',
      }), true).query).to.eql({
        client_id: 'identifier',
        redirect_uri: 'https://rp.example.com/cb',
        response_type: 'code',
        scope: 'openid',
      });
    });

    it('allows to overwrite the defaults', function () {
      expect(url.parse(this.client.authorizationUrl({
        scope: 'openid offline_access',
        redirect_uri: 'https://rp.example.com/cb',
        response_type: 'id_token',
      }), true).query).to.eql({
        client_id: 'identifier',
        scope: 'openid offline_access',
        redirect_uri: 'https://rp.example.com/cb',
        response_type: 'id_token',
      });
    });

    it('allows any other params to be provide too', function () {
      expect(url.parse(this.client.authorizationUrl({
        state: 'state',
        custom: 'property',
      }), true).query).to.contain({
        state: 'state',
        custom: 'property',
      });
    });

    it('auto-stringifies claims parameter', function () {
      expect(url.parse(this.client.authorizationUrl({
        claims: { id_token: { email: null } },
      }), true).query).to.contain({
        claims: '{"id_token":{"email":null}}',
      });
    });
  });

  describe('#authorizationCallback', function () {
    before(function () {
      const issuer = new Issuer({
        token_endpoint: 'https://op.example.com/token',
      });
      this.client = new issuer.Client({
        client_id: 'identifier',
        client_secret: 'secure',
      });
    });

    it('does an authorization_code grant with code and redirect_uri', function () {
      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            code: 'codeValue',
            redirect_uri: 'https://rp.example.com/cb',
            grant_type: 'authorization_code',
          });
        })
        .post('/token')
        .reply(200, {});

      return this.client.authorizationCallback('https://rp.example.com/cb', {
        code: 'codeValue',
      })
        .then(fail, () => {
          expect(nock.isDone()).to.be.true;
        });
    });

    it.skip('returns a TokenSet', function () {
      nock('https://op.example.com')
        .post('/token')
        .reply(200, {
          access_token: 'tokenValue',
        });

      return this.client.authorizationCallback('https://rp.example.com/cb', {})
        .then(set => {
          expect(set).to.be.instanceof(TokenSet);
          expect(set).to.have.property('access_token', 'tokenValue');
        });
    });

    it('rejects with OpenIdConnectError when part of the response', function () {
      return this.client.authorizationCallback('https://rp.example.com/cb', {
        error: 'invalid_request',
      }).then(fail, error => {
        expect(error).to.be.instanceof(OpenIdConnectError);
        expect(error).to.have.property('message', 'invalid_request');
      });
    });

    it('rejects with an Error when states mismatch (returned)', function () {
      return this.client.authorizationCallback('https://rp.example.com/cb', {
        state: 'should be checked for this',
      }).then(fail, error => {
        expect(error).to.be.instanceof(Error);
        expect(error).to.have.property('message', 'state mismatch');
      });
    });

    it('rejects with an Error when states mismatch (not returned)', function () {
      return this.client.authorizationCallback('https://rp.example.com/cb', {}, {
        state: 'should be this',
      })
        .then(fail, error => {
          expect(error).to.be.instanceof(Error);
          expect(error).to.have.property('message', 'state mismatch');
        });
    });

    it('rejects with an Error when states mismatch (general mismatch)', function () {
      return this.client.authorizationCallback('https://rp.example.com/cb', {
        state: 'is this',
      }, {
        state: 'should be this',
      })
        .then(fail, error => {
          expect(error).to.be.instanceof(Error);
          expect(error).to.have.property('message', 'state mismatch');
        });
    });
  });


  describe('#refresh', function () {
    before(function () {
      const issuer = new Issuer({
        token_endpoint: 'https://op.example.com/token',
      });
      this.client = new issuer.Client({
        client_id: 'identifier',
        client_secret: 'secure',
      });
    });

    it('does an refresh_token grant with refresh_token', function () {
      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            refresh_token: 'refreshValue',
            grant_type: 'refresh_token',
          });
        })
        .post('/token')
        .reply(200, {});

      return this.client.refresh('refreshValue')
        .then(fail, () => {
          expect(nock.isDone()).to.be.true;
        });
    });

    it.skip('returns a TokenSet', function () {
      nock('https://op.example.com')
        .post('/token')
        .reply(200, {
          access_token: 'tokenValue',
        });

      return this.client.refresh('refreshValue', {})
        .then(set => {
          expect(set).to.be.instanceof(TokenSet);
          expect(set).to.have.property('access_token', 'tokenValue');
        });
    });

    it('can take a TokenSet', function () {
      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            refresh_token: 'refreshValue',
            grant_type: 'refresh_token',
          });
        })
        .post('/token')
        .reply(200, {});

      return this.client.refresh(new TokenSet({
        access_token: 'present',
        refresh_token: 'refreshValue',
      }))
        .then(fail, () => {
          expect(nock.isDone()).to.be.true;
        });
    });

    it('rejects when passed a TokenSet not containing refresh_token', function () {
      return this.client.refresh(new TokenSet({
        access_token: 'present',
        // refresh_token: not
      }))
      .then(fail, error => {
        expect(error).to.be.instanceof(Error);
        expect(error).to.have.property('message', 'refresh_token not present in TokenSet');
      });
    });
  });

  it('#joseSecret', function () {
    const client = new BaseClient({ client_secret: 'rj_JR' });

    return client.joseSecret()
      .then(key => {
        // TODO: check the "k" value
        expect(key).to.have.property('kty', 'oct');
        return client.joseSecret().then(cached => {
          expect(key).to.equal(cached);
        });
      });
  });

  it('#inspect', function () {
    const issuer = new Issuer({ issuer: 'https://op.example.com' });
    const client = new issuer.Client({ client_id: 'identifier' });
    expect(client.inspect()).to.equal('Client <identifier>');
  });

  it('#metadata returns a copy of the clients metadata', function () {
    const issuer = new Issuer({ issuer: 'https://op.example.com' });
    const client = new issuer.Client({ client_id: 'identifier' });
    const expected = {
      application_type: ['web'],
      client_id: 'identifier',
      grant_types: ['authorization_code'],
      id_token_signed_response_alg: 'RS256',
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    };
    expect(client.metadata).not.to.equal(expected);
    expect(client.metadata).to.eql(expected);
  });

  describe('#userinfo', function () {
    it('takes a string token', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      nock('https://op.example.com')
        .matchHeader('authorization', 'Bearer tokenValue')
        .get('/me').reply(200, {});

      return client.userinfo('tokenValue').then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('takes a tokenset', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      nock('https://op.example.com')
        .matchHeader('authorization', 'Bearer tokenValue')
        .get('/me').reply(200, {});

      return client.userinfo(new TokenSet({
        id_token: 'foo',
        refresh_token: 'bar',
        access_token: 'tokenValue',
      })).then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('validates an access token is present in the tokenset', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      return client.userinfo(new TokenSet({
        id_token: 'foo',
        refresh_token: 'bar',
      })).then(fail, (err) => {
        expect(err.message).to.equal('access_token not present in TokenSet');
      });
    });

    it('can do a post call', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      nock('https://op.example.com')
        .post('/me').reply(200, {});

      return client.userinfo('tokenValue', { verb: 'POST' }).then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('can submit access token in a body when post', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            access_token: 'tokenValue',
          });
        })
        .post('/me').reply(200, {});

      return client.userinfo('tokenValue', { verb: 'POST', via: 'body' }).then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('can only submit access token in a body when post', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      expect(function () {
        client.userinfo('tokenValue', { via: 'body', verb: 'get' });
      }).to.throw('can only send body on POST');
    });

    it('can submit access token in a query when get', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      nock('https://op.example.com')
        .get('/me?access_token=tokenValue')
        .reply(200, {});

      return client.userinfo('tokenValue', { via: 'query' }).then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('can only submit access token in a query when get', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      expect(function () {
        client.userinfo('tokenValue', { via: 'query', verb: 'post' });
      }).to.throw('providers should only parse query strings for GET requests');
    });

    it('is rejected with OpenIdConnectError upon oidc error', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      nock('https://op.example.com')
        .get('/me')
        .reply(401, {
          error: 'invalid_token',
          error_description: 'bad things are happening',
        });

      return client.userinfo()
        .then(fail, function (error) {
          expect(error.name).to.equal('OpenIdConnectError');
          expect(error).to.have.property('message', 'invalid_token');
        });
    });

    it('is rejected with when non 200 is returned', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      nock('https://op.example.com')
        .get('/me')
        .reply(500, 'Internal Server Error');

      return client.userinfo()
        .then(fail, function (error) {
          expect(error).to.be.an.instanceof(got.HTTPError);
        });
    });

    it('is rejected with JSON.parse error upon invalid response', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client();

      nock('https://op.example.com')
        .get('/me')
        .reply(200, '{"notavalid"}');

      return client.userinfo()
        .then(fail, function (error) {
          expect(error).to.be.an.instanceof(SyntaxError);
          expect(error).to.have.property('message').matches(/Unexpected token/);
        });
    });
  });

  _.forEach({
    introspect: ['introspection_endpoint', 'token_introspection_endpoint'],
    revoke: ['revocation_endpoint', 'token_revocation_endpoint'],
  }, function (metas, method) {
    describe(`#${method}`, function () {
      metas.forEach(function (property) {
        it(`works with ${property} provided`, function () {
          expect(function () {
            const issuer = new Issuer({
              [property]: `https://op.example.com/token/${method}`,
            });
            const client = new issuer.Client();
            client[method]('tokenValue');
          }).not.to.throw();
        });
      });

      it('posts the token in a body returns the parsed response', function () {
        nock('https://rp.example.com')
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              token: 'tokenValue',
            });
          })
            .post(`/token/${method}`)
          .reply(200, {
            endpoint: 'response',
          });

        const issuer = new Issuer({
          [metas[0]]: `https://rp.example.com/token/${method}`,
        });
        const client = new issuer.Client();

        return client[method]('tokenValue')
          .then(response => expect(response).to.eql({ endpoint: 'response' }));
      });

      it('is rejected with OpenIdConnectError upon oidc error', function () {
        nock('https://rp.example.com')
          .post(`/token/${method}`)
          .reply(500, {
            error: 'server_error',
            error_description: 'bad things are happening',
          });

        const issuer = new Issuer({
          [metas[0]]: `https://rp.example.com/token/${method}`,
        });
        const client = new issuer.Client();

        return client[method]('tokenValue')
          .then(fail, function (error) {
            expect(error).to.have.property('message', 'server_error');
          });
      });

      it('is rejected with when non 200 is returned', function () {
        nock('https://rp.example.com')
          .post(`/token/${method}`)
          .reply(500, 'Internal Server Error');

        const issuer = new Issuer({
          [metas[0]]: `https://rp.example.com/token/${method}`,
        });
        const client = new issuer.Client();

        return client[method]('tokenValue')
          .then(fail, function (error) {
            expect(error).to.be.an.instanceof(got.HTTPError);
          });
      });

      it('is rejected with JSON.parse error upon invalid response', function () {
        nock('https://rp.example.com')
          .post(`/token/${method}`)
          .reply(200, '{"notavalid"}');

        const issuer = new Issuer({
          [metas[0]]: `https://rp.example.com/token/${method}`,
        });
        const client = new issuer.Client();

        return client[method]('tokenValue')
          .then(fail, function (error) {
            expect(error).to.be.an.instanceof(SyntaxError);
            expect(error).to.have.property('message').matches(/Unexpected token/);
          });
      });
    });
  });

  describe('#grant', function () {
    it('calls authenticatedPost with token endpoint and body', function () {
      const issuer = new Issuer({ token_endpoint: 'https://op.example.com/token' });
      const client = new issuer.Client();

      sinon.spy(client, 'authenticatedPost');

      client.grant({
        token: 'tokenValue',
      }).then(noop, noop);

      expect(client.authenticatedPost.args[0][0]).to.equal('https://op.example.com/token');
      expect(client.authenticatedPost.args[0][1]).to.eql({ body: { token: 'tokenValue' } });
    });
  });

  describe('#grantAuth', function () {
    context('when none', function () {
      it('forbids any call using grant like auth', function () {
        const client = new BaseClient({ token_endpoint_auth_method: 'none' });
        expect(function () { client.grantAuth(); })
          .to.throw('client not supposed to use grant authz');
      });
    });

    context('when client_secret_post', function () {
      it('returns the body httpOptions', function () {
        const client = new BaseClient({
          client_id: 'identifier',
          client_secret: 'secure',
          token_endpoint_auth_method: 'client_secret_post' });
        expect(client.grantAuth()).to.eql({
          body: { client_id: 'identifier', client_secret: 'secure' },
        });
      });
    });

    context('when client_secret_basic', function () {
      it('is the default', function () {
        const client = new BaseClient({ client_id: 'identifier', client_secret: 'secure' });
        expect(client.grantAuth()).to.eql({
          headers: { Authorization: 'Basic aWRlbnRpZmllcjpzZWN1cmU=' },
        });
      });
    });

    context('when client_secret_jwt', function () {
      before(function () {
        const issuer = new Issuer({
          token_endpoint: 'https://rp.example.com/token',
          token_endpoint_auth_signing_alg_values_supported: ['HS256', 'HS384'],
        });

        const client = new issuer.Client({
          client_id: 'identifier',
          client_secret: 'its gotta be a long secret and i mean at least 32 characters',
          token_endpoint_auth_method: 'client_secret_jwt' });

        return client.grantAuth().then((auth) => { this.auth = auth; });
      });

      it('promises a body', function () {
        expect(this.auth).to.have.property('body').and.is.an('object');
        expect(this.auth.body).to.have.property('client_assertion_type',
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
        expect(this.auth.body).to.have.property('client_assertion');
      });

      it('has a predefined payload properties', function () {
        const payload = JSON.parse(base64url.decode(this.auth.body.client_assertion.split('.')[1]));
        expect(payload).to.have.keys(['iat', 'exp', 'jti', 'iss', 'sub', 'aud']);

        expect(payload.iss).to.equal(payload.sub).to.equal('identifier');
        expect(payload.jti).to.be.a('string');
        expect(payload.iat).to.be.a('number');
        expect(payload.exp).to.be.a('number');
        expect(payload.aud).to.equal('https://rp.example.com/token');
      });

      it('has the right header properties', function () {
        const header = JSON.parse(base64url.decode(this.auth.body.client_assertion.split('.')[0]));
        expect(header).to.have.keys([
          'alg', 'typ',
        ]);

        expect(header.alg).to.equal('HS256');
        expect(header.typ).to.equal('JWT');
      });
    });

    context('when private_key_jwt', function () {
      before(function () {
        const issuer = new Issuer({
          token_endpoint: 'https://rp.example.com/token',
          token_endpoint_auth_signing_alg_values_supported: ['ES256', 'ES384'],
        });

        const keystore = jose.JWK.createKeyStore();

        return keystore.generate('EC', 'P-256').then(() => {
          const client = new issuer.Client({
            client_id: 'identifier',
            token_endpoint_auth_method: 'private_key_jwt' }, keystore);

          return client.grantAuth().then((auth) => { this.auth = auth; });
        });
      });

      it('promises a body', function () {
        expect(this.auth).to.have.property('body').and.is.an('object');
        expect(this.auth.body).to.have.property('client_assertion_type',
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
        expect(this.auth.body).to.have.property('client_assertion');
      });

      it('has a predefined payload properties', function () {
        const payload = JSON.parse(base64url.decode(this.auth.body.client_assertion.split('.')[1]));
        expect(payload).to.have.keys(['iat', 'exp', 'jti', 'iss', 'sub', 'aud']);

        expect(payload.iss).to.equal(payload.sub).to.equal('identifier');
        expect(payload.jti).to.be.a('string');
        expect(payload.iat).to.be.a('number');
        expect(payload.exp).to.be.a('number');
        expect(payload.aud).to.equal('https://rp.example.com/token');
      });

      it('has the right header properties', function () {
        const header = JSON.parse(base64url.decode(this.auth.body.client_assertion.split('.')[0]));
        expect(header).to.have.keys([
          'alg', 'typ', 'kid',
        ]);

        expect(header.alg).to.equal('ES256');
        expect(header.typ).to.equal('JWT');
        expect(header.kid).to.be.ok;
      });
    });
  });
});

describe('Client#validateIdToken', function () {
  before(function () {
    this.keystore = jose.JWK.createKeyStore();
    return this.keystore.generate('RSA', 512);
  });

  before(function () {
    this.issuer = new Issuer({
      issuer: 'https://op.example.com',
      jwks_uri: 'https://op.example.com/certs',
    });
    this.client = new this.issuer.Client({
      client_id: 'identifier',
      client_secret: 'its gotta be a long secret and i mean at least 32 characters',
    });

    this.IdToken = class IdToken {
      constructor(key, alg, payload) {
        return jose.JWS.createSign({
          fields: { alg, typ: 'JWT' },
          format: 'compact',
        }, { key, reference: !alg.startsWith('HS') }).update(JSON.stringify(payload)).final();
      }
    };
  });

  before(function () {
    nock('https://op.example.com')
      .persist()
      .get('/certs')
      .reply(200, this.keystore.toJSON());
  });

  after(nock.cleanAll);

  it('validates the id token and fulfills with input value (when string)', function () {
    return new this.IdToken(this.keystore.get(), 'RS256', {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    })
    .then((token) => this.client.validateIdToken(token).then((validated) => {
      expect(validated).to.equal(token);
    }));
  });

  it('validates the id token and fulfills with input value (when TokenSet)', function () {
    return new this.IdToken(this.keystore.get(), 'RS256', {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    })
    .then((token) => {
      const tokenset = new TokenSet({ id_token: token });
      return this.client.validateIdToken(tokenset).then((validated) => {
        expect(validated).to.equal(tokenset);
      });
    });
  });

  it('validates the id token and fulfills with input value (when signed by secret)', function () {
    const client = new this.issuer.Client({
      client_id: 'hs256-client',
      client_secret: 'its gotta be a long secret and i mean at least 32 characters',
      id_token_signed_response_alg: 'HS256',
    });

    return client.joseSecret().then(key => {
      return new this.IdToken(key, 'HS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
      .then((token) => {
        const tokenset = new TokenSet({ id_token: token });
        return client.validateIdToken(tokenset).then((validated) => {
          expect(validated).to.equal(tokenset);
        });
      });
    });
  });

  it('validates the id_token_signed_response_alg is the one used', function () {
    return this.client.joseSecret().then(key => {
      return new this.IdToken(key, 'HS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
      .then((token) => this.client.validateIdToken(token))
      .then(fail, error => {
        expect(error).to.have.property('message', 'unexpected algorithm used');
      });
    });
  });

  it('verifies the azp', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      azp: 'not the client',
      exp: now() + 3600,
      iat: now(),
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token))
    .then(fail, error => {
      expect(error).to.have.property('message', 'azp must be the client_id');
    });
  });

  it('verifies azp is present when more audiences are provided', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: [this.client.client_id, 'someone else'],
      exp: now() + 3600,
      iat: now(),
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token))
    .then(fail, error => {
      expect(error).to.have.property('message', 'missing required JWT property azp');
    });
  });

  it('verifies the audience when azp is there', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: [this.client.client_id, 'someone else'],
      azp: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token));
  });

  it('passes with nonce check', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      nonce: 'nonce!!!',
      aud: [this.client.client_id, 'someone else'],
      azp: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token, 'nonce!!!'));
  });

  it('validates nonce when provided to check for', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: [this.client.client_id, 'someone else'],
      azp: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token, 'nonce!!!'))
    .then(fail, error => {
      expect(error).to.have.property('message', 'nonce mismatch');
    });
  });

  it('validates nonce when in token', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      nonce: 'nonce!!!',
      aud: [this.client.client_id, 'someone else'],
      azp: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token))
    .then(fail, error => {
      expect(error).to.have.property('message', 'nonce mismatch');
    });
  });

  ['iss', 'sub', 'aud', 'exp', 'iat'].forEach(function (prop) {
    it(`verifies presence of payload property ${prop}`, function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      };

      delete payload[prop];

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
      .then((token) => this.client.validateIdToken(token))
      .then(fail, error => {
        expect(error).to.have.property('message', `missing required JWT property ${prop}`);
      });
    });
  });

  it('verifies iat is a number', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: 'not a number',
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token))
    .then(fail, error => {
      expect(error).to.have.property('message', 'iat is not a number');
    });
  });

  it('verifies iat is in the past', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: now() + 20,
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token))
    .then(fail, error => {
      expect(error).to.have.property('message', 'id_token issued in the future');
    });
  });

  it('verifies exp is a number', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: 'not a nunmber',
      iat: now(),
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token))
    .then(fail, error => {
      expect(error).to.have.property('message', 'exp is not a number');
    });
  });

  it('verifies exp is in the future', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() - 100,
      iat: now(),
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token))
    .then(fail, error => {
      expect(error).to.have.property('message', 'id_token expired');
    });
  });

  it('verifies nbf is a number', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
      nbf: 'notanumber',
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token))
    .then(fail, error => {
      expect(error).to.have.property('message', 'nbf is not a number');
    });
  });

  it('verifies nbf is in the past', function () {
    const payload = {
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
      nbf: now() + 20,
    };

    return new this.IdToken(this.keystore.get(), 'RS256', payload)
    .then((token) => this.client.validateIdToken(token))
    .then(fail, error => {
      expect(error).to.have.property('message', 'id_token not active yet');
    });
  });

  it('passes with the right at_hash', function () {
    const access_token = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'; // eslint-disable-line camelcase, max-len
    const at_hash = '77QmUPtjPfzWtF2AnpK9RQ'; // eslint-disable-line camelcase

    return new this.IdToken(this.keystore.get(), 'RS256', {
      at_hash,
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    })
    .then((token) => {
      const tokenset = new TokenSet({ access_token, id_token: token });
      return this.client.validateIdToken(tokenset);
    });
  });

  it('fails with the wrong at_hash', function () {
    const access_token = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'; // eslint-disable-line camelcase, max-len
    const at_hash = 'notvalid77QmUPtjPfzWtF2AnpK9RQ'; // eslint-disable-line camelcase

    return new this.IdToken(this.keystore.get(), 'RS256', {
      at_hash,
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    })
    .then((token) => {
      const tokenset = new TokenSet({ access_token, id_token: token });
      return this.client.validateIdToken(tokenset);
    })
    .then(fail, error => {
      expect(error).to.have.property('message', 'at_hash mismatch');
    });
  });

  it('passes with the right c_hash', function () {
    const code = 'Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk'; // eslint-disable-line camelcase, max-len
    const c_hash = 'LDktKdoQak3Pk0cnXxCltA'; // eslint-disable-line camelcase

    return new this.IdToken(this.keystore.get(), 'RS256', {
      c_hash,
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    })
    .then((token) => {
      const tokenset = new TokenSet({ code, id_token: token });
      return this.client.validateIdToken(tokenset);
    });
  });

  it('fails with the wrong c_hash', function () {
    const code = 'Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk'; // eslint-disable-line camelcase, max-len
    const c_hash = 'notvalidLDktKdoQak3Pk0cnXxCltA'; // eslint-disable-line camelcase

    return new this.IdToken(this.keystore.get(), 'RS256', {
      c_hash,
      iss: this.issuer.issuer,
      sub: 'userId',
      aud: this.client.client_id,
      exp: now() + 3600,
      iat: now(),
    })
    .then((token) => {
      const tokenset = new TokenSet({ code, id_token: token });
      return this.client.validateIdToken(tokenset);
    })
    .then(fail, error => {
      expect(error).to.have.property('message', 'c_hash mismatch');
    });
  });

  it('fails if tokenset without id_token is passed in', function () {
    expect(() => {
      this.client.validateIdToken(new TokenSet({
        access_token: 'tokenValue',
        // id_token not
      }));
    }).to.throw('id_token not present in TokenSet');
  });
});

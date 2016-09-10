'use strict';

const Issuer = require('../../lib').Issuer;
const _ = require('lodash');
const expect = require('chai').expect;
const BaseClient = require('../../lib/base_client');
const now = require('../../lib/unix_timestamp');
const url = require('url');
const querystring = require('querystring');
const base64url = require('base64url');
const nock = require('nock');
const sinon = require('sinon');
const OpenIdConnectError = require('../../lib/open_id_connect_error');
const TokenSet = require('../../lib/token_set');
const got = require('got');
const jose = require('node-jose');
const timekeeper = require('timekeeper');

const noop = () => {};
const fail = () => { throw new Error('expected promise to be rejected'); };
const encode = (object) => base64url.encode(JSON.stringify(object));

describe('Client', function () {
  afterEach(timekeeper.reset);
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

      return this.client.refresh('refreshValue').then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('returns a TokenSet', function () {
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
        .then(() => {
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
      })).then(fail, (error) => {
        expect(error.message).to.equal('access_token not present in TokenSet');
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

    describe('signed response (content-type = application/jwt)', function () {
      it('decodes and validates the id_token', function () {
        const issuer = new Issuer({
          userinfo_endpoint: 'https://op.example.com/me',
          issuer: 'https://op.example.com',
        });
        const client = new issuer.Client({
          client_id: 'foobar',
          userinfo_signed_response_alg: 'none',
        });

        const payload = {
          iss: issuer.issuer,
          sub: 'foobar',
          aud: client.client_id,
          exp: now() + 100,
          iat: now(),
        };

        nock('https://op.example.com')
          .get('/me')
          .reply(200, `${encode({ alg: 'none' })}.${encode(payload)}.`, {
            'content-type': 'application/jwt; charset=utf-8',
          });

        return client.userinfo()
          .then(userinfo => {
            expect(userinfo).to.be.an('object');
            expect(userinfo).to.eql(payload);
          });
      });

      it('validates the used alg of signed userinfo', function () {
        const issuer = new Issuer({
          userinfo_endpoint: 'https://op.example.com/me',
          issuer: 'https://op.example.com',
        });
        const client = new issuer.Client({
          client_id: 'foobar',
          userinfo_signed_response_alg: 'RS256',
        });

        const payload = {};

        nock('https://op.example.com')
          .get('/me')
          .reply(200, `${encode({ alg: 'none' })}.${encode(payload)}.`, {
            'content-type': 'application/jwt; charset=utf-8',
          });

        return client.userinfo().then(fail, (err) => {
          expect(err.message).to.eql('unexpected algorithm used');
        });
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

  it('can be also used for userinfo response validation', function () {
    const client = new this.issuer.Client({
      client_id: 'hs256-client',
      client_secret: 'its gotta be a long secret and i mean at least 32 characters',
      userinfo_signed_response_alg: 'HS256',
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
        return client.validateIdToken(token, null, 'userinfo').then((validated) => {
          expect(validated).to.equal(token);
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

describe('Client#fetchDistributedClaims', function () {
  afterEach(nock.cleanAll);
  before(function () {
    const issuer = new Issuer({
      authorization_endpoint: 'https://op.example.com/auth',
    });
    this.client = new issuer.Client({
      client_id: 'identifier',
    });
  });

  it('just returns userinfo if no distributed claims are to be fetched', function () {
    const userinfo = {
      sub: 'userID',
      _claim_sources: {
        src1: { JWT: 'not distributed' },
      },
    };
    return this.client.fetchDistributedClaims(userinfo)
      .then(result => {
        expect(result).to.equal(userinfo);
      });
  });

  it('fetches the claims from one or more distrubuted sources', function () {
    nock('https://src1.example.com')
      .matchHeader('authorization', 'Bearer foobar')
      .get('/claims').reply(200, {
        credit_history: 'foobar',
      });
    nock('https://src2.example.com')
      .get('/claims').reply(200, {
        email: 'foobar@example.com',
      });

    const userinfo = {
      sub: 'userID',
      _claim_names: {
        credit_history: 'src1',
        email: 'src2',
      },
      _claim_sources: {
        src1: { endpoint: 'https://src1.example.com/claims', access_token: 'foobar' },
        src2: { endpoint: 'https://src2.example.com/claims' },
      },
    };

    return this.client.fetchDistributedClaims(userinfo)
      .then(result => {
        expect(result).to.eql({
          sub: 'userID',
          credit_history: 'foobar',
          email: 'foobar@example.com',
        });
        expect(result).to.equal(userinfo);
      });
  });

  it('uses access token from provided param if not part of the claims', function () {
    nock('https://src1.example.com')
      .matchHeader('authorization', 'Bearer foobar')
      .get('/claims').reply(200, {
        credit_history: 'foobar',
      });

    const userinfo = {
      sub: 'userID',
      _claim_names: {
        credit_history: 'src1',
      },
      _claim_sources: {
        src1: { endpoint: 'https://src1.example.com/claims' },
      },
    };

    return this.client.fetchDistributedClaims(userinfo, { src1: 'foobar' })
      .then(result => {
        expect(result).to.eql({
          sub: 'userID',
          credit_history: 'foobar',
        });
        expect(result).to.equal(userinfo);
      });
  });

  it('validates claims that should be present are', function () {
    nock('https://src1.example.com')
      .matchHeader('authorization', 'Bearer foobar')
      .get('/claims').reply(200, {
        // credit_history: 'foobar',
      });

    const userinfo = {
      sub: 'userID',
      _claim_names: {
        credit_history: 'src1',
      },
      _claim_sources: {
        src1: { endpoint: 'https://src1.example.com/claims', access_token: 'foobar' },
      },
    };

    return this.client.fetchDistributedClaims(userinfo)
      .then(fail, function (error) {
        expect(error).to.have.property('src', 'src1');
        expect(error.message).to.equal('expected claim "credit_history" in "src1"');
      });
  });

  it('is rejected with OpenIdConnectError upon oidc error', function () {
    nock('https://src1.example.com')
      .matchHeader('authorization', 'Bearer foobar')
      .get('/claims')
      .reply(401, {
        error: 'invalid_token',
        error_description: 'bad things are happening',
      });

    const userinfo = {
      sub: 'userID',
      _claim_names: {
        credit_history: 'src1',
      },
      _claim_sources: {
        src1: { endpoint: 'https://src1.example.com/claims', access_token: 'foobar' },
      },
    };

    return this.client.fetchDistributedClaims(userinfo)
      .then(fail, function (error) {
        expect(error.name).to.equal('OpenIdConnectError');
        expect(error).to.have.property('message', 'invalid_token');
        expect(error).to.have.property('src', 'src1');
      });
  });
});

describe('Client#unpackAggregatedClaims', function () {
  function getJWT(payload, issuer) {
    const iss = `https://${issuer}-iss.example.com`;
    let keystore;
    payload.iss = iss;

    if (Issuer.registry.has(iss)) {
      keystore = Issuer.registry.get(iss).keystore();
    } else {
      const store = jose.JWK.createKeyStore();
      keystore = store.generate('RSA', 512).then(function () {
        const i = new Issuer({ issuer: iss, jwks_uri: `${iss}/certs` });

        nock(iss)
          .persist()
          .get('/certs')
          .reply(200, store.toJSON(true));

        return i.keystore();
      });
    }

    return keystore.then(function (k) {
      return jose.JWS.createSign({
        fields: {
          alg: 'RS256',
          typ: 'JWT',
        },
        format: 'compact',
      }, { key: k.get() }).update(JSON.stringify(payload)).final();
    });
  }

  before(function () {
    const issuer = new Issuer({
      authorization_endpoint: 'https://op.example.com/auth',
    });
    this.client = new issuer.Client({
      client_id: 'identifier',
    });
  });

  it('just returns userinfo if no aggregated claims are to be unpacked', function () {
    const userinfo = {
      sub: 'userID',
      _claim_sources: {
        src1: { endpoint: 'not distributed' },
      },
    };
    return this.client.unpackAggregatedClaims(userinfo)
      .then(result => {
        expect(result).to.equal(userinfo);
      });
  });

  it('unpacks the claims from one or more aggregated sources', function* () {
    const userinfo = {
      sub: 'userID',
      _claim_names: {
        credit_history: 'src1',
        email: 'src2',
      },
      _claim_sources: {
        src1: { JWT: yield getJWT({ credit_history: 'foobar' }, 'src1') },
        src2: { JWT: yield getJWT({ email: 'foobar@example.com' }, 'src2') },
      },
    };

    return this.client.unpackAggregatedClaims(userinfo)
      .then(result => {
        expect(result).to.eql({
          sub: 'userID',
          credit_history: 'foobar',
          email: 'foobar@example.com',
        });
        expect(result).to.equal(userinfo);
      });
  });

  it('autodiscovers new issuers', function* () {
    const userinfo = {
      sub: 'userID',
      _claim_names: {
        email_verified: 'cliff',
      },
      _claim_sources: {
        cliff: { JWT: yield getJWT({ email_verified: false }, 'cliff') },
      },
    };

    const iss = 'https://cliff-iss.example.com';

    const discovery = nock(iss)
      .get('/.well-known/openid-configuration')
      .reply(200, {
        iss,
        jwks_uri: `${iss}/certs`,
      });

    Issuer.registry.delete(iss);

    return this.client.unpackAggregatedClaims(userinfo)
      .then(result => {
        expect(result).to.eql({
          sub: 'userID',
          email_verified: false,
        });
        expect(result).to.equal(userinfo);
        expect(discovery.isDone()).to.be.true;
      });
  });

  it('validates claims that should be present are', function* () {
    const userinfo = {
      sub: 'userID',
      _claim_names: {
        credit_history: 'src1',
      },
      _claim_sources: {
        src1: { JWT: yield getJWT({}, 'src1') },
      },
    };

    return this.client.unpackAggregatedClaims(userinfo)
      .then(fail, function (error) {
        expect(error).to.have.property('src', 'src1');
        expect(error.message).to.equal('expected claim "credit_history" in "src1"');
      });
  });

  it('rejects discovery errors', function* () {
    const userinfo = {
      sub: 'userID',
      _claim_names: {
        email_verified: 'cliff',
      },
      _claim_sources: {
        cliff: { JWT: yield getJWT({ email_verified: false }, 'cliff') },
      },
    };

    const iss = 'https://cliff-iss.example.com';

    const discovery = nock(iss)
      .get('/.well-known/openid-configuration')
      .reply(500, 'Internal Server Error');

    Issuer.registry.delete(iss);

    return this.client.unpackAggregatedClaims(userinfo)
      .then(fail, error => {
        expect(discovery.isDone()).to.be.true;
        expect(error.name).to.equal('HTTPError');
        expect(error.src).to.equal('cliff');
      });
  });

  it('rejects JWT errors', function () {
    const userinfo = {
      sub: 'userID',
      _claim_names: {
        email_verified: 'src1',
      },
      _claim_sources: {
        src1: { JWT: 'not.a.jwt' },
      },
    };

    return this.client.unpackAggregatedClaims(userinfo)
      .then(fail, error => {
        expect(error.src).to.equal('src1');
      });
  });

  /* eslint-disable max-len */
  describe('signed and encrypted responses', function () {
    before(function () {
      return jose.JWK.asKeyStore({
        keys: [
          {
            kty: 'EC',
            kid: 'L3qrG8dSNYv6F-Hvv-qTdp_EkmgwjQX76DHmDZCoa4Q',
            crv: 'P-256',
            x: 'PDsKZY9JxlbrE-hHce_e_H7yjWgxftRIowdW9qxBqNQ',
            y: 'EAmrpjkbBkuBZAD2kvuL5mOXgdK_8t1t93yKGGHq_Y4',
            d: '59efvkfuCuVLW9Y4xvLvUyjARwgnSgwTLRc0UGpewLA',
          },
        ],
      }).then(keystore => { this.keystore = keystore; });
    });

    it('handles signed and encrypted id_tokens from implicit and code responses (test by hybrid)', function () {
      const time = new Date(1473076413242);
      timekeeper.freeze(time);
      const issuer = new Issuer({
        issuer: 'https://guarded-cliffs-8635.herokuapp.com/op',
        token_endpoint: 'https://op.example.com/token',
        userinfo_endpoint: 'https://op.example.com/me',
      });

      nock('https://op.example.com')
        .post('/token')
        .reply(200, {
          access_token: 'eyJraW5kIjoiQWNjZXNzVG9rZW4iLCJqdGkiOiJlMDk5YTI1ZC02MzA0LTQwMGItOTdhYi1hOTJhMzMzOTBlODgiLCJpYXQiOjE0NzMwNzY0MTMsImV4cCI6MTQ3MzA4MzYxMywiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.p_r4KvAu6lEY6JpGmRIGCkRRrovGeJcDfOw3O_gFkPRaY7bcJjNDUPlfY7_nyp3bWyqtveq55ozTZuddUL01KET7bKgxMq-dQ2SxGBvgN3KtHIRBud7Bw8Ax98YkiBKJJXC8xF00VZkkX-ZcUyXptPkUpBm0zeN6jmWmyFX-2QrbclLS8ZEK2Poc_y5PdNAtCCOTBfnq6roxzVQ5lM_aMQaSuPVd-Og6E_jBE6OE9oB4ikFa4S7EvZvFVDpGMLtUjxOazTURbqWY6OnuhuAiP6WZc1FxfQod462IqPERzl2qVJH9qQNr-iLuVLt_bzauHg33v1koTrdfETyoRAZH5w',
          expires_at: 1473083613,
          id_token: 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6IkwzcXJHOGRTTll2NkYtSHZ2LXFUZHBfRWttZ3dqUVg3NkRIbURaQ29hNFEiLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJJVXRTWnZOVzBubUNmT2Nwek5JSnBBS29FbGpOVkZyUlJGa2pDT3plYnlRIiwieSI6IjNEOXZ1V2VJNEdVajZWczZ4ZUJlMVZRM3dHQnhkU3BnTGdYcGZPUThmeEkifSwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6IkpXVCJ9.DVIPxvxnQASDiair_I_6e4M1Y8yMdzIneHMPq_LlBjo8QAiwjMQ1Uw.gdLKThNa_DcFmPGBmzOBkg.TQZ4qpEchLx9nnNIfG_N8d3sL-S-p1vpWbA3MnK68U60kX7i29s33fxhH3w5MQhZbgxjntrbRdE9wFsBzclr8hfwazBTpi6D5Ignug0xCZQYw7HBDrkq63-7PQQa2-rivTtxQxAWUZj7dnNE4Ixo9qaBkHod1EPf5xameCDzgrRa2oi2ISEE6ncQrvc7jnANeBQj0Q2OLmo9L7EIVQbEKejGfZ_0p5HiXmgFMpLbkLFwYhTdpiSUCkZlcym-e2tgbzHJmtF85cx2-yDwDNGLvY8y5ytW79_k_ckbHKVTjf_jRMagqM7Mt6TQ1fhm9T7FZ4q-96L0ItGb12jar2Aw6VWP1DAwUMZ1jA8mmllsWu-y7qc9Ert5rlJ7osZzMOgaNfX1sf5Xa7aOHysC-tVxknIPtxAamVJ7REGxmii-FO6En4zgJMt1PLUoTTK4tIpIX06VWDKI-dQzn46ple9xeuzCUvpvap823Xl9ONcVj4AF-YmHU-UkT96gx_6Owqcwm6synOh1l2O9rRi9jJnCg6egTqn1MHaVhTYaVhKQQUpE-voAoXoaJDoLQX2fC6IjF5H2xnc_1k61wGBJkX_7zqagNYGJyoluiQr5EGkB8pxANJVHNIW37ezJEIjnix5h_Fwzh_XElGzVsKeB-ih9X6ECSVJ1VIPopN5t38kGa8lQuM7vLr0i__cvYP8TgyE94nllEl-5f0gHOUQrpcUEqpsZYRBGcW_m8iU3nuvD0Em6nCvvzPUvlmCRyANQbs3A.H9oTPRc3ahVDUuYj3C9-gQ',
          refresh_token: 'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA',
          token_type: 'Bearer',
        });

      const client = new issuer.Client({
        client_id: '4e87dde4-ddd3-4c21-aef9-2f2f6bab43ca',
        client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
        id_token_encrypted_response_alg: 'ECDH-ES+A128KW',
        id_token_encrypted_response_enc: 'A128CBC-HS256',
        id_token_signed_response_alg: 'HS256',
      }, this.keystore);

      return client.authorizationCallback('http://oidc-client.dev/cb', {
        code: 'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiI3YzM5NzQyZC0yMGUyLTQ3YjEtYmM1MC1lN2VlYzhmN2IzNmYiLCJub25jZSI6ImM2NDVmZmZhNDAwNzU1MzJlZjI5YTJlYTYyN2NmYTM3IiwiaWF0IjoxNDczMDc2NDEyLCJleHAiOjE0NzMwNzcwMTIsImlzcyI6Imh0dHBzOi8vZ3VhcmRlZC1jbGlmZnMtODYzNS5oZXJva3VhcHAuY29tL29wIn0.jgUnZUBmsceb1cpqlsmiCOQ40Zx4JTRffGN_bAgYT4rLcEv3wOlzMSoVmU1cYkDbi-jjNAqkBjqxDWHcRJnQR4BAYOdyDVcGWD_aLkqGhUOCJHn_lwWqEKtSTgh-zXiqVIVC5NTA2BdhEfHhb-jnMQNrKkL2QNXOFvT9s6khZozOMXy-mUdfNfdSFHrcpFkFyGAUpezI9QmwToMB6KwoRHDYb2jcLBXdA5JLAnHw8lpz9yUaVQv7s97wY7Xgtt2zNFwQxiJWytYNHaJxQnOZje0_TvDjrZSA9IYKuKU1Q7f7-EBfQfFSGcsFK2NtGho3mNBEUDD2B8Qv1ipv50oU6Q',
        id_token: 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6IkwzcXJHOGRTTll2NkYtSHZ2LXFUZHBfRWttZ3dqUVg3NkRIbURaQ29hNFEiLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJyellvRzJXeTZtSWhIZ01pMk1SNmd0alpPbG40SzZnSVExVU0yS0tOaFBjIiwieSI6IjF0TmNVZTJSNHBPM2NRZUVtQTF6Z1AzNVdXV19xSUNCMDY3WHFZZGJPSXMifSwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6IkpXVCJ9.yMWht5iTHhr6EKd-Dy7vw_qkRnuh7RtFpLWfs0TOQ6IAIF6K5ieUKw.-wtcftFYgbs7Rj1g-zKaXw.s8BposTeAeUdqSIjKKYADk5THIP33_nLNmGcScQ94vHApM6lUeuMPNdtjGIRJfLoBnIjr0JLYUX_oB-8nXxDCgV19alT0xzc9bKMbb6FR7gHS4R6nVUFAumtpl50iwFs-xGIcVsrr76lQJv5m139EqSeCXse2OY8Q0YyBJgEb_hL4kDXpqxwAd-VqyQzyrAXd_pIlVUnydZ6BC4ZPvbN7RJPR8z1EN46GEYknweuyhT_5tD4FkcngJPRoXJ_KnEr9Q7qbIbCWMmn6bBO59uvv-MXCM2PXIaRNTwZ2_Vp0pB6LkmVC6kHcsotBBGzc-TH_5t87t4JhB1XtTyfl_Nn1YCETdVh8iJUTk_F6ntokka0PTvjXfVQZkqZHT6j6PqZzqMngHNh2lxaFRod9DxT00QEDHXoBGaMDIjBMAt0vI4vIeXqxIMtqJ3i8FMm9bociXo5kpRDgBgmTllJ8O7GDw5q0M7ZIg5dRr0aph8TeXDImwvbPhk32T6tXJVg1i8N7dTICVc0BTitp4cIw2TFXoiR3eSyLusrJ4H3qe-SNJUoq0sPBwzg1tEiDbsDaHhxiwLRu1rcyOcXEqT5Ry0bJM09I_ypEAX9JoA_5NbiY1PVx7rMDxDUreEBW_1xEG8rgXkAmVHHZWLUiEmxQ4RCnityGKIEbG7OFjOOd6CXuznnBEDV-F120bcDCaIClwYI.yFz2AdC2eJ7GX-9gYUMy8Q',
        state: '36853f4ea7c9d26f4b0b95f126afe6a2',
      }, { state: '36853f4ea7c9d26f4b0b95f126afe6a2', nonce: 'c645fffa40075532ef29a2ea627cfa37' });
    });

    it('handles signed and encrypted id_tokens from refresh grant', function () {
      const time = new Date(1473076413242);
      timekeeper.freeze(time);
      const issuer = new Issuer({
        issuer: 'https://guarded-cliffs-8635.herokuapp.com/op',
        token_endpoint: 'https://op.example.com/token',
      });

      nock('https://op.example.com')
        .post('/token')
        .reply(200, {
          access_token: 'eyJraW5kIjoiQWNjZXNzVG9rZW4iLCJqdGkiOiJlMDk5YTI1ZC02MzA0LTQwMGItOTdhYi1hOTJhMzMzOTBlODgiLCJpYXQiOjE0NzMwNzY0MTMsImV4cCI6MTQ3MzA4MzYxMywiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.p_r4KvAu6lEY6JpGmRIGCkRRrovGeJcDfOw3O_gFkPRaY7bcJjNDUPlfY7_nyp3bWyqtveq55ozTZuddUL01KET7bKgxMq-dQ2SxGBvgN3KtHIRBud7Bw8Ax98YkiBKJJXC8xF00VZkkX-ZcUyXptPkUpBm0zeN6jmWmyFX-2QrbclLS8ZEK2Poc_y5PdNAtCCOTBfnq6roxzVQ5lM_aMQaSuPVd-Og6E_jBE6OE9oB4ikFa4S7EvZvFVDpGMLtUjxOazTURbqWY6OnuhuAiP6WZc1FxfQod462IqPERzl2qVJH9qQNr-iLuVLt_bzauHg33v1koTrdfETyoRAZH5w',
          expires_at: 1473083613,
          id_token: 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6IkwzcXJHOGRTTll2NkYtSHZ2LXFUZHBfRWttZ3dqUVg3NkRIbURaQ29hNFEiLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJJVXRTWnZOVzBubUNmT2Nwek5JSnBBS29FbGpOVkZyUlJGa2pDT3plYnlRIiwieSI6IjNEOXZ1V2VJNEdVajZWczZ4ZUJlMVZRM3dHQnhkU3BnTGdYcGZPUThmeEkifSwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6IkpXVCJ9.DVIPxvxnQASDiair_I_6e4M1Y8yMdzIneHMPq_LlBjo8QAiwjMQ1Uw.gdLKThNa_DcFmPGBmzOBkg.TQZ4qpEchLx9nnNIfG_N8d3sL-S-p1vpWbA3MnK68U60kX7i29s33fxhH3w5MQhZbgxjntrbRdE9wFsBzclr8hfwazBTpi6D5Ignug0xCZQYw7HBDrkq63-7PQQa2-rivTtxQxAWUZj7dnNE4Ixo9qaBkHod1EPf5xameCDzgrRa2oi2ISEE6ncQrvc7jnANeBQj0Q2OLmo9L7EIVQbEKejGfZ_0p5HiXmgFMpLbkLFwYhTdpiSUCkZlcym-e2tgbzHJmtF85cx2-yDwDNGLvY8y5ytW79_k_ckbHKVTjf_jRMagqM7Mt6TQ1fhm9T7FZ4q-96L0ItGb12jar2Aw6VWP1DAwUMZ1jA8mmllsWu-y7qc9Ert5rlJ7osZzMOgaNfX1sf5Xa7aOHysC-tVxknIPtxAamVJ7REGxmii-FO6En4zgJMt1PLUoTTK4tIpIX06VWDKI-dQzn46ple9xeuzCUvpvap823Xl9ONcVj4AF-YmHU-UkT96gx_6Owqcwm6synOh1l2O9rRi9jJnCg6egTqn1MHaVhTYaVhKQQUpE-voAoXoaJDoLQX2fC6IjF5H2xnc_1k61wGBJkX_7zqagNYGJyoluiQr5EGkB8pxANJVHNIW37ezJEIjnix5h_Fwzh_XElGzVsKeB-ih9X6ECSVJ1VIPopN5t38kGa8lQuM7vLr0i__cvYP8TgyE94nllEl-5f0gHOUQrpcUEqpsZYRBGcW_m8iU3nuvD0Em6nCvvzPUvlmCRyANQbs3A.H9oTPRc3ahVDUuYj3C9-gQ',
          refresh_token: 'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA',
          token_type: 'Bearer',
        });

      const client = new issuer.Client({
        client_id: '4e87dde4-ddd3-4c21-aef9-2f2f6bab43ca',
        client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
        id_token_encrypted_response_alg: 'ECDH-ES+A128KW',
        id_token_encrypted_response_enc: 'A128CBC-HS256',
        id_token_signed_response_alg: 'HS256',
      }, this.keystore);

      return client.refresh('http://oidc-client.dev/cb', new TokenSet({
        refresh_token: 'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA',
      }), { nonce: null });
    });

    it('handles encrypted but not signed responses too', function () {
      const time = new Date(1473076413242);
      timekeeper.freeze(time);
      const issuer = new Issuer({
        issuer: 'https://guarded-cliffs-8635.herokuapp.com/op',
        userinfo_endpoint: 'https://op.example.com/me',
      });

      nock('https://op.example.com')
        .get('/me')
        .reply(200, 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6IkwzcXJHOGRTTll2NkYtSHZ2LXFUZHBfRWttZ3dqUVg3NkRIbURaQ29hNFEiLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI4SUpmUTJQU3JBTFlqd0oyd3ZXWGZoTDJGRmgyekRxVUU1dHpZRVYybTVJIiwieSI6IjhfRkFIdzVzZmJ2c1drQ0ZRLW1mN2I3VVFYempWS0UyNWE3LXVKbEZoZUkifSwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6IkpXVCJ9.KnATIoEGwPKAJHyKAKGVjmeuu4PmsKjXydV047kqzUzXFHPes60zSg.D50tt0pN1HygTtOs5Hu26Q.RWmwnKdALaafgNy3X9Zvvnb27XvJiDqFKQ9kqIOFBV-MtG0Q5dQaB5v6ldaExWTyugGAtP_s1LS8zlX-E9V5eHeXmJkYn9qIQbjJ9eHdHLk.uypPS5AVSBN9XNGqeVrzuQ', {
          'content-type': 'application/jwt; charset=utf-8',
        });

      const client = new issuer.Client({
        client_id: 'f21d5d1d-1c3f-4905-8ff1-5f553a2090b1',
        userinfo_encrypted_response_alg: 'ECDH-ES+A128KW',
        userinfo_encrypted_response_enc: 'A128CBC-HS256',
      }, this.keystore);

      return client.userinfo('accesstoken').then(userinfo => {
        expect(userinfo).to.eql({
          email: 'johndoe@example.com',
          sub: '0aa66887-8c86-4f3b-b521-5a00e01799ca',
        });
      });
    });
  });
});

'use strict';

const Issuer = require('../../lib').Issuer;
const _ = require('lodash');
const expect = require('chai').expect;
const BaseClient = require('../../lib/base_client');
const url = require('url');
const querystring = require('querystring');
const nock = require('nock');
const OpenIdConnectError = require('../../lib/open_id_connect_error');
const sinon = require('sinon');
const TokenSet = require('../../lib/token_set');
const got = require('got');
const fail = () => {
  throw new Error('expected promise to be rejected');
};

describe('Client', function () {
  afterEach(function () {
    nock.cleanAll();
  });

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
        token_endpoint: 'https://op.example.com/auth',
      });
      this.client = new issuer.Client({
        client_id: 'identifier',
        client_secret: 'secure',
      });

      sinon.stub(this.client, 'validateIdToken', function (value) {
        return value;
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
        .post('/auth')
        .reply(200, {});

      return this.client.authorizationCallback('https://rp.example.com/cb', {
        code: 'codeValue',
      });
    });

    it('returns a TokenSet', function () {
      nock('https://op.example.com')
        .post('/auth')
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
    afterEach(function () {
      nock.cleanAll();
    });

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
        .filteringRequestBody(/^access_token=tokenValue$/)
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
            client[method]('token');
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
});

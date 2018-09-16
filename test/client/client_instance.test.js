const url = require('url');
const querystring = require('querystring');
const stdhttp = require('http');

const MockRequest = require('readable-mock-req');
const _ = require('lodash');
const { expect } = require('chai');
const base64url = require('base64url');
const nock = require('nock');
const sinon = require('sinon');
const jose = require('node-jose');
const timekeeper = require('timekeeper');

const TokenSet = require('../../lib/token_set');
const OpenIdConnectError = require('../../lib/open_id_connect_error');
const now = require('../../lib/util/unix_timestamp');
const { Registry, Issuer } = require('../../lib');

const noop = () => {};
const fail = () => { throw new Error('expected promise to be rejected'); };
const encode = object => base64url.encode(JSON.stringify(object));

['useGot', 'useRequest'].forEach((httpProvider) => {
  describe(`Client - using ${httpProvider.substring(3).toLowerCase()}`, function () {
    before(function () {
      Issuer[httpProvider]();
    });

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

        const issuerWithQuery = new Issuer({
          authorization_endpoint: 'https://op.example.com/auth?foo=bar',
        });
        this.clientWithQuery = new issuerWithQuery.Client({
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

      it('keeps original query parameters', function () {
        expect(url.parse(this.clientWithQuery.authorizationUrl({
          redirect_uri: 'https://rp.example.com/cb',
        }), true).query).to.eql({
          client_id: 'identifier',
          redirect_uri: 'https://rp.example.com/cb',
          response_type: 'code',
          scope: 'openid',
          foo: 'bar',
        });
      });

      it('allows to overwrite the defaults', function () {
        expect(url.parse(this.client.authorizationUrl({
          scope: 'openid offline_access',
          redirect_uri: 'https://rp.example.com/cb',
          response_type: 'id_token',
          nonce: 'foobar',
        }), true).query).to.eql({
          client_id: 'identifier',
          scope: 'openid offline_access',
          redirect_uri: 'https://rp.example.com/cb',
          response_type: 'id_token',
          nonce: 'foobar',
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

      it('removes null and undefined values', function () {
        expect(url.parse(this.client.authorizationUrl({
          state: null,
          prompt: undefined,
        }), true).query).not.to.have.keys('state', 'prompt');
      });

      it('stringifies other values', function () {
        expect(url.parse(this.client.authorizationUrl({
          max_age: 300,
          foo: true,
        }), true).query).to.contain({
          max_age: '300',
          foo: 'true',
        });
      });
    });

    describe('#endSessionUrl', function () {
      before(function () {
        const issuer = new Issuer({
          end_session_endpoint: 'https://op.example.com/session/end',
        });
        this.client = new issuer.Client({
          client_id: 'identifier',
        });
        this.clientWithUris = new issuer.Client({
          post_logout_redirect_uris: ['https://rp.example.com/logout/cb'],
        });

        const issuerWithQuery = new Issuer({
          end_session_endpoint: 'https://op.example.com/session/end?foo=bar',
        });
        this.clientWithQuery = new issuerWithQuery.Client({
          client_id: 'identifier',
        });

        const issuerWithoutMeta = new Issuer({
          // end_session_endpoint: 'https://op.example.com/session/end?foo=bar',
        });
        this.clientWithoutMeta = new issuerWithoutMeta.Client({
          client_id: 'identifier',
        });
      });

      it("throws if the issuer doesn't have end_session_endpoint configured", function () {
        expect(() => {
          this.clientWithoutMeta.endSessionUrl();
        }).to.throw('end_session_endpoint must be configured on the issuer');
      });

      it('returns the end_session_endpoint only if nothing is passed', function () {
        expect(this.client.endSessionUrl()).to.eql('https://op.example.com/session/end');
        expect(this.clientWithQuery.endSessionUrl()).to.eql('https://op.example.com/session/end?foo=bar');
      });

      it('defaults the post_logout_redirect_uri if client has some', function () {
        expect(url.parse(this.clientWithUris.endSessionUrl(), true).query).to.eql({
          post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
        });
      });

      it('takes a TokenSet too', function () {
        const hint = new TokenSet({
          id_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
          refresh_token: 'bar',
          access_token: 'tokenValue',
        });
        expect(url.parse(this.client.endSessionUrl({
          id_token_hint: hint,
        }), true).query).to.eql({
          id_token_hint: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
        });
      });

      it('allows for recommended and optional query params to be passed in', function () {
        expect(url.parse(this.client.endSessionUrl({
          post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
          state: 'foo',
          id_token_hint: 'idtoken',
        }), true).query).to.eql({
          post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
          state: 'foo',
          id_token_hint: 'idtoken',
        });
        expect(url.parse(this.clientWithQuery.endSessionUrl({
          post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
          state: 'foo',
          id_token_hint: 'idtoken',
          foo: 'this will be ignored',
        }), true).query).to.eql({
          post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
          state: 'foo',
          foo: 'bar',
          id_token_hint: 'idtoken',
        });
      });
    });

    describe('#authorizationPost', function () {
      const REGEXP = /name="(.+)" value="(.+)"/g;

      function paramsFromHTML(html) {
        const params = {};

        const matches = html.match(REGEXP);
        matches.forEach((line) => {
          line.match(REGEXP);
          params[RegExp.$1] = RegExp.$2;
        });

        return params;
      }

      before(function () {
        const issuer = new Issuer({
          authorization_endpoint: 'https://op.example.com/auth',
        });
        this.client = new issuer.Client({
          client_id: 'identifier',
        });
      });

      it('returns a string with the url with some basic defaults', function () {
        expect(paramsFromHTML(this.client.authorizationPost({
          redirect_uri: 'https://rp.example.com/cb',
        }))).to.eql({
          client_id: 'identifier',
          redirect_uri: 'https://rp.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        });
      });

      it('allows to overwrite the defaults', function () {
        expect(paramsFromHTML(this.client.authorizationPost({
          scope: 'openid offline_access',
          redirect_uri: 'https://rp.example.com/cb',
          response_type: 'id_token',
          nonce: 'foobar',
        }))).to.eql({
          client_id: 'identifier',
          scope: 'openid offline_access',
          redirect_uri: 'https://rp.example.com/cb',
          response_type: 'id_token',
          nonce: 'foobar',
        });
      });

      it('allows any other params to be provide too', function () {
        expect(paramsFromHTML(this.client.authorizationPost({
          state: 'state',
          custom: 'property',
        }))).to.contain({
          state: 'state',
          custom: 'property',
        });
      });

      it('auto-stringifies claims parameter', function () {
        expect(paramsFromHTML(this.client.authorizationPost({
          claims: { id_token: { email: null } },
        }))).to.contain({
          claims: '{"id_token":{"email":null}}',
        });
      });
    });

    describe('#authorizationCallback', function () {
      before(function () {
        this.issuer = new Issuer({
          token_endpoint: 'https://op.example.com/token',
        });
        this.client = new this.issuer.Client({
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

      it('pushes default_max_age to #validateIdToken', function () {
        const client = new this.issuer.Client({
          client_id: 'with-default_max_age',
          client_secret: 'secure',
          default_max_age: 300,
        });

        nock('https://op.example.com')
          .post('/token')
          .reply(200, {
            id_token: 'foobar',
          });

        sinon.spy(client, 'validateIdToken');

        return client.authorizationCallback('https://rp.example.com/cb', {
          code: 'codeValue',
        })
          .then(fail, () => {
            expect(client.validateIdToken.calledOnce).to.be.true;
            expect(client.validateIdToken.firstCall.args[3]).to.equal(300);
          });
      });

      it('resolves a tokenset with just a state for response_type=none', function () {
        const state = { state: 'foo' };
        return this.client.authorizationCallback('https://rp.example.com/cb', state, state)
          .then((set) => {
            expect(set).to.be.instanceof(TokenSet);
            expect(set).to.have.property('state', 'foo');
          });
      });

      it('rejects with OpenIdConnectError when part of the response', function () {
        return this.client.authorizationCallback('https://rp.example.com/cb', {
          error: 'invalid_request',
        }).then(fail, (error) => {
          expect(error).to.be.instanceof(OpenIdConnectError);
          expect(error).to.have.property('error', 'invalid_request');
        });
      });

      describe('state checks', function () {
        it('rejects with an Error when states mismatch (returned)', function () {
          return this.client.authorizationCallback('https://rp.example.com/cb', {
            state: 'should be checked for this',
          }).then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'checks.state argument is missing');
          });
        });

        it('rejects with an Error when states mismatch (not returned)', function () {
          return this.client.authorizationCallback('https://rp.example.com/cb', {}, {
            state: 'should be this',
          })
            .then(fail, (error) => {
              expect(error).to.be.instanceof(Error);
              expect(error).to.have.property('message', 'state missing from the response');
            });
        });

        it('rejects with an Error when states mismatch (general mismatch)', function () {
          return this.client.authorizationCallback('https://rp.example.com/cb', {
            state: 'is this',
          }, {
            state: 'should be this',
          })
            .then(fail, (error) => {
              expect(error).to.be.instanceof(Error);
              expect(error).to.have.property('message', 'state mismatch');
            });
        });
      });

      describe('response type checks', function () {
        it('rejects with an Error when code is missing', function () {
          return this.client.authorizationCallback('https://rp.example.com/cb', {
            // code: 'foo',
            access_token: 'foo',
            token_type: 'Bearer',
            id_token: 'foo',
          }, {
            response_type: 'code id_token token',
          }).then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'code missing from response');
          });
        });

        it('rejects with an Error when id_token is missing', function () {
          return this.client.authorizationCallback('https://rp.example.com/cb', {
            code: 'foo',
            access_token: 'foo',
            token_type: 'Bearer',
            // id_token: 'foo',
          }, {
            response_type: 'code id_token token',
          }).then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'id_token missing from response');
          });
        });

        it('rejects with an Error when token_type is missing', function () {
          return this.client.authorizationCallback('https://rp.example.com/cb', {
            code: 'foo',
            access_token: 'foo',
            // token_type: 'Bearer',
            id_token: 'foo',
          }, {
            response_type: 'code id_token token',
          }).then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'token_type missing from response');
          });
        });

        it('rejects with an Error when access_token is missing', function () {
          return this.client.authorizationCallback('https://rp.example.com/cb', {
            code: 'foo',
            // access_token: 'foo',
            token_type: 'Bearer',
            id_token: 'foo',
          }, {
            response_type: 'code id_token token',
          }).then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'access_token missing from response');
          });
        });

        ['code', 'access_token', 'id_token'].forEach((param) => {
          it(`rejects with an Error when ${param} is encoutered during "none" response`, function () {
            return this.client.authorizationCallback('https://rp.example.com/cb', {
              [param]: 'foo',
            }, {
              response_type: 'none',
            }).then(fail, (error) => {
              expect(error).to.be.instanceof(Error);
              expect(error).to.have.property('message', 'unexpected params encountered for "none" response');
            });
          });
        });
      });
    });

    describe('#oauthCallback', function () {
      before(function () {
        this.issuer = new Issuer({
          token_endpoint: 'https://op.example.com/token',
        });
        this.client = new this.issuer.Client({
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
          .reply(200, {
            access_token: 'tokenValue',
          });

        return this.client.oauthCallback('https://rp.example.com/cb', {
          code: 'codeValue',
        }).then((set) => {
          expect(nock.isDone()).to.be.true;
          expect(set).to.be.instanceof(TokenSet);
          expect(set).to.have.property('access_token', 'tokenValue');
        });
      });

      it('handles implicit responses too', function () {
        return this.client.oauthCallback(undefined, {
          access_token: 'tokenValue',
        }).then((set) => {
          expect(set).to.be.instanceof(TokenSet);
          expect(set).to.have.property('access_token', 'tokenValue');
        });
      });

      describe('response type checks', function () {
        it('rejects with an Error when code is missing', function () {
          return this.client.oauthCallback('https://rp.example.com/cb', {
            // code: 'foo',
            access_token: 'foo',
            token_type: 'Bearer',
          }, {
            response_type: 'code token',
          }).then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'code missing from response');
          });
        });

        it('rejects with an Error when token_type is missing', function () {
          return this.client.oauthCallback('https://rp.example.com/cb', {
            code: 'foo',
            access_token: 'foo',
            // token_type: 'Bearer',
          }, {
            response_type: 'code token',
          }).then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'token_type missing from response');
          });
        });

        it('rejects with an Error when access_token is missing', function () {
          return this.client.oauthCallback('https://rp.example.com/cb', {
            code: 'foo',
            // access_token: 'foo',
            token_type: 'Bearer',
          }, {
            response_type: 'code token',
          }).then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'access_token missing from response');
          });
        });

        ['code', 'access_token'].forEach((param) => {
          it(`rejects with an Error when ${param} is encoutered during "none" response`, function () {
            return this.client.oauthCallback('https://rp.example.com/cb', {
              [param]: 'foo',
            }, {
              response_type: 'none',
            }).then(fail, (error) => {
              expect(error).to.be.instanceof(Error);
              expect(error).to.have.property('message', 'unexpected params encountered for "none" response');
            });
          });
        });
      });

      it('rejects with OpenIdConnectError when part of the response', function () {
        return this.client.oauthCallback('https://rp.example.com/cb', {
          error: 'invalid_request',
        }).then(fail, (error) => {
          expect(error).to.be.instanceof(OpenIdConnectError);
          expect(error).to.have.property('error', 'invalid_request');
        });
      });

      describe('state checks', function () {
        it('rejects with an Error when states mismatch (returned)', function () {
          return this.client.oauthCallback('https://rp.example.com/cb', {
            state: 'should be checked for this',
          }).then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'checks.state argument is missing');
          });
        });

        it('rejects with an Error when states mismatch (not returned)', function () {
          return this.client.oauthCallback('https://rp.example.com/cb', {}, {
            state: 'should be this',
          })
            .then(fail, (error) => {
              expect(error).to.be.instanceof(Error);
              expect(error).to.have.property('message', 'state missing from the response');
            });
        });

        it('rejects with an Error when states mismatch (general mismatch)', function () {
          return this.client.oauthCallback('https://rp.example.com/cb', {
            state: 'is this',
          }, {
            state: 'should be this',
          })
            .then(fail, (error) => {
              expect(error).to.be.instanceof(Error);
              expect(error).to.have.property('message', 'state mismatch');
            });
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
          .then((set) => {
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
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'refresh_token not present in TokenSet');
          });
      });
    });

    it('#joseSecret', function () {
      const issuer = new Issuer();
      const client = new issuer.Client({ client_secret: 'rj_JR' });

      return client.joseSecret()
        .then((key) => {
          expect(key).to.have.property('kty', 'oct');
          return client.joseSecret().then((cached) => {
            expect(key).to.equal(cached);
          });
        });
    });

    it('#derivedKey', function () {
      const issuer = new Issuer();
      const client = new issuer.Client({ client_secret: 'rj_JR' });

      return client.derivedKey('128')
        .then((key) => {
          expect(key).to.have.property('kty', 'oct');
          return client.derivedKey('128').then((cached) => {
            expect(key).to.equal(cached);
          });
        });
    });

    it('#inspect', function () {
      const issuer = new Issuer({ issuer: 'https://op.example.com' });
      const client = new issuer.Client({ client_id: 'identifier' });
      expect(client.inspect()).to.equal('Client <identifier>');
    });

    describe('#userinfo', function () {
      it('takes a string token', function () {
        const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
        const client = new issuer.Client();

        nock('https://op.example.com')
          .get('/me').reply(200, {});

        return client.userinfo('tokenValue').then(() => {
          expect(nock.isDone()).to.be.true;
        });
      });

      it('takes a tokenset', function () {
        const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
        const client = new issuer.Client({
          id_token_signed_response_alg: 'none',
        });

        nock('https://op.example.com')
          .get('/me').reply(200, {
            sub: 'subject',
          });

        return client.userinfo(new TokenSet({
          id_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
          refresh_token: 'bar',
          access_token: 'tokenValue',
        })).then(() => {
          expect(nock.isDone()).to.be.true;
        });
      });

      it('takes a tokenset and validates the subject in id_token is the same in userinfo', function () {
        const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
        const client = new issuer.Client({
          id_token_signed_response_alg: 'none',
        });

        nock('https://op.example.com')
          .get('/me').reply(200, {
            sub: 'different-subject',
          });

        return client.userinfo(new TokenSet({
          id_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
          refresh_token: 'bar',
          access_token: 'tokenValue',
        })).then(fail, (err) => {
          expect(nock.isDone()).to.be.true;
          expect(err.message).to.equal('userinfo sub mismatch');
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

      it('can add extra params in a body when post', function () {
        const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
        const client = new issuer.Client();

        nock('https://op.example.com')
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              access_token: 'tokenValue',
              foo: 'bar',
            });
          })
          .post('/me').reply(200, {});

        return client.userinfo('tokenValue', {
          verb: 'POST',
          via: 'body',
          params: { foo: 'bar' },
        }).then(() => {
          expect(nock.isDone()).to.be.true;
        });
      });

      it('can add extra params in a query when non-post', function () {
        const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
        const client = new issuer.Client();

        nock('https://op.example.com')
          .get('/me?foo=bar')
          .reply(200, {});

        return client.userinfo('tokenValue', {
          params: { foo: 'bar' },
        }).then(() => {
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
            expect(error).to.have.property('error', 'invalid_token');
            expect(error).to.have.property('error_description', 'bad things are happening');
          });
      });

      it('is rejected with OpenIdConnectError upon oidc error in www-authenticate header', function () {
        const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
        const client = new issuer.Client();

        nock('https://op.example.com')
          .get('/me')
          .reply(401, 'Unauthorized', {
            'WWW-Authenticate': 'Bearer error="invalid_token", error_description="bad things are happening"',
          });

        return client.userinfo()
          .then(fail, function (error) {
            expect(error.name).to.equal('OpenIdConnectError');
            expect(error).to.have.property('error', 'invalid_token');
            expect(error).to.have.property('error_description', 'bad things are happening');
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
            expect(error).to.be.an.instanceof(issuer.httpClient.HTTPError);
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

          return client.userinfo('accessToken')
            .then((userinfo) => {
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
            expect(err.message).to.eql('unexpected algorithm received');
          });
        });
      });
    });

    _.forEach({
      introspect: 'introspection_endpoint',
      revoke: 'revocation_endpoint',
    }, function (endpoint, method) {
      describe(`#${method}`, function () {
        it('posts the token in a body and returns the parsed response', function () {
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
            [endpoint]: `https://rp.example.com/token/${method}`,
          });
          const client = new issuer.Client();

          return client[method]('tokenValue')
            .then(response => expect(response).to.eql({ endpoint: 'response' }));
        });

        it('posts the token and a hint in a body', function () {
          nock('https://rp.example.com')
            .filteringRequestBody(function (body) {
              expect(querystring.parse(body)).to.eql({
                token: 'tokenValue',
                token_type_hint: 'access_token',
              });
            })
            .post(`/token/${method}`)
            .reply(200, {
              endpoint: 'response',
            });

          const issuer = new Issuer({
            [endpoint]: `https://rp.example.com/token/${method}`,
          });
          const client = new issuer.Client();

          return client[method]('tokenValue', 'access_token');
        });

        it('validates the hint is a string', function () {
          const issuer = new Issuer({
            [endpoint]: `https://rp.example.com/token/${method}`,
          });
          const client = new issuer.Client();
          expect(function () {
            client[method]('tokenValue', { nonstring: 'value' });
          }).to.throw('hint must be a string');
        });

        it('is rejected with OpenIdConnectError upon oidc error', function () {
          nock('https://rp.example.com')
            .post(`/token/${method}`)
            .reply(500, {
              error: 'server_error',
              error_description: 'bad things are happening',
            });

          const issuer = new Issuer({
            [endpoint]: `https://rp.example.com/token/${method}`,
          });
          const client = new issuer.Client();

          return client[method]('tokenValue')
            .then(fail, function (error) {
              expect(error).to.have.property('error', 'server_error');
              expect(error).to.have.property('error_description', 'bad things are happening');
            });
        });

        it('is rejected with when non 200 is returned', function () {
          nock('https://rp.example.com')
            .post(`/token/${method}`)
            .reply(500, 'Internal Server Error');

          const issuer = new Issuer({
            [endpoint]: `https://rp.example.com/token/${method}`,
          });
          const client = new issuer.Client();

          return client[method]('tokenValue')
            .then(fail, function (error) {
              expect(error).to.be.an.instanceof(issuer.httpClient.HTTPError);
            });
        });

        it('is rejected with JSON.parse error upon invalid response', function () {
          nock('https://rp.example.com')
            .post(`/token/${method}`)
            .reply(200, '{"notavalid"}');

          const issuer = new Issuer({
            [endpoint]: `https://rp.example.com/token/${method}`,
          });
          const client = new issuer.Client();

          return client[method]('tokenValue')
            .then(fail, function (error) {
              expect(error).to.be.an.instanceof(SyntaxError);
              expect(error).to.have.property('message').matches(/Unexpected token/);
            });
        });

        if (method === 'revoke') {
          it('handles empty bodies', function () {
            nock('https://rp.example.com')
              .post(`/token/${method}`)
              .reply(200);

            const issuer = new Issuer({
              [endpoint]: `https://rp.example.com/token/${method}`,
            });
            const client = new issuer.Client();

            return client[method]('tokenValue').then((response) => {
              expect(response).to.eql({});
            });
          });
        }
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

        expect(client.authenticatedPost.args[0][0]).to.equal('token');
        expect(client.authenticatedPost.args[0][1]).to.eql({ body: { token: 'tokenValue' } });
      });
    });

    describe('#authFor', function () {
      context('when none', function () {
        it('returns the body httpOptions', function () {
          const issuer = new Issuer();
          const client = new issuer.Client({
            client_id: 'identifier',
            client_secret: 'secure',
            token_endpoint_auth_method: 'none',
          });
          expect(client.authFor('token')).to.eql({
            body: { client_id: 'identifier' },
          });
        });
      });

      context('when client_secret_post', function () {
        it('returns the body httpOptions', function () {
          const issuer = new Issuer();
          const client = new issuer.Client({
            client_id: 'identifier',
            client_secret: 'secure',
            token_endpoint_auth_method: 'client_secret_post',
          });
          expect(client.authFor('token')).to.eql({
            body: { client_id: 'identifier', client_secret: 'secure' },
          });
        });
      });

      context('when client_secret_basic', function () {
        it('is the default', function () {
          const issuer = new Issuer();
          const client = new issuer.Client({ client_id: 'identifier', client_secret: 'secure' });
          expect(client.authFor('token')).to.eql({
            headers: { Authorization: 'Basic aWRlbnRpZmllcjpzZWN1cmU=' },
          });
        });

        it('works with non-text characters', function () {
          const issuer = new Issuer();
          const client = new issuer.Client({ client_id: 'an:identifier', client_secret: 'some secure & non-standard secret' });
          expect(client.authFor('token')).to.eql({
            headers: { Authorization: 'Basic YW4lM0FpZGVudGlmaWVyOnNvbWUrc2VjdXJlKyUyNitub24tc3RhbmRhcmQrc2VjcmV0' },
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
            token_endpoint_auth_method: 'client_secret_jwt',
          });

          return client.authFor('token').then((auth) => { this.auth = auth; });
        });

        it('promises a body', function () {
          expect(this.auth).to.have.property('body').and.is.an('object');
          expect(this.auth.body).to.have.property(
            'client_assertion_type',
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          );
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
              token_endpoint_auth_method: 'private_key_jwt',
            }, keystore);

            return client.authFor('token').then((auth) => { this.auth = auth; });
          });
        });

        it('promises a body', function () {
          expect(this.auth).to.have.property('body').and.is.an('object');
          expect(this.auth.body).to.have.property(
            'client_assertion_type',
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          );
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
    afterEach(function () {
      if (this.client) this.client.CLOCK_TOLERANCE = 0;
    });

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
        .then(token => this.client.validateIdToken(token).then((validated) => {
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

    it('validates the id token signature (when string)', function () {
      return new this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then(token => this.client.validateIdToken(token.slice(0, -1)).then(fail, (err) => {
          expect(err.message).to.equal('invalid signature');
        }));
    });

    it('validates the id token signature (when TokenSet)', function () {
      return new this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
          const tokenset = new TokenSet({ id_token: token.slice(0, -1) });
          return this.client.validateIdToken(tokenset).then(fail, (err) => {
            expect(err.message).to.equal('invalid signature');
          });
        });
    });

    it('validates the id token and fulfills with input value (when signed by secret)', function () {
      const client = new this.issuer.Client({
        client_id: 'hs256-client',
        client_secret: 'its gotta be a long secret and i mean at least 32 characters',
        id_token_signed_response_alg: 'HS256',
      });

      return client.joseSecret().then((key) => {
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

      return client.joseSecret().then((key) => {
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
      return this.client.joseSecret().then((key) => {
        return new this.IdToken(key, 'HS256', {
          iss: this.issuer.issuer,
          sub: 'userId',
          aud: this.client.client_id,
          exp: now() + 3600,
          iat: now(),
        })
          .then(token => this.client.validateIdToken(token))
          .then(fail, (error) => {
            expect(error).to.have.property('message', 'unexpected algorithm received');
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
        .then(token => this.client.validateIdToken(token))
        .then(fail, (error) => {
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
        .then(token => this.client.validateIdToken(token))
        .then(fail, (error) => {
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
        .then(token => this.client.validateIdToken(token));
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
        .then(token => this.client.validateIdToken(token, 'nonce!!!'));
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
        .then(token => this.client.validateIdToken(token, 'nonce!!!'))
        .then(fail, (error) => {
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
        .then(token => this.client.validateIdToken(token))
        .then(fail, (error) => {
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
          .then(token => this.client.validateIdToken(token))
          .then(fail, (error) => {
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
        .then(token => this.client.validateIdToken(token))
        .then(fail, (error) => {
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
        .then(token => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'id_token issued in the future');
        });
    });

    it('allows iat skew', function () {
      this.client.CLOCK_TOLERANCE = 5;
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now() + 5,
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => this.client.validateIdToken(token));
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
        .then(token => this.client.validateIdToken(token))
        .then(fail, (error) => {
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
        .then(token => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'id_token expired');
        });
    });

    it('allows exp skew', function () {
      this.client.CLOCK_TOLERANCE = 5;
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() - 4,
        iat: now(),
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => this.client.validateIdToken(token));
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
        .then(token => this.client.validateIdToken(token))
        .then(fail, (error) => {
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
        .then(token => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'id_token not active yet');
        });
    });

    it('allows nbf skew', function () {
      this.client.CLOCK_TOLERANCE = 5;
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
        nbf: now() + 5,
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => this.client.validateIdToken(token));
    });

    it('passes when auth_time is within max_age', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
        auth_time: now() - 200,
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => this.client.validateIdToken(token, null, null, 300));
    });

    it('verifies auth_time did not exceed max_age', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
        auth_time: now() - 600,
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => this.client.validateIdToken(token, null, null, 300))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'too much time has elapsed since the last End-User authentication');
        });
    });

    it('allows auth_time skew', function () {
      this.client.CLOCK_TOLERANCE = 5;
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
        auth_time: now() - 303,
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => this.client.validateIdToken(token, null, null, 300));
    });

    it('verifies auth_time is a number', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
        auth_time: 'foobar',
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => this.client.validateIdToken(token, null, null, 300))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'auth_time is not a number');
        });
    });

    it('ignores auth_time presence check when require_auth_time is true but null is passed', function () {
      const client = new this.issuer.Client({
        client_id: 'with-require_auth_time',
        require_auth_time: true,
      });

      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: client.client_id,
        exp: now() + 3600,
        iat: now(),
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => client.validateIdToken(token, null, null, null));
    });

    it('verifies auth_time is present when require_auth_time is true', function () {
      const client = new this.issuer.Client({
        client_id: 'with-require_auth_time',
        require_auth_time: true,
      });

      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: client.client_id,
        exp: now() + 3600,
        iat: now(),
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'missing required JWT property auth_time');
        });
    });

    it('verifies auth_time is present when maxAge is passed', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      };

      return new this.IdToken(this.keystore.get(), 'RS256', payload)
        .then(token => this.client.validateIdToken(token, null, null, 300))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'missing required JWT property auth_time');
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

    it('validates at_hash presence for implicit flow', function () {
      const access_token = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'; // eslint-disable-line camelcase, max-len

      return new this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
        // const tokenset = new TokenSet();
          return this.client.authorizationCallback(null, { access_token, id_token: token });
        })
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'missing required property at_hash');
        });
    });

    it('validates c_hash presence for hybrid flow', function () {
      const code = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'; // eslint-disable-line camelcase, max-len

      return new this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
        // const tokenset = new TokenSet();
          return this.client.authorizationCallback(null, { code, id_token: token });
        })
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'missing required property c_hash');
        });
    });

    it('validates state presence when s_hash is returned', function () {
      const s_hash = '77QmUPtjPfzWtF2AnpK9RQ'; // eslint-disable-line camelcase

      return new this.IdToken(this.keystore.get(), 'RS256', {
        s_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
          return this.client.authorizationCallback(null, { id_token: token });
        })
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'cannot verify s_hash, state not provided');
        });
    });

    it('validates s_hash', function () {
      const state = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'; // eslint-disable-line camelcase, max-len
      const s_hash = 'foobar'; // eslint-disable-line camelcase

      return new this.IdToken(this.keystore.get(), 'RS256', {
        s_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
          return this.client.authorizationCallback(null, { id_token: token, state }, { state });
        })
        .then(fail, (error) => {
          expect(error).to.have.property('message', 's_hash mismatch');
        });
    });

    it('passes with the right s_hash', function () {
      const state = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'; // eslint-disable-line camelcase, max-len
      const s_hash = '77QmUPtjPfzWtF2AnpK9RQ'; // eslint-disable-line camelcase

      return new this.IdToken(this.keystore.get(), 'RS256', {
        s_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
          return this.client.authorizationCallback(null, { id_token: token, state }, { state });
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
        .then(fail, (error) => {
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
        .then(fail, (error) => {
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

  describe('Distributed and Aggregated Claims', function () {
    function getJWT(payload, issuer) {
      const iss = issuer.startsWith('http') ? issuer : `https://${issuer}-iss.example.com`;
      let keystore;
      payload.iss = iss;

      if (Registry.has(iss)) {
        keystore = Registry.get(iss).keystore();
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

    describe('Client#fetchDistributedClaims', function () {
      afterEach(nock.cleanAll);
      before(function () {
        const issuer = new Issuer({
          issuer: 'https://op.example.com',
          jwks_uri: 'https://op.example.com/jwks',
          authorization_endpoint: 'https://op.example.com/auth',
        });
        this.client = new issuer.Client({
          client_id: 'identifier',
        });
        const store = jose.JWK.createKeyStore();

        return store.generate('RSA', 512).then(() => {
          nock(issuer.issuer)
            .get('/jwks')
            .reply(200, store.toJSON(true));

          return issuer.keystore();
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
          .then((result) => {
            expect(result).to.equal(userinfo);
          });
      });

      it('fetches the claims from one or more distributed sources', function () {
        return Promise.all([
          getJWT({ credit_history: 'foobar' }, 'src1'),
          getJWT({ email: 'foobar@example.com' }, 'src2'),
          getJWT({ gender: 'male' }, this.client.issuer.issuer),
        ]).then((jwts) => {
          nock('https://src1.example.com')
            .get('/claims').reply(200, jwts[0]);
          nock('https://src2.example.com')
            .get('/claims').reply(200, jwts[1]);
          nock('https://src3.example.com')
            .get('/claims').reply(200, [{ alg: 'none' }, { age: 27 }, ''].map((comp) => {
              if (typeof comp === 'object') {
                return base64url.encode(JSON.stringify(comp));
              }
              return comp;
            }).join('.'));
          nock(this.client.issuer.issuer)
            .get('/claims').reply(200, jwts[2]);

          const userinfo = {
            sub: 'userID',
            _claim_names: {
              credit_history: 'src1',
              email: 'src2',
              age: 'src3',
              gender: 'src4',
            },
            _claim_sources: {
              src1: { endpoint: 'https://src1.example.com/claims', access_token: 'foobar' },
              src2: { endpoint: 'https://src2.example.com/claims' },
              src3: { endpoint: 'https://src3.example.com/claims' },
              src4: { endpoint: `${this.client.issuer.issuer}/claims` },
            },
          };

          return this.client.fetchDistributedClaims(userinfo)
            .then((result) => {
              expect(result).to.eql({
                gender: 'male',
                age: 27,
                sub: 'userID',
                credit_history: 'foobar',
                email: 'foobar@example.com',
              });
              expect(result).to.equal(userinfo);
            });
        });
      });

      it('uses access token from provided param if not part of the claims', function () {
        return getJWT({ credit_history: 'foobar' }, 'src1').then((jwt) => {
          nock('https://src1.example.com')
            .matchHeader('authorization', 'Bearer foobar')
            .get('/claims').reply(200, jwt);

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
            .then((result) => {
              expect(result).to.eql({
                sub: 'userID',
                credit_history: 'foobar',
              });
              expect(result).to.equal(userinfo);
            });
        });
      });

      it('validates claims that should be present are', function () {
        return getJWT({
          // credit_history: 'foobar',
        }, 'src1').then((jwt) => {
          nock('https://src1.example.com')
            .get('/claims').reply(200, jwt);

          const userinfo = {
            sub: 'userID',
            _claim_names: {
              credit_history: 'src1',
            },
            _claim_sources: {
              src1: { endpoint: 'https://src1.example.com/claims' },
            },
          };

          return this.client.fetchDistributedClaims(userinfo)
            .then(fail, function (error) {
              expect(error).to.have.property('src', 'src1');
              expect(error.message).to.equal('expected claim "credit_history" in "src1"');
            });
        });
      });

      it('is rejected with OpenIdConnectError upon oidc error', function () {
        nock('https://src1.example.com')
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
            expect(error).to.have.property('error', 'invalid_token');
            expect(error).to.have.property('error_description', 'bad things are happening');
            expect(error).to.have.property('src', 'src1');
          });
      });

      it('is rejected with OpenIdConnectError upon oidc error in www-authenticate header', function () {
        nock('https://src1.example.com')
          .get('/claims')
          .reply(401, 'Unauthorized', {
            'WWW-Authenticate': 'Bearer error="invalid_token", error_description="bad things are happening"',
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
            expect(error).to.have.property('error', 'invalid_token');
            expect(error).to.have.property('error_description', 'bad things are happening');
            expect(error).to.have.property('src', 'src1');
          });
      });
    });

    describe('Client#unpackAggregatedClaims', function () {
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
          .then((result) => {
            expect(result).to.equal(userinfo);
          });
      });

      it('unpacks the claims from one or more aggregated sources', function () {
        return Promise.all([
          getJWT({ credit_history: 'foobar' }, 'src1'),
          getJWT({ email: 'foobar@example.com' }, 'src2'),
        ]).then((jwts) => {
          const userinfo = {
            sub: 'userID',
            _claim_names: {
              credit_history: 'src1',
              email: 'src2',
            },
            _claim_sources: {
              src1: { JWT: jwts[0] },
              src2: { JWT: jwts[1] },
            },
          };

          return this.client.unpackAggregatedClaims(userinfo)
            .then((result) => {
              expect(result).to.eql({
                sub: 'userID',
                credit_history: 'foobar',
                email: 'foobar@example.com',
              });
              expect(result).to.equal(userinfo);
            });
        });
      });

      it('autodiscovers new issuers', function () {
        return getJWT({ email_verified: false }, 'cliff').then((cliff) => {
          const userinfo = {
            sub: 'userID',
            _claim_names: {
              email_verified: 'cliff',
            },
            _claim_sources: {
              cliff: { JWT: cliff },
            },
          };

          const iss = 'https://cliff-iss.example.com';

          const discovery = nock(iss)
            .get('/.well-known/openid-configuration')
            .reply(200, {
              issuer: iss,
              jwks_uri: `${iss}/certs`,
            });

          Registry.delete(iss);

          return this.client.unpackAggregatedClaims(userinfo)
            .then((result) => {
              expect(result).to.eql({
                sub: 'userID',
                email_verified: false,
              });
              expect(result).to.equal(userinfo);
              expect(discovery.isDone()).to.be.true;
            });
        });
      });

      it('validates claims that should be present are', function () {
        return getJWT({}, 'src1').then((jwt) => {
          const userinfo = {
            sub: 'userID',
            _claim_names: {
              credit_history: 'src1',
            },
            _claim_sources: {
              src1: { JWT: jwt },
            },
          };

          return this.client.unpackAggregatedClaims(userinfo)
            .then(fail, function (error) {
              expect(error).to.have.property('src', 'src1');
              expect(error.message).to.equal('expected claim "credit_history" in "src1"');
            });
        });
      });

      it('rejects discovery errors', function () {
        return getJWT({ email_verified: false }, 'cliff').then((cliff) => {
          const userinfo = {
            sub: 'userID',
            _claim_names: {
              email_verified: 'cliff',
            },
            _claim_sources: {
              cliff: { JWT: cliff },
            },
          };

          const iss = 'https://cliff-iss.example.com';

          const discovery = nock(iss)
            .get('/.well-known/openid-configuration')
            .reply(500, 'Internal Server Error');

          Registry.delete(iss);

          return this.client.unpackAggregatedClaims(userinfo)
            .then(fail, (error) => {
              expect(discovery.isDone()).to.be.true;
              expect(error.name).to.equal('HTTPError');
              expect(error.src).to.equal('cliff');
            });
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
          .then(fail, (error) => {
            expect(error.src).to.equal('src1');
          });
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
        }).then((keystore) => { this.keystore = keystore; });
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
          session_state: 'foobar.foo',
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

        return client.userinfo('accesstoken').then((userinfo) => {
          expect(userinfo).to.eql({
            email: 'johndoe@example.com',
            sub: '0aa66887-8c86-4f3b-b521-5a00e01799ca',
          });
        });
      });

      it('handles symmetric encryption', function () {
        const time = new Date(1474477036849);
        timekeeper.freeze(time);
        const issuer = new Issuer({ issuer: 'http://localhost:3000/op' });

        const client = new issuer.Client({
          client_id: '0d9413a4-61c1-4b2b-8d84-a82464c1556c',
          client_secret: 'l73jho9z9mL0GAomiQwbw08ARqro2tJ4E4qhJ+PZhNQoU6G6D23UDF91L9VR7iJ4',
          id_token_encrypted_response_alg: 'A128KW',
          id_token_encrypted_response_enc: 'A128CBC-HS256',
          id_token_signed_response_alg: 'HS256',
        });

        return client.authorizationCallback('http://oidc-client.dev/cb', {
          id_token: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0.mAnRgJuG85tPgVMlFVcDnJF4aX63y0ZaqnRvv5EB32kp1kaJ17Oedg.fIf22AkMIaL-BylAMNSw7Q.aLMcch8U-Wx-6Y9xPti5b-H63AthqlCihBLCBZvRYd476HyCAzvuGMGzvHOuPFgFaAsxzOWkWNULOtQB2TiE2wLwCatrU2yUgaUisfXUKq1Lw0AFXyZmqcot-RNlf8hucoFHp7e9AoflKGibHEie80xHgw04jxTT7B0Y_OhpSng1cWBd3AU7UwCFKOngUugdBZ2dOmZ2zyq1oYY5FDmhm4hfB0a05s7jwImsXLsYK1LLw7wBjSzKBCJZwR055T0NbsadK1ze3rbwmx9fEruANSDSwUxsapbv1nvFPGvf03Da7FPOztVaLEraRkhXQIq1oAV2sXgKS2nD8nsEsAzJqt1iARmkj0udwmdhpHdnpRBtFJNEAAfEJf8B3ZbwvD7k0HaWEupLIdnY0nqiYKfjDUB9oFAjFOTnjrjqMt4fI73Axh5BcG6n-wCYxF3zGPGLhV_wR8usG_JKIZIeyaVik7isGBEPnFW98RX1Te5TUDLG-J84QrwauTpMkv99h_fkuJI-m1TfOTDAN2mZcTpQyuCZFDDjaYArhSMTUHgx2XSffPS8QmV8LqWMgwodyfxbGEvhbr_jpECXMV5J_ZXuKA.tCM9AdCCGHwLHXxzec7wtg',
        }, { nonce: '9cda9a61a2b01b31aa0b31d3c33631a1' });
      });
    });

    describe('#callbackParams', function () {
      before(function () {
        const issuer = new Issuer({ issuer: 'http://localhost:3000/op' });
        this.client = new issuer.Client({ client_id: 'client_id' });
      });

      before(function () {
        this.origIncomingMessage = stdhttp.IncomingMessage;
        stdhttp.IncomingMessage = MockRequest;
      });

      after(function () {
        stdhttp.IncomingMessage = this.origIncomingMessage;
      });

      it('returns query params from full uri', function () {
        expect(this.client.callbackParams('http://oidc-client.dev/cb?code=code')).to.eql({ code: 'code' });
      });

      it('returns query params from node request uri', function () {
        expect(this.client.callbackParams('/cb?code=code')).to.eql({ code: 'code' });
      });

      it('works with IncomingMessage (GET + query)', function () {
        const req = new MockRequest('GET', '/cb?code=code');
        expect(this.client.callbackParams(req)).to.eql({ code: 'code' });
      });

      it('works with IncomingMessage (POST + pre-parsed string)', function () {
        const req = new MockRequest('POST', '/cb', {
          body: 'code=code',
        });
        expect(this.client.callbackParams(req)).to.eql({ code: 'code' });
      });

      it('works with IncomingMessage (POST + pre-parsed object)', function () {
        const req = new MockRequest('POST', '/cb', {
          body: { code: 'code' },
        });
        expect(this.client.callbackParams(req)).to.eql({ code: 'code' });
      });

      it('works with IncomingMessage (POST + pre-parsed buffer)', function () {
        const req = new MockRequest('POST', '/cb', {
          body: Buffer.from('code=code'),
        });
        expect(this.client.callbackParams(req)).to.eql({ code: 'code' });
      });

      it('rejects nonbody parsed POSTs', function () {
        const req = new MockRequest('POST', '/cb');
        expect(() => {
          this.client.callbackParams(req);
        }).to.throw('incoming message body missing, include a body parser prior to this call');
      });

      it('rejects non-object,buffer,string parsed bodies', function () {
        const req = new MockRequest('POST', '/cb', { body: true });
        expect(() => {
          this.client.callbackParams(req);
        }).to.throw('invalid IncomingMessage body object');
      });

      it('rejects IncomingMessage other than GET, POST', function () {
        const req = new MockRequest('PUT', '/cb', {
          body: { code: 'code' },
        });
        expect(() => {
          this.client.callbackParams(req);
        }).to.throw('invalid IncomingMessage method');
      });

      it('fails for other than strings or IncomingMessage', function () {
        expect(() => {
          this.client.callbackParams({});
        }).to.throw('#callbackParams only accepts string urls, http.IncomingMessage or a lookalike');
        expect(() => {
          this.client.callbackParams(true);
        }).to.throw('#callbackParams only accepts string urls, http.IncomingMessage or a lookalike');
        expect(() => {
          this.client.callbackParams([]);
        }).to.throw('#callbackParams only accepts string urls, http.IncomingMessage or a lookalike');
      });
    });

    describe('#requestObject', function () {
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

      it('sign alg=none', function () {
        const client = new this.issuer.Client({ client_id: 'client_id', request_object_signing_alg: 'none' });

        return client.requestObject({ state: 'foobar' })
          .then((signed) => {
            const parts = signed.split('.');
            expect(JSON.parse(base64url.decode(parts[0]))).to.eql({ alg: 'none', typ: 'JWT' });
            expect(JSON.parse(base64url.decode(parts[1]))).to.eql({
              iss: 'client_id', client_id: 'client_id', aud: 'https://op.example.com', state: 'foobar',
            });
            expect(parts[2]).to.equal('');
          });
      });

      it('sign alg=HSxxx', function () {
        const client = new this.issuer.Client({ client_id: 'client_id', request_object_signing_alg: 'HS256', client_secret: 'atleast32byteslongforHS256mmkay?' });

        return client.requestObject({ state: 'foobar' })
          .then((signed) => {
            const parts = signed.split('.');
            expect(JSON.parse(base64url.decode(parts[0]))).to.eql({ alg: 'HS256', typ: 'JWT' });
            expect(JSON.parse(base64url.decode(parts[1]))).to.eql({
              iss: 'client_id', client_id: 'client_id', aud: 'https://op.example.com', state: 'foobar',
            });
            expect(parts[2].length).to.be.ok;
          });
      });

      it('sign alg=RSxxx', function () {
        const client = new this.issuer.Client({ client_id: 'client_id', request_object_signing_alg: 'RS256' }, this.keystore);

        return client.requestObject({ state: 'foobar' })
          .then((signed) => {
            const parts = signed.split('.');
            expect(JSON.parse(base64url.decode(parts[0]))).to.contain({ alg: 'RS256', typ: 'JWT' }).and.have.property('kid');
            expect(JSON.parse(base64url.decode(parts[1]))).to.eql({
              iss: 'client_id', client_id: 'client_id', aud: 'https://op.example.com', state: 'foobar',
            });
            expect(parts[2].length).to.be.ok;
          });
      });

      it('encrypts for issuer using issuer\'s public key', function () {
        const client = new this.issuer.Client({ client_id: 'client_id', request_object_encryption_alg: 'RSA1_5', request_object_encryption_enc: 'A128CBC-HS256' });

        return client.requestObject({ state: 'foobar' })
          .then((encrypted) => {
            const parts = encrypted.split('.');
            expect(JSON.parse(base64url.decode(parts[0]))).to.contain({ alg: 'RSA1_5', enc: 'A128CBC-HS256', cty: 'JWT' }).and.have.property('kid');
          });
      });

      it('encrypts for issuer using pre-shared client_secret (PBES2)', function () {
        const client = new this.issuer.Client({
          client_id: 'client_id',
          client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
          request_object_encryption_alg: 'PBES2-HS256+A128KW',
        });

        return client.requestObject({ state: 'foobar' })
          .then((encrypted) => {
            const parts = encrypted.split('.');
            expect(JSON.parse(base64url.decode(parts[0]))).to.contain({ alg: 'PBES2-HS256+A128KW', enc: 'A128CBC-HS256', cty: 'JWT' }).and.not.have.property('kid');
          });
      });

      it('encrypts for issuer using pre-shared client_secret (A\\d{3}KW)', function () {
        const client = new this.issuer.Client({
          client_id: 'client_id',
          client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
          request_object_encryption_alg: 'A128KW',
        });

        return client.requestObject({ state: 'foobar' })
          .then((encrypted) => {
            const parts = encrypted.split('.');
            expect(JSON.parse(base64url.decode(parts[0]))).to.contain({ alg: 'A128KW', enc: 'A128CBC-HS256', cty: 'JWT' }).and.not.have.property('kid');
          });
      });
    });
  });
});

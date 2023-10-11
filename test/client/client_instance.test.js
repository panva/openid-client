const url = require('url');
const { isNumber, isUndefined } = require('util');
const querystring = require('querystring');
const stdhttp = require('http');

const MockRequest = require('readable-mock-req');
const { expect } = require('chai');
const base64url = require('base64url');
const nock = require('nock');
const sinon = require('sinon');
const jose = require('jose');
const timekeeper = require('timekeeper');

const TokenSet = require('../../lib/token_set');
const { OPError, RPError } = require('../../lib/errors');
const now = require('../../lib/helpers/unix_timestamp');
const { Issuer, custom } = require('../../lib');
const clientInternal = require('../../lib/helpers/client');
const issuerInternal = require('../../lib/helpers/issuer');
const KeyStore = require('../keystore');

const fail = () => {
  throw new Error('expected promise to be rejected');
};
const encode = (object) => base64url.encode(JSON.stringify(object));

function getSearchParams(input) {
  const parsed = url.parse(input);
  if (!parsed.search) return {};
  return querystring.parse(parsed.search.substring(1));
}

describe('Client', () => {
  afterEach(timekeeper.reset);
  afterEach(nock.cleanAll);

  describe('#authorizationUrl', function () {
    before(function () {
      const issuer = new Issuer({
        issuer: 'https://op.example.com',
        authorization_endpoint: 'https://op.example.com/auth',
      });
      this.client = new issuer.Client({
        client_id: 'identifier',
      });
      this.clientWithMeta = new issuer.Client({
        client_id: 'identifier',
        response_types: ['code id_token'],
        redirect_uris: ['https://rp.example.com/cb'],
      });
      this.clientWithMultipleMetas = new issuer.Client({
        client_id: 'identifier',
        response_types: ['code id_token', 'id_token'],
        redirect_uris: ['https://rp.example.com/cb', 'https://rp.example.com/cb2'],
      });

      const issuerWithQuery = new Issuer({
        authorization_endpoint: 'https://op.example.com/auth?foo=bar',
      });
      this.clientWithQuery = new issuerWithQuery.Client({
        client_id: 'identifier',
      });
    });

    it('returns a string with the url with some basic defaults', function () {
      expect(
        getSearchParams(
          this.client.authorizationUrl({
            redirect_uri: 'https://rp.example.com/cb',
          }),
        ),
      ).to.eql({
        client_id: 'identifier',
        redirect_uri: 'https://rp.example.com/cb',
        response_type: 'code',
        scope: 'openid',
      });
    });

    it('returns a string with the url and client meta specific defaults', function () {
      expect(
        getSearchParams(
          this.clientWithMeta.authorizationUrl({
            nonce: 'foo',
          }),
        ),
      ).to.eql({
        nonce: 'foo',
        client_id: 'identifier',
        redirect_uri: 'https://rp.example.com/cb',
        response_type: 'code id_token',
        scope: 'openid',
      });
    });

    it('returns a string with the url and no defaults if client has more metas', function () {
      expect(getSearchParams(this.clientWithMultipleMetas.authorizationUrl())).to.eql({
        client_id: 'identifier',
        scope: 'openid',
      });
    });

    it('keeps original query parameters', function () {
      expect(
        getSearchParams(
          this.clientWithQuery.authorizationUrl({
            redirect_uri: 'https://rp.example.com/cb',
          }),
        ),
      ).to.eql({
        client_id: 'identifier',
        redirect_uri: 'https://rp.example.com/cb',
        response_type: 'code',
        scope: 'openid',
        foo: 'bar',
      });
    });

    it('allows to overwrite the defaults', function () {
      expect(
        getSearchParams(
          this.client.authorizationUrl({
            scope: 'openid offline_access',
            redirect_uri: 'https://rp.example.com/cb',
            response_type: 'id_token',
            nonce: 'foobar',
          }),
        ),
      ).to.eql({
        client_id: 'identifier',
        scope: 'openid offline_access',
        redirect_uri: 'https://rp.example.com/cb',
        response_type: 'id_token',
        nonce: 'foobar',
      });
    });

    it('allows any other params to be provide too', function () {
      expect(
        getSearchParams(
          this.client.authorizationUrl({
            state: 'state',
            custom: 'property',
          }),
        ),
      ).to.contain({
        state: 'state',
        custom: 'property',
      });
    });

    it('allows resource to passed as an array', function () {
      expect(
        getSearchParams(
          this.client.authorizationUrl({
            resource: ['urn:example:com', 'urn:example-2:com'],
          }),
        ),
      ).to.deep.contain({
        resource: ['urn:example:com', 'urn:example-2:com'],
      });
    });

    it('auto-stringifies claims parameter', function () {
      expect(
        getSearchParams(
          this.client.authorizationUrl({
            claims: { id_token: { email: null } },
          }),
        ),
      ).to.contain({
        claims: '{"id_token":{"email":null}}',
      });
    });

    it('removes null and undefined values', function () {
      expect(
        getSearchParams(
          this.client.authorizationUrl({
            state: null,
            prompt: undefined,
          }),
        ),
      ).not.to.have.keys('state', 'prompt');
    });

    it('stringifies other values', function () {
      expect(
        getSearchParams(
          this.client.authorizationUrl({
            max_age: 300,
            foo: true,
          }),
        ),
      ).to.contain({
        max_age: '300',
        foo: 'true',
      });
    });

    it('throws on non-object inputs', function () {
      expect(() => {
        this.client.authorizationUrl(true);
      }).to.throw(TypeError, 'params must be a plain object');
    });

    it('returns a space-delimited scope parameter', function () {
      expect(
        this.client.authorizationUrl({
          state: 'state',
          scope: 'openid profile email',
        }),
      ).to.eql('https://op.example.com/auth?client_id=identifier&scope=openid%20profile%20email&response_type=code&state=state');
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
        client_id: 'identifier',
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

    it('returns the end_session_endpoint with client_id if nothing is passed', function () {
      expect(this.client.endSessionUrl()).to.eql(
        'https://op.example.com/session/end?client_id=identifier',
      );
      expect(this.clientWithQuery.endSessionUrl()).to.eql(
        'https://op.example.com/session/end?foo=bar&client_id=identifier',
      );
    });

    it('defaults the post_logout_redirect_uri if client has some', function () {
      expect(getSearchParams(this.clientWithUris.endSessionUrl())).to.eql({
        client_id: 'identifier',
        post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
      });
    });

    it('takes a TokenSet too', function () {
      const hint = new TokenSet({
        id_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
        refresh_token: 'bar',
        access_token: 'tokenValue',
      });
      expect(
        getSearchParams(
          this.client.endSessionUrl({
            id_token_hint: hint,
          }),
        ),
      ).to.eql({
        client_id: 'identifier',
        id_token_hint: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
      });
    });

    it('when TokenSet is passed in it MUST have an id_token', function () {
      const hint = new TokenSet({
        refresh_token: 'bar',
        access_token: 'tokenValue',
      });
      expect(() =>
        this.client.endSessionUrl({
          id_token_hint: hint,
        }),
      ).to.throw(TypeError, 'id_token not present in TokenSet');
    });

    it('allows to override default applied values', function () {
      expect(
        getSearchParams(
          this.client.endSessionUrl({
            post_logout_redirect_uri: 'override',
            client_id: 'override',
          }),
        ),
      ).to.eql({
        post_logout_redirect_uri: 'override',
        client_id: 'override',
      });
    });

    it('allows for recommended and optional query params to be passed in', function () {
      expect(
        getSearchParams(
          this.client.endSessionUrl({
            post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
            state: 'foo',
            id_token_hint: 'idtoken',
          }),
        ),
      ).to.eql({
        post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
        state: 'foo',
        id_token_hint: 'idtoken',
        client_id: 'identifier',
      });
      expect(
        getSearchParams(
          this.clientWithQuery.endSessionUrl({
            post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
            state: 'foo',
            id_token_hint: 'idtoken',
            foo: 'this will be ignored',
          }),
        ),
      ).to.eql({
        post_logout_redirect_uri: 'https://rp.example.com/logout/cb',
        state: 'foo',
        foo: 'bar',
        id_token_hint: 'idtoken',
        client_id: 'identifier',
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
      expect(
        paramsFromHTML(
          this.client.authorizationPost({
            redirect_uri: 'https://rp.example.com/cb',
          }),
        ),
      ).to.eql({
        client_id: 'identifier',
        redirect_uri: 'https://rp.example.com/cb',
        response_type: 'code',
        scope: 'openid',
      });
    });

    it('allows to overwrite the defaults', function () {
      expect(
        paramsFromHTML(
          this.client.authorizationPost({
            scope: 'openid offline_access',
            redirect_uri: 'https://rp.example.com/cb',
            response_type: 'id_token',
            nonce: 'foobar',
          }),
        ),
      ).to.eql({
        client_id: 'identifier',
        scope: 'openid offline_access',
        redirect_uri: 'https://rp.example.com/cb',
        response_type: 'id_token',
        nonce: 'foobar',
      });
    });

    it('allows any other params to be provide too', function () {
      expect(
        paramsFromHTML(
          this.client.authorizationPost({
            state: 'state',
            custom: 'property',
          }),
        ),
      ).to.contain({
        state: 'state',
        custom: 'property',
      });
    });

    it('auto-stringifies claims parameter', function () {
      expect(
        paramsFromHTML(
          this.client.authorizationPost({
            claims: { id_token: { email: null } },
          }),
        ),
      ).to.contain({
        claims: '{"id_token":{"email":null}}',
      });
    });

    it('throws on non-object inputs', function () {
      expect(() => {
        this.client.authorizationPost(true);
      }).to.throw(TypeError, 'params must be a plain object');
    });
  });

  describe('#callback', function () {
    before(function () {
      this.issuer = new Issuer({
        issuer: 'https://op.example.com',
        token_endpoint: 'https://op.example.com/token',
      });
      this.issuerWithIssResponse = new Issuer({
        issuer: 'https://op.example.com',
        token_endpoint: 'https://op.example.com/token',
        authorization_response_iss_parameter_supported: true,
      });
      this.client = new this.issuer.Client({
        client_id: 'identifier',
        client_secret: 'secure',
      });
    });

    it('does an authorization_code grant with code and redirect_uri', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            code: 'codeValue',
            redirect_uri: 'https://rp.example.com/cb',
            grant_type: 'authorization_code',
          });
        })
        .post('/token', () => true) // to make sure filteringRequestBody works
        .reply(200, {});

      return this.client
        .callback('https://rp.example.com/cb', {
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
        .matchHeader('Accept', 'application/json')
        .post('/token')
        .reply(200, {
          id_token: 'foobar',
        });

      sinon.spy(client, 'validateIdToken');

      return client
        .callback('https://rp.example.com/cb', {
          code: 'codeValue',
        })
        .then(fail, () => {
          expect(client.validateIdToken.calledOnce).to.be.true;
          expect(client.validateIdToken.firstCall.args[3]).to.equal(300);
        });
    });

    it('resolves a tokenset with just a state for response_type=none', function () {
      const state = { state: 'foo' };
      return this.client.callback('https://rp.example.com/cb', state, state).then((set) => {
        expect(set).to.be.instanceof(TokenSet);
        expect(set).to.have.property('state', 'foo');
      });
    });

    it('rejects with OPError when part of the response', function () {
      return this.client
        .callback('https://rp.example.com/cb', {
          error: 'invalid_request',
        })
        .then(fail, (error) => {
          expect(error).to.be.instanceof(OPError);
          expect(error).to.have.property('error', 'invalid_request');
        });
    });

    describe('state checks', function () {
      it('rejects with an Error when states mismatch (returned)', function () {
        return this.client
          .callback('https://rp.example.com/cb', {
            state: 'should be checked for this',
          })
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'checks.state argument is missing');
          });
      });

      it('rejects with an Error when states mismatch (not returned)', function () {
        return this.client
          .callback(
            'https://rp.example.com/cb',
            {},
            {
              state: 'should be this',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'state missing from the response');
          });
      });

      it('rejects with an Error when states mismatch (general mismatch)', function () {
        return this.client
          .callback(
            'https://rp.example.com/cb',
            {
              state: 'foo',
            },
            {
              state: 'bar',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error)
              .to.have.property('message')
              .that.matches(/^state mismatch, expected \S+, got: \S+$/);
          });
      });
    });

    describe('jarm response mode', function () {
      it('consumes JARM responses', async function () {
        const client = new this.issuerWithIssResponse.Client({
          client_id: 'identifier',
          client_secret: 'secure',
          authorization_signed_response_alg: 'HS256',
        });

        const response = await new jose.SignJWT({
          code: 'foo',
          iss: this.issuerWithIssResponse.issuer,
          aud: client.client_id,
        })
          .setIssuedAt()
          .setExpirationTime('5m')
          .setProtectedHeader({ alg: 'HS256' })
          .sign(new TextEncoder().encode(client.client_secret));

        nock('https://op.example.com')
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Length', isNumber)
          .matchHeader('Transfer-Encoding', isUndefined)
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              code: 'foo',
              redirect_uri: 'https://rp.example.com/cb',
              grant_type: 'authorization_code',
            });
          })
          .post('/token', () => true) // to make sure filteringRequestBody works
          .reply(200, {});

        await client
          .callback(
            'https://rp.example.com/cb',
            {
              response,
            },
            {
              jarm: true,
            },
          )
          .then(
            () => {},
            () => {},
          );

        expect(nock.isDone()).to.be.true;
      });

      it('consumes encrypted JARM responses', async function () {
        const client = new this.issuerWithIssResponse.Client({
          client_id: 'identifier',
          client_secret: 'secure',
          authorization_signed_response_alg: 'HS256',
          authorization_encrypted_response_alg: 'dir',
          authorization_encrypted_response_enc: 'A128GCM',
        });

        const cleartext = new TextEncoder().encode(
          await new jose.SignJWT({
            code: 'foo',
            iss: this.issuerWithIssResponse.issuer,
            aud: client.client_id,
          })
            .setIssuedAt()
            .setExpirationTime('5m')
            .setProtectedHeader({ alg: 'HS256' })
            .sign(new TextEncoder().encode(client.client_secret)),
        );

        const response = await new jose.CompactEncrypt(cleartext)
          .setProtectedHeader({
            alg: 'dir',
            enc: 'A128GCM',
          })
          .encrypt(await client.secretForAlg('A128GCM'));

        nock('https://op.example.com')
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Length', isNumber)
          .matchHeader('Transfer-Encoding', isUndefined)
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              code: 'foo',
              redirect_uri: 'https://rp.example.com/cb',
              grant_type: 'authorization_code',
            });
          })
          .post('/token', () => true) // to make sure filteringRequestBody works
          .reply(200, {});

        await client
          .callback(
            'https://rp.example.com/cb',
            {
              response,
            },
            {
              jarm: true,
            },
          )
          .then(
            () => {},
            () => {},
          );

        expect(nock.isDone()).to.be.true;
      });

      it('rejects the callback unless JARM was used', function () {
        return this.client
          .callback(
            'https://rp.example.com/cb',
            {
              code: 'foo',
            },
            {
              jarm: true,
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'expected a JARM response');
          });
      });

      it('verifies the JARM alg', async function () {
        const client = new this.issuerWithIssResponse.Client({
          client_id: 'identifier',
          client_secret: 'secure',
          authorization_signed_response_alg: 'HS256',
        });

        const response = await new jose.SignJWT({
          code: 'foo',
          iss: this.issuerWithIssResponse.issuer,
          aud: client.client_id,
        })
          .setIssuedAt()
          .setProtectedHeader({ alg: 'HS256' })
          .setExpirationTime('5m')
          .sign(new TextEncoder().encode(client.client_secret));

        return this.client
          .callback(
            'https://rp.example.com/cb',
            {
              response,
            },
            {
              jarm: true,
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property(
              'message',
              'unexpected JWT alg received, expected RS256, got: HS256',
            );
          });
      });
    });

    describe('response type checks', function () {
      it('rejects with an Error when code is missing', function () {
        return this.client
          .callback(
            'https://rp.example.com/cb',
            {
              // code: 'foo',
              access_token: 'foo',
              token_type: 'Bearer',
              id_token: 'foo',
            },
            {
              response_type: 'code id_token token',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'code missing from response');
          });
      });

      it('rejects with an Error when id_token is missing', function () {
        return this.client
          .callback(
            'https://rp.example.com/cb',
            {
              code: 'foo',
              access_token: 'foo',
              token_type: 'Bearer',
              // id_token: 'foo',
            },
            {
              response_type: 'code id_token token',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'id_token missing from response');
          });
      });

      it('rejects with an Error when token_type is missing', function () {
        return this.client
          .callback(
            'https://rp.example.com/cb',
            {
              code: 'foo',
              access_token: 'foo',
              // token_type: 'Bearer',
              id_token: 'foo',
            },
            {
              response_type: 'code id_token token',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'token_type missing from response');
          });
      });

      it('rejects with an Error when access_token is missing', function () {
        return this.client
          .callback(
            'https://rp.example.com/cb',
            {
              code: 'foo',
              // access_token: 'foo',
              token_type: 'Bearer',
              id_token: 'foo',
            },
            {
              response_type: 'code id_token token',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'access_token missing from response');
          });
      });
      ['code', 'access_token', 'id_token'].forEach((param) => {
        it(`rejects with an Error when ${param} is encoutered during "none" response`, function () {
          return this.client
            .callback(
              'https://rp.example.com/cb',
              {
                [param]: 'foo',
              },
              {
                response_type: 'none',
              },
            )
            .then(fail, (error) => {
              expect(error).to.be.instanceof(Error);
              expect(error).to.have.property(
                'message',
                'unexpected params encountered for "none" response',
              );
            });
        });
      });
    });
  });

  describe('#oauthCallback', function () {
    before(function () {
      this.issuer = new Issuer({
        issuer: 'https://op.example.com',
        token_endpoint: 'https://op.example.com/token',
      });
      this.issuerWithIssResponse = new Issuer({
        issuer: 'https://op.example.com',
        token_endpoint: 'https://op.example.com/token',
        authorization_response_iss_parameter_supported: true,
      });
      this.client = new this.issuer.Client({
        client_id: 'identifier',
        client_secret: 'secure',
      });
    });

    it('does an authorization_code grant with code and redirect_uri', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            code: 'codeValue',
            redirect_uri: 'https://rp.example.com/cb',
            grant_type: 'authorization_code',
          });
        })
        .post('/token', () => true) // to make sure filteringRequestBody works
        .reply(200, {
          access_token: 'tokenValue',
        });

      return this.client
        .oauthCallback('https://rp.example.com/cb', {
          code: 'codeValue',
        })
        .then((set) => {
          expect(nock.isDone()).to.be.true;
          expect(set).to.be.instanceof(TokenSet);
          expect(set).to.have.property('access_token', 'tokenValue');
        });
    });

    it('handles implicit responses too', function () {
      return this.client
        .oauthCallback(undefined, {
          access_token: 'tokenValue',
        })
        .then((set) => {
          expect(set).to.be.instanceof(TokenSet);
          expect(set).to.have.property('access_token', 'tokenValue');
        });
    });

    describe('OAuth 2.0 Authorization Server Issuer Identification', function () {
      it('iss mismatch in oauthCallback()', function () {
        return this.client
          .oauthCallback(undefined, {
            iss: 'https://other-op.example.com',
          })
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property(
              'message',
              'iss mismatch, expected https://op.example.com, got: https://other-op.example.com',
            );
          });
      });

      it('iss mismatch in callback()', function () {
        return this.client
          .callback(undefined, {
            iss: 'https://other-op.example.com',
          })
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property(
              'message',
              'iss mismatch, expected https://op.example.com, got: https://other-op.example.com',
            );
          });
      });

      it('iss missing in oauthCallback()', function () {
        const client = new this.issuerWithIssResponse.Client({
          client_id: 'identifier',
        });
        return client.oauthCallback(undefined, {}).then(fail, (error) => {
          expect(error).to.be.instanceof(Error);
          expect(error).to.have.property('message', 'iss missing from the response');
        });
      });

      it('iss missing in callback()', function () {
        const client = new this.issuerWithIssResponse.Client({
          client_id: 'identifier',
        });
        return client.callback(undefined, {}).then(fail, (error) => {
          expect(error).to.be.instanceof(Error);
          expect(error).to.have.property('message', 'iss missing from the response');
        });
      });
    });

    describe('jarm response mode', function () {
      it('consumes JARM responses', async function () {
        const client = new this.issuerWithIssResponse.Client({
          client_id: 'identifier',
          client_secret: 'secure',
          authorization_signed_response_alg: 'HS256',
        });

        const response = await new jose.SignJWT({
          code: 'foo',
          iss: this.issuerWithIssResponse.issuer,
          aud: client.client_id,
        })
          .setIssuedAt()
          .setProtectedHeader({ alg: 'HS256' })
          .setExpirationTime('5m')
          .sign(new TextEncoder().encode(client.client_secret));

        nock('https://op.example.com')
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Length', isNumber)
          .matchHeader('Transfer-Encoding', isUndefined)
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              code: 'foo',
              redirect_uri: 'https://rp.example.com/cb',
              grant_type: 'authorization_code',
            });
          })
          .post('/token', () => true) // to make sure filteringRequestBody works
          .reply(200, {});

        await client
          .oauthCallback(
            'https://rp.example.com/cb',
            {
              response,
            },
            {
              jarm: true,
            },
          )
          .then(
            () => {},
            () => {},
          );

        expect(nock.isDone()).to.be.true;
      });

      it('consumes encrypted JARM responses', async function () {
        const client = new this.issuerWithIssResponse.Client({
          client_id: 'identifier',
          client_secret: 'secure',
          authorization_signed_response_alg: 'HS256',
          authorization_encrypted_response_alg: 'dir',
          authorization_encrypted_response_enc: 'A128GCM',
        });

        const cleartext = new TextEncoder().encode(
          await new jose.SignJWT({
            code: 'foo',
            iss: this.issuerWithIssResponse.issuer,
            aud: client.client_id,
          })
            .setIssuedAt()
            .setExpirationTime('5m')
            .setProtectedHeader({ alg: 'HS256' })
            .sign(new TextEncoder().encode(client.client_secret)),
        );

        const response = await new jose.CompactEncrypt(cleartext)
          .setProtectedHeader({
            alg: 'dir',
            enc: 'A128GCM',
          })
          .encrypt(await client.secretForAlg('A128GCM'));

        nock('https://op.example.com')
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Length', isNumber)
          .matchHeader('Transfer-Encoding', isUndefined)
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              code: 'foo',
              redirect_uri: 'https://rp.example.com/cb',
              grant_type: 'authorization_code',
            });
          })
          .post('/token', () => true) // to make sure filteringRequestBody works
          .reply(200, {});

        await client
          .oauthCallback(
            'https://rp.example.com/cb',
            {
              response,
            },
            {
              jarm: true,
            },
          )
          .then(
            () => {},
            () => {},
          );

        expect(nock.isDone()).to.be.true;
      });

      it('rejects the callback unless JARM was used', function () {
        return this.client
          .oauthCallback(
            'https://rp.example.com/cb',
            {
              code: 'foo',
            },
            {
              jarm: true,
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'expected a JARM response');
          });
      });

      it('verifies the JARM alg', async function () {
        const client = new this.issuerWithIssResponse.Client({
          client_id: 'identifier',
          client_secret: 'secure',
          authorization_signed_response_alg: 'HS256',
        });

        const response = await new jose.SignJWT({
          code: 'foo',
          iss: this.issuer.issuer,
          aud: client.client_id,
        })
          .setIssuedAt()
          .setProtectedHeader({ alg: 'HS256' })
          .setExpirationTime('5m')
          .sign(new TextEncoder().encode(client.client_secret));

        return this.client
          .oauthCallback(
            'https://rp.example.com/cb',
            {
              response,
            },
            {
              jarm: true,
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property(
              'message',
              'unexpected JWT alg received, expected RS256, got: HS256',
            );
          });
      });
    });

    describe('cannot be used for id_token responses', function () {
      it('rejects when id_token was issued by the authorization endpoint', function () {
        return this.client
          .oauthCallback('https://rp.example.com/cb', {
            code: 'foo',
            id_token: 'foo',
          })
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property(
              'message',
              'id_token detected in the response, you must use client.callback() instead of client.oauthCallback()',
            );
          });
      });

      it('ignores the id_token when falsy', function () {
        return this.client
          .oauthCallback('https://rp.example.com/cb', {
            access_token: 'foo',
            token_type: 'bearer',
            id_token: '',
          })
          .then((tokenset) => {
            expect(tokenset).not.to.have.property('id_token');
          });
      });

      it('rejects when id_token was issued by the token endpoint', function () {
        nock('https://op.example.com')
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Length', isNumber)
          .matchHeader('Transfer-Encoding', isUndefined)
          .post('/token')
          .reply(200, { id_token: 'foo' });

        return this.client
          .oauthCallback('https://rp.example.com/cb', {
            code: 'foo',
          })
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property(
              'message',
              'id_token detected in the response, you must use client.callback() instead of client.oauthCallback()',
            );
          });
      });

      it('ignores the the token endpoint id_token property when falsy', function () {
        nock('https://op.example.com')
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Length', isNumber)
          .matchHeader('Transfer-Encoding', isUndefined)
          .post('/token')
          .reply(200, { id_token: '' });

        return this.client
          .oauthCallback('https://rp.example.com/cb', {
            code: 'foo',
          })
          .then((tokenset) => {
            expect(tokenset).not.to.have.property('id_token');
          });
      });
    });

    describe('response type checks', function () {
      it('rejects with an Error when code is missing', function () {
        return this.client
          .oauthCallback(
            'https://rp.example.com/cb',
            {
              // code: 'foo',
              access_token: 'foo',
              token_type: 'Bearer',
            },
            {
              response_type: 'code token',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'code missing from response');
          });
      });

      it('rejects with an Error when token_type is missing', function () {
        return this.client
          .oauthCallback(
            'https://rp.example.com/cb',
            {
              code: 'foo',
              access_token: 'foo',
              // token_type: 'Bearer',
            },
            {
              response_type: 'code token',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'token_type missing from response');
          });
      });

      it('rejects with an Error when access_token is missing', function () {
        return this.client
          .oauthCallback(
            'https://rp.example.com/cb',
            {
              code: 'foo',
              // access_token: 'foo',
              token_type: 'Bearer',
            },
            {
              response_type: 'code token',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'access_token missing from response');
          });
      });
      ['code', 'access_token'].forEach((param) => {
        it(`rejects with an Error when ${param} is encoutered during "none" response`, function () {
          return this.client
            .oauthCallback(
              'https://rp.example.com/cb',
              {
                [param]: 'foo',
              },
              {
                response_type: 'none',
              },
            )
            .then(fail, (error) => {
              expect(error).to.be.instanceof(Error);
              expect(error).to.have.property(
                'message',
                'unexpected params encountered for "none" response',
              );
            });
        });
      });
    });

    it('rejects with OPError when part of the response', function () {
      return this.client
        .oauthCallback('https://rp.example.com/cb', {
          error: 'invalid_request',
        })
        .then(fail, (error) => {
          expect(error).to.be.instanceof(OPError);
          expect(error).to.have.property('error', 'invalid_request');
        });
    });

    describe('state checks', function () {
      it('rejects with an Error when states mismatch (returned)', function () {
        return this.client
          .oauthCallback('https://rp.example.com/cb', {
            state: 'should be checked for this',
          })
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'checks.state argument is missing');
          });
      });

      it('rejects with an Error when states mismatch (not returned)', function () {
        return this.client
          .oauthCallback(
            'https://rp.example.com/cb',
            {},
            {
              state: 'should be this',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error).to.have.property('message', 'state missing from the response');
          });
      });

      it('rejects with an Error when states mismatch (general mismatch)', function () {
        return this.client
          .oauthCallback(
            'https://rp.example.com/cb',
            {
              state: 'foo',
            },
            {
              state: 'bar',
            },
          )
          .then(fail, (error) => {
            expect(error).to.be.instanceof(Error);
            expect(error)
              .to.have.property('message')
              .that.matches(/^state mismatch, expected \S+, got: \S+$/);
          });
      });
    });
  });

  describe('#refresh', function () {
    before(function () {
      const issuer = new Issuer({
        issuer: 'https://op.example.com',
        token_endpoint: 'https://op.example.com/token',
      });
      this.client = new issuer.Client({
        client_id: 'identifier',
        client_secret: 'secure',
        id_token_signed_response_alg: 'HS256',
      });
    });

    it('does an refresh_token grant with refresh_token', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            refresh_token: 'refreshValue',
            grant_type: 'refresh_token',
          });
        })
        .post('/token', () => true) // to make sure filteringRequestBody works
        .reply(200, {});

      return this.client.refresh('refreshValue').then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('returns a TokenSet', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/token')
        .reply(200, {
          access_token: 'tokenValue',
        });

      return this.client.refresh('refreshValue', {}).then((set) => {
        expect(set).to.be.instanceof(TokenSet);
        expect(set).to.have.property('access_token', 'tokenValue');
      });
    });

    it('can take a TokenSet', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            refresh_token: 'refreshValue',
            grant_type: 'refresh_token',
          });
        })
        .post('/token', () => true) // to make sure filteringRequestBody works
        .reply(200, {});

      return this.client
        .refresh(
          new TokenSet({
            access_token: 'present',
            refresh_token: 'refreshValue',
          }),
        )
        .then(() => {
          expect(nock.isDone()).to.be.true;
        });
    });

    it('passes ID Token validations when ID Token is returned', async function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/token') // to make sure filteringRequestBody works
        .reply(200, {
          access_token: 'present',
          refresh_token: 'refreshValue',
          id_token: await new jose.SignJWT({
            sub: 'foo',
            iss: this.client.issuer.issuer,
            aud: this.client.client_id,
          })
            .setIssuedAt()
            .setProtectedHeader({ alg: 'HS256' })
            .setExpirationTime('5m')
            .sign(new TextEncoder().encode(this.client.client_secret)),
        });

      return this.client.refresh(
        new TokenSet({
          access_token: 'present',
          refresh_token: 'refreshValue',
          id_token: await new jose.SignJWT({
            sub: 'foo',
            iss: this.client.issuer.issuer,
            aud: this.client.client_id,
          })
            .setIssuedAt()
            .setProtectedHeader({ alg: 'HS256' })
            .setExpirationTime('6m')
            .sign(new TextEncoder().encode(this.client.client_secret)),
        }),
      );
    });

    it('rejects when returned ID Token sub does not match the one passed in', async function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/token') // to make sure filteringRequestBody works
        .reply(200, {
          access_token: 'present',
          refresh_token: 'refreshValue',
          id_token: await new jose.SignJWT({
            sub: 'bar',
            iss: this.client.issuer.issuer,
            aud: this.client.client_id,
          })
            .setProtectedHeader({ alg: 'HS256' })
            .setIssuedAt()
            .setExpirationTime('5m')
            .sign(new TextEncoder().encode(this.client.client_secret)),
        });

      return this.client
        .refresh(
          new TokenSet({
            access_token: 'present',
            refresh_token: 'refreshValue',
            id_token: await new jose.SignJWT({
              sub: 'foo',
              iss: this.client.issuer.issuer,
              aud: this.client.client_id,
            })
              .setProtectedHeader({ alg: 'HS256' })
              .setExpirationTime('5m')
              .setIssuedAt()
              .sign(new TextEncoder().encode(this.client.client_secret)),
          }),
        )
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'sub mismatch, expected foo, got: bar');
        });
    });

    it('rejects when passed a TokenSet not containing refresh_token', function () {
      return this.client
        .refresh(
          new TokenSet({
            access_token: 'present',
            // refresh_token: not
          }),
        )
        .then(fail, (error) => {
          expect(error).to.be.instanceof(Error);
          expect(error).to.have.property('message', 'refresh_token not present in TokenSet');
        });
    });
  });

  it('#secretForAlg', function () {
    const issuer = new Issuer();
    const client = new issuer.Client({ client_id: 'identifier', client_secret: 'rj_JR' });

    expect(new TextDecoder().decode(client.secretForAlg('HS256'))).to.eql(client.client_secret);
  });

  it('#encryptionSecret', async function () {
    const issuer = new Issuer();
    const client = new issuer.Client({ client_id: 'identifier', client_secret: 'rj_JR' });

    for (const len of [120, 128, 184, 192, 248, 256]) {
      const key = client.encryptionSecret(String(len));

      expect(key).to.have.lengthOf(len >> 3);
    }

    expect(() => client.encryptionSecret('1024')).to.throw(
      'unsupported symmetric encryption key derivation',
    );
  });

  describe('#userinfo', function () {
    it('takes a string token', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .matchHeader('Authorization', 'Bearer tokenValue')
        .get('/me')
        .reply(200, {});

      return client.userinfo('tokenValue').then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('only GET and POST is supported', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.userinfo('tokenValue', { method: 'PUT' }).then(fail, (error) => {
        expect(error).to.be.instanceof(TypeError);
        expect(error.message).to.eql('#userinfo() method can only be POST or a GET');
      });
    });

    it('takes a string token and a tokenType option', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .matchHeader('Authorization', 'DPoP tokenValue')
        .get('/me')
        .reply(200, {});

      return client.userinfo('tokenValue', { tokenType: 'DPoP' }).then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('takes a tokenset', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        id_token_signed_response_alg: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .matchHeader('Authorization', 'Bearer tokenValue')
        .get('/me')
        .reply(200, {
          sub: 'subject',
        });

      return client
        .userinfo(
          new TokenSet({
            id_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
            refresh_token: 'bar',
            access_token: 'tokenValue',
          }),
        )
        .then(() => {
          expect(nock.isDone()).to.be.true;
        });
    });

    it('takes a tokenset with a token_type', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        id_token_signed_response_alg: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .matchHeader('Authorization', 'DPoP tokenValue')
        .get('/me')
        .reply(200, {
          sub: 'subject',
        });

      return client
        .userinfo(
          new TokenSet({
            id_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
            refresh_token: 'bar',
            access_token: 'tokenValue',
            token_type: 'DPoP',
          }),
        )
        .then(() => {
          expect(nock.isDone()).to.be.true;
        });
    });

    it('takes a tokenset and validates the subject in id_token is the same in userinfo', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        id_token_signed_response_alg: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .get('/me')
        .reply(200, {
          sub: 'different-subject',
        });

      return client
        .userinfo(
          new TokenSet({
            id_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
            refresh_token: 'bar',
            access_token: 'tokenValue',
          }),
        )
        .then(fail, (err) => {
          expect(nock.isDone()).to.be.true;
          expect(err.message).to.equal(
            'userinfo sub mismatch, expected subject, got: different-subject',
          );
        });
    });

    it('validates an access token is present in the tokenset', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client
        .userinfo(
          new TokenSet({
            id_token: 'foo',
            refresh_token: 'bar',
          }),
        )
        .then(fail, (error) => {
          expect(error.message).to.equal('access_token not present in TokenSet');
        });
    });

    it('can do a post call', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .matchHeader('Content-Type', '')
        .post('/me')
        .reply(200, {});

      return client.userinfo('tokenValue', { method: 'POST' }).then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('can submit access token in a body when post', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .matchHeader('Content-Type', 'application/x-www-form-urlencoded')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            access_token: 'tokenValue',
          });
        })
        .post('/me', () => true) // to make sure filteringRequestBody works
        .reply(200, {});

      return client.userinfo('tokenValue', { method: 'POST', via: 'body' }).then(() => {
        expect(nock.isDone()).to.be.true;
      });
    });

    it('can add extra params in a body when post', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .matchHeader('Content-Type', 'application/x-www-form-urlencoded')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            access_token: 'tokenValue',
            foo: 'bar',
          });
        })
        .post('/me', () => true) // to make sure filteringRequestBody works
        .reply(200, {});

      return client
        .userinfo('tokenValue', {
          method: 'POST',
          via: 'body',
          params: { foo: 'bar' },
        })
        .then(() => {
          expect(nock.isDone()).to.be.true;
        });
    });

    it('can add extra params in a body when post (but via header)', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .matchHeader('Authorization', 'Bearer tokenValue')
        .matchHeader('Content-Type', 'application/x-www-form-urlencoded')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            foo: 'bar',
          });
        })
        .post('/me', () => true) // to make sure filteringRequestBody works
        .reply(200, {});

      return client
        .userinfo('tokenValue', {
          method: 'POST',
          params: { foo: 'bar' },
        })
        .then(() => {
          expect(nock.isDone()).to.be.true;
        });
    });

    it('can add extra params in a query when non-post', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .matchHeader('Authorization', 'Bearer tokenValue')
        .get('/me?foo=bar')
        .reply(200, {});

      return client
        .userinfo('tokenValue', {
          params: { foo: 'bar' },
        })
        .then(() => {
          expect(nock.isDone()).to.be.true;
        });
    });

    it('can only submit access token in a body when post', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client
        .userinfo('tokenValue', { via: 'body', method: 'get' })
        .then(fail, ({ message }) => {
          expect(message).to.eql('can only send body on POST');
        });
    });

    it('is rejected with OPError upon oidc error', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .get('/me')
        .reply(401, {
          error: 'invalid_token',
          error_description: 'bad things are happening',
        });

      return client.userinfo('foo').then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error).to.have.property('error', 'invalid_token');
        expect(error).to.have.property('error_description', 'bad things are happening');
      });
    });

    it('is rejected with OPError upon oidc error in www-authenticate header', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .get('/me')
        .reply(401, 'Unauthorized', {
          'WWW-Authenticate':
            'Bearer error="invalid_token", error_description="bad things are happening"',
        });

      return client.userinfo('foo').then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error).to.have.property('error', 'invalid_token');
        expect(error).to.have.property('error_description', 'bad things are happening');
      });
    });

    it('is rejected with when non 200 is returned', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .get('/me')
        .reply(500, 'Internal Server Error');

      return client.userinfo('foo').then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error.message).to.eql('expected 200 OK, got: 500 Internal Server Error');
        expect(error).to.have.property('response');
      });
    });

    it('is rejected with JSON.parse error upon invalid response', function () {
      const issuer = new Issuer({ userinfo_endpoint: 'https://op.example.com/me' });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .get('/me')
        .reply(200, '{"notavalid"}');

      return client.userinfo('foo').then(fail, function (error) {
        expect(error.message).to.match(/in JSON at position 12/);
        expect(error).to.have.property('response');
      });
    });

    describe('signed response (content-type = application/jwt)', function () {
      it('decodes and validates the JWT userinfo', function () {
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
          .matchHeader('Accept', 'application/jwt')
          .reply(200, `${encode({ alg: 'none' })}.${encode(payload)}.`, {
            'content-type': 'application/jwt; charset=utf-8',
          });

        return client.userinfo('accessToken').then((userinfo) => {
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
          .matchHeader('Accept', 'application/jwt')
          .reply(200, `${encode({ alg: 'none' })}.${encode(payload)}.`, {
            'content-type': 'application/jwt; charset=utf-8',
          });

        return client.userinfo('foo').then(fail, (err) => {
          expect(err.message).to.eql('unexpected JWT alg received, expected RS256, got: none');
        });
      });

      it('validates the response is a application/jwt', function () {
        const issuer = new Issuer({
          userinfo_endpoint: 'https://op.example.com/me',
          issuer: 'https://op.example.com',
        });
        const client = new issuer.Client({
          client_id: 'foobar',
          userinfo_signed_response_alg: 'RS256',
        });

        nock('https://op.example.com').get('/me').reply(200, {});

        return client.userinfo('foo').then(fail, (err) => {
          expect(err.message).to.eql(
            'expected application/jwt response from the userinfo_endpoint',
          );
        });
      });
    });
  });

  describe('#introspect', function () {
    it('posts the token in a body and returns the parsed response', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            token: 'tokenValue',
            client_id: 'identifier',
          });
        })
        .post('/token/introspect', () => true) // to make sure filteringRequestBody works
        .reply(200, {
          endpoint: 'response',
        });

      const issuer = new Issuer({
        introspection_endpoint: 'https://op.example.com/token/introspect',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client
        .introspect('tokenValue')
        .then((response) => expect(response).to.eql({ endpoint: 'response' }));
    });

    it('posts the token and a hint in a body', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            client_id: 'identifier',
            token: 'tokenValue',
            token_type_hint: 'access_token',
          });
        })
        .post('/token/introspect', () => true) // to make sure filteringRequestBody works
        .reply(200, {
          endpoint: 'response',
        });

      const issuer = new Issuer({
        introspection_endpoint: 'https://op.example.com/token/introspect',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.introspect('tokenValue', 'access_token');
    });

    it('validates the hint is a string', function () {
      const issuer = new Issuer({
        introspection_endpoint: 'https://op.example.com/token/introspect',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });
      return client.introspect('tokenValue', { nonstring: 'value' }).then(fail, ({ message }) => {
        expect(message).to.eql('hint must be a string');
      });
    });

    it('is rejected with OPError upon oidc error', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/token/introspect')
        .reply(500, {
          error: 'server_error',
          error_description: 'bad things are happening',
        });

      const issuer = new Issuer({
        introspection_endpoint: 'https://op.example.com/token/introspect',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.introspect('tokenValue').then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error).to.have.property('error', 'server_error');
        expect(error).to.have.property('error_description', 'bad things are happening');
      });
    });

    it('is rejected with when non 200 is returned', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/token/introspect')
        .reply(500, 'Internal Server Error');

      const issuer = new Issuer({
        introspection_endpoint: 'https://op.example.com/token/introspect',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.introspect('tokenValue').then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error.message).to.eql('expected 200 OK, got: 500 Internal Server Error');
        expect(error).to.have.property('response');
      });
    });

    it('is rejected with JSON.parse error upon invalid response', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/token/introspect')
        .reply(200, '{"notavalid"}');

      const issuer = new Issuer({
        introspection_endpoint: 'https://op.example.com/token/introspect',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.introspect('tokenValue').then(fail, function (error) {
        expect(error.message).to.match(/in JSON at position 12/);
        expect(error).to.have.property('response');
      });
    });
  });

  describe('#revoke', function () {
    it('posts the token in a body and returns undefined', function () {
      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            client_id: 'identifier',
            token: 'tokenValue',
          });
        })
        .post('/token/revoke', () => true) // to make sure filteringRequestBody works
        .reply(200, {
          endpoint: 'response',
        });

      const issuer = new Issuer({
        revocation_endpoint: 'https://op.example.com/token/revoke',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.revoke('tokenValue').then((response) => expect(response).to.be.undefined);
    });

    it('posts the token and a hint in a body', function () {
      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            client_id: 'identifier',
            token: 'tokenValue',
            token_type_hint: 'access_token',
          });
        })
        .post('/token/revoke', () => true) // to make sure filteringRequestBody works
        .reply(200, {
          endpoint: 'response',
        });

      const issuer = new Issuer({
        revocation_endpoint: 'https://op.example.com/token/revoke',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.revoke('tokenValue', 'access_token');
    });

    it('validates the hint is a string', function () {
      const issuer = new Issuer({
        revocation_endpoint: 'https://op.example.com/token/revoke',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });
      return client.revoke('tokenValue', { nonstring: 'value' }).then(fail, ({ message }) => {
        expect(message).to.eql('hint must be a string');
      });
    });

    it('is rejected with OPError upon oidc error', function () {
      nock('https://op.example.com').post('/token/revoke').reply(500, {
        error: 'server_error',
        error_description: 'bad things are happening',
      });

      const issuer = new Issuer({
        revocation_endpoint: 'https://op.example.com/token/revoke',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.revoke('tokenValue').then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error).to.have.property('error', 'server_error');
        expect(error).to.have.property('error_description', 'bad things are happening');
      });
    });

    it('is rejected with when non 200 is returned', function () {
      nock('https://op.example.com').post('/token/revoke').reply(500, 'Internal Server Error');

      const issuer = new Issuer({
        revocation_endpoint: 'https://op.example.com/token/revoke',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.revoke('tokenValue').then(fail, function (error) {
        expect(error.name).to.equal('OPError');
        expect(error.message).to.eql('expected 200 OK, got: 500 Internal Server Error');
        expect(error).to.have.property('response');
      });
    });

    it('completely ignores the response, even invalid or html one', function () {
      nock('https://op.example.com').post('/token/revoke').reply(200, '{"notavalid"}');

      const issuer = new Issuer({
        revocation_endpoint: 'https://op.example.com/token/revoke',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.revoke('tokenValue');
    });

    it('handles empty bodies', function () {
      nock('https://op.example.com').post('/token/revoke').reply(200);

      const issuer = new Issuer({
        revocation_endpoint: 'https://op.example.com/token/revoke',
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'none',
      });

      return client.revoke('tokenValue');
    });
  });

  describe('#authFor', function () {
    describe('when none', function () {
      it('returns the body httpOptions', async function () {
        const issuer = new Issuer();
        const client = new issuer.Client({
          client_id: 'identifier',
          client_secret: 'secure',
          token_endpoint_auth_method: 'none',
        });
        expect(await clientInternal.authFor.call(client, 'token')).to.eql({
          form: { client_id: 'identifier' },
        });
      });
    });

    describe('when client_secret_post', function () {
      it('returns the body httpOptions', async function () {
        const issuer = new Issuer();
        const client = new issuer.Client({
          client_id: 'identifier',
          client_secret: 'secure',
          token_endpoint_auth_method: 'client_secret_post',
        });
        expect(await clientInternal.authFor.call(client, 'token')).to.eql({
          form: { client_id: 'identifier', client_secret: 'secure' },
        });
      });

      it('requires client_secret to be set', function () {
        const issuer = new Issuer();
        const client = new issuer.Client({
          client_id: 'an:identifier',
          token_endpoint_auth_method: 'client_secret_post',
        });
        return clientInternal.authFor.call(client, 'token').then(fail, (error) => {
          expect(error).to.be.instanceof(TypeError);
          expect(error.message).to.eql(
            'client_secret_post client authentication method requires a client_secret',
          );
        });
      });

      it('allows client_secret to be empty string', async function () {
        const issuer = new Issuer();
        const client = new issuer.Client({
          client_id: 'an:identifier',
          client_secret: '',
          token_endpoint_auth_method: 'client_secret_post',
        });
        expect(await clientInternal.authFor.call(client, 'token')).to.eql({
          form: { client_id: 'an:identifier', client_secret: '' },
        });
      });
    });

    describe('when client_secret_basic', function () {
      it('is the default', async function () {
        const issuer = new Issuer();
        const client = new issuer.Client({ client_id: 'identifier', client_secret: 'secure' });
        expect(await clientInternal.authFor.call(client, 'token')).to.eql({
          headers: { Authorization: 'Basic aWRlbnRpZmllcjpzZWN1cmU=' },
        });
      });

      it('works with non-text characters', async function () {
        const issuer = new Issuer();
        const client = new issuer.Client({
          client_id: 'an:identifier',
          client_secret: 'some secure & non-standard secret',
        });
        expect(await clientInternal.authFor.call(client, 'token')).to.eql({
          headers: {
            Authorization:
              'Basic YW4lM0FpZGVudGlmaWVyOnNvbWUrc2VjdXJlKyUyNitub24tc3RhbmRhcmQrc2VjcmV0',
          },
        });
      });

      it('requires client_secret to be set', function () {
        const issuer = new Issuer();
        const client = new issuer.Client({ client_id: 'an:identifier' });
        return clientInternal.authFor.call(client, 'token').then(fail, (error) => {
          expect(error).to.be.instanceof(TypeError);
          expect(error.message).to.eql(
            'client_secret_basic client authentication method requires a client_secret',
          );
        });
      });

      it('allows client_secret to be empty string', async function () {
        const issuer = new Issuer();
        const client = new issuer.Client({ client_id: 'an:identifier', client_secret: '' });
        expect(await clientInternal.authFor.call(client, 'token')).to.eql({
          headers: { Authorization: 'Basic YW4lM0FpZGVudGlmaWVyOg==' },
        });
      });
    });

    describe('when client_secret_jwt', function () {
      before(function () {
        const issuer = new Issuer({
          issuer: 'https://op.example.com',
          token_endpoint: 'https://op.example.com/token',
          token_endpoint_auth_signing_alg_values_supported: ['HS256', 'HS384'],
        });

        const client = new issuer.Client({
          client_id: 'identifier',
          client_secret: 'its gotta be a long secret and i mean at least 32 characters',
          token_endpoint_auth_method: 'client_secret_jwt',
        });

        return Promise.all([
          clientInternal.authFor.call(client, 'token').then((auth) => {
            this.auth = auth;
          }),
          clientInternal.authFor
            .call(client, 'token', { clientAssertionPayload: { aud: 'https://rp.example.com' } })
            .then((auth) => {
              this.authWithClientAssertionPayload = auth;
            }),
        ]);
      });

      it('promises a body', function () {
        expect(this.auth).to.have.property('form').and.is.an('object');
        expect(this.auth.form).to.have.property(
          'client_assertion_type',
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        );
        expect(this.auth.form).to.have.property('client_assertion');
      });

      it('has a predefined payload properties', function () {
        const payload = JSON.parse(base64url.decode(this.auth.form.client_assertion.split('.')[1]));
        expect(payload).to.have.keys(['iat', 'exp', 'jti', 'iss', 'sub', 'aud']);

        expect(payload.iss).to.equal(payload.sub).to.equal('identifier');
        expect(payload.jti).to.be.a('string');
        expect(payload.iat).to.be.a('number');
        expect(payload.exp).to.be.a('number');
        expect(payload.aud).to.include('https://op.example.com/token');
        expect(payload.aud).to.include('https://op.example.com');
      });

      it('can use clientAssertionPayload to change the default payload properties', function () {
        const payload = JSON.parse(
          base64url.decode(this.authWithClientAssertionPayload.form.client_assertion.split('.')[1]),
        );
        expect(payload).to.have.keys(['iat', 'exp', 'jti', 'iss', 'sub', 'aud']);

        expect(payload.iss).to.equal(payload.sub).to.equal('identifier');
        expect(payload.jti).to.be.a('string');
        expect(payload.iat).to.be.a('number');
        expect(payload.exp).to.be.a('number');
        expect(payload.aud).to.equal('https://rp.example.com');
      });

      it('has the right header properties', function () {
        const header = JSON.parse(base64url.decode(this.auth.form.client_assertion.split('.')[0]));
        expect(header).to.have.keys(['alg']);

        expect(header.alg).to.equal('HS256');
      });

      it('requires client_secret to be set on the client', function () {
        const issuer = new Issuer({
          issuer: 'https://op.example.com',
          token_endpoint: 'https://op.example.com/token',
        });
        const client = new issuer.Client({
          client_id: 'identifier',
          token_endpoint_auth_method: 'client_secret_jwt',
          token_endpoint_auth_signing_alg: 'HS256',
        });

        return clientInternal.authFor.call(client, 'token').then(fail, (error) => {
          expect(error).to.be.instanceof(TypeError);
          expect(error.message).to.eql('client_secret is required');
        });
      });
    });

    describe('when private_key_jwt', function () {
      describe('works as expected', () => {
        before(function () {
          const issuer = new Issuer({
            issuer: 'https://op.example.com',
            token_endpoint: 'https://op.example.com/token',
            token_endpoint_auth_signing_alg_values_supported: ['ES256', 'ES384'],
          });

          const keystore = new KeyStore();

          return keystore.generate('EC', 'P-256').then(() => {
            const client = new issuer.Client(
              {
                client_id: 'identifier',
                token_endpoint_auth_method: 'private_key_jwt',
              },
              keystore.toJWKS(true),
            );

            return Promise.all([
              clientInternal.authFor.call(client, 'token').then((auth) => {
                this.auth = auth;
              }),
              clientInternal.authFor
                .call(client, 'token', {
                  clientAssertionPayload: { aud: 'https://rp.example.com' },
                })
                .then((auth) => {
                  this.authWithClientAssertionPayload = auth;
                }),
            ]);
          });
        });

        it('promises a body', function () {
          expect(this.auth).to.have.property('form').and.is.an('object');
          expect(this.auth.form).to.have.property(
            'client_assertion_type',
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          );
          expect(this.auth.form).to.have.property('client_assertion');
        });

        it('has a predefined payload properties', function () {
          const payload = JSON.parse(
            base64url.decode(this.auth.form.client_assertion.split('.')[1]),
          );
          expect(payload).to.have.keys(['iat', 'exp', 'jti', 'iss', 'sub', 'aud']);

          expect(payload.iss).to.equal(payload.sub).to.equal('identifier');
          expect(payload.jti).to.be.a('string');
          expect(payload.iat).to.be.a('number');
          expect(payload.exp).to.be.a('number');
          expect(payload.aud).to.include('https://op.example.com/token');
          expect(payload.aud).to.include('https://op.example.com');
        });

        it('can use clientAssertionPayload to change the default payload properties', function () {
          const payload = JSON.parse(
            base64url.decode(
              this.authWithClientAssertionPayload.form.client_assertion.split('.')[1],
            ),
          );
          expect(payload).to.have.keys(['iat', 'exp', 'jti', 'iss', 'sub', 'aud']);

          expect(payload.iss).to.equal(payload.sub).to.equal('identifier');
          expect(payload.jti).to.be.a('string');
          expect(payload.iat).to.be.a('number');
          expect(payload.exp).to.be.a('number');
          expect(payload.aud).to.equal('https://rp.example.com');
        });

        it('has the right header properties', function () {
          const header = JSON.parse(
            base64url.decode(this.auth.form.client_assertion.split('.')[0]),
          );
          expect(header).to.have.keys(['alg', 'kid']);

          expect(header.alg).to.equal('ES256');
          expect(header.kid).to.be.ok;
        });

        it('requires jwks to be provided when the client was instantiated', function () {
          const issuer = new Issuer({
            issuer: 'https://op.example.com',
            token_endpoint: 'https://op.example.com/token',
          });
          const client = new issuer.Client({
            client_id: 'identifier',
            token_endpoint_auth_method: 'private_key_jwt',
            token_endpoint_auth_signing_alg: 'RS256',
          });

          return clientInternal.authFor.call(client, 'token').then(fail, (error) => {
            expect(error).to.be.instanceof(TypeError);
            expect(error.message).to.eql(
              'no client jwks provided for signing a client assertion with',
            );
          });
        });
      });

      describe('alg resolution', () => {
        it('rejects when no valid key is present', () => {
          const issuer = new Issuer({
            issuer: 'https://op.example.com',
            token_endpoint: 'https://op.example.com/token',
          });

          const keystore = new KeyStore();

          return keystore.generate('EC', 'P-256').then(() => {
            const client = new issuer.Client(
              {
                client_id: 'identifier',
                token_endpoint_auth_method: 'private_key_jwt',
                token_endpoint_auth_signing_alg: 'EdDSA',
              },
              keystore.toJWKS(true),
            );

            return clientInternal.authFor.call(client, 'token').then(fail, (err) => {
              expect(err).to.have.property(
                'message',
                'no key found in client jwks to sign a client assertion with using alg EdDSA',
              );
            });
          });
        });
      });
    });
  });

  describe('Client#validateIdToken', function () {
    afterEach(function () {
      if (this.client) {
        this.client[custom.clock_tolerance] = 0;
      }
    });

    before(function () {
      this.keystore = new KeyStore();
      return this.keystore.generate('RSA');
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
      this.clientWith3rdParty = new this.issuer.Client(
        {
          client_id: 'identifier',
          client_secret: 'its gotta be a long secret and i mean at least 32 characters',
        },
        undefined,
        { additionalAuthorizedParties: 'authorized third party' },
      );
      this.clientWith3rdParties = new this.issuer.Client(
        {
          client_id: 'identifier',
          client_secret: 'its gotta be a long secret and i mean at least 32 characters',
        },
        undefined,
        { additionalAuthorizedParties: ['authorized third party', 'another third party'] },
      );

      this.fapiClient = new this.issuer.FAPI1Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'tls_client_auth',
      });

      this.IdToken = async (jwkOrSecret, alg, payload) => {
        let key;
        if (jwkOrSecret instanceof Uint8Array) {
          key = jwkOrSecret;
        } else {
          key = await jose.importJWK(jwkOrSecret, alg);
        }
        return new jose.SignJWT(payload)
          .setProtectedHeader({
            alg,
            typ: 'oauth-authz-req+jwt',
            kid: alg.startsWith('HS') ? undefined : key.kid,
          })
          .sign(key);
      };
    });

    before(function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json, application/jwk-set+json')
        .persist()
        .get('/certs')
        .reply(200, this.keystore.toJWKS());
    });

    after(nock.cleanAll);

    it('validates the id token and fulfills with input value (when string)', function () {
      return this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      }).then((token) =>
        this.client.validateIdToken(token).then((validated) => {
          expect(validated).to.equal(token);
        }),
      );
    });

    it('validates the id token and fulfills with input value (when TokenSet)', function () {
      return this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      }).then((token) => {
        const tokenset = new TokenSet({ id_token: token });
        return this.client.validateIdToken(tokenset).then((validated) => {
          expect(validated).to.equal(tokenset);
        });
      });
    });

    it('validates the id token signature (when string)', function () {
      return this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      }).then((token) =>
        this.client.validateIdToken(token.slice(0, -1)).then(fail, (err) => {
          expect(err.message).to.equal('failed to validate JWT signature');
        }),
      );
    });

    it('validates the id token signature (when TokenSet)', function () {
      return this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      }).then((token) => {
        const tokenset = new TokenSet({ id_token: token.slice(0, -1) });
        return this.client.validateIdToken(tokenset).then(fail, (err) => {
          expect(err.message).to.equal('failed to validate JWT signature');
        });
      });
    });

    it('validates the id token and fulfills with input value (when signed by secret)', function () {
      const client = new this.issuer.Client({
        client_id: 'hs256-client',
        client_secret: 'its gotta be a long secret and i mean at least 32 characters',
        id_token_signed_response_alg: 'HS256',
      });

      return this.IdToken(client.secretForAlg('HS256'), 'HS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: client.client_id,
        exp: now() + 3600,
        iat: now(),
      }).then((token) => {
        const tokenset = new TokenSet({ id_token: token });
        return client.validateIdToken(tokenset).then((validated) => {
          expect(validated).to.equal(tokenset);
        });
      });
    });

    it('validates the id_token_signed_response_alg is the one used', function () {
      return this.IdToken(this.client.secretForAlg('HS256'), 'HS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property(
            'message',
            'unexpected JWT alg received, expected RS256, got: HS256',
          );
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'azp mismatch, got: not the client');
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
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

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.client.validateIdToken(token),
      );
    });

    it('rejects unknown additional party azp values (single additional value)', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: [this.client.client_id, 'someone else'],
        azp: 'some unknown third party',
        exp: now() + 3600,
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.clientWith3rdParty.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'azp mismatch, got: some unknown third party');
        });
    });

    it('allows configured additional party azp value (single additional value)', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: [this.client.client_id, 'someone else'],
        azp: 'authorized third party',
        exp: now() + 3600,
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.clientWith3rdParty.validateIdToken(token),
      );
    });

    it('allows the default (client_id) additional party azp value (single additional value)', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: [this.client.client_id, 'someone else'],
        azp: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.clientWith3rdParty.validateIdToken(token),
      );
    });

    it('rejects unknown additional party azp values (multiple additional values)', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: [this.client.client_id, 'someone else'],
        azp: 'some unknown third party',
        exp: now() + 3600,
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.clientWith3rdParties.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'azp mismatch, got: some unknown third party');
        });
    });

    it('allows configured additional party azp value (multiple additional values)', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: [this.client.client_id, 'someone else'],
        azp: 'authorized third party',
        exp: now() + 3600,
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.clientWith3rdParties.validateIdToken(token),
      );
    });

    it('allows the default (client_id) additional party azp value (multiple additional values)', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: [this.client.client_id, 'someone else'],
        azp: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.clientWith3rdParties.validateIdToken(token),
      );
    });

    it('verifies the audience when string', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: 'someone else',
        exp: now() + 3600,
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property(
            'message',
            'aud mismatch, expected identifier, got: someone else',
          );
        });
    });

    it('verifies the audience when array', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: ['someone else', 'and another'],
        azp: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property(
            'message',
            'aud is missing the client_id, expected identifier to be included in ["someone else","and another"]',
          );
        });
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

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.client.validateIdToken(token, 'nonce!!!'),
      );
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token, 'nonce!!!'))
        .then(fail, (error) => {
          expect(error).to.have.property(
            'message',
            'nonce mismatch, expected nonce!!!, got: undefined',
          );
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property(
            'message',
            'nonce mismatch, expected undefined, got: nonce!!!',
          );
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

        return this.IdToken(this.keystore.get(), 'RS256', payload)
          .then((token) => this.client.validateIdToken(token))
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'JWT iat claim must be a JSON numeric value');
        });
    });

    it('allows iat skew', function () {
      this.client[custom.clock_tolerance] = 5;
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now() + 5,
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.client.validateIdToken(token),
      );
    });

    it('verifies exp is a number', function () {
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: 'not a nunmber',
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'JWT exp claim must be a JSON numeric value');
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error)
            .to.have.property('message')
            .that.matches(/^JWT expired, now \d+, exp \d+$/);
        });
    });

    it('allows exp skew', function () {
      this.client[custom.clock_tolerance] = 6;
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() - 4,
        iat: now(),
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.client.validateIdToken(token),
      );
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'JWT nbf claim must be a JSON numeric value');
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token))
        .then(fail, (error) => {
          expect(error)
            .to.have.property('message')
            .that.matches(/^JWT not active yet, now \d+, nbf \d+$/);
        });
    });

    it('allows nbf skew', function () {
      this.client[custom.clock_tolerance] = 5;
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
        nbf: now() + 5,
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.client.validateIdToken(token),
      );
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

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.client.validateIdToken(token, undefined, null, 300),
      );
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token, null, null, 300))
        .then(fail, (error) => {
          expect(error)
            .to.have.property('message')
            .that.matches(
              /^too much time has elapsed since the last End-User authentication, max_age 300, auth_time: \d+, now \d+$/,
            );
        });
    });

    it('allows auth_time skew', function () {
      this.client[custom.clock_tolerance] = 5;
      const payload = {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
        auth_time: now() - 303,
      };

      return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
        this.client.validateIdToken(token, undefined, null, 300),
      );
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token, null, null, 300))
        .then(fail, (error) => {
          expect(error).to.have.property(
            'message',
            'JWT auth_time claim must be a JSON numeric value',
          );
        });
    });

    // const {skipMaxAgeCheck} = require('../../lib/client')
    // console.log(skipMaxAgeCheck)

    // it.only('ignores auth_time presence check when require_auth_time is true but the private symbol is passed', function () {
    //   const client = new this.issuer.Client({
    //     client_id: 'with-require_auth_time',
    //     require_auth_time: true,
    //   });

    //   const payload = {
    //     iss: this.issuer.issuer,
    //     sub: 'userId',
    //     aud: client.client_id,
    //     exp: now() + 3600,
    //     iat: now(),
    //   };

    //   return this.IdToken(this.keystore.get(), 'RS256', payload).then((token) =>
    //     client.validateIdToken(token, undefined, null, skipMaxAgeCheck),
    //   );
    // });

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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => client.validateIdToken(token))
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

      return this.IdToken(this.keystore.get(), 'RS256', payload)
        .then((token) => this.client.validateIdToken(token, null, null, 300))
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'missing required JWT property auth_time');
        });
    });

    it('passes with the right at_hash', function () {
      const access_token = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
      const at_hash = '77QmUPtjPfzWtF2AnpK9RQ';

      return this.IdToken(this.keystore.get(), 'RS256', {
        at_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      }).then((token) => {
        const tokenset = new TokenSet({ access_token, id_token: token });
        return this.client.validateIdToken(tokenset);
      });
    });

    it('validates at_hash presence for implicit flow', function () {
      const access_token = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';

      return this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
          // const tokenset = new TokenSet();
          return this.client.callback(null, { access_token, id_token: token });
        })
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'missing required property at_hash');
        });
    });

    it('validates c_hash presence for hybrid flow', function () {
      const code = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';

      return this.IdToken(this.keystore.get(), 'RS256', {
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
          // const tokenset = new TokenSet();
          return this.client.callback(null, { code, id_token: token });
        })
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'missing required property c_hash');
        });
    });

    it('FAPIClient validates s_hash presence', function () {
      const code = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
      const c_hash = '77QmUPtjPfzWtF2AnpK9RQ';

      return this.IdToken(this.keystore.get(), 'PS256', {
        c_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.fapiClient.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
          // const tokenset = new TokenSet();
          return this.fapiClient.callback(
            null,
            { code, id_token: token, state: 'foo' },
            { state: 'foo' },
          );
        })
        .then(fail, (error) => {
          expect(error).to.have.property('message', 'missing required property s_hash');
        });
    });

    it('FAPIClient checks iat is fresh', function () {
      const code = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
      const c_hash = '77QmUPtjPfzWtF2AnpK9RQ';
      const s_hash = 'LCa0a2j_xo_5m0U8HTBBNA';

      return this.IdToken(this.keystore.get(), 'PS256', {
        c_hash,
        s_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.fapiClient.client_id,
        exp: now() + 3600,
        iat: now() - 3601,
      })
        .then((token) => {
          // const tokenset = new TokenSet();
          return this.fapiClient.callback(
            null,
            { code, id_token: token, state: 'foo' },
            { state: 'foo' },
          );
        })
        .then(fail, (error) => {
          expect(error)
            .to.have.property('message')
            .matches(/^JWT issued too far in the past, now \d+, iat \d+/);
        });
    });

    it('validates state presence when s_hash is returned', function () {
      const s_hash = '77QmUPtjPfzWtF2AnpK9RQ';

      return this.IdToken(this.keystore.get(), 'RS256', {
        s_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
          return this.client.callback(null, { id_token: token });
        })
        .then(fail, (error) => {
          expect(error).to.have.property(
            'message',
            'cannot verify s_hash, "checks.state" property not provided',
          );
        });
    });

    it('validates s_hash', function () {
      const state = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
      const s_hash = 'foobar';

      return this.IdToken(this.keystore.get(), 'RS256', {
        s_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      })
        .then((token) => {
          return this.client.callback(null, { id_token: token, state }, { state });
        })
        .then(fail, (error) => {
          expect(error)
            .to.have.property('message')
            .that.matches(/^s_hash mismatch, expected \S+, got: \S+$/);
        });
    });

    it('passes with the right s_hash', function () {
      const state = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
      const s_hash = '77QmUPtjPfzWtF2AnpK9RQ';

      return this.IdToken(this.keystore.get(), 'RS256', {
        s_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      }).then((token) => {
        return this.client.callback(null, { id_token: token, state }, { state });
      });
    });

    it('fails with the wrong at_hash', function () {
      const access_token = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
      const at_hash = 'notvalid77QmUPtjPfzWtF2AnpK9RQ';

      return this.IdToken(this.keystore.get(), 'RS256', {
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
          expect(error)
            .to.have.property('message')
            .that.matches(/^at_hash mismatch, expected \S+, got: \S+$/);
        });
    });

    it('passes with the right c_hash', function () {
      const code = 'Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk';
      const c_hash = 'LDktKdoQak3Pk0cnXxCltA';

      return this.IdToken(this.keystore.get(), 'RS256', {
        c_hash,
        iss: this.issuer.issuer,
        sub: 'userId',
        aud: this.client.client_id,
        exp: now() + 3600,
        iat: now(),
      }).then((token) => {
        const tokenset = new TokenSet({ code, id_token: token });
        return this.client.validateIdToken(tokenset);
      });
    });

    it('fails with the wrong c_hash', function () {
      const code = 'Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk';
      const c_hash = 'notvalidLDktKdoQak3Pk0cnXxCltA';

      return this.IdToken(this.keystore.get(), 'RS256', {
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
          expect(error)
            .to.have.property('message')
            .that.matches(/^c_hash mismatch, expected \S+, got: \S+$/);
        });
    });

    it('fails if tokenset without id_token is passed in', function () {
      return this.client
        .validateIdToken(
          new TokenSet({
            access_token: 'tokenValue',
            // id_token not
          }),
        )
        .then(fail, ({ message }) => {
          expect(message).to.eql('id_token not present in TokenSet');
        });
    });
  });

  describe('private #decryptIdToken', function () {
    it("to decrypt tokenset's id_token it must have one", async () => {
      const issuer = new Issuer();
      const client = new issuer.Client({
        client_id: 'identifier',
        id_token_encrypted_response_alg: 'RSA-OAEP',
      });

      return client.decryptIdToken(new TokenSet()).then(fail, (err) => {
        expect(err).to.be.instanceof(TypeError);
        expect(err.message).to.eql('id_token not present in TokenSet');
      });
    });

    it('verifies the id token is using the right alg', async () => {
      const issuer = new Issuer();
      const client = new issuer.Client({
        client_id: 'identifier',
        id_token_encrypted_response_alg: 'RSA-OAEP',
      });

      const header = base64url.encode(
        JSON.stringify({
          alg: 'RSA1_5',
          enc: 'A128CBC-HS256',
        }),
      );

      return client.decryptIdToken(`${header}....`).then(fail, (err) => {
        expect(err).to.have.property(
          'message',
          'unexpected JWE alg received, expected RSA-OAEP, got: RSA1_5',
        );
      });
    });

    it('verifies the id token is using the right enc (explicit)', async () => {
      const issuer = new Issuer();
      const client = new issuer.Client({
        client_id: 'identifier',
        id_token_encrypted_response_alg: 'RSA-OAEP',
        id_token_encrypted_response_enc: 'A128CBC-HS256',
      });

      const header = base64url.encode(
        JSON.stringify({
          alg: 'RSA-OAEP',
          enc: 'A128GCM',
        }),
      );

      return client.decryptIdToken(`${header}....`).then(fail, (err) => {
        expect(err).to.have.property(
          'message',
          'unexpected JWE enc received, expected A128CBC-HS256, got: A128GCM',
        );
      });
    });

    it('verifies the id token is using the right enc (defaulted to)', async () => {
      const issuer = new Issuer();
      const client = new issuer.Client({
        client_id: 'identifier',
        id_token_encrypted_response_alg: 'RSA-OAEP',
      });

      const header = base64url.encode(
        JSON.stringify({
          alg: 'RSA-OAEP',
          enc: 'A128GCM',
        }),
      );

      return client.decryptIdToken(`${header}....`).then(fail, (err) => {
        expect(err).to.have.property(
          'message',
          'unexpected JWE enc received, expected A128CBC-HS256, got: A128GCM',
        );
      });
    });
  });

  describe('signed and encrypted responses', function () {
    before(function () {
      this.keystore = new KeyStore({
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
      });
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
        .matchHeader('Accept', 'application/json')
        .post('/token')
        .reply(200, {
          access_token:
            'eyJraW5kIjoiQWNjZXNzVG9rZW4iLCJqdGkiOiJlMDk5YTI1ZC02MzA0LTQwMGItOTdhYi1hOTJhMzMzOTBlODgiLCJpYXQiOjE0NzMwNzY0MTMsImV4cCI6MTQ3MzA4MzYxMywiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.p_r4KvAu6lEY6JpGmRIGCkRRrovGeJcDfOw3O_gFkPRaY7bcJjNDUPlfY7_nyp3bWyqtveq55ozTZuddUL01KET7bKgxMq-dQ2SxGBvgN3KtHIRBud7Bw8Ax98YkiBKJJXC8xF00VZkkX-ZcUyXptPkUpBm0zeN6jmWmyFX-2QrbclLS8ZEK2Poc_y5PdNAtCCOTBfnq6roxzVQ5lM_aMQaSuPVd-Og6E_jBE6OE9oB4ikFa4S7EvZvFVDpGMLtUjxOazTURbqWY6OnuhuAiP6WZc1FxfQod462IqPERzl2qVJH9qQNr-iLuVLt_bzauHg33v1koTrdfETyoRAZH5w',
          expires_at: 1473083613,
          id_token:
            'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Inc2Ukx4a3phWDV5cGtwU1pMemJVbkVfWjh4WEYtS3R2OXc0Tno0MVZFeVEiLCJ5IjoiUTFwM1l6a3h3VHhFZ1lnZ0szNFpKcnkyT1JCMGloYXEyOXdtSUVqTnZNWSJ9fQ..EqZ4s3iLxrVhuZwF4NDa7A.tkg5i4LQXECXNFXh1j9yo5TjhhIlrzp_BZbdEI18f2jINVIwXu08eRrpQAI-OAaO4MbxiX73fLD_jDplHIUz5NDxiuxuQT2DCzynK66Tqs76OELATBAkW7FUGDJPWjotXXuUzNBgvs0xKz8q6a04udqfATH4-tZkyVLkNS0Z8mpAejRdkacYfvdSSJk842e3qHsOowlX7Tiu7OY60dBkKXO7hrPtvsX2XdseREYnA_A3P4jNdIhWhZMUxR2X-FSgChzwRIFPFRJsp1xiHkfxfHaPjHPmj3JlDPlubNrUcz-2WWxeBd9qVjqlAyqRorNr30KwCwVTaIHwfLrTjXzFfVOJBXAdIJ7FjX7lUbnc9DjcV6cNN2IdHTET7aoC6ysfGYLAwVtN9sLXRgeJXdl6-56f0eg_ZbLbOWLj3qJPuDSTVu7r6L3sebNx4uBTzAu-e8i1uukw6e63AHzVa3Z57tTGtzaFHogDH0f_JuQRhaJcwDJdoJKmksVT33W6mxza0WttqXXj9NXzfJUdRs3B9vpf1h9Yvol9Rlii2OmwLGC17sZe-W2NX1ibS87ZQiEFzuLWfmU4ygagg7O7A5fJ4Olo_aY6Ow7qqggIjAhL3J24lsMtlVR3VGKWsmvtW4eoojy6nnfkcJreSHAjPby9c4_giSic_MCSe9K1jU2Kyftj-XBJD5DSZlt97ZT9NA4aI-DXBs6Mx14dXrZ15BYDVxvYU-YmUnJpASueGB7bp5TMjE2YC2cEPsHgiJnU1Yi0.KMTcJ07KhD0-g4V89Z0PBg',
          refresh_token:
            'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA',
          token_type: 'Bearer',
        });

      const client = new issuer.Client(
        {
          client_id: '4e87dde4-ddd3-4c21-aef9-2f2f6bab43ca',
          client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
          id_token_encrypted_response_alg: 'ECDH-ES',
          id_token_signed_response_alg: 'HS256',
        },
        this.keystore.toJWKS(true),
      );

      return client.callback(
        'http://oidc-client.dev/cb',
        {
          code: 'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiI3YzM5NzQyZC0yMGUyLTQ3YjEtYmM1MC1lN2VlYzhmN2IzNmYiLCJub25jZSI6ImM2NDVmZmZhNDAwNzU1MzJlZjI5YTJlYTYyN2NmYTM3IiwiaWF0IjoxNDczMDc2NDEyLCJleHAiOjE0NzMwNzcwMTIsImlzcyI6Imh0dHBzOi8vZ3VhcmRlZC1jbGlmZnMtODYzNS5oZXJva3VhcHAuY29tL29wIn0.jgUnZUBmsceb1cpqlsmiCOQ40Zx4JTRffGN_bAgYT4rLcEv3wOlzMSoVmU1cYkDbi-jjNAqkBjqxDWHcRJnQR4BAYOdyDVcGWD_aLkqGhUOCJHn_lwWqEKtSTgh-zXiqVIVC5NTA2BdhEfHhb-jnMQNrKkL2QNXOFvT9s6khZozOMXy-mUdfNfdSFHrcpFkFyGAUpezI9QmwToMB6KwoRHDYb2jcLBXdA5JLAnHw8lpz9yUaVQv7s97wY7Xgtt2zNFwQxiJWytYNHaJxQnOZje0_TvDjrZSA9IYKuKU1Q7f7-EBfQfFSGcsFK2NtGho3mNBEUDD2B8Qv1ipv50oU6Q',
          id_token:
            'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlBWMGt5MEMyWmpoY0tJeGM4dDRfMmR1S0NNMGlLbTFlUHRoM3RtNkV4c0EiLCJ5Ijoib3hpOXhUNEZzWUdnU1hzdUVDb3kzYnN6X0VHNDAxcFppbG81MjVDTFZCUSJ9fQ..Fk7uOrLHo3StxuO7JKmqhA.ShAxwMhoneNdxPpc5bDvag-ISjcTAjIKVHTVwMCBIWofVpqCWCL-WiNtm9S-YQf08oVm0hEptqaWIkIUFuqRK56DAP_anxtBPjQhX_oFDOnN76rPg0KNW9hgcRYOQ9MkUEYtaDgslcWAlv-xy_DpQ7_V2lYudVCcSLW26YK0TZlH5bOTPkVD6t1JgYb4cdgATzjzZCAgiDvWYuDZ1FmzRf53FRlQfCeB_sPjvag-sr-ZkcygEjLF86-JvOs4a6Ccz6gPs2WBtVSycYi6NuKJt0nlIBYbSazF5cT_ACHcfveMbgLeO2-GFekY6DhiRyHFgbA03G-yRlFLUbtzxZI_vBe_NuZf2pyiyv4xCNI9bvl_0LCvu0T_R6ss0OzBm9dK6tfEe5mkmi1ku_eiA2HHzk_BK4VLbP0urinZGethJcqXEIjuBr1pUKduQfVtUQMfnVPxLUI9PykO1H-QxVAcnsB6p3q0jkXvTvFBhsbFhA0cwKWF2qqpW6JXH19ULt0wNgzAGxghtox-t8QWb_qUO0Ql69AdmoTlydLB16aLf7JEH_vQBHXtSuDwAyEqccU8-EKMXHh4w6T92t6IjsXXr1x_JlCoByTEqG-bpGilPuYbh90cin7DyyniC2p-gM8pOIdpP9cDnKwRHGTPyw7YR16_0JCdmJOn7NO07zlYZMfgdmD-S2S49D23nd1SkECw.V__rYTSwfHvJsRe4auyNjw',
          state: '36853f4ea7c9d26f4b0b95f126afe6a2',
          session_state: 'foobar.foo',
        },
        { state: '36853f4ea7c9d26f4b0b95f126afe6a2', nonce: 'c645fffa40075532ef29a2ea627cfa37' },
      );
    });

    it('handles signed and encrypted id_tokens from refresh grant', function () {
      const time = new Date(1473076413242);
      timekeeper.freeze(time);
      const issuer = new Issuer({
        issuer: 'https://guarded-cliffs-8635.herokuapp.com/op',
        token_endpoint: 'https://op.example.com/token',
      });

      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/token')
        .reply(200, {
          access_token:
            'eyJraW5kIjoiQWNjZXNzVG9rZW4iLCJqdGkiOiJlMDk5YTI1ZC02MzA0LTQwMGItOTdhYi1hOTJhMzMzOTBlODgiLCJpYXQiOjE0NzMwNzY0MTMsImV4cCI6MTQ3MzA4MzYxMywiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.p_r4KvAu6lEY6JpGmRIGCkRRrovGeJcDfOw3O_gFkPRaY7bcJjNDUPlfY7_nyp3bWyqtveq55ozTZuddUL01KET7bKgxMq-dQ2SxGBvgN3KtHIRBud7Bw8Ax98YkiBKJJXC8xF00VZkkX-ZcUyXptPkUpBm0zeN6jmWmyFX-2QrbclLS8ZEK2Poc_y5PdNAtCCOTBfnq6roxzVQ5lM_aMQaSuPVd-Og6E_jBE6OE9oB4ikFa4S7EvZvFVDpGMLtUjxOazTURbqWY6OnuhuAiP6WZc1FxfQod462IqPERzl2qVJH9qQNr-iLuVLt_bzauHg33v1koTrdfETyoRAZH5w',
          expires_at: 1473083613,
          id_token:
            'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ik8yQzZHZnBFVGgyUDBCWVNSN1dtWDZXVTBiV1FXcVZud1lwRGVwbVI1NVkiLCJ5IjoiVG5pc0dTSWZMQUxNYzZHVUlydVBmeWFzMm9mQ3JPV3llZ2EyMW5pZG1KTSJ9fQ..RiTOrMAlM4pq6RfwnitLKA.oSERr76vgdbiYm1yQZfkwPonBzdrheypkueK9S5dRVodZDf1BKTr5-eM2VBgjYJ2R8KS5EAAJeJBxnlno3AnfO242ZQbqJP144S8sCj0lZmQoZJ6VzJavADXAf4LiprDblzV8J64pBnmvwjQN9Mk_KKNA34QoAebJZEP9A7RCLUck_oqb7vsLTM_LUyXyXxm7QiWUPdnUCzCCqcJW3SysFeJo1VZTZCwFxK0zrcja-vv9SUSoS7yvQuGRVXS3L08BglTN7SLWVujsPMJWbxmj_zYhoy14DQIckoBU7ver-2PoJOukl6m4yaY9n9LWZ5mUGDb3PbnwuFYxb1rDm2EmvlkhbXFdIuRciIOQTqgeei0TU61Ff_Vt0tinZNThYMQgX4DFc7HILBU7lMwwVUMdYqamE3suRr3qUIlD2RdSNiO87jxaiDFrosGU1fVVulcGmkFN4DX5kyd8lxMs33yPS1uO0G_NViFe-fwxd95JAYXOEiofnHFIYuHgrxfioBMoojYQl8PgLZFj8yxzGVflOyzJQgiYQA-BSAPI1bL2P_J2Jlnhdtv3cJ-bdG1pcwAa6zyzwSEXU5i6p9_TGs4nM15p-QlC3mgtjKkLtC64OL0ucc2Frb6dzKyZTOePu6PcecafNucSaMq1ERhRmQOdigDj1nwHUYs3akx31CHp-eXa9jctuy_C5l_YbBJOiUViZK2dJFNuMJQnMhPcSf6wQdVTQmXCxsSnRN158XYDhgVqqe4U6CROsKiCRQSKqpZ.Yo7zj4wMR89oWSH5Twfzzg',
          refresh_token:
            'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA',
          token_type: 'Bearer',
        });

      const client = new issuer.Client(
        {
          client_id: '4e87dde4-ddd3-4c21-aef9-2f2f6bab43ca',
          client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
          id_token_encrypted_response_alg: 'ECDH-ES',
          id_token_signed_response_alg: 'HS256',
        },
        this.keystore.toJWKS(true),
      );

      return client.refresh(
        'http://oidc-client.dev/cb',
        new TokenSet({
          refresh_token:
            'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA',
        }),
        { nonce: null },
      );
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
        .reply(
          200,
          'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlNPZDJZYUZ0cE0xS3lPNkt4a2tCeGxEVEVXcGVvanlqandqald5c1BOVEUiLCJ5IjoiTEVKZGlqazRXc01XZU9JOHdBN1JLSEQ3Q2NxUXN3V25kVnVoeXl2aFl4byJ9fQ..Az5OORCn8IJCYCKg2AGs2A.ACZMiNTTclMiHui8cAgje6xmU4MWwUfU5aPduSxwmSZKMCEiQST3ZpRknWgitklLhd1B7w7zz9wcu7A-yt51ZTaVfO7B9ZrismOrQRX6pTc.xAu2T_3edWUipVASAaMBmw',
          {
            'content-type': 'application/jwt; charset=utf-8',
          },
        );

      const client = new issuer.Client(
        {
          client_id: 'f21d5d1d-1c3f-4905-8ff1-5f553a2090b1',
          userinfo_encrypted_response_alg: 'ECDH-ES',
        },
        this.keystore.toJWKS(true),
      );

      return client.userinfo('accesstoken').then((userinfo) => {
        expect(userinfo).to.eql({
          email: 'johndoe@example.com',
          sub: '0aa66887-8c86-4f3b-b521-5a00e01799ca',
        });
      });
    });

    it('verifies no invalid unsigned plain JSON jwe payloads get through', function () {
      const time = new Date(1473076413242);
      timekeeper.freeze(time);
      const issuer = new Issuer({
        issuer: 'https://guarded-cliffs-8635.herokuapp.com/op',
        userinfo_endpoint: 'https://op.example.com/me',
      });

      nock('https://op.example.com')
        .get('/me')
        .reply(
          200,
          'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkhqMWZtUGxHTEJ2VE5SbnE0SlpWcTNjd3FUTXUxYXYzYjBicEJUWlR0bWciLCJ5IjoieWs5Tkl1WkJiRl9UTjQwRHlCcERjMGNGek5EUUVzRVQ5ZTlJNk1NY2dTayJ9fQ..VonL8dThfAnH4qmUjGv5tA.7CZxo9EWjucIklvP8D7RWg.QpvgGnrKL4xLIKI86qkwRg',
          {
            'content-type': 'application/jwt; charset=utf-8',
          },
        );

      const client = new issuer.Client(
        {
          client_id: 'f21d5d1d-1c3f-4905-8ff1-5f553a2090b1',
          userinfo_encrypted_response_alg: 'ECDH-ES',
        },
        this.keystore.toJWKS(true),
      );

      return client.userinfo('accesstoken').then(fail, (err) => {
        expect(err.message).to.eql('failed to parse userinfo JWE payload as JSON');
      });
    });

    it('handles valid but no object top-level unsigned plain JSON jwe payloads', function () {
      const time = new Date(1473076413242);
      timekeeper.freeze(time);
      const issuer = new Issuer({
        issuer: 'https://guarded-cliffs-8635.herokuapp.com/op',
        userinfo_endpoint: 'https://op.example.com/me',
      });

      nock('https://op.example.com')
        .get('/me')
        .reply(
          200,
          'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlJDLUs1Q0oxaHM1OUVab3FRbDdIckZfYkRTNGtmbVRkV2NDUktiVUdNSlEiLCJ5IjoicDRLdGhQNlBZbE04LU5XQVBLSThjTThnOHRXUjU3RGp2V2s5QUVMTF9jdyJ9fQ..0UsI_8FRDyu9Ww3UsgPutg.RlHWtr8ezCPO4BahKEm2FA.6irHMjkZtOFnUVwrZkuxtw',
          {
            'content-type': 'application/jwt; charset=utf-8',
          },
        );

      const client = new issuer.Client(
        {
          client_id: 'f21d5d1d-1c3f-4905-8ff1-5f553a2090b1',
          userinfo_encrypted_response_alg: 'ECDH-ES',
        },
        this.keystore.toJWKS(true),
      );

      return client.userinfo('accesstoken').then(fail, (err) => {
        expect(err.message).to.eql('failed to parse userinfo JWE payload as JSON');
      });
    });

    it('handles symmetric encryption', function () {
      const time = new Date(1474477036849);
      timekeeper.freeze(time);
      const issuer = new Issuer({ issuer: 'http://localhost:3000/op' });

      const client = new issuer.Client({
        client_id: '0d9413a4-61c1-4b2b-8d84-a82464c1556c',
        client_secret: 'l73jho9z9mL0GAomiQwbw08ARqro2tJ4E4qhJ+PZhNQoU6G6D23UDF91L9VR7iJ4',
        id_token_encrypted_response_alg: 'A128GCMKW',
        id_token_signed_response_alg: 'HS256',
      });

      return client.callback(
        'http://oidc-client.dev/cb',
        {
          id_token:
            'eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIiwidGFnIjoiUUF6cjEwTFI4M0gzYzdLN3ZfMDgyZyIsIml2IjoiUWM2c3RLVTg4Ty1oWnZiMyJ9.wvD9dnE40HVAMPuHI7h3wpFZx3OOnNjSUzsOtPXVL8w.XZlxpE3exE3l8kqZkWgoyg.vfK1f2HI_AuYzQbstHeMpq19qdRgESLQuk5RHj9IzPW9Zj0dvKsEJ8a7MQjo6zepNhpP-rUbV06WDw_c2T0riB5SfsVBNLSazxSo9HxCiuzIpYFledAmfkUI0nQDlR1swKxetYYPSR0jEjZNDjIV7vgG8RD3cqImqMYz43QgBSbZqgvMxLcvxzekXWwnXaUTxB0AA8tvQk94JgFl_vcZ3Hln82DPsw7ZdAcNoNqtC79JBI2W7o4SR4rv42OhUf3kJjuPHp9ch28wEAD7O3kfN-YFJE2HdLP97yWi0esR4MmKpCDJymIUBeuyZUrNqnrHTTv6BQEKFX8mL0KQf-XqeQpyw1-1iqfu57bZfAxXzcnRUnQc54XsRBKVHdjKh7lIK8TNmluI1vHEanFYRQntg86yjqIxmpXqiSogSxWfwi6cAF_Zgzr-4koG-ENtVz8c-Szi3ZaTCjLOvt-uPCe1kLR66t_iNCGDawMiLLkcF5bXm9tfUyUlb0_O0bdQW74P9fbVnyEXWp8v6vVu8WLEuYCK2pztMgjp8UuJmfPS6ls2uK42Samvk9soPO9HRNSiROO8nyGU-6V7iTJH5EB_lQ.2WIYHXy2FMNd78p7BYZvBQ',
        },
        { nonce: '9cda9a61a2b01b31aa0b31d3c33631a1' },
      );
    });
  });

  describe('#callbackParams', function () {
    before(function () {
      const issuer = new Issuer({ issuer: 'http://localhost:3000/op' });
      this.client = new issuer.Client({ client_id: 'identifier' });
    });

    describe('when passed a string', () => {
      it('returns query params from full uri', function () {
        expect(this.client.callbackParams('http://oidc-client.dev/cb?code=code')).to.eql({
          code: 'code',
        });
      });

      it('returns query params from node request uri', function () {
        expect(this.client.callbackParams('/cb?code=code')).to.eql({ code: 'code' });
      });
    });

    describe('when http.IncomingMessage', () => {
      before(function () {
        this.origIncomingMessage = stdhttp.IncomingMessage;
        stdhttp.IncomingMessage = MockRequest;
      });

      after(function () {
        stdhttp.IncomingMessage = this.origIncomingMessage;
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
        }).to.throw(
          'incoming message body missing, include a body parser prior to this method call',
        );
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
        }).to.throw(
          '#callbackParams only accepts string urls, http.IncomingMessage or a lookalike',
        );
        expect(() => {
          this.client.callbackParams(true);
        }).to.throw(
          '#callbackParams only accepts string urls, http.IncomingMessage or a lookalike',
        );
        expect(() => {
          this.client.callbackParams([]);
        }).to.throw(
          '#callbackParams only accepts string urls, http.IncomingMessage or a lookalike',
        );
      });
    });
  });

  describe('#requestObject', function () {
    before(function () {
      this.keystore = new KeyStore();
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
        .matchHeader('Accept', 'application/json, application/jwk-set+json')
        .get('/certs')
        .reply(200, this.keystore.toJWKS());

      return issuerInternal.keystore.call(this.issuer);
    });

    after(nock.cleanAll);

    it('verifies keystore is set', function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        request_object_signing_alg: 'EdDSA',
      });

      return client.requestObject({ state: 'foobar' }).then(fail, (err) => {
        expect(err).to.be.instanceof(TypeError);
        expect(err.message).to.eql('no keystore present for client, cannot sign using alg EdDSA');
      });
    });

    it('verifies keystore has the appropriate key', async function () {
      const keystore = new KeyStore();
      await keystore.generate('EC');
      const client = new this.issuer.Client(
        { client_id: 'identifier', request_object_signing_alg: 'EdDSA' },
        keystore.toJWKS(true),
      );

      return client.requestObject({ state: 'foobar' }).then(fail, (err) => {
        expect(err).to.be.instanceof(TypeError);
        expect(err.message).to.eql('no key to sign with found for alg EdDSA');
      });
    });

    it('sign alg=none', function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        request_object_signing_alg: 'none',
      });

      return client.requestObject({ state: 'foobar' }).then((signed) => {
        const parts = signed.split('.');
        expect(JSON.parse(base64url.decode(parts[0]))).to.eql({
          alg: 'none',
          typ: 'oauth-authz-req+jwt',
        });
        const { jti, iat, exp, ...jwt } = JSON.parse(base64url.decode(parts[1]));
        expect(jwt).to.eql({
          iss: 'identifier',
          client_id: 'identifier',
          aud: 'https://op.example.com',
          state: 'foobar',
        });
        expect(jti).to.be.a('string');
        expect(iat).to.be.a('number');
        expect(exp).to.be.a('number');
        expect(iat + 300).to.eql(exp);
        expect(parts[2]).to.equal('');
      });
    });

    it('sign alg=HSxxx', function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        request_object_signing_alg: 'HS256',
        client_secret: 'atleast32byteslongforHS256mmkay?',
      });

      return client.requestObject({ state: 'foobar' }).then((signed) => {
        const parts = signed.split('.');
        expect(JSON.parse(base64url.decode(parts[0]))).to.eql({
          alg: 'HS256',
          typ: 'oauth-authz-req+jwt',
        });
        const { jti, iat, exp, ...jwt } = JSON.parse(base64url.decode(parts[1]));
        expect(jwt).to.eql({
          iss: 'identifier',
          client_id: 'identifier',
          aud: 'https://op.example.com',
          state: 'foobar',
        });
        expect(jti).to.be.a('string');
        expect(iat).to.be.a('number');
        expect(exp).to.be.a('number');
        expect(iat + 300).to.eql(exp);
        expect(parts[2].length).to.be.ok;
      });
    });

    it('sign alg=RSxxx', function () {
      const client = new this.issuer.Client(
        { client_id: 'identifier', request_object_signing_alg: 'RS256' },
        this.keystore.toJWKS(true),
      );

      return client.requestObject({ state: 'foobar' }).then((signed) => {
        const parts = signed.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'RS256', typ: 'oauth-authz-req+jwt' })
          .and.have.property('kid');
        const { jti, iat, exp, ...jwt } = JSON.parse(base64url.decode(parts[1]));
        expect(jwt).to.eql({
          iss: 'identifier',
          client_id: 'identifier',
          aud: 'https://op.example.com',
          state: 'foobar',
        });
        expect(jti).to.be.a('string');
        expect(iat).to.be.a('number');
        expect(exp).to.be.a('number');
        expect(iat + 300).to.eql(exp);
        expect(parts[2].length).to.be.ok;
      });
    });

    it("encrypts for issuer using issuer's public key (explicit enc)", function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        request_object_encryption_alg: 'RSA1_5',
        request_object_encryption_enc: 'A128CBC-HS256',
      });

      return client.requestObject({ state: 'foobar' }).then((encrypted) => {
        const parts = encrypted.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'RSA1_5', enc: 'A128CBC-HS256', cty: 'oauth-authz-req+jwt' })
          .and.have.property('kid');
      });
    });

    it("encrypts for issuer using issuer's public key (default enc)", function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        request_object_encryption_alg: 'RSA1_5',
      });

      return client.requestObject({ state: 'foobar' }).then((encrypted) => {
        const parts = encrypted.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'RSA1_5', enc: 'A128CBC-HS256', cty: 'oauth-authz-req+jwt' })
          .and.have.property('kid');
      });
    });

    it('encrypts for issuer using pre-shared client_secret (A\\d{3}GCMKW)', function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
        request_object_encryption_alg: 'A128GCMKW',
      });

      return client.requestObject({ state: 'foobar' }).then((encrypted) => {
        const parts = encrypted.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'A128GCMKW', enc: 'A128CBC-HS256', cty: 'oauth-authz-req+jwt' })
          .and.not.have.property('kid');
      });
    });

    it('encrypts for issuer using pre-shared client_secret (dir + A128CBC-HS256)', function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
        request_object_encryption_alg: 'dir',
        request_object_encryption_enc: 'A128CBC-HS256',
      });

      return client.requestObject({ state: 'foobar' }).then((encrypted) => {
        const parts = encrypted.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'dir', enc: 'A128CBC-HS256', cty: 'oauth-authz-req+jwt' })
          .and.not.have.property('kid');
      });
    });

    it('encrypts for issuer using pre-shared client_secret (dir + A192CBC-HS384)', function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
        request_object_encryption_alg: 'dir',
        request_object_encryption_enc: 'A192CBC-HS384',
      });

      return client.requestObject({ state: 'foobar' }).then((encrypted) => {
        const parts = encrypted.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'dir', enc: 'A192CBC-HS384', cty: 'oauth-authz-req+jwt' })
          .and.not.have.property('kid');
      });
    });

    it('encrypts for issuer using pre-shared client_secret (dir + A256CBC-HS512)', function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
        request_object_encryption_alg: 'dir',
        request_object_encryption_enc: 'A256CBC-HS512',
      });

      return client.requestObject({ state: 'foobar' }).then((encrypted) => {
        const parts = encrypted.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'dir', enc: 'A256CBC-HS512', cty: 'oauth-authz-req+jwt' })
          .and.not.have.property('kid');
      });
    });

    it('encrypts for issuer using pre-shared client_secret (dir + defaulted to A128CBC-HS256)', function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
        request_object_encryption_alg: 'dir',
      });

      return client.requestObject({ state: 'foobar' }).then((encrypted) => {
        const parts = encrypted.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'dir', enc: 'A128CBC-HS256', cty: 'oauth-authz-req+jwt' })
          .and.not.have.property('kid');
      });
    });

    if (!('electron' in process.versions)) {
      it('encrypts for issuer using pre-shared client_secret (PBES2)', function () {
        const client = new this.issuer.Client({
          client_id: 'identifier',
          client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
          request_object_encryption_alg: 'PBES2-HS256+A128KW',
        });

        return client.requestObject({ state: 'foobar' }).then((encrypted) => {
          const parts = encrypted.split('.');
          expect(JSON.parse(base64url.decode(parts[0])))
            .to.contain({
              alg: 'PBES2-HS256+A128KW',
              enc: 'A128CBC-HS256',
              cty: 'oauth-authz-req+jwt',
            })
            .and.not.have.property('kid');
        });
      });

      it('encrypts for issuer using pre-shared client_secret (A\\d{3}KW)', function () {
        const client = new this.issuer.Client({
          client_id: 'identifier',
          client_secret: 'GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ',
          request_object_encryption_alg: 'A128KW',
        });

        return client.requestObject({ state: 'foobar' }).then((encrypted) => {
          const parts = encrypted.split('.');
          expect(JSON.parse(base64url.decode(parts[0])))
            .to.contain({ alg: 'A128KW', enc: 'A128CBC-HS256', cty: 'oauth-authz-req+jwt' })
            .and.not.have.property('kid');
        });
      });
    }

    it('throws on non-object inputs', function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        request_object_signing_alg: 'none',
      });
      return client.requestObject(true).then(fail, (err) => {
        expect(err).to.be.instanceof(TypeError);
        expect(err.message).to.eql('requestObject must be a plain object');
      });
    });

    describe('FAPIClient', function () {
      it('includes nbf by default', function () {
        const client = new this.issuer.FAPI1Client(
          {
            client_id: 'identifier',
            request_object_signing_alg: 'PS256',
            token_endpoint_auth_method: 'private_key_jwt',
          },
          this.keystore.toJWKS(true),
        );
        return client.requestObject({}).then((signed) => {
          const { iat, exp, nbf } = JSON.parse(base64url.decode(signed.split('.')[1]));

          expect(iat).to.be.ok;
          expect(exp).to.eql(iat + 300);
          expect(nbf).to.eql(iat);
        });
      });
    });
  });

  describe('#requestObject (encryption when multiple keys match)', function () {
    before(function () {
      this.keystore = new KeyStore();
      return Promise.all([this.keystore.generate('RSA'), this.keystore.generate('RSA')]);
    });

    before(function () {
      this.issuer = new Issuer({
        issuer: 'https://op.example.com',
        jwks_uri: 'https://op.example.com/certs',
      });
    });

    before(function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json, application/jwk-set+json')
        .get('/certs')
        .reply(200, this.keystore.toJWKS());

      return issuerInternal.keystore.call(this.issuer);
    });

    after(nock.cleanAll);

    it("encrypts for issuer using issuer's public key (explicit enc)", function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        request_object_encryption_alg: 'RSA1_5',
        request_object_encryption_enc: 'A128CBC-HS256',
      });

      return client.requestObject({ state: 'foobar' }).then((encrypted) => {
        const parts = encrypted.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'RSA1_5', enc: 'A128CBC-HS256', cty: 'oauth-authz-req+jwt' })
          .and.have.property('kid');
      });
    });

    it("encrypts for issuer using issuer's public key (default enc)", function () {
      const client = new this.issuer.Client({
        client_id: 'identifier',
        request_object_encryption_alg: 'RSA1_5',
      });

      return client.requestObject({ state: 'foobar' }).then((encrypted) => {
        const parts = encrypted.split('.');
        expect(JSON.parse(base64url.decode(parts[0])))
          .to.contain({ alg: 'RSA1_5', enc: 'A128CBC-HS256', cty: 'oauth-authz-req+jwt' })
          .and.have.property('kid');
      });
    });
  });

  describe('#pushedAuthorizationRequest', function () {
    before(function () {
      this.issuer = new Issuer({
        issuer: 'https://op.example.com',
        pushed_authorization_request_endpoint: 'https://op.example.com/par',
      });
      this.client = new this.issuer.Client({
        client_id: 'identifier',
        client_secret: 'secure',
        response_type: ['code'],
        grant_types: ['authorization_code'],
        redirect_uris: ['https://rp.example.com/cb'],
      });
    });

    it('requires the issuer to have pushed_authorization_request_endpoint declared', async () => {
      const issuer = new Issuer({ issuer: 'https://op.example.com' });
      const client = new issuer.Client({ client_id: 'identifier' });

      return client.pushedAuthorizationRequest().then(fail, (error) => {
        expect(error).to.be.instanceof(TypeError);
        expect(error.message).to.eql(
          'pushed_authorization_request_endpoint must be configured on the issuer',
        );
      });
    });

    it('performs an authenticated post and returns the response', async function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            client_id: 'identifier',
            redirect_uri: 'https://rp.example.com/cb',
            response_type: 'code',
            scope: 'openid',
          });
        })
        .post('/par', () => true) // to make sure filteringRequestBody works
        .reply(201, { expires_in: 60, request_uri: 'urn:ietf:params:oauth:request_uri:random' });

      return this.client.pushedAuthorizationRequest().then((response) => {
        expect(response).to.have.property('expires_in', 60);
        expect(response).to.have.property(
          'request_uri',
          'urn:ietf:params:oauth:request_uri:random',
        );
      });
    });

    it('handles incorrect status code', async function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/par')
        .reply(200, { expires_in: 60, request_uri: 'urn:ietf:params:oauth:request_uri:random' });

      return this.client.pushedAuthorizationRequest().then(fail, (error) => {
        expect(error).to.be.instanceof(OPError);
        expect(error).to.have.property('message', 'expected 201 Created, got: 200 OK');
      });
    });

    it('handles request being part of the params', async function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            client_id: 'identifier',
            request: 'jwt',
          });
        })
        .post('/par', () => true) // to make sure filteringRequestBody works
        .reply(201, { expires_in: 60, request_uri: 'urn:ietf:params:oauth:request_uri:random' });

      return this.client.pushedAuthorizationRequest({ request: 'jwt' });
    });

    it('rejects with OPError when part of the response', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/par')
        .reply(400, { error: 'invalid_request', error_description: 'description' });

      return this.client.pushedAuthorizationRequest({ request: 'jwt' }).then(fail, (error) => {
        expect(error).to.be.instanceof(OPError);
        expect(error).to.have.property('error', 'invalid_request');
        expect(error).to.have.property('error_description', 'description');
      });
    });

    it('rejects with RPError when request_uri is missing from the response', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/par')
        .reply(201, { expires_in: 60 });

      return this.client.pushedAuthorizationRequest().then(fail, (error) => {
        expect(error).to.be.instanceof(RPError);
        expect(error).to.have.property('response');
        expect(error).to.have.property(
          'message',
          'expected request_uri in Pushed Authorization Successful Response',
        );
      });
    });

    it('rejects with RPError when request_uri is not a string', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/par')
        .reply(201, { request_uri: null, expires_in: 60 });

      return this.client.pushedAuthorizationRequest().then(fail, (error) => {
        expect(error).to.be.instanceof(RPError);
        expect(error).to.have.property('response');
        expect(error).to.have.property(
          'message',
          'invalid request_uri value in Pushed Authorization Successful Response',
        );
      });
    });

    it('rejects with RPError when expires_in is missing from the response', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/par')
        .reply(201, { request_uri: 'urn:ietf:params:oauth:request_uri:random' });

      return this.client.pushedAuthorizationRequest().then(fail, (error) => {
        expect(error).to.be.instanceof(RPError);
        expect(error).to.have.property('response');
        expect(error).to.have.property(
          'message',
          'expected expires_in in Pushed Authorization Successful Response',
        );
      });
    });

    it('rejects with RPError when expires_in is not a string', function () {
      nock('https://op.example.com')
        .matchHeader('Accept', 'application/json')
        .post('/par')
        .reply(201, { expires_in: null, request_uri: 'urn:ietf:params:oauth:request_uri:random' });

      return this.client.pushedAuthorizationRequest().then(fail, (error) => {
        expect(error).to.be.instanceof(RPError);
        expect(error).to.have.property('response');
        expect(error).to.have.property(
          'message',
          'invalid expires_in value in Pushed Authorization Successful Response',
        );
      });
    });
  });
});

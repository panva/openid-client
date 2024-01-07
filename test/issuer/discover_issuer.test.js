const { expect } = require('chai');
const sinon = require('sinon');
const nock = require('nock');

const { Issuer, custom } = require('../../lib');

const fail = () => {
  throw new Error('expected promise to be rejected');
};

const success = {
  authorization_endpoint: 'https://op.example.com/o/oauth2/v2/auth',
  issuer: 'https://op.example.com',
  jwks_uri: 'https://op.example.com/oauth2/v3/certs',
  token_endpoint: 'https://op.example.com/oauth2/v4/token',
  userinfo_endpoint: 'https://op.example.com/oauth2/v3/userinfo',
};

describe('Issuer#discover()', () => {
  afterEach(nock.cleanAll);

  describe('custom /.well-known', function () {
    it('accepts and assigns the discovered metadata', function () {
      nock('https://op.example.com', { allowUnmocked: true })
        .get('/.well-known/example-configuration')
        .reply(200, success);

      return Issuer.discover('https://op.example.com/.well-known/example-configuration').then(
        function (issuer) {
          expect(issuer).to.have.property(
            'authorization_endpoint',
            'https://op.example.com/o/oauth2/v2/auth',
          );
          expect(issuer).to.have.property('issuer', 'https://op.example.com');
          expect(issuer).to.have.property('jwks_uri', 'https://op.example.com/oauth2/v3/certs');
          expect(issuer).to.have.property(
            'token_endpoint',
            'https://op.example.com/oauth2/v4/token',
          );
          expect(issuer).to.have.property(
            'userinfo_endpoint',
            'https://op.example.com/oauth2/v3/userinfo',
          );
        },
      );
    });
  });

  describe('/.well-known/openid-configuration', function () {
    it('accepts and assigns the discovered metadata', function () {
      nock('https://op.example.com', { allowUnmocked: true })
        .matchHeader('Accept', 'application/json')
        .get('/.well-known/openid-configuration')
        .reply(200, success);

      return Issuer.discover('https://op.example.com/.well-known/openid-configuration').then(
        function (issuer) {
          expect(issuer).to.have.property(
            'authorization_endpoint',
            'https://op.example.com/o/oauth2/v2/auth',
          );
          expect(issuer).to.have.property('issuer', 'https://op.example.com');
          expect(issuer).to.have.property('jwks_uri', 'https://op.example.com/oauth2/v3/certs');
          expect(issuer).to.have.property(
            'token_endpoint',
            'https://op.example.com/oauth2/v4/token',
          );
          expect(issuer).to.have.property(
            'userinfo_endpoint',
            'https://op.example.com/oauth2/v3/userinfo',
          );
        },
      );
    });

    it('can be discovered by ommiting the well-known part', function () {
      nock('https://op.example.com', { allowUnmocked: true })
        .get('/.well-known/openid-configuration')
        .reply(200, {
          issuer: 'https://op.example.com',
        });

      return Issuer.discover('https://op.example.com').then(function (issuer) {
        expect(issuer).to.have.property('issuer', 'https://op.example.com');
      });
    });

    it('discovering issuers with path components (with trailing slash)', function () {
      nock('https://op.example.com', { allowUnmocked: true })
        .get('/oidc/.well-known/openid-configuration')
        .reply(200, {
          issuer: 'https://op.example.com/oidc',
        });

      return Issuer.discover('https://op.example.com/oidc/').then(function (issuer) {
        expect(issuer).to.have.property('issuer', 'https://op.example.com/oidc');
      });
    });

    it('discovering issuers with path components (without trailing slash)', function () {
      nock('https://op.example.com', { allowUnmocked: true })
        .get('/oidc/.well-known/openid-configuration')
        .reply(200, {
          issuer: 'https://op.example.com/oidc',
        });

      return Issuer.discover('https://op.example.com/oidc').then(function (issuer) {
        expect(issuer).to.have.property('issuer', 'https://op.example.com/oidc');
      });
    });

    it('discovering issuers with well known uri including path and query', function () {
      nock('https://op.example.com', { allowUnmocked: true })
        .get('/oidc/.well-known/openid-configuration')
        .query({ foo: 'bar' })
        .reply(200, {
          issuer: 'https://op.example.com/oidc',
        });

      return Issuer.discover(
        'https://op.example.com/oidc/.well-known/openid-configuration?foo=bar',
      ).then(function (issuer) {
        expect(issuer).to.have.property('issuer', 'https://op.example.com/oidc');
      });
    });
  });

  describe('/.well-known/oauth-authorization-server', function () {
    it('accepts and assigns the discovered metadata', function () {
      nock('https://op.example.com', { allowUnmocked: true })
        .get('/.well-known/oauth-authorization-server')
        .reply(200, success);

      return Issuer.discover('https://op.example.com/.well-known/oauth-authorization-server').then(
        function (issuer) {
          expect(issuer).to.have.property(
            'authorization_endpoint',
            'https://op.example.com/o/oauth2/v2/auth',
          );
          expect(issuer).to.have.property('issuer', 'https://op.example.com');
          expect(issuer).to.have.property('jwks_uri', 'https://op.example.com/oauth2/v3/certs');
          expect(issuer).to.have.property(
            'token_endpoint',
            'https://op.example.com/oauth2/v4/token',
          );
          expect(issuer).to.have.property(
            'userinfo_endpoint',
            'https://op.example.com/oauth2/v3/userinfo',
          );
        },
      );
    });

    it('discovering issuers with well known uri including path and query', function () {
      nock('https://op.example.com', { allowUnmocked: true })
        .get('/.well-known/oauth-authorization-server/oauth2')
        .query({ foo: 'bar' })
        .reply(200, {
          issuer: 'https://op.example.com/oauth2',
        });

      return Issuer.discover(
        'https://op.example.com/.well-known/oauth-authorization-server/oauth2?foo=bar',
      ).then(function (issuer) {
        expect(issuer).to.have.property('issuer', 'https://op.example.com/oauth2');
      });
    });
  });

  it('assigns Discovery 1.0 defaults 1/2', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(200, {
        authorization_endpoint: 'https://op.example.com/o/oauth2/v2/auth',
        issuer: 'https://op.example.com',
        jwks_uri: 'https://op.example.com/oauth2/v3/certs',
        token_endpoint: 'https://op.example.com/oauth2/v4/token',
        userinfo_endpoint: 'https://op.example.com/oauth2/v3/userinfo',
      });

    return Issuer.discover('https://op.example.com/.well-known/openid-configuration').then(
      (issuer) => {
        expect(issuer).to.have.property('claims_parameter_supported', false);
        expect(issuer)
          .to.have.property('grant_types_supported')
          .to.eql(['authorization_code', 'implicit']);
        expect(issuer).to.have.property('request_parameter_supported', false);
        expect(issuer).to.have.property('request_uri_parameter_supported', true);
        expect(issuer).to.have.property('require_request_uri_registration', false);
        expect(issuer).to.have.property('response_modes_supported').to.eql(['query', 'fragment']);
        expect(issuer).to.have.property('claim_types_supported').to.eql(['normal']);
        expect(issuer)
          .to.have.property('token_endpoint_auth_methods_supported')
          .to.eql(['client_secret_basic']);
      },
    );
  });

  it('assigns Discovery 1.0 defaults 2/2', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(200, {
        authorization_endpoint: 'https://op.example.com/o/oauth2/v2/auth',
        issuer: 'https://op.example.com',
        jwks_uri: 'https://op.example.com/oauth2/v3/certs',
        token_endpoint: 'https://op.example.com/oauth2/v4/token',
        userinfo_endpoint: 'https://op.example.com/oauth2/v3/userinfo',
      });

    return Issuer.discover('https://op.example.com').then((issuer) => {
      expect(issuer).to.have.property('claims_parameter_supported', false);
      expect(issuer)
        .to.have.property('grant_types_supported')
        .to.eql(['authorization_code', 'implicit']);
      expect(issuer).to.have.property('request_parameter_supported', false);
      expect(issuer).to.have.property('request_uri_parameter_supported', true);
      expect(issuer).to.have.property('require_request_uri_registration', false);
      expect(issuer).to.have.property('response_modes_supported').to.eql(['query', 'fragment']);
      expect(issuer).to.have.property('claim_types_supported').to.eql(['normal']);
      expect(issuer)
        .to.have.property('token_endpoint_auth_methods_supported')
        .to.eql(['client_secret_basic']);
    });
  });

  it('is rejected with OPError upon oidc error', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(500, {
        error: 'server_error',
        error_description: 'bad things are happening',
      });

    return Issuer.discover('https://op.example.com').then(fail, function (error) {
      expect(error.name).to.equal('OPError');
      expect(error).to.have.property('error', 'server_error');
      expect(error).to.have.property('error_description', 'bad things are happening');
    });
  });

  it('is rejected with Error when no absolute URL is provided', function () {
    return Issuer.discover('op.example.com/.well-known/foobar').then(fail, function (error) {
      expect(error.name).to.equal('TypeError');
      expect(error).to.have.property('message', 'only valid absolute URLs can be requested');
    });
  });

  it('is rejected with RPError when error is not a string', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(400, {
        error: {},
        error_description: 'bad things are happening',
      });

    return Issuer.discover('https://op.example.com').then(fail, function (error) {
      expect(error.name).to.equal('OPError');
      expect(error.message).to.eql('expected 200 OK, got: 400 Bad Request');
      expect(error).to.have.property('response');
    });
  });

  it('is rejected with when non 200 is returned', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(500, 'Internal Server Error');

    return Issuer.discover('https://op.example.com').then(fail, function (error) {
      expect(error.name).to.equal('OPError');
      expect(error.message).to.eql('expected 200 OK, got: 500 Internal Server Error');
      expect(error).to.have.property('response');
    });
  });

  it('is rejected with JSON.parse error upon invalid response', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(200, '{"notavalid"}');

    return Issuer.discover('https://op.example.com').then(fail, function (error) {
      expect(error.message).to.match(/in JSON at position 12/);
      expect(error).to.have.property('response');
    });
  });

  it('is rejected when no body is returned', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(200);

    return Issuer.discover('https://op.example.com').then(fail, function (error) {
      expect(error.name).to.equal('OPError');
      expect(error).to.have.property(
        'message',
        'expected 200 OK with body but no body was returned',
      );
    });
  });

  it('is rejected when unepexted status code is returned', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(301);

    return Issuer.discover('https://op.example.com').then(fail, function (error) {
      expect(error.name).to.equal('OPError');
      expect(error).to.have.property('message', 'expected 200 OK, got: 301 Moved Permanently');
    });
  });

  describe('HTTP_OPTIONS', () => {
    afterEach(() => {
      delete Issuer[custom.http_options];
    });

    it('allows for http options to be defined for Issuer.discover calls', async () => {
      nock('https://op.example.com')
        .matchHeader('custom', 'foo')
        .get('/.well-known/openid-configuration')
        .reply(200, success);

      const httpOptions = sinon.stub().callsFake(() => ({ headers: { custom: 'foo' } }));
      Issuer[custom.http_options] = httpOptions;

      await Issuer.discover('https://op.example.com/.well-known/openid-configuration');

      expect(nock.isDone()).to.be.true;
      sinon.assert.callCount(httpOptions, 1);
    });
  });
});
